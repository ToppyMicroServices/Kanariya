import test from "node:test";
import assert from "node:assert/strict";
import vm from "node:vm";
import { randomUUID } from "node:crypto";
import { js } from "../src/viewer.js";

const importPrefix = 'import { getDocument, GlobalWorkerOptions } from "/pdfjs/pdf.min.mjs";\n';
assert.ok(js.startsWith(importPrefix), "the viewer must use the local PDF.js module");
const script = js.slice(importPrefix.length);
const maxBytes = 1048576, maxPagePixels = 4000000, maxTotalPixels = 12000000;
function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}
function viewer(options = {}) {
  const elements = Object.fromEntries(["open", "close", "status", "document"].map(id => [id, {
    hidden: id === "close" || id === "document", disabled: false, textContent: "",
    clientWidth: options.clientWidth ?? 1000, children: [], listeners: new Map(),
    addEventListener(name, fn) { this.listeners.set(name, fn); },
    replaceChildren(...children) { this.children = children; },
    append(child) { this.children.push(child); },
  }]));
  const events = new Map(), requests = [], loadingTasks = [], renderTasks = [], canvases = [], pdfPages = [];
  const stageStarts = new Map(), timers = new Map(), scheduledTimers = [];
  const location = { hash: "#" + randomUUID() }, globalWorkerOptions = {};
  let timerId = 0, pageCount = 0;
  function stage(name) {
    if (!stageStarts.has(name)) stageStarts.set(name, deferred());
    stageStarts.get(name).resolve();
  }
  function canvas() {
    const result = {
      width: 300, height: 150, attributes: new Map(),
      setAttribute(name, value) { this.attributes.set(name, value); },
      getContext(kind) { assert.equal(kind, "2d"); return { canvas: this }; },
    };
    canvases.push(result); return result;
  }
  function page() {
    const result = {
      cleanupCalls: 0,
      getViewport({ scale }) {
        const dimensions = options.pageDimensions ?? { width: 600, height: 800 };
        return { width: dimensions.width * scale, height: dimensions.height * scale };
      },
      render(parameters) {
        stage("render");
        const task = {
          parameters, cancelCalls: 0,
          cancel() { this.cancelCalls++; },
          promise: options.renderResult ? options.renderResult(renderTasks.length + 1, result) : Promise.resolve(),
        };
        renderTasks.push(task); return task;
      },
      cleanup() { this.cleanupCalls++; },
    };
    pdfPages.push(result); return result;
  }
  function getDocument(parameters) {
    stage("loading");
    const pdf = {
      numPages: options.numPages ?? 1,
      getPage(number) {
        pageCount++; stage("page"); const nextPage = page();
        return options.pageResult ? options.pageResult(pageCount, nextPage, number) : Promise.resolve(nextPage);
      },
    };
    const task = {
      parameters, pdf, destroyCalls: 0,
      destroy() { this.destroyCalls++; return Promise.resolve(); },
      promise: options.loadingResult ? options.loadingResult(loadingTasks.length + 1, pdf) : Promise.resolve(pdf),
    };
    loadingTasks.push(task); return task;
  }
  function response(settings = {}) {
    return {
      ok: settings.ok ?? true,
      headers: new Headers({ "content-type": "application/pdf", ...settings.headers }),
      arrayBuffer() {
        stage("body");
        return options.bodyResult ? options.bodyResult() : Promise.resolve(new Uint8Array([37, 80, 68, 70]).buffer);
      },
    };
  }
  vm.runInNewContext(script, {
    document: { getElementById: id => elements[id], createElement: kind => { assert.equal(kind, "canvas"); return canvas(); } },
    location, AbortController, Uint8Array, devicePixelRatio: options.devicePixelRatio ?? 1,
    getDocument, GlobalWorkerOptions: globalWorkerOptions, crypto: { randomUUID },
    addEventListener: (name, fn) => events.set(name, fn),
    fetch: (url, requestOptions) => {
      requests.push({ url, options: requestOptions }); stage("fetch");
      return options.fetchResult ? options.fetchResult(requests.length, response) : Promise.resolve(response());
    },
    setTimeout: (callback, milliseconds) => {
      const timer = { id: ++timerId, callback, milliseconds };
      timers.set(timer.id, timer); scheduledTimers.push(timer); return timer.id;
    },
    clearTimeout: id => timers.delete(id),
  });
  return {
    ...elements, location, requests, loadingTasks, renderTasks, canvases, pdfPages, timers, scheduledTimers,
    globalWorkerOptions, response,
    wait: name => {
      if (!stageStarts.has(name)) stageStarts.set(name, deferred());
      return stageStarts.get(name).promise;
    },
    openDocument: () => elements.open.listeners.get("click")(),
    closeDocument: () => elements.close.listeners.get("click")(),
    event: name => events.get(name)(),
  };
}
function close(v, event) { if (event === "close") v.closeDocument(); else v.event(event); }
function assertClosed(v) {
  assert.equal(v.document.hidden, true); assert.equal(v.document.children.length, 0);
  assert.equal(v.close.hidden, true); assert.equal(v.open.disabled, false);
  for (const canvas of v.canvases) { assert.equal(canvas.width, 0); assert.equal(canvas.height, 0); }
}

test("open uses an uncached same-origin POST and distinguishes queued from rendered", async () => {
  const response = deferred(), rendering = deferred();
  const v = viewer({ fetchResult: () => response.promise, renderResult: () => rendering.promise });
  const opening = v.openDocument();
  assert.equal(v.open.disabled, true); assert.equal(v.close.hidden, false); assert.equal(v.document.hidden, true);
  const { url, options } = v.requests[0];
  assert.equal(url, "/v1/documents/" + v.location.hash.slice(1) + "/open");
  assert.equal(options.method, "POST"); assert.equal(options.credentials, "same-origin");
  assert.equal(options.cache, "no-store"); assert.equal(options.redirect, "error");
  assert.match(JSON.parse(options.body).requestId, /^[0-9a-f-]{36}$/);
  assert.equal(v.globalWorkerOptions.workerSrc, "/pdfjs/pdf.worker.min.mjs");
  response.resolve(v.response()); await v.wait("render");
  assert.match(v.status.textContent, /通知を待機列に登録しました。文書を表示しています/);
  assert.equal(v.document.children.length, 0); assert.equal(v.document.hidden, true);
  rendering.resolve(); await opening;
  assert.equal(v.document.children.length, 1); assert.equal(v.document.hidden, false); assert.equal(v.open.disabled, false);
  assert.equal(v.canvases[0].attributes.get("aria-label"), "1 / 1 ページ");
  assert.equal(v.pdfPages[0].cleanupCalls, 1);
  assert.equal(v.status.textContent, "文書を表示しました（1ページ）。復号操作を記録し、通知を待機列に登録しました。");
  assert.equal(v.timers.size, 0);
});
for (const event of ["close", "pagehide", "hashchange"]) {
  test(`${event} prevents a late fetch from reopening the document even if abort is ignored`, async () => {
    const result = deferred(), v = viewer({ fetchResult: () => result.promise }), opening = v.openDocument();
    close(v, event); const closedStatus = v.status.textContent;
    assert.equal(v.requests[0].options.signal.aborted, true);
    result.resolve(v.response()); await opening;
    assertClosed(v); assert.equal(v.loadingTasks.length, 0); assert.equal(v.status.textContent, closedStatus);
  });
  test(`${event} during body reading wipes late bytes and prevents rendering`, async () => {
    const body = deferred(), bytes = new Uint8Array([1, 2, 3]);
    const v = viewer({ bodyResult: () => body.promise }), opening = v.openDocument();
    await v.wait("body"); close(v, event); const closedStatus = v.status.textContent;
    body.resolve(bytes.buffer); await opening;
    assertClosed(v); assert.equal(v.loadingTasks.length, 0); assert.deepEqual([...bytes], [0, 0, 0]);
    assert.equal(v.status.textContent, closedStatus);
  });
  for (const phase of ["loading", "page", "render"]) {
    test(`${event} during ${phase} prevents late canvas insertion when cancellation is ignored`, async () => {
      const paused = deferred(); let complete;
      const hook = phase === "loading" ? "loadingResult" : phase === "page" ? "pageResult" : "renderResult";
      const v = viewer({ [hook]: (_count, value) => { complete = value; return paused.promise; } });
      const opening = v.openDocument(); await v.wait(phase); close(v, event); const closedStatus = v.status.textContent;
      assert.ok(v.loadingTasks[0].destroyCalls >= 1);
      if (phase === "render") assert.ok(v.renderTasks[0].cancelCalls >= 1);
      paused.resolve(phase === "render" ? undefined : complete); await opening;
      assertClosed(v); assert.equal(v.status.textContent, closedStatus);
    });
  }
  test(`${event} clears the DOM and canvas backing storage after display`, async () => {
    const v = viewer({ numPages: 2 }); await v.openDocument();
    assert.equal(v.document.children.length, 2); assert.ok(v.canvases.every(canvas => canvas.width > 0 && canvas.height > 0));
    close(v, event); assertClosed(v); assert.ok(v.loadingTasks[0].destroyCalls >= 1);
  });
}
for (const phase of ["fetch", "body", "render"]) {
  test(`a changed fragment rejects an old ${phase} before hashchange runs`, async () => {
    const paused = deferred(), bytes = new Uint8Array([1, 2, 3]);
    const options = phase === "fetch" ? { fetchResult: () => paused.promise }
      : phase === "body" ? { bodyResult: () => paused.promise } : { renderResult: () => paused.promise };
    const v = viewer(options), opening = v.openDocument(); await v.wait(phase);
    v.location.hash = "#" + randomUUID();
    paused.resolve(phase === "fetch" ? v.response() : phase === "body" ? bytes.buffer : undefined); await opening;
    assert.equal(v.document.children.length, 0); assert.equal(v.document.hidden, true);
    if (phase === "body") assert.deepEqual([...bytes], [0, 0, 0]);
    v.event("hashchange"); assertClosed(v); assert.equal(v.requests[0].options.signal.aborted, true);
  });
}
for (const fails of [false, true]) {
  test(`a stale ${fails ? "failed" : "successful"} request cannot change a newer open's controls`, async () => {
    const first = deferred(), second = deferred();
    const v = viewer({ fetchResult: count => count === 1 ? first.promise : second.promise });
    const opening1 = v.openDocument(); v.closeDocument(); const opening2 = v.openDocument();
    const loadingStatus = v.status.textContent;
    if (fails) first.reject(new Error("synthetic failure")); else first.resolve(v.response());
    await opening1;
    assert.equal(v.open.disabled, true); assert.equal(v.close.hidden, false); assert.equal(v.status.textContent, loadingStatus);
    assert.equal(v.document.children.length, 0);
    assert.notEqual(JSON.parse(v.requests[0].options.body).requestId, JSON.parse(v.requests[1].options.body).requestId);
    second.resolve(v.response()); await opening2;
    assert.equal(v.document.children.length, 1); assert.equal(v.document.hidden, false); assert.equal(v.open.disabled, false);
  });
  test(`a stale ${fails ? "failed" : "successful"} render cannot change a newer open's controls`, async () => {
    const rendering = deferred(), second = deferred();
    const v = viewer({
      fetchResult: (count, response) => count === 1 ? Promise.resolve(response()) : second.promise,
      renderResult: count => count === 1 ? rendering.promise : Promise.resolve(),
    });
    const opening1 = v.openDocument(); await v.wait("render");
    v.closeDocument(); const opening2 = v.openDocument(), loadingStatus = v.status.textContent;
    if (fails) rendering.reject(new Error("synthetic old render failure")); else rendering.resolve();
    await opening1;
    assert.equal(v.open.disabled, true); assert.equal(v.close.hidden, false); assert.equal(v.status.textContent, loadingStatus);
    assert.equal(v.document.children.length, 0); assert.equal(v.canvases[0].width, 0); assert.equal(v.canvases[0].height, 0);
    second.resolve(v.response()); await opening2;
    assert.equal(v.document.children.length, 1); assert.equal(v.document.children[0], v.canvases[1]);
    assert.equal(v.document.hidden, false); assert.equal(v.open.disabled, false);
  });
}
test("a rejected open restores controls without claiming registration", async () => {
  const v = viewer({ fetchResult: (_count, response) => Promise.resolve(response({ ok: false })) });
  await v.openDocument(); assertClosed(v); assert.equal(v.loadingTasks.length, 0);
  assert.match(v.status.textContent, /文書を開けませんでした/); assert.doesNotMatch(v.status.textContent, /登録は完了/);
});
for (const phase of ["loading", "page", "render"]) {
  test(`a ${phase} failure after registration keeps the completed decryption and queue wording`, async () => {
    const hook = phase === "loading" ? "loadingResult" : phase === "page" ? "pageResult" : "renderResult";
    const v = viewer({ [hook]: () => Promise.reject(new Error("synthetic display failure")) });
    await v.openDocument(); assertClosed(v);
    assert.equal(v.status.textContent, "復号操作と通知登録は完了しましたが、文書を表示できませんでした。");
    assert.ok(v.loadingTasks[0].destroyCalls >= 1);
  });
}
for (const numPages of [0, 21, 1.5, NaN]) {
  test(`invalid PDF page count ${numPages} is rejected before page rendering`, async () => {
    const v = viewer({ numPages }); await v.openDocument(); assertClosed(v);
    assert.equal(v.pdfPages.length, 0); assert.equal(v.status.textContent, "復号操作と通知登録は完了しましたが、文書を表示できませんでした。");
  });
}
for (const length of [0, maxBytes + 1]) {
  test(`a ${length}-byte PDF body is wiped and rejected before PDF.js receives it`, async () => {
    const bytes = new Uint8Array(length).fill(19), v = viewer({ bodyResult: () => Promise.resolve(bytes.buffer) });
    await v.openDocument(); assertClosed(v); assert.equal(v.loadingTasks.length, 0);
    assert.equal(bytes.every(byte => byte === 0), true);
  });
}
for (const declared of [String(maxBytes + 1), "-1", "no-length", "1.5"]) {
  test(`invalid declared body length ${declared} stops before body reading`, async () => {
    let bodyReads = 0;
    const v = viewer({ fetchResult: (_count, response) => Promise.resolve(response({ headers: { "content-length": declared } })), bodyResult: () => { bodyReads++; return Promise.resolve(new ArrayBuffer(4)); } });
    await v.openDocument(); assertClosed(v); assert.equal(bodyReads, 0); assert.equal(v.loadingTasks.length, 0);
  });
}
for (const numPages of [3, 20]) {
  test(`${numPages} large pages fit both the per-page and total canvas pixel limits`, async () => {
    const v = viewer({ numPages, pageDimensions: { width: 1000, height: 2000 }, devicePixelRatio: 2 });
    await v.openDocument(); assert.equal(v.document.children.length, numPages);
    const sizes = v.canvases.map(canvas => canvas.width * canvas.height);
    assert.ok(sizes.every(pixels => pixels > 0 && pixels <= maxPagePixels));
    assert.ok(sizes.reduce((sum, pixels) => sum + pixels, 0) <= maxTotalPixels);
    v.closeDocument(); assertClosed(v);
  });
}
for (const dimensions of [{ width: Infinity, height: 100 }, { width: 0, height: 100 }, { width: 100, height: NaN }]) {
  test(`invalid page dimensions ${dimensions.width} x ${dimensions.height} cannot allocate a canvas`, async () => {
    const v = viewer({ pageDimensions: dimensions }); await v.openDocument();
    assertClosed(v); assert.equal(v.canvases.length, 0);
  });
}
for (const registered of [false, true]) {
  test(`the thirty-second timeout ${registered ? "after" : "before"} registration preserves accurate status`, async () => {
    const paused = deferred(); let complete;
    const v = viewer(registered ? { loadingResult: (_count, pdf) => { complete = pdf; return paused.promise; } } : { fetchResult: () => paused.promise });
    const opening = v.openDocument(); await v.wait(registered ? "loading" : "fetch");
    assert.equal(v.scheduledTimers.length, 1); assert.equal(v.scheduledTimers[0].milliseconds, 30000);
    v.scheduledTimers[0].callback(); assertClosed(v); assert.equal(v.timers.size, 0);
    const expected = registered ? "復号操作と通知登録は完了しましたが、表示が時間内に完了しませんでした。" : "処理が時間内に完了しませんでした。サービスの状態をご確認ください。";
    assert.equal(v.status.textContent, expected);
    paused.resolve(registered ? complete : v.response()); await opening;
    assertClosed(v); assert.equal(v.status.textContent, expected);
    if (registered) assert.ok(v.loadingTasks[0].destroyCalls >= 1);
  });
}
test("a render timeout cancels the task and clears a previously displayed page", async () => {
  const paused = deferred(), secondRenderStarted = deferred();
  const v = viewer({ numPages: 2, renderResult: count => {
    if (count === 2) { secondRenderStarted.resolve(); return paused.promise; }
    return Promise.resolve();
  } });
  const opening = v.openDocument();
  await secondRenderStarted.promise;
  assert.equal(v.renderTasks.length, 2);
  assert.equal(v.document.children.length, 1);
  v.scheduledTimers[0].callback(); assertClosed(v); assert.ok(v.renderTasks[1].cancelCalls >= 1);
  const expected = "復号操作と通知登録は完了しましたが、表示が時間内に完了しませんでした。";
  assert.equal(v.status.textContent, expected);
  paused.resolve(); await opening; assertClosed(v); assert.equal(v.status.textContent, expected);
});
test("an old queued timeout callback cannot close a newer open", async () => {
  const first = deferred(), second = deferred();
  const v = viewer({ fetchResult: count => count === 1 ? first.promise : second.promise });
  const opening1 = v.openDocument(), staleTimer = v.scheduledTimers[0];
  v.closeDocument(); const opening2 = v.openDocument(), loadingStatus = v.status.textContent;
  staleTimer.callback();
  assert.equal(v.open.disabled, true); assert.equal(v.status.textContent, loadingStatus);
  assert.equal(v.requests[1].options.signal.aborted, false);
  first.resolve(v.response()); await opening1;
  second.resolve(v.response()); await opening2;
  assert.equal(v.document.children.length, 1); assert.equal(v.document.hidden, false);
});
