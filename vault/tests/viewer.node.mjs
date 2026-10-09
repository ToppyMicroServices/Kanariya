import test from "node:test";
import assert from "node:assert/strict";
import vm from "node:vm";
import { randomUUID } from "node:crypto";
import { js, passwordJs, html, passwordHtml } from "../src/viewer.js";

const importPrefix = 'import { getDocument, GlobalWorkerOptions } from "/pdfjs/pdf.min.mjs";\n';
assert.ok(js.startsWith(importPrefix), "the viewer must use the local PDF.js module");
const script = js.slice(importPrefix.length);
const passwordImportPrefix = 'import { getDocument, GlobalWorkerOptions } from "/p/assets/pdfjs/pdf.min.mjs";\n';
assert.ok(passwordJs.startsWith(passwordImportPrefix));
const passwordScript = passwordJs.slice(passwordImportPrefix.length);
const maxBytes = 1048576, maxPagePixels = 4000000, maxTotalPixels = 12000000;
function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}
function viewer(options = {}) {
  const elements = Object.fromEntries(["open", "close", "download", "status", "deadline", "document", "unlock-form", "password", "unlock", "logout"].map(id => [id, {
    hidden: id === "close" || id === "document", disabled: false, textContent: "", value: "",
    clientWidth: options.clientWidth ?? 1000, children: [], listeners: new Map(),
    addEventListener(name, fn) { this.listeners.set(name, fn); },
    replaceChildren(...children) { this.children = children; },
    append(child) { this.children.push(child); },
  }]));
  const events = new Map(), requests = [], loadingTasks = [], renderTasks = [], canvases = [], pdfPages = [];
  const downloads = [], objectURLs = new Map();
  const stageStarts = new Map(), timers = new Map(), scheduledTimers = [];
  const id = randomUUID(), now = options.now ?? 1800000000000;
  const location = { hash: options.passwordMode ? "" : "#" + id, pathname: options.passwordMode ? "/p/" + id : "/", search: "" }, globalWorkerOptions = {};
  const clock = { now };
  const history = Object.fromEntries(["pushState", "replaceState"].map(method => [method, function (_state, _unused, url) {
    assert.equal(this, history); if (url === undefined) return;
    const next = new URL(url, "https://viewer.example" + location.pathname + location.search + location.hash);
    location.pathname = next.pathname; location.search = next.search; location.hash = next.hash;
  }]));
  const browserDocument = { hidden: false, body: { append() {} }, getElementById: id => elements[id], createElement: kind => {
    if (kind === "a") return { href: "", download: "", remove() {}, click() { downloads.push({ href: this.href, filename: this.download, blob: objectURLs.get(this.href) }); } };
    assert.equal(kind, "canvas"); return canvas();
  }, addEventListener: (name, fn) => events.set(name, fn) };
  function sessionResponse(settings = {}) {
    return { ok: settings.ok ?? true, headers: new Headers({ "content-type": "application/json", ...settings.headers }), json: () => Promise.resolve(settings.value ?? { expiresAt: clock.now + 600000, sessionExpiresAt: clock.now + 300000 }) };
  }
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
      headers: new Headers({ "content-type": "application/pdf", "x-vault-expires-at": String(clock.now + 600000), ...(options.passwordMode ? { "x-vault-session-expires-at": String(clock.now + 300000) } : {}), ...settings.headers }),
      arrayBuffer() {
        stage("body");
        return options.bodyResult ? options.bodyResult() : Promise.resolve(new Uint8Array([37, 80, 68, 70]).buffer);
      },
    };
  }
  vm.runInNewContext(options.passwordMode ? passwordScript : script, {
    document: browserDocument, Date: { now: () => clock.now },
    location, history, AbortController, Uint8Array, Blob, URL: {
      createObjectURL(blob) { const url = "blob:https://viewer.example/" + randomUUID(); objectURLs.set(url, blob); return url; },
      revokeObjectURL(url) { objectURLs.delete(url); },
    }, devicePixelRatio: options.devicePixelRatio ?? 1,
    getDocument, GlobalWorkerOptions: globalWorkerOptions, crypto: { randomUUID },
    addEventListener: (name, fn) => events.set(name, fn),
    fetch: (url, requestOptions) => {
      requests.push({ url, options: requestOptions }); stage("fetch");
      return options.fetchResult ? options.fetchResult(requests.length, response, sessionResponse, url, requestOptions) : Promise.resolve(url.endsWith("/open") ? response() : sessionResponse());
    },
    setTimeout: (callback, milliseconds) => {
      const timer = { id: ++timerId, callback, milliseconds };
      timers.set(timer.id, timer); scheduledTimers.push(timer); return timer.id;
    },
    clearTimeout: id => timers.delete(id),
  });
  return {
    ...elements, location, requests, loadingTasks, renderTasks, canvases, pdfPages, timers, scheduledTimers, downloads, objectURLs,
    globalWorkerOptions, response, sessionResponse, browserDocument, clock, id, history,
    wait: name => {
      if (!stageStarts.has(name)) stageStarts.set(name, deferred());
      return stageStarts.get(name).promise;
    },
    openDocument: () => elements.open.listeners.get("click")(),
    closeDocument: () => elements.close.listeners.get("click")(),
    downloadDocument: () => elements.download.listeners.get("click")(),
    event: (name, value = {}) => events.get(name)(value),
    unlockDocument: (password = "synthetic-shared-password") => { elements.password.value = password; return elements["unlock-form"].listeners.get("submit")({ preventDefault() {} }); },
    logOutDocument: () => elements.logout.listeners.get("click")(),
    advance: milliseconds => { clock.now += milliseconds; },
    fireTimer: async milliseconds => {
      const timer = [...timers.values()].find(timer => timer.milliseconds === milliseconds);
      assert.ok(timer, "expected a scheduled " + milliseconds + "ms timer");
      timers.delete(timer.id); return timer.callback();
    },
  };
}
function close(v, event) { if (event === "close") v.closeDocument(); else { if (event === "visibilitychange") v.browserDocument.hidden = true; v.event(event); } }
function assertClosed(v, locked = false) {
  assert.equal(v.document.hidden, true); assert.equal(v.document.children.length, 0);
  assert.equal(v.close.hidden, true); assert.equal(v.open.disabled, locked);
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
  assert.match(v.status.textContent, /文書提供者への通知を受け付けました。文書を表示しています/);
  assert.equal(v.document.children.length, 0); assert.equal(v.document.hidden, true);
  rendering.resolve(); await opening;
  assert.equal(v.document.children.length, 1); assert.equal(v.document.hidden, false); assert.equal(v.open.disabled, false);
  assert.equal(v.canvases[0].attributes.get("aria-label"), "1 / 1 ページ");
  assert.equal(v.pdfPages[0].cleanupCalls, 1);
  assert.equal(v.status.textContent, "文書を表示しました（1ページ）。閲覧を記録し、文書提供者への通知を受け付けました。");
  assert.equal(v.timers.size, 1); // Policy expiry remains armed while displayed.
});
for (const event of ["close", "pagehide", "hashchange", "popstate", "visibilitychange"]) {
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
    assert.equal(v.status.textContent, "閲覧の記録と通知の受付は完了しましたが、文書を表示できませんでした。");
    assert.ok(v.loadingTasks[0].destroyCalls >= 1);
  });
}
for (const numPages of [0, 21, 1.5, NaN]) {
  test(`invalid PDF page count ${numPages} is rejected before page rendering`, async () => {
    const v = viewer({ numPages }); await v.openDocument(); assertClosed(v);
    assert.equal(v.pdfPages.length, 0); assert.equal(v.status.textContent, "閲覧の記録と通知の受付は完了しましたが、文書を表示できませんでした。");
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
    assert.equal(v.scheduledTimers.length, registered ? 2 : 1); assert.equal(v.scheduledTimers[0].milliseconds, 30000);
    v.scheduledTimers[0].callback(); assertClosed(v); assert.equal(v.timers.size, 0);
    const expected = registered ? "閲覧の記録と通知の受付は完了しましたが、表示が時間内に完了しませんでした。" : "処理が時間内に完了しませんでした。サービスの状態をご確認ください。";
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
  const expected = "閲覧の記録と通知の受付は完了しましたが、表示が時間内に完了しませんでした。";
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

test("both pages state copy limitations and keep Access and shared-password entry points distinct", () => {
  assert.match(html, /認証済みアカウント/); assert.doesNotMatch(html, /unlock-form/);
  assert.match(passwordHtml, /閲覧用パスワード/); assert.match(passwordHtml, /id="unlock-form"/);
  assert.match(passwordHtml, /type="password" autocomplete="off"/);
  assert.match(passwordHtml, /id="open" type="button" disabled/);
  assert.match(passwordHtml, /src="\/p\/assets\/viewer.js"/);
  assert.match(passwordHtml, /href="\/p\/assets\/viewer.css"/);
  for (const source of [html, passwordHtml]) {
    assert.match(source, /保存済みのPDFやスクリーンショットには閲覧期限は適用されず、回収もできません/);
    assert.doesNotMatch(source, /PDF暗号化パスワード|type="file"|download=|window.print/);
  }
  for (const source of [js, passwordJs]) assert.doesNotMatch(source, /localStorage|sessionStorage|indexedDB|document.cookie|console\./);
});

test("password unlock erases the input immediately and does not open or audit a document", async () => {
  const first = deferred(), v = viewer({ passwordMode: true, fetchResult: () => first.promise });
  assert.equal(v.open.disabled, true); assert.equal(v.logout.hidden, true);
  const unlocking = v.unlockDocument("not-a-PDF-encryption-password");
  assert.equal(v.password.value, ""); assert.equal(v.unlock.disabled, true); assert.equal(v.password.disabled, true);
  const { url, options } = v.requests[0];
  assert.equal(url, "/p/" + v.id + "/session"); assert.equal(options.method, "POST");
  assert.equal(options.headers["content-type"], "application/json");
  assert.equal(options.credentials, "same-origin"); assert.equal(options.cache, "no-store"); assert.equal(options.redirect, "error");
  assert.deepEqual(JSON.parse(options.body), { password: "not-a-PDF-encryption-password" });
  first.resolve(v.sessionResponse()); await unlocking;
  assert.equal(v.requests.length, 1); assert.equal(v.loadingTasks.length, 0); assert.equal(v.open.disabled, false);
  assert.equal(v["unlock-form"].hidden, true); assert.equal(v.logout.hidden, false); assert.equal(v.password.value, "");
  assert.match(v.status.textContent, /認証が完了しました/); assert.equal(v.globalWorkerOptions.workerSrc, "/p/assets/pdfjs/pdf.worker.min.mjs");
});

test("password Open requires explicit unlock, then uses a fresh same-origin audited POST", async () => {
  const v = viewer({ passwordMode: true });
  await v.openDocument(); assert.equal(v.requests.length, 0);
  await v.unlockDocument(); await v.openDocument();
  const { url, options } = v.requests[1];
  assert.equal(url, "/p/" + v.id + "/open"); assert.equal(options.method, "POST");
  assert.deepEqual(Object.keys(JSON.parse(options.body)), ["requestId"]);
  assert.match(JSON.parse(options.body).requestId, /^[0-9a-f-]{36}$/);
  assert.equal(options.headers["content-type"], "application/json");
  assert.equal(options.credentials, "same-origin"); assert.equal(options.cache, "no-store"); assert.equal(options.redirect, "error");
  assert.equal(v.loadingTasks[0].parameters.standardFontDataUrl, "/p/assets/pdfjs/standard_fonts/");
  assert.equal(v.document.hidden, false); assert.equal(v.open.disabled, false);
});

for (const value of [null, "", "wrong", "1.5", "Infinity", "1800000000000", "9007199254740992"]) {
  test(`invalid Access expiry header ${value} fails closed before PDF parsing`, async () => {
    const v = viewer({ fetchResult: (_n, response) => Promise.resolve(response({ headers: { "x-vault-expires-at": value } })) });
    await v.openDocument(); assertClosed(v); assert.equal(v.loadingTasks.length, 0);
    assert.match(v.status.textContent, /閲覧の記録と通知の受付は完了/);
  });
}

test("Access pages and PDF bytes are cleared at the server policy expiry", async () => {
  const bytes = new Uint8Array([37, 80, 68, 70]);
  const v = viewer({ bodyResult: () => Promise.resolve(bytes.buffer), fetchResult: (_n, response) => Promise.resolve(response({ headers: { "x-vault-expires-at": "1800000000100" } })) });
  await v.openDocument(); assert.equal(v.document.hidden, false);
  v.advance(100); await v.fireTimer(100);
  assertClosed(v); assert.deepEqual([...bytes], [0, 0, 0, 0]); assert.match(v.status.textContent, /有効期限が切れた/);
});

for (const passwordMode of [false, true]) {
  test(`${passwordMode ? "password" : "Access"} expiry during an ignored slow render cannot expose a late canvas`, async () => {
    const rendered = deferred(), v = viewer({ passwordMode, renderResult: () => rendered.promise });
    if (passwordMode) await v.unlockDocument();
    const opening = v.openDocument(); await v.wait("render");
    v.advance(passwordMode ? 300000 : 600000);
    await v.fireTimer(passwordMode ? 300000 : 600000);
    const expiredStatus = v.status.textContent;
    rendered.resolve(); await opening; assertClosed(v, passwordMode); assert.equal(v.status.textContent, expiredStatus);
  });
}

for (const settings of [
  { ok: false }, { headers: { "content-type": "text/html" } },
  { value: { expiresAt: 1800000600000 } },
  { value: { expiresAt: 1800000600000, sessionExpiresAt: 1800000000000 } },
  { value: { expiresAt: "1800000600000", sessionExpiresAt: "invalid" } },
]) {
  test(`invalid password unlock response ${JSON.stringify(settings)} leaves the reader locked`, async () => {
    const v = viewer({ passwordMode: true, fetchResult: (_n, _response, sessionResponse) => Promise.resolve(sessionResponse(settings)) });
    await v.unlockDocument(); assertClosed(v, true); assert.equal(v.password.value, "");
    assert.equal(v.unlock.disabled, false); assert.equal(v.logout.hidden, true); assert.equal(v.timers.size, 0);
    assert.match(v.status.textContent, /認証できませんでした/);
  });
}

for (const event of ["pagehide", "hashchange", "popstate", "visibilitychange"]) {
  test(`${event} cancels a late password unlock without restoring controls or retaining the password`, async () => {
    const first = deferred(), v = viewer({ passwordMode: true, fetchResult: () => first.promise });
    const unlocking = v.unlockDocument(); close(v, event); const status = v.status.textContent;
    assert.equal(v.requests[0].options.signal.aborted, true);
    first.resolve(v.sessionResponse()); await unlocking;
    assertClosed(v, true); assert.equal(v.password.value, ""); assert.equal(v.status.textContent, status);
    assert.equal(v.logout.hidden, true); assert.equal(v.timers.size, 0);
  });
  test(`${event} clears password pages, cancels the revocation timer, and requires a new unlock`, async () => {
    const v = viewer({ passwordMode: true }); await v.unlockDocument(); await v.openDocument();
    close(v, event); assertClosed(v, true); assert.equal(v.timers.size, 0); assert.equal(v["unlock-form"].hidden, false);
    assert.equal(v.logout.hidden, true); assert.equal(v.password.value, "");
  });
}

for (const phase of ["fetch", "body", "loading", "page", "render"]) {
  test(`a changed password document path rejects stale ${phase} work without waiting for navigation events`, async () => {
    const paused = deferred(), bytes = new Uint8Array([1, 2, 3]); let complete;
    const hook = phase === "loading" ? "loadingResult" : phase === "page" ? "pageResult" : "renderResult";
    const options = phase === "fetch" ? { fetchResult: (n, _r, sr) => n === 1 ? Promise.resolve(sr()) : paused.promise }
      : phase === "body" ? { bodyResult: () => paused.promise }
      : { [hook]: (_n, value) => { complete = value; return paused.promise; } };
    const v = viewer({ passwordMode: true, ...options }); await v.unlockDocument();
    const opening = v.openDocument(); await v.wait(phase);
    v.location.pathname = "/p/" + randomUUID();
    paused.resolve(phase === "fetch" ? v.response() : phase === "body" ? bytes.buffer : phase === "render" ? undefined : complete);
    await opening; assertClosed(v, true); assert.equal(v.timers.size, 0);
    if (phase === "body") assert.deepEqual([...bytes], [0, 0, 0]);
  });
}

test("a password session expires while unlocked even before Open", async () => {
  const v = viewer({ passwordMode: true }); await v.unlockDocument();
  v.advance(300000); await v.fireTimer(300000);
  assertClosed(v, true); assert.equal(v.requests.length, 1); assert.match(v.status.textContent, /有効期限が切れた/);
});

test("the earlier document expiry wins over the password session deadline", async () => {
  const v = viewer({ passwordMode: true, fetchResult: (_n, response, sessionResponse, url) => Promise.resolve(url.endsWith("/open") ? response({ headers: { "x-vault-expires-at": "1800000000050" } }) : sessionResponse()) });
  await v.unlockDocument(); await v.openDocument();
  v.advance(50); await v.fireTimer(50); assertClosed(v, true); assert.equal(v.timers.size, 0);
});

test("password display checks revocation every fifteen seconds without decrypting again", async () => {
  const v = viewer({ passwordMode: true }); await v.unlockDocument(); await v.openDocument();
  v.advance(15000); await v.fireTimer(15000);
  const { url, options } = v.requests[2];
  assert.equal(url, "/p/" + v.id + "/status"); assert.equal(options.method, "GET"); assert.equal(options.body, undefined);
  assert.equal(options.credentials, "same-origin"); assert.equal(options.cache, "no-store"); assert.equal(options.redirect, "error");
  assert.equal(v.document.hidden, false); assert.equal(v.loadingTasks.length, 1);
  assert.ok([...v.timers.values()].some(timer => timer.milliseconds === 15000));
  assert.ok([...v.timers.values()].some(timer => timer.milliseconds === 285000), "status cannot extend the original session deadline");
});

for (const failure of ["revoked", "malformed", "network"]) {
  test(`${failure} password status wipes displayed pages and locks the reader`, async () => {
    const v = viewer({ passwordMode: true, fetchResult: (_n, response, sessionResponse, url) => {
      if (url.endsWith("/status")) return failure === "network" ? Promise.reject(new Error("synthetic"))
        : Promise.resolve(sessionResponse(failure === "revoked" ? { ok: false } : { value: {} }));
      return Promise.resolve(url.endsWith("/open") ? response() : sessionResponse());
    } });
    await v.unlockDocument(); await v.openDocument();
    v.advance(15000); await v.fireTimer(15000); assertClosed(v, true); assert.equal(v.timers.size, 0);
    assert.match(v.status.textContent, /閲覧権限を確認できなかった/);
  });
}

test("a hung status request fails closed and its late success cannot re-enable Open", async () => {
  const pending = deferred(), v = viewer({ passwordMode: true, fetchResult: (_n, response, sessionResponse, url) => url.endsWith("/status") ? pending.promise : Promise.resolve(url.endsWith("/open") ? response() : sessionResponse()) });
  await v.unlockDocument(); await v.openDocument();
  v.advance(15000); const checking = v.fireTimer(15000);
  v.advance(10000); await v.fireTimer(10000); const status = v.status.textContent;
  assertClosed(v, true); assert.equal(v.requests[2].options.signal.aborted, true);
  pending.resolve(v.sessionResponse()); await checking;
  assertClosed(v, true); assert.equal(v.status.textContent, status); assert.equal(v.timers.size, 0);
});

test("a stale revocation failure cannot lock a newer open or change its controls", async () => {
  const pending = deferred(), v = viewer({ passwordMode: true, fetchResult: (_n, response, sessionResponse, url) => url.endsWith("/status") ? pending.promise : Promise.resolve(url.endsWith("/open") ? response() : sessionResponse()) });
  await v.unlockDocument(); await v.openDocument(); v.advance(15000); const checking = v.fireTimer(15000);
  v.closeDocument(); await v.openDocument(); const status = v.status.textContent;
  pending.resolve(v.sessionResponse({ ok: false })); await checking;
  assert.equal(v.document.hidden, false); assert.equal(v.open.disabled, false); assert.equal(v.status.textContent, status);
  assert.equal(v.document.children[0], v.canvases[1]);
});

test("logout clears pages immediately, sends the exact JSON delete, and blocks concurrent unlock", async () => {
  const pending = deferred(), v = viewer({ passwordMode: true, fetchResult: (_n, response, sessionResponse, url, options) => options.method === "DELETE" ? pending.promise : Promise.resolve(url.endsWith("/open") ? response() : sessionResponse()) });
  await v.unlockDocument(); await v.openDocument(); const loggingOut = v.logOutDocument();
  assertClosed(v, true); assert.equal(v.logout.disabled, true); assert.equal(v.unlock.disabled, true);
  const { url, options } = v.requests[2];
  assert.equal(url, "/p/" + v.id + "/session"); assert.equal(options.method, "DELETE"); assert.equal(options.body, "{}");
  assert.equal(options.headers["content-type"], "application/json"); assert.equal(options.credentials, "same-origin");
  await v.unlockDocument(); assert.equal(v.requests.length, 3); assert.equal(v.password.value, "");
  pending.resolve(v.sessionResponse()); await loggingOut; assertClosed(v, true);
  assert.equal(v.unlock.disabled, false); assert.equal(v.logout.hidden, true); assert.equal(v.status.textContent, "ログアウトしました。");
});

for (const fails of [false, true]) {
  test(`a stale ${fails ? "failed" : "successful"} unlock cannot change a newer unlock's controls`, async () => {
    const old = deferred(), next = deferred(), v = viewer({ passwordMode: true, fetchResult: n => n === 1 ? old.promise : next.promise });
    const first = v.unlockDocument(); v.event("pagehide"); const second = v.unlockDocument(); const status = v.status.textContent;
    if (fails) old.reject(new Error("synthetic")); else old.resolve(v.sessionResponse());
    await first; assert.equal(v.unlock.disabled, true); assert.equal(v.open.disabled, true); assert.equal(v.status.textContent, status);
    next.resolve(v.sessionResponse()); await second; assert.equal(v.open.disabled, false); assert.equal(v.logout.hidden, false);
  });
}

test("Back/Forward cache restoration clears any authenticated view and input", async () => {
  const v = viewer({ passwordMode: true }); await v.unlockDocument(); await v.openDocument();
  v.password.value = "synthetic"; v.event("pageshow", { persisted: true });
  assertClosed(v, true); assert.equal(v.password.value, ""); assert.equal(v.timers.size, 0);
});

for (const method of ["pushState", "replaceState"]) {
  for (const passwordMode of [false, true]) {
    test(`${method} immediately wipes a ${passwordMode ? "password" : "Access"} view on same-document path changes`, async () => {
      const v = viewer({ passwordMode }); if (passwordMode) await v.unlockDocument(); await v.openDocument();
      v.history[method]({}, "", "/changed-path");
      assertClosed(v, passwordMode); assert.equal(v.timers.size, 0); assert.match(v.status.textContent, /文書リンクが変わりました/);
    });
  }
}

test("history state-only updates leave the current document visible", async () => {
  const v = viewer(); await v.openDocument(); v.history.replaceState({ unrelated: true }, "");
  assert.equal(v.document.hidden, false); assert.equal(v.open.disabled, false);
});

test("a rejected password Open clears the local session and never claims successful registration", async () => {
  const v = viewer({ passwordMode: true, fetchResult: (_n, response, sessionResponse, url) => Promise.resolve(url.endsWith("/open") ? response({ ok: false }) : sessionResponse()) });
  await v.unlockDocument(); await v.openDocument(); assertClosed(v, true); assert.equal(v.timers.size, 0);
  assert.match(v.status.textContent, /文書を開けませんでした/); assert.doesNotMatch(v.status.textContent, /登録は完了/);
});

test("password Open without a session expiry header wipes data and locks", async () => {
  const v = viewer({ passwordMode: true, fetchResult: (_n, response, sessionResponse, url) => Promise.resolve(url.endsWith("/open") ? response({ headers: { "x-vault-session-expires-at": "" } }) : sessionResponse()) });
  await v.unlockDocument(); await v.openDocument(); assertClosed(v, true); assert.equal(v.loadingTasks.length, 0); assert.equal(v.timers.size, 0);
});

test("logout failure reports uncertainty while keeping the reader locked", async () => {
  const v = viewer({ passwordMode: true, fetchResult: (_n, response, sessionResponse, url, options) => Promise.resolve(options.method === "DELETE" ? sessionResponse({ ok: false }) : url.endsWith("/open") ? response() : sessionResponse()) });
  await v.unlockDocument(); await v.openDocument(); await v.logOutDocument(); assertClosed(v, true);
  assert.equal(v.status.textContent, "表示は閉じましたが、ログアウトを確認できませんでした。"); assert.equal(v.timers.size, 0);
});

const recipientFilename = 'CV_株式会社テスト 御中.pdf';
const filenameHeader = { 'x-vault-download-filename': encodeURIComponent(recipientFilename) };
for (const passwordMode of [false, true]) {
  test(`named PDF download reauthorizes and releases a named file (${passwordMode ? 'password' : 'Access'})`, async () => {
    const v = viewer({ passwordMode, fetchResult: (_n, response, sessionResponse, url) => Promise.resolve(
      url.endsWith('/open') ? response({ headers: filenameHeader }) : sessionResponse()) });
    assert.equal(v.download.hidden, true); await v.downloadDocument(); assert.equal(v.requests.length, 0);
    if (passwordMode) await v.unlockDocument();
    await v.openDocument(); assert.equal(v.download.hidden, false);
    const before = v.requests.length;
    await v.downloadDocument();
    assert.equal(v.requests.length, before + 1);
    const first = v.requests[before - 1], last = v.requests[before];
    assert.equal(last.url, first.url); assert.equal(last.options.method, 'POST');
    assert.equal(last.options.credentials, 'same-origin'); assert.equal(last.options.cache, 'no-store'); assert.equal(last.options.redirect, 'error');
    assert.notEqual(JSON.parse(first.options.body).requestId, JSON.parse(last.options.body).requestId);
    assert.equal(v.downloads.length, 1); assert.equal(v.downloads[0].filename, recipientFilename);
    assert.equal(v.downloads[0].blob.type, 'application/pdf');
    assert.deepEqual([...new Uint8Array(await v.downloads[0].blob.arrayBuffer())], [37, 80, 68, 70]);
    assert.match(v.status.textContent, /保存を開始/); assert.equal(v.objectURLs.size, 1);
    await v.fireTimer(1000); assert.equal(v.objectURLs.size, 0);
  });
}

test('unnamed and unsafe filenames never expose a download action', async () => {
  for (const filename of [null, '%GG', encodeURIComponent('CV_../test.pdf'), encodeURIComponent('CV_\\evil.pdf'),
    encodeURIComponent('CV_\r\nname.pdf'), encodeURIComponent('CV_\u202ename.pdf'), encodeURIComponent('wrong.pdf'),
    encodeURIComponent('CV_' + 'x'.repeat(200) + '.pdf')]) {
    const v = viewer({ fetchResult: (_n, response) => Promise.resolve(response({ headers: filename === null ? {} : { 'x-vault-download-filename': filename } })) });
    await v.openDocument(); assert.equal(v.download.hidden, true); await v.downloadDocument();
    assert.equal(v.requests.length, 1); assert.equal(v.downloads.length, 0);
  }
});

for (const change of ['close', 'pagehide', 'hashchange', 'visibilitychange', 'expiry']) {
  test(`${change} prevents a delayed download response from saving a PDF`, async () => {
    const late = deferred();
    const v = viewer({ fetchResult: (n, response) => n === 1 ? Promise.resolve(response({ headers: filenameHeader })) : late.promise });
    await v.openDocument(); const downloading = v.downloadDocument();
    if (change === 'expiry') v.advance(600001); else close(v, change);
    late.resolve(v.response({ headers: filenameHeader })); await downloading;
    assert.equal(v.downloads.length, 0); assert.equal(v.objectURLs.size, 0); assert.equal(v.download.hidden, true);
  });
}

test('logout cancels an in-flight password download even when transport ignores abort', async () => {
  const late = deferred();
  const v = viewer({ passwordMode: true, fetchResult: (n, response, sessionResponse, url) => n === 3 ? late.promise : Promise.resolve(
    url.endsWith('/open') ? response({ headers: filenameHeader }) : sessionResponse()) });
  await v.unlockDocument(); await v.openDocument(); const downloading = v.downloadDocument();
  // Close always cancels in-flight work; the now-available logout ends the session.
  v.closeDocument(); await v.logOutDocument(); late.resolve(v.response({ headers: filenameHeader })); await downloading;
  assert.equal(v.downloads.length, 0); assert.equal(v.download.hidden, true); assert.equal(v.objectURLs.size, 0);
});

for (const failure of ['unauthorized', 'renamed', 'expired', 'oversized', 'wrong-type']) {
  test(`download rejects ${failure} responses and clears the viewer`, async () => {
    const v = viewer({ fetchResult: (n, response) => Promise.resolve(n === 1 ? response({ headers: filenameHeader }) : response({
      ok: failure !== 'unauthorized', headers: { ...filenameHeader,
        ...(failure === 'renamed' ? { 'x-vault-download-filename': encodeURIComponent('CV_other.pdf') } : {}),
        ...(failure === 'expired' ? { 'x-vault-expires-at': '1' } : {}),
        ...(failure === 'oversized' ? { 'content-length': String(maxBytes + 1) } : {}),
        ...(failure === 'wrong-type' ? { 'content-type': 'text/html' } : {}),
      },
    })) });
    await v.openDocument(); await v.downloadDocument();
    assert.equal(v.downloads.length, 0); assert.equal(v.download.hidden, true); assert.equal(v.document.hidden, true);
    assert.equal(v.objectURLs.size, 0);
  });
}


test("document deadline is displayed in Japan time, independently of a shorter login session", async () => {
  const v = viewer({ passwordMode: true, now: Date.UTC(2026, 9, 9, 12) });
  assert.equal(v.deadline.textContent, "閲覧期限：認証後に表示します。");
  await v.unlockDocument();
  assert.equal(v.deadline.textContent, "閲覧期限：2026/10/09 21:10:00（日本時間）");
  await v.openDocument();
  assert.equal(v.deadline.textContent, "閲覧期限：2026/10/09 21:10:00（日本時間）");
  v.advance(300000); await v.fireTimer(300000);
  assertClosed(v, true); assert.equal(v.deadline.textContent, "閲覧期限：認証後に表示します。");
});

test("Access displays the server document deadline and clears it on close", async () => {
  const v = viewer({ now: Date.UTC(2026, 9, 9, 12) });
  assert.equal(v.deadline.textContent, "閲覧期限：文書を開く際に表示します。");
  await v.openDocument();
  assert.equal(v.deadline.textContent, "閲覧期限：2026/10/09 21:10:00（日本時間）");
  v.closeDocument(); assert.equal(v.deadline.textContent, "閲覧期限：文書を開く際に表示します。");
});

test("late unlock cannot restore a deadline after navigation", async () => {
  const result = deferred(), v = viewer({ passwordMode: true, fetchResult: () => result.promise });
  const unlocking = v.unlockDocument(); v.event("pagehide");
  result.resolve(v.sessionResponse()); await unlocking;
  assert.equal(v.deadline.textContent, "閲覧期限：認証後に表示します。"); assertClosed(v, true);
});

test("unrepresentable calendar dates do not interrupt valid session controls", async () => {
  const v = viewer({ passwordMode: true, fetchResult: (_n, _response, sessionResponse) => Promise.resolve(sessionResponse({ value: { expiresAt: Number.MAX_SAFE_INTEGER, sessionExpiresAt: 1800000300000 } })) });
  await v.unlockDocument();
  assert.equal(v.open.disabled, false); assert.equal(v.deadline.textContent, "閲覧期限：日時を表示できません。");
});

test("status updates show a shortened document deadline and logout clears it", async () => {
  const v = viewer({ passwordMode: true, now: Date.UTC(2026, 9, 9, 12), fetchResult: (_n, response, sessionResponse, url, request) => Promise.resolve(url.endsWith("/open") ? response() : url.endsWith("/status") ? sessionResponse({ value: { expiresAt: Date.UTC(2026, 9, 9, 12, 2), sessionExpiresAt: Date.UTC(2026, 9, 9, 12, 5) } }) : sessionResponse()) });
  await v.unlockDocument(); await v.openDocument(); await v.fireTimer(15000);
  assert.equal(v.deadline.textContent, "閲覧期限：2026/10/09 21:02:00（日本時間）");
  await v.logOutDocument(); assert.equal(v.deadline.textContent, "閲覧期限：認証後に表示します。");
});
