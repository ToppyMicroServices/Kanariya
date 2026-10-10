import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { createHash } from 'node:crypto';
import { js, workerJs } from '../src/registration-preview.js';

const source = new TextEncoder().encode('%PDF-1.4\nSYNTHETIC_SOURCE\n');
const final = new TextEncoder().encode('%PDF-1.4\nSYNTHETIC_FINAL\n');
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const deferred = () => { let resolve, reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; };
const settled = async () => { for (let count = 0; count < 12; count++) await new Promise(resolve => setImmediate(resolve)); };

function browser(options = {}) {
  const canvases = [], drawings = [], workers = [], timers = new Map(), loads = [], renders = [], readers = [], pageCleanups = [];
  let timerId = 0, fileReads = 0;
  class Element {
    constructor(tag) { this.tagName = tag; this.children = []; this.style = {}; this.attributes = {}; this.textContent = ''; this.clientWidth = 800; this.hidden = false; }
    append(...nodes) { this.children.push(...nodes); }
    replaceChildren(...nodes) { this.children = nodes; }
    setAttribute(name, value) { this.attributes[name] = value; }
    set innerHTML(_) { throw new Error('unexpected_HTML'); }
  }
  const document = { createElement(tag) {
    const element = new Element(tag);
    if (tag !== 'canvas') return element;
    canvases.push(element); element.width = 0; element.height = 0;
    const context = { font: '', measureText(text) { const size = Number.parseInt(this.font); return { width: [...text].reduce((sum, c) => sum + (c.codePointAt(0) > 127 ? size : size * .6), 0) * (options.measureFactor ?? 1) }; },
      clearRect() {}, fillText(text, x, y) { drawings.push({ text, x, y, font: this.font, fillStyle: this.fillStyle, alpha: this.globalAlpha,
        width: element.width, height: element.height }); } };
    element.getContext = () => options.noCanvas ? null : context;
    element.toBlob = callback => {
      if (options.stallPng) return;
      const bytes = new Uint8Array([137, 80, 78, 71, 13, 10, 26, 10]);
      callback(options.invalidPng ? null : { size: bytes.length, arrayBuffer: async () => bytes.slice().buffer });
    };
    return element;
  } };
  class Worker {
    constructor(url, settings) { this.url = url; this.settings = settings; this.terminations = 0; workers.push(this); }
    terminate() { this.terminations++; }
    postMessage(input, transfer) {
      this.input = structuredClone(input, { transfer }); this.transferCount = transfer.length; this.savedHandler = this.onmessage;
      if (options.stallWorker) return;
      queueMicrotask(() => {
        if (options.workerError) { this.onerror({ preventDefault() {} }); return; }
        const bytes = final.slice(), result = { bytes, sourceSha256: sha(this.input.bytes), finalSha256: sha(bytes), pages: 2, ...options.reply };
        const reply = structuredClone(result, { transfer: [result.bytes.buffer] }); this.lastReply = reply;
        this.onmessage?.({ data: reply });
      });
    }
  }
  function getDocument(settings) {
    const transferred = structuredClone(settings.data, { transfer: [settings.data.buffer] });
    const load = { settings, transferred, destroyed: 0, destroy() { this.destroyed++; return Promise.resolve(); } }; loads.push(load);
    const pdf = { numPages: options.pages ?? 2, async getPage(number) {
      if (options.pagePromise) return options.pagePromise;
      return {
        getViewport({ scale }) { return { width: (options.width ?? 600) * scale, height: (options.height ?? 800) * scale }; },
        render(settings) { const render = { settings, cancelled: 0, promise: options.renderPromise ?? Promise.resolve(), cancel() { this.cancelled++; } }; renders.push(render); return render; },
        streamTextContent() {
          let read = 0; const reader = { cancelled: 0, released: 0,
            async read() { if (options.textPromise) return options.textPromise; return read++ ? { done: true } : { done: false, value: { items: [{ str: options.text ?? '<img src=x> 合成本文', hasEOL: true }] } }; },
            cancel() { this.cancelled++; return Promise.resolve(); }, releaseLock() { this.released++; } }; readers.push(reader); return { getReader: () => reader };
        },
        cleanup() { pageCleanups.push(number); },
      };
    } };
    load.promise = options.loadingPromise ?? Promise.resolve(pdf); return load;
  }
  const GlobalWorkerOptions = {};
  const context = { document, Worker, getDocument, GlobalWorkerOptions, Uint8Array, TextEncoder, DOMException, AbortController,
    crypto: globalThis.crypto, devicePixelRatio: 2, queueMicrotask,
    setTimeout(fn, ms) { const id = ++timerId; timers.set(id, { fn, ms }); return id; }, clearTimeout(id) { timers.delete(id); },
    fetch() { throw new Error('unexpected_network'); }, localStorage: new Proxy({}, { get() { throw new Error('unexpected_storage'); } }),
    console: new Proxy({}, { get() { throw new Error('unexpected_log'); } }) };
  const script = js.replace(/^import .*;\n/, '').replace(/export (?=async function|function)/g, '');
  const api = vm.runInNewContext(`(()=>{${script}\nreturn {prepareRegistration,showRegistrationPreview,clearRegistrationPreview};})()`, context);
  const file = { size: source.length, async arrayBuffer() { fileReads++; return source.slice().buffer; } };
  return { ...api, file, container: new Element('div'), canvases, drawings, workers, timers, loads, renders, readers, pageCleanups, GlobalWorkerOptions,
    get fileReads() { return fileReads; }, expire() { const entries = [...timers.values()]; for (const entry of entries) { assert.equal(entry.ms, 20000); entry.fn(); } } };
}

test('preparation transfers only local PDF and a readable gray raster to one self-hosted Worker', async () => {
  const ui = browser(), result = await ui.prepareRegistration(ui.file, ' 株式会社ダミー ', true);
  assert.deepEqual(result.bytes, final); assert.equal(result.sourceSha256, sha(source)); assert.equal(result.finalSha256, sha(final)); assert.equal(result.pages, 2);
  const worker = ui.workers[0]; assert.equal(worker.url, '/v1/admin/assets/pdf-preparation-worker.js'); assert.equal(worker.settings.type, 'module');
  assert.equal(worker.transferCount, 2); assert.deepEqual(worker.input.bytes, source); assert.equal(worker.input.recipientName, '株式会社ダミー');
  assert.equal(worker.input.watermarkEnabled, true); assert.equal(worker.input.watermarkPng.length, 8);
  assert.equal(worker.terminations, 1); assert.equal(ui.fileReads, 1); assert.equal(ui.timers.size, 0);
  assert.equal(ui.drawings[0].text, '開示先: 株式会社ダミー'); assert.equal(ui.drawings[0].fillStyle, 'rgb(115,115,115)'); assert.equal(ui.drawings[0].alpha, 1);
  const drawing = ui.drawings[0], size = Number.parseInt(drawing.font);
  const textWidth = [...drawing.text].reduce((sum, c) => sum + (c.codePointAt(0) > 127 ? size : size * .6), 0);
  assert.equal(drawing.width, Math.ceil(textWidth + 96)); assert.equal(drawing.height, size + 64);
  assert.equal(drawing.x, drawing.width / 2); assert.equal(drawing.y, drawing.height / 2);
  assert.ok(drawing.width < 2048 && drawing.height < 256); assert.ok(size >= 48);
  assert.equal(ui.canvases[0].width, 0); assert.equal(ui.canvases[0].height, 0);
});

test('disabled watermark still runs PDF preparation without allocating a raster', async () => {
  const ui = browser(); await ui.prepareRegistration(ui.file, '個人ダミー', false);
  assert.equal(ui.canvases.length, 0); assert.equal(ui.workers[0].input.watermarkPng, null); assert.equal(ui.workers[0].transferCount, 1);
});

test('long names wrap to at most two lines and never use less than 48 pixels', async () => {
  const ui = browser(); await ui.prepareRegistration(ui.file, '界'.repeat(60), true);
  assert.equal(ui.drawings.length, 2);
  const size = Number.parseInt(ui.drawings[0].font), longest = Math.max(...ui.drawings.map(drawing =>
    [...drawing.text].reduce((sum, c) => sum + (c.codePointAt(0) > 127 ? size : size * .6), 0)));
  assert.ok(ui.drawings.every(drawing => Number.parseInt(drawing.font) >= 48 && drawing.height === 2 * size + 24 + 64 &&
    drawing.width === Math.ceil(longest + 96) && drawing.width <= 2048 && drawing.x === drawing.width / 2));
  const tooLong = browser({ measureFactor: 5 });
  await assert.rejects(tooLong.prepareRegistration(tooLong.file, '界'.repeat(60), true), /pdf_preparation_failed/);
  assert.equal(tooLong.workers.length, 0); assert.equal(tooLong.canvases[0].width, 0);
});

test('invalid file size, name and watermark type fail before reading a file or starting a Worker', async () => {
  for (const [file, name, enabled] of [[{ size: 1048577, arrayBuffer() { throw new Error('unexpected_read'); } }, 'dummy', true],
    [{ size: 1, arrayBuffer() { throw new Error('unexpected_read'); } }, 'dummy', true], [null, 'dummy', true],
    [browser().file, '../dummy', true], [browser().file, '界'.repeat(61), true], [browser().file, 'dummy', 'true']]) {
    const ui = browser(); await assert.rejects(ui.prepareRegistration(file, name, enabled), /pdf_preparation_failed/); assert.equal(ui.workers.length, 0);
  }
});

test('the emitted module accepts Latin and Japanese names and rejects actual controls, bidi and path characters', async () => {
  for (const name of ['Example Organization', '株式会社ダミー', '担当e\u0301']) {
    const ui = browser(); await ui.prepareRegistration(ui.file, name, false);
    assert.equal(ui.workers[0].input.recipientName, name.normalize('NFC'));
  }
  for (const name of ['dummy\u0000', 'dummy\n', 'dummy\u007f', 'dummy\u202e', 'dummy\u2066', 'dummy\\name', 'dummy/name']) {
    const ui = browser(); await assert.rejects(ui.prepareRegistration(ui.file, name, false), /pdf_preparation_failed/);
    assert.equal(ui.fileReads, 0); assert.equal(ui.workers.length, 0);
  }
});

test('wrong source bytes, unavailable Canvas and an invalid PNG fail without starting a Worker', async () => {
  for (const options of [{ noCanvas: true }, { invalidPng: true }]) {
    const ui = browser(options); await assert.rejects(ui.prepareRegistration(ui.file, 'dummy', true), /pdf_preparation_failed/); assert.equal(ui.workers.length, 0); assert.equal(ui.timers.size, 0);
  }
  const ui = browser(); await assert.rejects(ui.prepareRegistration({ size: source.length, arrayBuffer: async () => new Uint8Array(source.length).buffer }, 'dummy', false), /pdf_preparation_failed/);
  assert.equal(ui.workers.length, 0);
});

for (const options of [{ workerError: true }, { reply: { pages: 21 } }, { reply: { sourceSha256: 'c'.repeat(64) } },
  { reply: { finalSha256: 'c'.repeat(64) } }, { reply: { extra: true } }]) test('failed or mismatched Worker replies cannot produce a prepared copy', async () => {
  const ui = browser(options); await assert.rejects(ui.prepareRegistration(ui.file, 'dummy', false), /pdf_preparation_failed/);
  assert.equal(ui.workers[0].terminations, 1); assert.equal(ui.timers.size, 0);
  if (ui.workers[0].lastReply) assert.ok(ui.workers[0].lastReply.bytes.every(value => value === 0));
});

test('abort and timeout terminate the Worker, reject results, and erase a captured late reply', async () => {
  for (const abort of [true, false]) {
    const ui = browser({ stallWorker: true }), controller = new AbortController();
    const pending = ui.prepareRegistration(ui.file, 'dummy', false, controller.signal); const rejected = assert.rejects(pending, abort ? { name: 'AbortError' } : /pdf_preparation_failed/);
    await settled(); assert.equal(ui.workers.length, 1); const worker = ui.workers[0];
    if (abort) controller.abort(); else ui.expire(); await rejected;
    assert.equal(worker.terminations, 1); assert.equal(ui.timers.size, 0);
    const bytes = final.slice(); worker.savedHandler({ data: { bytes, sourceSha256: sha(source), finalSha256: sha(bytes), pages: 2 } });
    assert.ok(bytes.every(value => value === 0));
  }
});

test('timeout also bounds a stalled file read and a stalled PNG conversion', async () => {
  const gate = deferred(), ui = browser();
  const pending = ui.prepareRegistration({ size: source.length, arrayBuffer: () => gate.promise }, 'dummy', false);
  const rejected = assert.rejects(pending, /pdf_preparation_failed/); ui.expire(); await rejected;
  const late = source.slice(); gate.resolve(late.buffer); await settled(); assert.ok(late.every(value => value === 0)); assert.equal(ui.workers.length, 0);
  const raster = browser({ stallPng: true }), rasterPending = raster.prepareRegistration(raster.file, 'dummy', true);
  const rasterRejected = assert.rejects(rasterPending, /pdf_preparation_failed/); await settled(); raster.expire(); await rasterRejected;
  assert.equal(raster.canvases[0].width, 0); assert.equal(raster.workers.length, 0);
});

test('preview renders only a final-byte copy, with bounded canvases, safe text, and self-hosted PDF.js options', async () => {
  const ui = browser({ pages: 20 }), bytes = final.slice();
  await ui.showRegistrationPreview(ui.container, { bytes, pages: 20 }); assert.deepEqual(bytes, final);
  assert.equal(ui.GlobalWorkerOptions.workerSrc, '/p/assets/pdfjs/pdf.worker.min.mjs');
  const load = ui.loads[0]; assert.deepEqual(load.transferred, final); assert.equal(load.destroyed, 1); assert.equal(ui.timers.size, 0);
  assert.equal(load.settings.standardFontDataUrl, '/p/assets/pdfjs/standard_fonts/');
  assert.equal(load.settings.isEvalSupported, false); assert.equal(load.settings.enableXfa, false); assert.equal(load.settings.useWasm, false);
  assert.equal(load.settings.disableAutoFetch, true); assert.equal(load.settings.disableStream, true);
  assert.equal(ui.container.children.length, 20); assert.equal(ui.pageCleanups.length, 20);
  assert.ok(ui.renders.every(render => render.settings.canvas.width * render.settings.canvas.height <= 4000000));
  assert.ok(ui.renders.reduce((sum, render) => sum + render.settings.canvas.width * render.settings.canvas.height, 0) <= 12000000);
  const body = ui.container.children[0].children[1].children[1]; assert.equal(body.textContent, '<img src=x> 合成本文');
  ui.clearRegistrationPreview(ui.container); assert.equal(ui.container.children.length, 0); assert.equal(ui.container.hidden, true); assert.equal(body.textContent, '');
  assert.ok(ui.canvases.every(canvas => canvas.width === 0 && canvas.height === 0)); assert.deepEqual(bytes, final);
});

test('abort cancels a pending render, destroys PDF loading, and prevents late DOM insertion', async () => {
  const gate = deferred(), ui = browser({ renderPromise: gate.promise }), controller = new AbortController();
  const pending = ui.showRegistrationPreview(ui.container, { bytes: final.slice(), pages: 2 }, controller.signal);
  const rejected = assert.rejects(pending, { name: 'AbortError' }); await settled(); assert.equal(ui.renders.length, 1);
  controller.abort(); await rejected; gate.resolve(); await settled();
  assert.ok(ui.renders[0].cancelled >= 1); assert.ok(ui.loads[0].destroyed >= 1); assert.equal(ui.container.children.length, 0);
  assert.equal(ui.timers.size, 0); assert.ok(ui.canvases.every(canvas => canvas.width === 0));
});

test('clear cancels a pending text stream and a replacement preview cannot receive old pages', async () => {
  const gate = deferred(), ui = browser({ textPromise: gate.promise });
  const pending = ui.showRegistrationPreview(ui.container, { bytes: final.slice(), pages: 2 });
  const rejected = assert.rejects(pending, { name: 'AbortError' }); await settled(); assert.equal(ui.readers.length, 1);
  ui.clearRegistrationPreview(ui.container); await rejected; gate.resolve({ done: true }); await settled();
  assert.ok(ui.readers[0].cancelled >= 1); assert.equal(ui.readers[0].released, 1); assert.equal(ui.container.children.length, 0);
  assert.ok(ui.loads[0].destroyed >= 1);
});

test('preview timeout and mismatched page counts clear all partial output', async () => {
  const gate = deferred(), ui = browser({ loadingPromise: gate.promise });
  const pending = ui.showRegistrationPreview(ui.container, { bytes: final.slice(), pages: 2 }); const rejected = assert.rejects(pending, /pdf_preparation_failed/);
  ui.expire(); await rejected; assert.ok(ui.loads[0].destroyed >= 1); assert.equal(ui.container.children.length, 0);
  const mismatch = browser({ pages: 3 }); await assert.rejects(mismatch.showRegistrationPreview(mismatch.container, { bytes: final.slice(), pages: 2 }), /pdf_preparation_failed/);
  assert.equal(mismatch.container.children.length, 0); assert.ok(mismatch.loads[0].destroyed >= 1);
});

test('Worker adapter passes the exact preparation contract and exposes only a fixed failure', async () => {
  for (const fail of [false, true]) {
    const posted = [], input = { bytes: source.slice(), recipientName: 'dummy', watermarkEnabled: false, watermarkPng: null };
    let calls = 0; const context = { self: { postMessage(value, transfer) { posted.push(transfer ? structuredClone(value, { transfer }) : structuredClone(value)); } },
      async preparePdf(value) { calls++; assert.equal(value, input); if (fail) throw new Error('SENSITIVE_PRIVATE_FAILURE');
        return { bytes: final.slice(), sourceSha256: sha(source), finalSha256: sha(final), pages: 2 }; } };
    vm.runInNewContext(workerJs.replace(/^import .*;\n/, ''), context);
    await context.self.onmessage({ data: input }); await context.self.onmessage({ data: input });
    assert.equal(calls, 1); assert.equal(posted.length, 1); assert.ok(input.bytes.every(value => value === 0));
    if (fail) assert.deepEqual(posted[0], { error: 'pdf_preparation_failed' });
    else { assert.deepEqual(posted[0].bytes, final); assert.equal(posted[0].sourceSha256, sha(source)); }
    assert.ok(!JSON.stringify(posted).includes('SENSITIVE_PRIVATE_FAILURE'));
  }
});
