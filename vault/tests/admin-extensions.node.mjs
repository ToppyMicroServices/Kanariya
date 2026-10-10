import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { html, js } from '../src/admin-extensions.js';

const id = 'd4dbffb4-8567-48c3-94c5-e74aaf3e2291', uploadId = '82afbc08-7a90-4d12-971d-dc3f5b93cbcc';
const now = Date.UTC(2026, 9, 10, 0, 0), future = now + 24 * 3600000;
const names = ['registration-panel', 'registration-form', 'registration-file', 'registration-expiry', 'registration-replace',
  'register-pdf', 'registration-status', 'registration-reload', 'registration-list', 'contacts-panel', 'contacts-form',
  'contact-emails', 'save-contacts', 'contacts-status', 'contacts-reload', 'logs-panel', 'logs-status', 'log-rows', 'logs-reload', 'logs-next'];
function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}
function json(value, status = 200) { return Response.json(value, { status }); }
function pdfFile({ name = 'synthetic.pdf', size, body = '%PDF-1.4\nSYNTHETIC_BROWSER_ONLY\n', buffer } = {}) {
  const bytes = new TextEncoder().encode(body);
  return { name, size: size ?? bytes.length, reads: 0, async arrayBuffer() { this.reads++; return buffer ?? bytes.slice().buffer; } };
}
function documentSummary(overrides = {}) {
  return { id: uploadId, status: 'private', fileName: 'synthetic.pdf', size: 123,
    createdAt: now, expiresAt: future, replaceOf: null, ...overrides };
}
function browser(options = {}) {
  function element() {
    return { textContent: '', value: '', disabled: false, hidden: false, open: false, checked: false, files: [], children: [],
      listeners: new Map(), addEventListener(event, callback) { this.listeners.set(event, callback); },
      replaceChildren(...children) { this.children = children; }, append(...children) { this.children.push(...children); },
      set innerHTML(_) { throw new Error('untrusted_html_sink'); } };
  }
  const elements = Object.fromEntries(names.map(name => [name, element()])), events = new Map(), requests = [], timers = new Map();
  let timerId = 0;
  const state = { contacts: { revision: 0, emails: [] }, registry: { revision: 0, pending: 0, documents: [] },
    logs: { events: [], nextCursor: null, retentionDays: 30 }, ...options.state };
  class BrowserDate extends Date { static now() { return now; } }
  vm.runInNewContext(js, {
    document: { getElementById: name => elements[name], createElement: () => element() },
    Date: BrowserDate, Intl, Uint8Array, TextDecoder, AbortController, btoa,
    crypto: { randomUUID: () => uploadId },
    addEventListener: (event, callback) => events.set(event, callback),
    setTimeout: (callback, milliseconds) => { const key = ++timerId; timers.set(key, { callback, milliseconds }); return key; },
    clearTimeout: key => timers.delete(key),
    fetch: async (path, request) => {
      requests.push({ path, request });
      if (options.fetch) return options.fetch(path, request, state, requests.length);
      if (path === '/v1/management') return json({ documentId: id });
      if (path.endsWith('/recipients')) {
        if (request.method === 'POST') { const input = JSON.parse(request.body); state.contacts = { revision: state.contacts.revision + 1, emails: input.emails }; }
        return json(state.contacts);
      }
      if (path.endsWith('/logs')) return json(state.logs);
      if (path === '/v1/registrations') {
        if (request.method === 'POST') {
          const input = JSON.parse(request.body);
          state.registry = { revision: state.registry.revision + 1, pending: 0,
            documents: [...state.registry.documents, documentSummary({ id: input.id, fileName: input.fileName,
              size: Buffer.from(input.pdfBase64, 'base64').length, expiresAt: input.expiresAt, replaceOf: input.replaceOf })] };
          return json(state.registry, 201);
        }
        return json(state.registry);
      }
      throw new Error('unexpected_request');
    },
  });
  return { elements, requests, events, state, timers,
    async open(section) { const panel = elements[section + '-panel']; panel.open = true; panel.listeners.get('toggle')(); await settled(); },
    click(name) { return elements[name].listeners.get('click')(); },
    submit(section) { return elements[section + '-form'].listeners.get('submit')({ preventDefault() {} }); },
    event(name, value = {}) { return events.get(name)(value); },
    select(file = pdfFile()) { elements['registration-file'].files = [file]; elements['registration-expiry'].value = '2026-10-11T09:00'; return file; },
    posts() { return requests.filter(({ request }) => request.method === 'POST'); },
  };
}
async function settled() { await new Promise(resolve => setImmediate(resolve)); await new Promise(resolve => setImmediate(resolve)); }

test('owner extensions load only bootstrap until a section is opened and never acquire PDF content', async () => {
  const ui = browser(); await settled();
  assert.deepEqual(ui.requests.map(({ path }) => path), ['/v1/management']);
  await ui.open('logs'); assert.deepEqual(ui.requests.map(({ path }) => path), ['/v1/management', `/v1/documents/${id}/logs`]);
  assert.equal(ui.elements['logs-status'].textContent, '記録はありません。');
  for (const { path, request } of ui.requests) {
    assert.equal(request.method, 'GET'); assert.equal(request.credentials, 'same-origin');
    assert.equal(request.cache, 'no-store'); assert.equal(request.redirect, 'error');
    assert.doesNotMatch(path, /\/(open|session|revoke)$/);
  }
});

test('opening contacts and registry reads bounded metadata without submitting anything', async () => {
  const ui = browser({ state: { contacts: { revision: 2, emails: ['Reader@example.test'] } } }); await settled();
  await ui.open('contacts'); await ui.open('registration');
  assert.equal(ui.elements['contact-emails'].value, 'Reader@example.test');
  assert.equal(ui.elements['save-contacts'].disabled, false); assert.equal(ui.elements['register-pdf'].disabled, false);
  assert.equal(ui.elements['registration-expiry'].min, '2026-10-10T09:01');
  assert.deepEqual(ui.requests.map(({ path }) => path), ['/v1/management', `/v1/documents/${id}/recipients`, '/v1/registrations']);
  assert.equal(ui.posts().length, 0);
});

test('contacts send the loaded revision once and keep additional submissions disabled while pending', async () => {
  const gate = deferred();
  const ui = browser({ fetch(path, request) {
    if (path === '/v1/management') return json({ documentId: id });
    if (request.method === 'GET') return json({ revision: 7, emails: ['old@example.test'] });
    return gate.promise;
  } }); await settled(); await ui.open('contacts');
  ui.elements['contact-emails'].value = ' Reader@example.test \r\n\nsecond@example.test';
  const pending = ui.submit('contacts'); ui.submit('contacts');
  assert.equal(ui.posts().length, 1); assert.equal(ui.elements['save-contacts'].disabled, true);
  assert.deepEqual(JSON.parse(ui.posts()[0].request.body), { emails: ['Reader@example.test', 'second@example.test'], expectedRevision: 7 });
  gate.resolve(json({ revision: 8, emails: ['Reader@example.test', 'second@example.test'] })); await pending;
  assert.equal(ui.elements['save-contacts'].disabled, false); assert.equal(ui.elements['contacts-status'].textContent, '開示先メールを保存しました。');
});

test('too many contact lines are rejected before a request', async () => {
  const ui = browser(); await settled(); await ui.open('contacts');
  ui.elements['contact-emails'].value = Array.from({ length: 51 }, (_, index) => `reader${index}@example.test`).join('\n');
  await ui.submit('contacts'); assert.equal(ui.posts().length, 0); assert.match(ui.elements['contacts-status'].textContent, /50件まで/);
});

for (const status of [400, 409, 503]) test(`contact save status ${status} requires a read before another mutation`, async () => {
  const ui = browser({ fetch(path, request) {
    if (path === '/v1/management') return json({ documentId: id });
    if (request.method === 'GET') return json({ revision: 3, emails: ['existing@example.test'] });
    return json({ error: 'synthetic_failure' }, status);
  } }); await settled(); await ui.open('contacts'); ui.elements['contact-emails'].value = 'next@example.test';
  await ui.submit('contacts'); assert.equal(ui.elements['save-contacts'].disabled, true);
  assert.match(ui.elements['contacts-status'].textContent, status === 400 ? /メールアドレスを確認/ : /再読み込み/);
  await ui.submit('contacts'); assert.equal(ui.posts().length, 1);
  ui.click('contacts-reload'); await settled(); assert.equal(ui.elements['save-contacts'].disabled, false);
  assert.equal(ui.elements['contact-emails'].value, 'existing@example.test'); assert.equal(ui.posts().length, 1);
});

test('log pages keep shared-password identity unknown and distinguish notification acceptance from receipt', async () => {
  const ui = browser({ state: { logs: { retentionDays: 30, nextCursor: 'opaque-encrypted-cursor', events: [
    { id: uploadId, at: now, subject: 'shared-password', outcome: 'decrypted', notifications: [{ state: 'accepted' }] },
    { id, at: now - 60000, subject: '<img src=x onerror=alert(1)>', outcome: 'requested', notifications: [{ state: 'pending' }] },
  ] } } }); await settled(); await ui.open('logs');
  const rows = ui.elements['log-rows'].children;
  assert.equal(rows[0].children[1].textContent, '本人未確認（共通パスワード）');
  assert.equal(rows[0].children[3].textContent, '送信受付済み');
  assert.equal(rows[1].children[1].textContent, 'Access認証済み');
  assert.equal(rows[1].children[1].children[0].textContent, '認証ID: <img src=x onerror=alert(1)>');
  assert.equal(rows[1].children[2].textContent, '結果未確認'); assert.equal(ui.elements['logs-next'].hidden, false);
  ui.click('logs-next'); await settled();
  assert.equal(ui.posts().length, 1); assert.equal(ui.posts()[0].path, `/v1/documents/${id}/logs`);
  assert.deepEqual(JSON.parse(ui.posts()[0].request.body), { cursor: 'opaque-encrypted-cursor' });
});

test('malformed log states and invalid bootstrap IDs do not display trusted evidence', async () => {
  const ui = browser({ state: { logs: { retentionDays: 30, nextCursor: null, events: [
    { id: uploadId, at: now, subject: 'shared-password', outcome: 'decrypted', notifications: [{ state: 'invented' }] },
  ] } } }); await settled(); await ui.open('logs');
  assert.equal(ui.elements['log-rows'].children.length, 0); assert.match(ui.elements['logs-status'].textContent, /読み込めません/);
  const invalid = browser({ fetch: async () => json({ documentId: '../other' }) }); await settled();
  await invalid.open('registration'); await invalid.open('contacts'); await invalid.open('logs');
  assert.equal(invalid.requests.length, 1); assert.equal(invalid.elements['register-pdf'].disabled, true); assert.equal(invalid.elements['save-contacts'].disabled, true);
});

test('private registration sends one bounded PDF with Japan time and optional replacement metadata', async () => {
  const ui = browser(); await settled(); await ui.open('registration');
  const file = ui.select(); ui.elements['registration-replace'].checked = true;
  await ui.submit('registration'); await settled();
  assert.equal(ui.posts().length, 1); const post = ui.posts()[0]; assert.equal(post.path, '/v1/registrations');
  assert.equal(post.request.headers['content-type'], 'application/json');
  const input = JSON.parse(post.request.body);
  assert.deepEqual({ ...input, pdfBase64: undefined }, { id: uploadId, fileName: 'synthetic.pdf', expiresAt: future,
    replaceOf: id, expectedRevision: 0, pdfBase64: undefined });
  assert.match(Buffer.from(input.pdfBase64, 'base64').toString(), /^%PDF-1\.4/);
  assert.equal(file.reads, 1); assert.match(ui.elements['registration-status'].textContent, /登録済み.*非公開/);
  assert.match(ui.elements['registration-list'].children[0].textContent, /差し替え候補/);
  assert.ok(ui.requests.every(({ path }) => !path.endsWith('/open')));
});

test('filename rendering uses text and never creates a public link for a private candidate', async () => {
  const filename = '<img src=x onerror=alert(1)>.pdf';
  const ui = browser({ state: { registry: { revision: 1, pending: 0, documents: [documentSummary({ fileName: filename })] } } });
  await settled(); await ui.open('registration');
  assert.match(ui.elements['registration-list'].children[0].textContent, /^<img src=x onerror=alert\(1\)>\.pdf — 非公開/);
  assert.equal(ui.elements['registration-list'].children[0].children.length, 0); assert.equal(ui.posts().length, 0);
});

test('registration rejects missing, oversized, non-PDF and invalid-expiry files before uploading', async () => {
  const ui = browser(); await settled(); await ui.open('registration');
  for (const file of [pdfFile({ size: 4 }), pdfFile({ size: 1048577 }), pdfFile({ name: 'file.txt' }),
    pdfFile({ name: 'a'.repeat(117) + '.pdf' }), pdfFile({ name: 'file\n.pdf' })]) {
    ui.select(file); await ui.submit('registration'); assert.equal(file.reads, 0);
  }
  const badHeader = ui.select(pdfFile({ body: 'not a PDF' })); await ui.submit('registration'); assert.equal(badHeader.reads, 1);
  const wrongSize = ui.select(pdfFile({ size: 500 })); await ui.submit('registration'); assert.equal(wrongSize.reads, 1);
  const dateFile = ui.select();
  for (const date of ['2026-02-30T10:00', '2026-10-10T09:00', '2026-10-11T09:00Z']) {
    ui.elements['registration-expiry'].value = date; await ui.submit('registration');
  }
  assert.equal(dateFile.reads, 0); assert.equal(ui.posts().length, 0);
});

test('an unknown registration result blocks repeat upload until a matching read confirms it', async () => {
  let confirmed = false;
  const ui = browser({ fetch(path, request) {
    if (path === '/v1/management') return json({ documentId: id });
    if (request.method === 'POST') throw new Error('synthetic_connection_lost');
    return json({ revision: confirmed ? 1 : 0, pending: confirmed ? 0 : 1,
      documents: confirmed ? [documentSummary()] : [] });
  } }); await settled(); await ui.open('registration'); ui.select(); await ui.submit('registration'); await settled();
  assert.equal(ui.posts().length, 1); assert.equal(ui.elements['register-pdf'].disabled, true);
  await ui.submit('registration'); assert.equal(ui.posts().length, 1);
  assert.match(ui.elements['registration-status'].textContent, /登録は確認できません/);
  confirmed = true; ui.click('registration-reload'); await settled();
  assert.equal(ui.elements['register-pdf'].disabled, false); assert.match(ui.elements['registration-status'].textContent, /登録済み/);
  assert.equal(ui.posts().length, 1);
});

test('durable pending registrations are presented as private incomplete candidates', async () => {
  const ui = browser({ state: { registry: { revision: 0, pending: 2, documents: [] } } }); await settled(); await ui.open('registration');
  assert.match(ui.elements['registration-status'].textContent, /確認できていない登録が 2 件.*非公開/);
  assert.equal(ui.posts().length, 0);
});

test('twenty completed or pending registrations disable upload before reading any PDF bytes', async () => {
  for (const [completed, pending] of [[20, 0], [15, 5], [0, 20]]) {
    const documents = Array.from({ length: completed }, (_, index) => documentSummary({
      id: `82afbc08-7a90-4d12-971d-${String(index).padStart(12, '0')}`,
    }));
    const ui = browser({ state: { registry: { revision: completed, pending, documents } } });
    await settled(); await ui.open('registration');
    assert.equal(ui.elements['register-pdf'].disabled, true);
    assert.match(ui.elements['registration-status'].textContent, /登録上限の20件/);
    const file = ui.select(); await ui.submit('registration');
    assert.equal(file.reads, 0); assert.equal(ui.posts().length, 0);
  }
});

test('pagehide cancels metadata reads and ignores late contact values', async () => {
  const gate = deferred();
  const ui = browser({ fetch(path) { return path === '/v1/management' ? json({ documentId: id }) : gate.promise; } });
  await settled(); ui.elements['contacts-panel'].open = true; ui.elements['contacts-panel'].listeners.get('toggle')();
  const request = ui.requests.at(-1).request; ui.event('pagehide'); assert.equal(request.signal.aborted, true);
  gate.resolve(json({ revision: 1, emails: ['late@example.test'] })); await settled();
  assert.equal(ui.elements['contact-emails'].value, ''); assert.equal(ui.elements['save-contacts'].disabled, true);
});

test('pagehide during a registration does not enable a second upload on restoration', async () => {
  const gate = deferred();
  const ui = browser({ fetch(path, request) {
    if (path === '/v1/management') return json({ documentId: id });
    if (request.method === 'POST') return gate.promise;
    return json({ revision: 0, pending: 0, documents: [] });
  } }); await settled(); await ui.open('registration'); ui.select();
  const pending = ui.submit('registration'); await settled(); assert.equal(ui.posts().length, 1);
  ui.event('pagehide'); assert.equal(ui.posts()[0].request.signal.aborted, true);
  gate.reject(new Error('abort')); await pending; ui.event('pageshow', { persisted: true }); await settled();
  assert.equal(ui.elements['register-pdf'].disabled, true); await ui.submit('registration'); assert.equal(ui.posts().length, 1);
});

test('owner extension controls are collapsed, labelled and free from inline script or secret fields', () => {
  assert.doesNotMatch(html, /<details[^>]*\sopen(?:\s|=|>)/);
  assert.doesNotMatch(html, /<script|\son\w+=|\sstyle=|type="password"|mailto:/i);
  assert.match(html, /登録したPDFは非公開です/); assert.match(html, /本人を確認するものではありません/);
  assert.match(html, /<th scope="col">日時（日本時間）/); assert.match(html, /role="status" aria-live="polite"/);
});
