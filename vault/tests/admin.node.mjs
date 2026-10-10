import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { html, css, js } from '../src/admin.js';

const id = 'd4dbffb4-8567-48c3-94c5-e74aaf3e2291';
const now = Date.UTC(2026, 9, 10, 0, 0);
const original = { id, mime: 'application/pdf', size: 123, authMode: 'password', recipientName: 'ダミー開示先', expiresAt: now + 12 * 3600000, sealedExpiresAt: now + 30 * 3600000, revoked: false, pending: 0, failed: 0, providerAccepted: 0 };
function deferred() {
  let resolve;
  const promise = new Promise(yes => { resolve = yes; });
  return { promise, resolve };
}
function response(value, status = 200, type = 'application/json') {
  return { ok: status >= 200 && status < 300, status, headers: new Headers({ 'content-type': type }), text: async () => JSON.stringify(value) };
}
function management(options = {}) {
  const elements = Object.fromEntries(['status', 'error', 'reload', 'owner-page', 'management', 'sharing-state', 'recipient-row', 'recipient', 'deadline', 'copy-link', 'preview', 'expiry-form', 'expires-at', 'save-expiry', 'expiry-limit', 'stop-sharing', 'stop-confirmation', 'confirm-stop', 'cancel-stop'].map(name => [name, {
    textContent: '', value: '', hidden: true, disabled: false, attributes: new Map(), listeners: new Map(),
    addEventListener(event, callback) { this.listeners.set(event, callback); },
    setAttribute(name, value) { this.attributes.set(name, value); },
    removeAttribute(name) { this.attributes.delete(name); if (name === 'href') this.href = ''; },
    focus() { browserDocument.activeElement = this; },
  }]));
  const events = new Map(), requests = [], copied = [], navigations = [], timers = new Map();
  const clock = { now }, browserDocument = { getElementById: name => elements[name] };
  const state = { metadata: { ...original, ...options.metadata } };
  class BrowserDate extends Date { static now() { return clock.now; } }
  let timerId = 0;
  vm.runInNewContext(js, {
    document: browserDocument, Date: BrowserDate, Intl, AbortController,
    location: { origin: 'https://vault.example', reload() { navigations.push('/v1/admin'); } },
    navigator: { clipboard: { writeText: async value => { copied.push(value); if (options.clipboardReject) throw new Error('denied'); } } },
    addEventListener: (event, callback) => events.set(event, callback),
    setTimeout: (callback, milliseconds) => { const key = ++timerId; timers.set(key, { callback, milliseconds }); return key; },
    clearTimeout: key => timers.delete(key),
    fetch: (url, request) => {
      requests.push({ url, request });
      if (options.fetch) return options.fetch(url, request, state, requests.length);
      if (url === '/v1/management') return Promise.resolve(response({ documentId: id }));
      if (url.endsWith('/metadata')) return Promise.resolve(response(state.metadata));
      if (url.endsWith('/expiry')) { state.metadata.expiresAt = JSON.parse(request.body).expiresAt; return Promise.resolve(response({ expiresAt: state.metadata.expiresAt })); }
      if (url.endsWith('/revoke')) { state.metadata.revoked = true; return Promise.resolve(response({ revoked: true })); }
      throw new Error('Unexpected request');
    },
  });
  return {
    elements, requests, copied, navigations, timers, state, clock, browserDocument,
    event: (event, value = {}) => events.get(event)(value),
    click: name => elements[name].listeners.get('click')(),
    submit: () => elements['expiry-form'].listeners.get('submit')({ preventDefault() {} }),
    input: value => { elements['expires-at'].value = value; elements['expires-at'].listeners.get('input')(); },
  };
}
async function settled() { await new Promise(resolve => setImmediate(resolve)); }

test('management loads metadata only and presents protected links without decrypting a PDF', async () => {
  const ui = management(); await settled();
  assert.equal(ui.elements.management.hidden, false);
  assert.equal(ui.elements['sharing-state'].textContent, '共有中');
  assert.equal(ui.elements.recipient.textContent, 'ダミー開示先');
  assert.equal(ui.elements['expires-at'].value, '2026-10-10T21:00');
  assert.equal(ui.elements['expires-at'].max, '2026-10-11T15:00');
  assert.match(ui.elements.deadline.textContent, /21:00.*日本時間/);
  assert.equal(ui.elements.preview.href, 'https://vault.example/p/' + id);
  assert.deepEqual(ui.requests.map(({ url }) => url), ['/v1/management', '/v1/documents/' + id + '/metadata']);
  for (const { request } of ui.requests) {
    assert.equal(request.method, 'GET'); assert.equal(request.credentials, 'same-origin');
    assert.equal(request.cache, 'no-store'); assert.equal(request.redirect, 'error');
  }
  assert.deepEqual(ui.copied, []);
  await ui.click('copy-link'); assert.deepEqual(ui.copied, ['https://vault.example/p/' + id]);
});

test('Access documents retain the existing Access viewer route', async () => {
  const ui = management({ metadata: { authMode: 'access', recipientName: null } }); await settled();
  assert.equal(ui.elements.preview.href, 'https://vault.example/#' + id);
  assert.equal(ui.elements['recipient-row'].hidden, true);
});

test('changing a deadline sends Japan time and the exact previous deadline once', async () => {
  const gate = deferred();
  const ui = management({ fetch(url, request, state) {
    if (url === '/v1/management') return Promise.resolve(response({ documentId: id }));
    if (url.endsWith('/metadata')) return Promise.resolve(response(state.metadata));
    state.metadata.expiresAt = JSON.parse(request.body).expiresAt; return gate.promise;
  } });
  await settled(); ui.input('2026-10-11T12:34'); ui.submit(); ui.submit();
  const mutation = ui.requests.filter(({ request }) => request.method === 'POST');
  assert.equal(mutation.length, 1);
  assert.equal(mutation[0].url, '/v1/documents/' + id + '/expiry');
  assert.deepEqual(JSON.parse(mutation[0].request.body), { expiresAt: Date.UTC(2026, 9, 11, 3, 34), expectedExpiresAt: original.expiresAt });
  assert.equal(mutation[0].request.headers['content-type'], 'application/json');
  assert.equal(ui.elements['save-expiry'].disabled, true);
  gate.resolve(response({ expiresAt: ui.state.metadata.expiresAt })); await settled();
  assert.equal(ui.elements.status.textContent, '閲覧期限を保存しました。');
  assert.equal(ui.elements['expires-at'].value, '2026-10-11T12:34');
});

test('invalid, expired and beyond-sealed deadlines cause no mutation', async () => {
  const ui = management(); await settled();
  for (const value of ['2026-02-30T10:00', '2026-10-10T09:00', '2026-10-11T15:01', '2026-10-11T12:34Z']) {
    ui.input(value); ui.submit(); await settled();
    assert.equal(ui.elements['save-expiry'].disabled, true);
  }
  assert.equal(ui.requests.filter(({ request }) => request.method === 'POST').length, 0);
});

test('a conflicting deadline refreshes metadata and does not automatically retry saving', async () => {
  const ui = management({ fetch(url, request, state) {
    if (url === '/v1/management') return Promise.resolve(response({ documentId: id }));
    if (url.endsWith('/metadata')) return Promise.resolve(response(state.metadata));
    state.metadata.expiresAt = now + 11 * 3600000; return Promise.resolve(response({ error: 'conflict' }, 409));
  } });
  await settled(); ui.input('2026-10-10T22:00'); ui.submit(); await settled();
  assert.equal(ui.requests.filter(({ request }) => request.method === 'POST').length, 1);
  assert.equal(ui.elements['expires-at'].value, '2026-10-10T20:00');
  assert.match(ui.elements.error.textContent, /表示を更新しました/);
});

test('sharing ends only after an explicit confirmation and cannot be re-enabled', async () => {
  const ui = management(); await settled();
  ui.click('confirm-stop'); await settled(); assert.equal(ui.requests.length, 2);
  ui.click('stop-sharing'); assert.equal(ui.elements['stop-confirmation'].hidden, false);
  assert.equal(ui.browserDocument.activeElement, ui.elements['confirm-stop']);
  ui.click('cancel-stop'); ui.click('confirm-stop'); await settled(); assert.equal(ui.requests.length, 2);
  ui.click('stop-sharing'); ui.click('confirm-stop'); ui.click('confirm-stop'); await settled();
  const mutation = ui.requests.filter(({ request }) => request.method === 'POST');
  assert.equal(mutation.length, 1); assert.equal(mutation[0].url, '/v1/documents/' + id + '/revoke');
  assert.deepEqual(JSON.parse(mutation[0].request.body), {});
  assert.equal(ui.elements['sharing-state'].textContent, '共有終了');
  assert.equal(ui.elements['save-expiry'].disabled, true); assert.equal(ui.elements['stop-sharing'].disabled, true);
  assert.equal(ui.elements.preview.href, ''); assert.equal(ui.elements['copy-link'].disabled, true);
});

test('unknown mutation results require a read before another change', async () => {
  const ui = management({ fetch(url, request, state) {
    if (url === '/v1/management') return Promise.resolve(response({ documentId: id }));
    if (url.endsWith('/metadata')) return Promise.resolve(response(state.metadata));
    return Promise.reject(new Error('connection lost'));
  } });
  await settled(); ui.input('2026-10-10T22:00'); ui.submit(); await settled();
  assert.equal(ui.elements.reload.hidden, false); assert.equal(ui.elements['save-expiry'].disabled, true);
  ui.submit(); assert.equal(ui.requests.filter(({ request }) => request.method === 'POST').length, 1);
  ui.click('reload'); await settled();
  assert.equal(ui.elements['save-expiry'].disabled, false);
  assert.deepEqual(ui.navigations, []);
});

for (const code of [401, 403]) test('owner authorization failure ' + code + ' clears document controls', async () => {
  const ui = management({ fetch: async () => response({ error: 'not_allowed' }, code) }); await settled();
  assert.equal(ui.elements.management.hidden, true); assert.equal(ui.elements['save-expiry'].disabled, true);
  assert.match(ui.elements.error.textContent, /管理者としてログインし直してください/);
  assert.equal(ui.elements.reload.textContent, 'ログインし直す');
  ui.click('reload'); assert.deepEqual(ui.navigations, ['/v1/admin']);
  assert.equal(ui.requests.length, 1);
});

test('an ambiguous fetch failure provides a manual owner page link and read-only retry', async () => {
  const ui = management({ fetch: async () => { throw new TypeError('redirect or network failure'); } }); await settled();
  assert.equal(ui.elements['owner-page'].hidden, false);
  assert.match(ui.elements.error.textContent, /管理ページを開き直してください/);
  ui.click('reload'); await settled();
  assert.equal(ui.requests.length, 2); assert.ok(ui.requests.every(({ request }) => request.method === 'GET'));
  assert.deepEqual(ui.navigations, []);
});

test('invalid document routing and malformed metadata never create a sharing link', async () => {
  for (const documentId of ['../other', '<script>alert(1)</script>']) {
    const ui = management({ fetch: async () => response({ documentId }) }); await settled();
    assert.equal(ui.requests.length, 1); assert.equal(ui.elements.management.hidden, true);
  }
  for (const metadata of [{ authMode: 'public' }, { id: '../other' }, { expiresAt: original.sealedExpiresAt + 1 }, { recipientName: { html: 'unsafe' } }]) {
    const ui = management({ metadata }); await settled(); assert.equal(ui.elements.management.hidden, true);
  }
});

test('recipient text remains text and pagehide cancels late state updates', async () => {
  const gate = deferred();
  const ui = management({ metadata: { recipientName: '<img src=x onerror=alert(1)>' }, fetch(url, request, state) {
    if (url === '/v1/management') return Promise.resolve(response({ documentId: id }));
    if (url.endsWith('/metadata')) return Promise.resolve(response(state.metadata));
    return gate.promise;
  } });
  await settled(); assert.equal(ui.elements.recipient.textContent, '<img src=x onerror=alert(1)>');
  ui.input('2026-10-10T22:00'); ui.submit(); const mutation = ui.requests.at(-1);
  ui.event('pagehide'); assert.equal(mutation.request.signal.aborted, true);
  gate.resolve(response({ expiresAt: now + 14 * 3600000 })); await settled();
  assert.equal(ui.elements.management.hidden, true); assert.equal(ui.elements.recipient.textContent, '');
  assert.equal(ui.elements.status.textContent, ''); assert.equal(ui.requests.length, 3);
});

test('protected page supports strict CSP and keeps limitations in the collapsed guidance', () => {
  assert.match(html, /href="\/v1\/admin\/assets\/admin.css"/);
  assert.match(html, /src="\/v1\/admin\/assets\/admin.js" type="module"/);
  assert.doesNotMatch(html, /<style|\sstyle=|\son\w+=|<script(?![^>]*src=)/i);
  assert.match(html, /<details[^>]*><summary>ご案内<\/summary><p>現在はダミーPDFを共有しています/);
  assert.doesNotMatch(html, /type="password"|パスワードの変更|アップロード/);
  assert.match(css, /prefers-reduced-motion/); assert.match(css, /@media\(max-width:540px\)/);
});
