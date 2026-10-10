import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { html, js } from '../src/link-admin.js';
import { html as adminHtml, linksJs } from '../src/admin.js';

const id = '39d0e59d-e5a6-4c02-a8b9-b2a169071eea';
const grantId = 'ea928a13-d8e0-4873-9b66-8fc9372c6760';
const now = Date.UTC(2026, 9, 10), expiry = now + 3600000;
const origin = 'https://vault.example', url = `${origin}/p/${id}#link=${'a'.repeat(64)}`;
const names = ['links-panel', 'links-status', 'links-controls', 'links-recipient', 'links-form',
  'links-expiry', 'links-create', 'links-limit', 'links-issued', 'links-url', 'links-copy', 'links-list', 'links-refresh'];
const json = (value, status = 200) => Response.json(value, { status });
const link = (overrides = {}) => ({ id: grantId, createdAt: now, expiresAt: expiry, revoked: false, ...overrides });
const snapshot = (overrides = {}) => ({ revision: 0, links: [], recipientName: '株式会社ダミー', documentExpiresAt: expiry,
  revoked: false, enabled: true, ...overrides });
function deferred() { let resolve; const promise = new Promise(yes => { resolve = yes; }); return { promise, resolve }; }
async function settled() { await new Promise(resolve => setImmediate(resolve)); await new Promise(resolve => setImmediate(resolve)); }

function browser(options = {}) {
  function element() {
    return { textContent: '', value: '', hidden: false, disabled: false, open: false, children: [], listeners: new Map(),
      addEventListener(name, callback) { this.listeners.set(name, callback); },
      append(...children) { this.children.push(...children); }, replaceChildren(...children) { this.children = children; },
      set innerHTML(_) { throw new Error('unsafe_html'); } };
  }
  const elements = Object.fromEntries(names.map(name => [name, element()])), requests = [], events = new Map(), copies = [], timers = new Map();
  const state = { status: snapshot(), ...options.state };
  let clock = now, timerId = 0;
  class BrowserDate extends Date { static now() { return clock; } }
  vm.runInNewContext(js, {
    Date: BrowserDate, Intl, Uint8Array, TextDecoder, AbortController,
    location: { origin }, document: { getElementById: name => elements[name], createElement: () => element() },
    navigator: { clipboard: { async writeText(value) { copies.push(value); if (options.clipboardReject) throw new Error(); } } },
    addEventListener: (name, callback) => events.set(name, callback),
    setTimeout: (callback, milliseconds) => { const key = ++timerId; timers.set(key, { callback, at: clock + milliseconds }); return key; },
    clearTimeout: key => timers.delete(key),
    fetch: async (path, request) => {
      requests.push({ path, request });
      if (options.fetch) return options.fetch(path, request, state);
      if (path === '/v1/management') return json({ documentId: id });
      if (path !== `/v1/documents/${id}/links`) throw new Error('unexpected_request');
      if (request.method !== 'POST') return json(state.status);
      const body = JSON.parse(request.body);
      if (body.action === 'create') {
        state.status = snapshot({ ...state.status, revision: state.status.revision + 1, links: [link({ expiresAt: body.expiresAt })] });
        return json({ revision: state.status.revision, link: state.status.links[0], url }, 201);
      }
      state.status = snapshot({ ...state.status, revision: state.status.revision + 1,
        links: state.status.links.map(value => value.id === body.linkId ? { ...value, revoked: true } : value) });
      return json(state.status);
    },
  });
  return { elements, requests, state, copies, timers,
    async open() { elements['links-panel'].open = true; elements['links-panel'].listeners.get('toggle')(); await settled(); },
    click(name) { return elements[name].listeners.get('click')(); },
    submit() { return elements['links-form'].listeners.get('submit')({ preventDefault() {} }); },
    input(value) { elements['links-expiry'].value = value; elements['links-expiry'].listeners.get('input')(); },
    event(name, value = {}) { return events.get(name)(value); },
    posts() { return requests.filter(({ request }) => request.method === 'POST'); },
    stop(index = 0) { return elements['links-list'].children[index].children[1].listeners.get('click')(); },
    advance(milliseconds) { clock += milliseconds; for (const [key, timer] of [...timers]) if (timer.at <= clock) { timers.delete(key); timer.callback(); } },
  };
}

test('owner link panel is folded, lazy and integrated without sending notifications or fetching a PDF', async () => {
  const ui = browser(); await settled();
  assert.match(html, /<details id="links-panel"><summary>閲覧用URL<\/summary>/);
  assert.match(adminHtml, /src="\/v1\/admin\/assets\/links\.js" type="module"/); assert.equal(linksJs, js);
  assert.doesNotMatch(html, /<a\s|<img|https?:\/\//);
  assert.deepEqual(ui.requests.map(({ path }) => path), ['/v1/management']);
  await ui.open(); assert.deepEqual(ui.requests.map(({ path }) => path), ['/v1/management', `/v1/documents/${id}/links`]);
  assert.equal(ui.elements['links-recipient'].textContent, '株式会社ダミー');
  assert.equal(ui.elements['links-expiry'].value, '2026-10-10T10:00');
  assert.equal(ui.elements['links-create'].disabled, false); assert.equal(ui.elements['links-url'].value, '');
  assert.equal(ui.posts().length, 0); assert.equal(ui.copies.length, 0);
  for (const { request } of ui.requests) {
    assert.equal(request.method, 'GET'); assert.equal(request.credentials, 'same-origin');
    assert.equal(request.cache, 'no-store'); assert.equal(request.redirect, 'error');
  }
});

test('create is explicit, confirms the grant and returns a copyable URL only once in page memory', async () => {
  const ui = browser(); await settled(); await ui.open(); ui.submit(); ui.submit(); await settled();
  assert.equal(ui.posts().length, 1);
  assert.deepEqual(JSON.parse(ui.posts()[0].request.body), { action: 'create', expiresAt: expiry, expectedRevision: 0 });
  assert.equal(ui.requests.length, 4); assert.equal(ui.requests[3].request.method, 'GET');
  assert.equal(ui.elements['links-url'].value, url); assert.equal(ui.elements['links-copy'].disabled, false);
  assert.equal(ui.elements['links-issued'].hidden, false); assert.equal(ui.elements['links-list'].children.length, 1);
  await ui.click('links-copy'); assert.deepEqual(ui.copies, [url]);
  assert.equal(ui.requests.filter(({ path }) => path.includes('#link=') || path.includes('/open')).length, 0);
  ui.click('links-refresh'); await settled(); assert.equal(ui.elements['links-url'].value, '');
  assert.equal(ui.elements['links-issued'].hidden, true); assert.equal(ui.elements['links-list'].children.length, 1);
  assert.doesNotMatch(js, /localStorage|sessionStorage|console\.|innerHTML|createElement\("a"\)/);
});

test('revoking one issued grant clears its secret and shows its irreversible stopped state', async () => {
  const ui = browser(); await settled(); await ui.open(); ui.submit(); await settled();
  ui.stop(); await settled();
  assert.deepEqual(JSON.parse(ui.posts()[1].request.body), { action: 'revoke', linkId: grantId, expectedRevision: 1 });
  assert.equal(ui.elements['links-url'].value, ''); assert.equal(ui.elements['links-copy'].disabled, true);
  assert.match(ui.elements['links-list'].children[0].children[0].children[0].textContent, /停止済み/);
  assert.equal(ui.elements['links-list'].children[0].children.length, 1); assert.equal(ui.elements['links-create'].disabled, false);
});

test('expiry, inactive documents and disabled link sharing cannot produce a mutation even through synthetic controls', async () => {
  for (const status of [snapshot({ enabled: false }), snapshot({ revoked: true }), snapshot({ documentExpiresAt: now })]) {
    const ui = browser({ state: { status } }); await settled(); await ui.open(); ui.submit(); await settled();
    assert.equal(ui.posts().length, 0); assert.equal(ui.elements['links-create'].disabled, true);
  }
  const ui = browser(); await settled(); await ui.open(); ui.submit(); await settled(); ui.advance(3600001);
  await ui.click('links-copy'); assert.equal(ui.elements['links-url'].value, ''); assert.equal(ui.elements['links-copy'].disabled, true);
  assert.equal(ui.copies.length, 0); assert.equal(ui.elements['links-list'].children[0].children.length, 1);
});

test('invalid calendar dates and deadlines beyond the document deadline produce no mutation', async () => {
  const ui = browser(); await settled(); await ui.open();
  for (const value of ['2026-02-30T10:00', '2026-10-10T09:00', '2026-10-10T10:01', '2026-10-10T10:00Z']) {
    ui.input(value); ui.submit(); await settled(); assert.equal(ui.elements['links-create'].disabled, true);
  }
  assert.equal(ui.posts().length, 0);
});

for (const status of [400, 401, 403, 409, 429, 503]) test(`uncertain create status ${status} blocks retries until an explicit state read`, async () => {
  const ui = browser({ fetch(path, request) {
    if (path === '/v1/management') return json({ documentId: id });
    return request.method === 'POST' ? json({ error: 'synthetic' }, status) : json(snapshot());
  } }); await settled(); await ui.open(); ui.submit(); await settled();
  assert.equal(ui.elements['links-create'].disabled, true); assert.equal(ui.elements['links-url'].value, '');
  ui.submit(); await settled(); assert.equal(ui.posts().length, 1);
  ui.click('links-refresh'); await settled(); assert.equal(ui.elements['links-create'].disabled, false); assert.equal(ui.posts().length, 1);
});

test('a create response needs a fresh authoritative grant read before exposing a secret', async () => {
  let reads = 0;
  const ui = browser({ fetch(path, request) {
    if (path === '/v1/management') return json({ documentId: id });
    if (request.method === 'GET') { reads++; return json(reads === 1 ? snapshot() : snapshot({ revision: 1, links: [link({ revoked: true })] })); }
    return json({ revision: 1, link: link(), url }, 201);
  } }); await settled(); await ui.open(); ui.submit(); await settled();
  assert.equal(ui.elements['links-url'].value, ''); assert.equal(ui.elements['links-copy'].disabled, true);
  assert.equal(ui.elements['links-create'].disabled, true); assert.match(ui.elements['links-status'].textContent, /発行結果を確認できません/);
});

test('untrusted URL, wrong document and malformed create response never become copyable', async () => {
  for (const value of [
    { revision: 1, link: link(), url: url.replace(origin, 'https://attacker.example') },
    { revision: 1, link: link(), url: url.replace(id, grantId) },
    { revision: 1, link: link(), url: url + '&extra=secret' },
    { revision: 1, link: link(), url: url.replace('#link=', '?link=') },
    { revision: 1, link: link(), url: url.replace(/a{64}$/, 'A'.repeat(64)) },
    { revision: 0, link: link(), url },
    { revision: 1, link: link({ expiresAt: expiry + 1 }), url },
    { revision: 1, link: link(), url, secret: 'not permitted' },
  ]) {
    const ui = browser({ fetch(path, request) {
      if (path === '/v1/management') return json({ documentId: id });
      return request.method === 'GET' ? json(snapshot()) : json(value, 201);
    } }); await settled(); await ui.open(); ui.submit(); await settled(); await ui.click('links-copy');
    assert.equal(ui.elements['links-url'].value, ''); assert.equal(ui.copies.length, 0); assert.equal(ui.requests.length, 3);
  }
});

test('disclosure names are rendered as text and do not cause HTML or network activity', async () => {
  const recipientName = '<img src=x onerror=alert(1)>', ui = browser({ state: { status: snapshot({ recipientName }) } });
  await settled(); await ui.open(); assert.equal(ui.elements['links-recipient'].textContent, recipientName);
  assert.equal(ui.requests.length, 2); assert.equal(ui.posts().length, 0);
});

test('malformed, duplicate, expanded and oversized grant snapshots fail closed', async () => {
  for (const status of [snapshot({ revision: -1 }), snapshot({ recipientName: 'x'.repeat(201) }), snapshot({ recipientName: 'private\nname' }),
    snapshot({ links: [link(), link()] }), snapshot({ links: [link({ id: '../elsewhere' })] }),
    snapshot({ links: [link({ secret: 'not permitted' })] }), snapshot({ links: [link({ createdAt: expiry })] }),
    snapshot({ links: Array.from({ length: 21 }, () => link()) }), snapshot({ documentExpiresAt: 8640000000000000 }), snapshot({ url }), snapshot({ padding: 'x'.repeat(65536) })]) {
    const ui = browser({ state: { status } }); await settled(); await ui.open(); ui.submit(); await settled();
    assert.equal(ui.elements['links-create'].disabled, true); assert.equal(ui.posts().length, 0);
    assert.equal(ui.elements['links-list'].children.length, 0); assert.equal(ui.elements['links-url'].value, '');
  }
});

test('twenty active grants block another issue; stopped grants leave room for explicit replacement', async () => {
  const links = Array.from({ length: 20 }, (_, index) => link({ id: `00000000-0000-4000-8000-${String(index).padStart(12, '0')}` }));
  const ui = browser({ state: { status: snapshot({ links }) } }); await settled(); await ui.open(); ui.submit(); await settled();
  assert.equal(ui.posts().length, 0); assert.equal(ui.elements['links-create'].disabled, true);
  ui.state.status = snapshot({ links: links.map(value => ({ ...value, revoked: true })) }); ui.click('links-refresh'); await settled();
  assert.equal(ui.elements['links-create'].disabled, false);
});

test('pagehide clears secrets and aborts pending operations; a late result cannot repopulate restored state', async () => {
  const old = deferred(), fresh = deferred(); let reads = 0;
  const ui = browser({ fetch(path, request) {
    if (path === '/v1/management') return json({ documentId: id });
    if (request.method === 'POST') return old.promise;
    reads++; return reads === 1 ? json(snapshot()) : fresh.promise;
  } }); await settled(); await ui.open(); ui.submit(); await settled();
  ui.event('pagehide'); assert.equal(ui.posts()[0].request.signal.aborted, true); assert.equal(ui.elements['links-url'].value, '');
  ui.event('pageshow', { persisted: true }); await settled(); assert.equal(reads, 2);
  old.resolve(json({ revision: 1, link: link(), url }, 201)); await settled();
  assert.equal(ui.elements['links-url'].value, ''); assert.equal(ui.elements['links-create'].disabled, true);
  fresh.resolve(json(snapshot())); await settled(); assert.equal(ui.elements['links-create'].disabled, false);
  const issued = browser(); await settled(); await issued.open(); issued.submit(); await settled(); issued.event('pagehide');
  assert.equal(issued.elements['links-url'].value, ''); assert.equal(issued.elements['links-issued'].hidden, true);
  await issued.click('links-copy'); assert.equal(issued.copies.length, 0);
});

test('timeout aborts the request and keeps create unavailable until its outcome is checked', async () => {
  const gate = deferred();
  const ui = browser({ fetch(path, request) {
    if (path === '/v1/management') return json({ documentId: id });
    if (request.method === 'GET') return json(snapshot());
    return gate.promise;
  } }); await settled(); await ui.open(); ui.submit(); await settled(); ui.advance(15001);
  assert.equal(ui.posts()[0].request.signal.aborted, true); assert.equal(ui.elements['links-create'].disabled, true);
  gate.resolve(json({ revision: 1, link: link(), url }, 201)); await settled();
  assert.equal(ui.elements['links-url'].value, ''); assert.equal(ui.elements['links-create'].disabled, true);
  assert.match(ui.elements['links-status'].textContent, /発行結果を確認できません/);
});
