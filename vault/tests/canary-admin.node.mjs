import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { html, js } from '../src/canary-admin.js';

const id = '39d0e59d-e5a6-4c02-a8b9-b2a169071eea', token = 'kr_' + 'a'.repeat(64);
const now = Date.UTC(2026, 9, 10), expiry = now + 3600000;
const names = ['canary-panel', 'canary-status', 'canary-controls', 'canary-create', 'canary-revoke',
  'canary-refresh', 'canary-url', 'canary-copy', 'canary-deadline', 'canary-logs', 'canary-events'];
const json = (value, status = 200) => Response.json(value, { status });
const summary = (canary = null) => ({ configured: true, documentId: id, canary });
const item = (overrides = {}) => ({ token, state: 'active', expiresAt: expiry, hitCount: 0,
  lastSeenAt: null, url: 'https://kanariya.toppymicros.com/canary/' + token, ...overrides });
function deferred() { let resolve, reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; }
async function settled() { await new Promise(resolve => setImmediate(resolve)); await new Promise(resolve => setImmediate(resolve)); }

function browser(options = {}) {
  function element() {
    return { textContent: '', value: '', disabled: false, hidden: false, open: false, children: [], listeners: new Map(),
      addEventListener(name, callback) { this.listeners.set(name, callback); },
      replaceChildren(...children) { this.children = children; },
      set innerHTML(_) { throw new Error('untrusted_html_sink'); } };
  }
  const elements = Object.fromEntries(names.map(name => [name, element()])), requests = [], events = new Map(), copies = [], timers = new Map();
  let clock = now, timerId = 0;
  const state = { status: summary(), logs: { configured: true, documentId: id, events: [] }, ...options.state };
  class BrowserDate extends Date { static now() { return clock; } }
  vm.runInNewContext(js, {
    Date: BrowserDate, Intl, Uint8Array, TextDecoder, AbortController, URL,
    document: { getElementById: name => elements[name], createElement: () => element() },
    navigator: { clipboard: { async writeText(value) { copies.push(value); } } },
    addEventListener: (name, callback) => events.set(name, callback),
    setTimeout: (callback, milliseconds) => { const key = ++timerId; timers.set(key, { callback, at: clock + milliseconds }); return key; },
    clearTimeout: key => timers.delete(key),
    fetch: async (path, request) => {
      requests.push({ path, request });
      if (options.fetch) return options.fetch(path, request, state);
      if (path === '/v1/management') return json({ documentId: id });
      if (path.endsWith('/canary-logs')) return json(state.logs);
      if (path !== `/v1/documents/${id}/canary`) throw new Error('unexpected_request');
      if (request.method === 'POST') state.status = summary(item(JSON.parse(request.body).action === 'revoke' ? { state: 'revoked' } : {}));
      return json(state.status, request.method === 'POST' ? 201 : 200);
    },
  });
  return { elements, requests, state, timers, copies,
    async open() { elements['canary-panel'].open = true; elements['canary-panel'].listeners.get('toggle')(); await settled(); },
    click(name) { return elements[name].listeners.get('click')(); },
    event(name, value = {}) { return events.get(name)(value); },
    posts() { return requests.filter(({ request }) => request.method === 'POST'); },
    advance(milliseconds) { clock += milliseconds; for (const [key, timer] of [...timers]) if (timer.at <= clock) { timers.delete(key); timer.callback(); } },
  };
}

test('Canary remains folded and lazy; no image, link, PDF or automatic notification request is generated', async () => {
  const ui = browser(); await settled();
  assert.match(html, /<details id="canary-panel">/); assert.doesNotMatch(html, /<img|<a\s|https?:\/\//);
  assert.deepEqual(ui.requests.map(({ path }) => path), ['/v1/management']);
  await ui.open(); assert.deepEqual(ui.requests.map(({ path }) => path), ['/v1/management', `/v1/documents/${id}/canary`]);
  assert.equal(ui.posts().length, 0); assert.equal(ui.elements['canary-create'].disabled, false);
  assert.equal(ui.elements['canary-url'].value, '');
  for (const { path, request } of ui.requests) {
    assert.equal(request.method, 'GET'); assert.equal(request.credentials, 'same-origin');
    assert.equal(request.redirect, 'error'); assert.equal(request.cache, 'no-store'); assert.doesNotMatch(path, /\/open|\/test|\/canary\/kr_/);
  }
});

test('an absent binding is shown as unconnected and cannot issue a mutation even from a synthetic click', async () => {
  const ui = browser({ state: { status: { configured: false, documentId: id, canary: null } } }); await settled(); await ui.open();
  assert.equal(ui.elements['canary-controls'].hidden, true); assert.match(ui.elements['canary-status'].textContent, /未接続/);
  ui.click('canary-create'); ui.click('canary-revoke'); await ui.click('canary-copy'); await ui.click('canary-logs');
  assert.equal(ui.posts().length, 0); assert.equal(ui.requests.length, 2); assert.equal(ui.copies.length, 0);
});

test('create runs once, preserves its pending boundary and enables only copying an active fixed URL', async () => {
  const gate = deferred(); const ui = browser({ fetch(path, request) {
    if (path === '/v1/management') return json({ documentId: id });
    if (request.method === 'GET') return json(summary());
    return gate.promise;
  } }); await settled(); await ui.open();
  ui.click('canary-create'); ui.click('canary-create'); assert.equal(ui.posts().length, 1);
  assert.deepEqual(JSON.parse(ui.posts()[0].request.body), { action: 'create' }); assert.equal(ui.elements['canary-create'].disabled, true);
  gate.resolve(json(summary(item()), 201)); await settled();
  assert.equal(ui.elements['canary-create'].disabled, true); assert.equal(ui.elements['canary-revoke'].disabled, false);
  assert.match(ui.elements['canary-deadline'].textContent, /2026\/10\/10 10:00.*日本時間/);
  await ui.click('canary-copy'); assert.deepEqual(ui.copies, [item().url]);
  assert.equal(ui.requests.length, 3); assert.match(ui.elements['canary-status'].textContent, /コピーしました/);
});

for (const code of [409, 503]) test(`a ${code} mutation response prevents reissuing until an explicit state read`, async () => {
  const ui = browser({ fetch(path, request) {
    if (path === '/v1/management') return json({ documentId: id });
    return request.method === 'POST' ? json({ error: 'synthetic' }, code) : json(summary());
  } }); await settled(); await ui.open(); ui.click('canary-create'); await settled();
  assert.equal(ui.elements['canary-create'].disabled, true); assert.match(ui.elements['canary-status'].textContent, /再読み込み/);
  ui.click('canary-create'); await settled(); assert.equal(ui.posts().length, 1); assert.equal(ui.requests.length, 3);
  ui.click('canary-refresh'); await settled(); assert.equal(ui.elements['canary-create'].disabled, false);
  assert.equal(ui.posts().length, 1); assert.equal(ui.requests.length, 4);
});

test('revoke is explicit and clears the URL rather than retaining an inactive usable-looking value', async () => {
  const ui = browser({ state: { status: summary(item()) } }); await settled(); await ui.open();
  ui.click('canary-revoke'); await settled(); assert.deepEqual(JSON.parse(ui.posts()[0].request.body), { action: 'revoke' });
  assert.equal(ui.elements['canary-url'].value, ''); assert.equal(ui.elements['canary-copy'].disabled, true);
  await ui.click('canary-copy'); assert.equal(ui.copies.length, 0); assert.equal(ui.elements['canary-create'].disabled, false);
});

test('expiry clears the URL and blocks a synthetic copy even before its scheduled refresh', async () => {
  const ui = browser({ state: { status: summary(item({ expiresAt: now + 1000 })) } }); await settled(); await ui.open();
  ui.advance(1001); await ui.click('canary-copy');
  assert.equal(ui.elements['canary-url'].value, ''); assert.equal(ui.elements['canary-copy'].disabled, true);
  assert.equal(ui.elements['canary-revoke'].disabled, true); assert.equal(ui.elements['canary-create'].disabled, false); assert.equal(ui.copies.length, 0);
});

test('logs are explicit, bounded and distinguish URL requests and send acceptance from PDF decryption and delivery', async () => {
  const event = { id: 'b'.repeat(32), at: now, outcome: 'url_requested', notifications: [{ type: 'email', state: 'accepted' }] };
  const ui = browser({ state: { logs: { configured: true, documentId: id, events: [event] } } }); await settled(); await ui.open();
  assert.equal(ui.elements['canary-events'].children.length, 0); await ui.click('canary-logs');
  assert.match(ui.elements['canary-events'].children[0].textContent, /URLへのアクセス.*送信受付済み/);
  assert.doesNotMatch(ui.elements['canary-events'].children[0].textContent, /復号|配送完了|受信済み/);
  assert.equal(ui.posts().length, 0); assert.equal(ui.requests[2].path, `/v1/documents/${id}/canary-logs`);
  ui.state.logs.events = Array.from({ length: 51 }, () => event); await ui.click('canary-logs');
  assert.equal(ui.elements['canary-events'].children.length, 0); assert.match(ui.elements['canary-status'].textContent, /読み込めません/);
  ui.state.logs.events = [{ ...event, id: '<img src=x onerror=alert(1)>' }]; await ui.click('canary-logs');
  assert.equal(ui.elements['canary-events'].children.length, 0);
});

test('owner logs show source IP, network and referrer hostname as text without triggering requests', async () => {
  const network = '<img src=x onerror=alert(1)>', event = { id: 'b'.repeat(32), at: now, outcome: 'url_requested', notifications: [],
    source: { ip: '198.51.100.9', country: 'JP', asn: 64500, network, refererHost: 'careers.example.test' } };
  const ui = browser({ state: { logs: { configured: true, documentId: id, events: [event] } } }); await settled(); await ui.open();
  await ui.click('canary-logs');
  const text = ui.elements['canary-events'].children[0].textContent;
  assert.match(text, /接続元IP: 198\.51\.100\.9（JP）/);
  assert.ok(text.includes('ネットワーク: ' + network + ' AS64500'));
  assert.match(text, /参照元サイト: careers\.example\.test/);
  assert.equal(ui.requests.length, 3); assert.equal(ui.posts().length, 0);
  assert.match(html, /<summary>ご案内<\/summary>.*接続元IP・ネットワーク・参照元サイト/);
  for (const source of [null, undefined, { ip: '2001:db8::9', country: '', asn: null, network: '', refererHost: '' }]) {
    ui.state.logs.events = [{ ...event, source }]; await ui.click('canary-logs');
    const displayed = ui.elements['canary-events'].children[0].textContent;
    if (source) { assert.match(displayed, /接続元IP: 2001:db8::9/); assert.doesNotMatch(displayed, /ネットワーク:|参照元サイト:/); }
    else assert.match(displayed, /接続元情報なし/);
  }
});

test('malformed source fields and expanded records clear owner logs without rendering', async () => {
  const source = { ip: '198.51.100.9', country: 'JP', asn: 64500, network: 'Example network', refererHost: 'careers.example.test' };
  const event = { id: 'b'.repeat(32), at: now, outcome: 'url_requested', notifications: [], source };
  const ui = browser({ state: { logs: { configured: true, documentId: id, events: [event] } } }); await settled(); await ui.open();
  await ui.click('canary-logs'); assert.equal(ui.elements['canary-events'].children.length, 1);
  for (const invalid of [{}, [], { ...source, ip: '<img src=x>' }, { ...source, ip: '198.51.100.999' },
    { ...source, ip: '0198.51.100.9' }, { ...source, ip: '2001:db8::9%en0' }, { ...source, ip: 'a'.repeat(46) },
    { ...source, country: 'jp' }, { ...source, asn: 4294967296 }, { ...source, asn: 0 }, { ...source, asn: '64500' },
    { ...source, network: 'x'.repeat(161) }, { ...source, network: 'name\nPRIVATE' }, { ...source, network: 'name\u0085PRIVATE' },
    { ...source, refererHost: 'user:secret@careers.example.test' }, { ...source, refererHost: 'careers.example.test:443' },
    { ...source, refererHost: 'careers.example.test/private' }, { ...source, refererHost: 'careers.example.test?email=private' },
    { ...source, refererHost: 'Careers.example.test' }, { ...source, refererHost: 'x'.repeat(254) }, { ...source, email: 'private@example.test' },
  ]) {
    ui.state.logs.events = [{ ...event, source: invalid }]; await ui.click('canary-logs');
    assert.equal(ui.elements['canary-events'].children.length, 0); assert.match(ui.elements['canary-status'].textContent, /読み込めません/);
  }
  for (const invalid of [{ ...event, readerEmail: 'private@example.test' }, { ...event, notifications: [{ state: 'accepted' }] },
    { ...event, at: 0 }, { ...event, at: 8640000000000001 }]) {
    ui.state.logs.events = [invalid]; await ui.click('canary-logs'); assert.equal(ui.elements['canary-events'].children.length, 0);
  }
  ui.state.logs = { configured: true, documentId: id, events: [event], extra: 'private' };
  await ui.click('canary-logs'); assert.equal(ui.elements['canary-events'].children.length, 0);
  assert.equal(ui.posts().length, 0);
});

test('invalid IDs and foreign URL responses cannot produce a URL or enable a mutation', async () => {
  const invalid = browser({ fetch: async () => json({ documentId: '../admin' }) }); await settled(); await invalid.open();
  assert.equal(invalid.requests.length, 1); assert.equal(invalid.elements['canary-create'].disabled, true);
  const foreign = browser({ state: { status: summary(item({ url: 'https://attacker.example/canary/' + token })) } }); await settled(); await foreign.open();
  assert.equal(foreign.elements['canary-url'].value, ''); assert.equal(foreign.elements['canary-create'].disabled, true);
});

test('oversized responses fail closed before displaying or mutating Canary state', async () => {
  const ui = browser({ fetch(path) { return path === '/v1/management' ? json({ documentId: id }) : json({ ...summary(item()), padding: 'x'.repeat(65536) }); } });
  await settled(); await ui.open(); assert.equal(ui.elements['canary-url'].value, ''); assert.equal(ui.elements['canary-create'].disabled, true);
  ui.click('canary-create'); await settled(); assert.equal(ui.posts().length, 0);
});

test('page restoration rechecks state and late responses cannot unlock or repopulate the restored page', async () => {
  const old = deferred(), fresh = deferred(); let reads = 0;
  const ui = browser({ fetch(path, request) {
    if (path === '/v1/management') return json({ documentId: id });
    if (request.method === 'GET') { reads++; return reads === 1 ? json(summary()) : fresh.promise; }
    return old.promise;
  } }); await settled(); await ui.open(); ui.click('canary-create'); await settled();
  ui.event('pagehide'); assert.equal(ui.posts()[0].request.signal.aborted, true); assert.equal(ui.elements['canary-url'].value, '');
  ui.event('pageshow', { persisted: true }); await settled(); assert.equal(reads, 2); assert.equal(ui.elements['canary-create'].disabled, true);
  old.resolve(json(summary(item()), 201)); await settled();
  assert.equal(ui.elements['canary-url'].value, ''); assert.equal(ui.elements['canary-create'].disabled, true);
  ui.click('canary-create'); assert.equal(ui.posts().length, 1);
  fresh.resolve(json(summary())); await settled(); assert.equal(ui.elements['canary-create'].disabled, false);
});
