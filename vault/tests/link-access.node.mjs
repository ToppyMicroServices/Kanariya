import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { generateKeyPair, exportJWK, SignJWT } from 'jose';
import worker, { VaultDocument } from '../src/worker.js';
import { newKey, importKey, sealDocument, openJSON, sealJSON, utf8 } from '../src/crypto.js';
import { hashToken } from '../src/password.js';
import { MAX_READER_LINKS } from '../src/links.js';

const originalFetch = globalThis.fetch;
after(() => { globalThis.fetch = originalFetch; });
const pair = await generateKeyPair('RS256', { extractable: true });
const jwk = { ...await exportJWK(pair.publicKey), kid: 'link-fixture', use: 'sig', alg: 'RS256' };
const PASSWORD = 'synthetic link fallback password';
let fixtureNumber = 0;
function list(map, options) {
  let entries = [...map].filter(([key]) => key.startsWith(options.prefix) && (!options.end || key < options.end) && (!options.start || key >= options.start))
    .sort(([a], [b]) => a.localeCompare(b));
  if (options.reverse) entries.reverse();
  return new Map(entries.slice(0, options.limit));
}
class Storage {
  constructor() { this.map = new Map(); this.alarmAt = null; this.tail = Promise.resolve(); }
  async get(key) { return structuredClone(this.map.get(key)); }
  async list(options) { return list(this.map, options); }
  transaction(operation) {
    const result = this.tail.then(async () => {
      const draft = new Map(structuredClone([...this.map])); let alarmAt = this.alarmAt;
      const value = await operation({ get: async key => structuredClone(draft.get(key)), list: async options => list(draft, options),
        put: async (key, data) => { draft.set(key, structuredClone(data)); }, delete: async key => draft.delete(key),
        setAlarm: async at => { alarmAt = at; }, deleteAlarm: async () => { alarmAt = null; } });
      this.map = draft; this.alarmAt = alarmAt; return value;
    });
    this.tail = result.catch(() => {}); return result;
  }
}
// These fixtures have only synthetic PDF bytes, local keys and a mock provider.
async function fixture({ authMode = 'password', expiresAt = Date.now() + 600000, recipientName = 'Synthetic Recipient' } = {}) {
  const id = crypto.randomUUID(), subject = 'synthetic-reader', pdf = utf8('%PDF-1.4\nSYNTHETIC_LINK_DOCUMENT\n');
  const env = { PUBLIC_ORIGIN: 'https://vault.example.test', ACCESS_ISSUER: `https://link-fixture-${++fixtureNumber}.cloudflareaccess.com`,
    ACCESS_AUDIENCE: 'synthetic-audience', VAULT_WRAP_KEY: newKey(), VAULT_AUDIT_KEY: newKey(), VAULT_OWNER_SUB: 'synthetic-owner',
    PASSWORD_READER_ENABLED: '1', WEBHOOK_URL: 'https://notify.example.test/synthetic-link-path' };
  const wrappingKey = await importKey(env.VAULT_WRAP_KEY), auditKey = await importKey(env.VAULT_AUDIT_KEY);
  let record = await sealDocument({ id, bytes: pdf, expiresAt, subjects: authMode === 'password' ? [] : [subject], authMode,
    ...(authMode === 'password' ? { password: PASSWORD } : {}), recipientName }, wrappingKey);
  const pinRecord = () => { env.DUMMY_DOCUMENT_ID = id; env.DUMMY_RECORD_SHA256 = createHash('sha256').update(JSON.stringify(record)).digest('hex'); };
  pinRecord();
  const storage = new Storage(), context = `journal:v1:link-object-${id}`, ctx = { storage, id: { toString: () => `link-object-${id}` } };
  let instance = new VaultDocument(ctx, env), reads = 0, recordHandler;
  const calls = [], cookieLinks = new Map(), issuedTokens = new Map();
  env.VAULT_DOCUMENTS = { async get(name) { reads++; assert.equal(name, `${id}.sealed.json`);
    if (recordHandler) await recordHandler();
    const bytes = utf8(JSON.stringify(record)); return { size: bytes.length, body: new Response(bytes).body }; } };
  env.VAULT = { idFromName: value => { assert.equal(value, id); return value; }, get: () => instance };
  globalThis.fetch = async (url, options) => {
    if (String(url) === `${env.ACCESS_ISSUER}/cdn-cgi/access/certs`) return Response.json({ keys: [jwk] });
    assert.equal(String(url), env.WEBHOOK_URL);
    calls.push(JSON.parse(options.body)); return new Response('synthetic provider response', { status: 202 });
  };
  async function token(sub = subject) {
    return new SignJWT({ sub, iss: env.ACCESS_ISSUER, aud: env.ACCESS_AUDIENCE, iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + 600 })
      .setProtectedHeader({ alg: 'RS256', kid: 'link-fixture' }).sign(pair.privateKey);
  }
  async function request(action = 'session', options = {}) {
    const access = options.access === true, method = options.method || (['status', 'metadata', 'links', 'logs'].includes(action) ? 'GET' : 'POST');
    const linkContext = options.linkContext === undefined ? cookieLinks.get(options.cookie) : options.linkContext;
    const headers = { origin: env.PUBLIC_ORIGIN, 'content-type': 'application/json', 'cf-connecting-ip': '192.0.2.1',
      ...(options.cookie ? { cookie: options.cookie } : {}), ...(linkContext ? { 'x-vault-reader-link': linkContext } : {}),
      ...(options.subject ? { 'cf-access-jwt-assertion': await token(options.subject) } : {}), ...options.headers };
    const body = options.body ?? JSON.stringify(action === 'session' && method === 'POST' ? { password: PASSWORD } :
      action === 'open' ? { requestId: options.requestId || crypto.randomUUID() } : {});
    const url = `${env.PUBLIC_ORIGIN}${access ? '/v1/documents' : '/p'}/${options.id || id}/${action}${options.query || ''}`;
    const req = new Request(options.url || url, { method, headers, ...(['GET', 'HEAD'].includes(method) ? {} : { body }) });
    return options.direct ? instance.fetch(req) : worker.fetch(req, env);
  }
  async function create(expires = expiresAt, expectedRevision) {
    if (expectedRevision === undefined) {
      const response = await request('links', { access: true, subject: env.VAULT_OWNER_SUB }); assert.equal(response.status, 200);
      expectedRevision = (await response.json()).revision;
    }
    const response = await request('links', { access: true, subject: env.VAULT_OWNER_SUB, method: 'POST',
      body: JSON.stringify({ action: 'create', expiresAt: expires, expectedRevision }) });
    assert.equal(response.status, 200, await response.clone().text());
    const value = await response.json(), match = /^#link=([0-9a-f]{64})$/.exec(new URL(value.url).hash);
    assert.ok(match, 'The one-time credential stays in the URL fragment');
    issuedTokens.set(match[1], value.link.id);
    return { ...value, token: match[1], response };
  }
  async function login(linkToken) {
    const response = await request('session', { body: JSON.stringify(linkToken === undefined ? { password: PASSWORD } : { linkToken }) });
    assert.equal(response.status, 200, await response.clone().text());
    const setCookie = response.headers.get('set-cookie'); assert.ok(setCookie);
    const cookie = setCookie.split(';')[0], body = await response.json();
    if (linkToken === undefined) assert.equal(body.linkId, undefined);
    else assert.equal(body.linkId, issuedTokens.get(linkToken));
    cookieLinks.set(cookie, body.linkId);
    return { cookie, setCookie, response, body };
  }
  async function state() { const box = await storage.get('encrypted-journal'); return box ? openJSON(box, auditKey, context) : null; }
  return { env, id, subject, pdf, recipientName, expiresAt, storage, auditKey, wrappingKey, context, token, request, create, login, state, calls, pinRecord,
    get reads() { return reads; }, get record() { return record; }, set record(value) { record = value; },
    set recordHandler(value) { recordHandler = value; },
    restart() { instance = new VaultDocument(ctx, env); }, alarm() { return instance.alarm(); },
    async writeState(value) { storage.map.set('encrypted-journal', await sealJSON(value, auditKey, context)); } };
}
async function withClock(at, operation) {
  const original = Date.now; Date.now = () => at;
  try { return await operation(); } finally { Date.now = original; }
}
function privateResponse(response) {
  assert.match(response.headers.get('cache-control'), /no-store/);
  assert.equal(response.headers.get('referrer-policy'), 'no-referrer');
  assert.equal(response.headers.get('cdn-cache-control'), 'no-store');
  assert.notEqual(response.headers.get('access-control-allow-origin'), '*');
}
async function stop(f, linkId, expectedRevision) {
  return f.request('links', { access: true, subject: f.env.VAULT_OWNER_SUB, method: 'POST', body: JSON.stringify({ action: 'revoke', linkId, expectedRevision }) });
}
function deferred() { let resolve; const promise = new Promise(r => { resolve = r; }); return { promise, resolve }; }
async function within(promise, milliseconds = 1000) {
  let timer;
  try { return await Promise.race([promise, new Promise(resolve => { timer = setTimeout(() => resolve(null), milliseconds); })]); }
  finally { clearTimeout(timer); }
}

test('only the Access owner can read or manage reader links, before key and document access', async () => {
  const f = await fixture(); let keyReads = 0;
  for (const name of ['VAULT_WRAP_KEY', 'VAULT_AUDIT_KEY']) { const value = f.env[name]; Object.defineProperty(f.env, name, { get() { keyReads++; return value; } }); }
  for (const method of ['GET', 'POST']) {
    for (const options of [{}, { subject: f.subject }, { headers: { 'cf-access-authenticated-user-email': 'synthetic-owner@example.test' } }]) {
      const response = await f.request('links', { access: true, method, body: 'not JSON', ...options });
      assert.ok([401, 403].includes(response.status)); privateResponse(response);
    }
  }
  assert.equal(keyReads, 0); assert.equal(f.reads, 0); assert.equal(f.storage.map.size, 0);
});

test('owner creation returns one secret URL and later lists expose only grant metadata', async () => {
  const f = await fixture({ recipientName: '株式会社 ダミー開示先' });
  const empty = await f.request('links', { access: true, subject: f.env.VAULT_OWNER_SUB });
  assert.equal(empty.status, 200); assert.deepEqual(await empty.json(), { revision: 0, links: [], recipientName: f.recipientName,
    documentExpiresAt: f.expiresAt, revoked: false, enabled: true });
  const grant = await f.create(); privateResponse(grant.response);
  const url = new URL(grant.url); assert.equal(url.origin, f.env.PUBLIC_ORIGIN); assert.equal(url.pathname, `/p/${f.id}`); assert.equal(url.search, '');
  const listed = await f.request('links', { access: true, subject: f.env.VAULT_OWNER_SUB }); privateResponse(listed);
  const value = await listed.json(); assert.equal(value.revision, 1); assert.deepEqual(value.links, [grant.link]);
  assert.ok(!JSON.stringify(value).includes(grant.token)); assert.ok(!JSON.stringify(value).includes('hash'));
  const state = await f.state(); assert.equal(state.readerLinks.entries[0].hash, await hashToken(grant.token));
  for (const secret of [grant.token, PASSWORD, f.recipientName, 'SYNTHETIC_LINK_DOCUMENT']) assert.ok(!JSON.stringify([...f.storage.map]).includes(secret));
  assert.ok(!JSON.stringify(state).includes(grant.token)); assert.equal(state.events.length, 0); assert.equal(state.jobs.length, 0);
});

test('visiting a secret URL serves only a viewer shell and cannot decrypt or notify', async () => {
  const f = await fixture(), grant = await f.create(), reads = f.reads, state = await f.state();
  const response = await worker.fetch(new Request(grant.url), f.env);
  assert.equal(response.status, 200); privateResponse(response);
  const text = await response.text(); assert.doesNotMatch(text, /SYNTHETIC_LINK_DOCUMENT/); assert.ok(!text.includes(grant.token));
  assert.equal(f.reads, reads); assert.deepEqual(await f.state(), state); assert.equal(f.calls.length, 0);
});

test('a link session requires no password and records a non-identifying link subject only after explicit PDF open', async () => {
  const f = await fixture(), grant = await f.create(), session = await f.login(grant.token);
  assert.match(session.setCookie, /Secure; HttpOnly; SameSite=Strict/); assert.match(session.setCookie, /Max-Age=\d+/); privateResponse(session.response);
  assert.equal((await f.state()).events.length, 0); assert.equal((await f.state()).jobs.length, 0); assert.equal(f.calls.length, 0);
  const response = await f.request('open', { cookie: session.cookie }); assert.equal(response.status, 200); privateResponse(response);
  assert.deepEqual(new Uint8Array(await response.arrayBuffer()), f.pdf);
  assert.equal(decodeURIComponent(response.headers.get('x-vault-download-filename')), `CV_${f.recipientName}.pdf`);
  const state = await f.state(); assert.equal(state.events[0].subject, `shared-link:${grant.link.id}`); assert.equal(state.events[0].outcome, 'decrypted');
  assert.equal(state.sessions[0].linkId, grant.link.id); assert.ok(state.jobs.length > 0);
  assert.ok(!JSON.stringify(state).includes(grant.token)); assert.ok(!JSON.stringify(state.jobs).includes(grant.token));
  await f.alarm(); assert.equal(f.calls.length, 1); assert.ok(!JSON.stringify(f.calls).includes(grant.token));
});

test('malformed link credentials are rejected before storage, key imports and document reads', async () => {
  const f = await fixture(); let keyReads = 0;
  for (const name of ['VAULT_WRAP_KEY', 'VAULT_AUDIT_KEY']) { const value = f.env[name]; Object.defineProperty(f.env, name, { get() { keyReads++; return value; } }); }
  for (const value of [{ linkToken: null }, { linkToken: '' }, { linkToken: 'a'.repeat(63) }, { linkToken: 'A'.repeat(64) },
    { linkToken: 'g'.repeat(64) }, { linkToken: 'a'.repeat(64), extra: true }, { linkToken: 'a'.repeat(64), password: PASSWORD }, {}, []]) {
    const response = await f.request('session', { body: JSON.stringify(value) }); assert.equal(response.status, 400); privateResponse(response);
  }
  assert.equal(keyReads, 0); assert.equal(f.reads, 0); assert.equal(f.storage.map.size, 0);
});

test('unknown well-formed link credentials cannot trigger R2 reads or wrapping-key access', async () => {
  const f = await fixture(), grant = await f.create(), before = await f.state(), reads = f.reads; let wrapReads = 0;
  const wrappingKey = f.env.VAULT_WRAP_KEY; Object.defineProperty(f.env, 'VAULT_WRAP_KEY', { get() { wrapReads++; return wrappingKey; } });
  const forged = grant.token.slice(0, -1) + (grant.token.endsWith('a') ? 'b' : 'a');
  const response = await f.request('session', { body: JSON.stringify({ linkToken: forged }) });
  assert.equal(response.status, 401); assert.equal(response.headers.get('set-cookie'), null); privateResponse(response);
  assert.equal(f.reads, reads); assert.equal(wrapReads, 0); assert.deepEqual(await f.state(), before);
});

test('individual link revocation invalidates its cookies without locking out other links or password readers', async () => {
  const f = await fixture(), first = await f.create(), firstSession = await f.login(first.token), second = await f.create(),
    secondSession = await f.login(second.token), passwordSession = await f.login();
  const response = await stop(f, first.link.id, 2); assert.equal(response.status, 200);
  assert.equal((await response.json()).revision, 3);
  f.restart();
  for (const action of ['status', 'open']) assert.ok([401, 403].includes((await f.request(action, { cookie: firstSession.cookie })).status));
  const reads = f.reads;
  assert.equal((await f.request('session', { body: JSON.stringify({ linkToken: first.token }) })).status, 401); assert.equal(f.reads, reads);
  assert.equal((await f.request('open', { cookie: secondSession.cookie })).status, 200);
  assert.equal((await f.request('open', { cookie: passwordSession.cookie })).status, 200);
  assert.ok(!(await f.state()).sessions.some(session => session.linkId === first.link.id));
});

test('link expiry bounds cookies, status and PDF headers and cannot outlast the document', async () => {
  const f = await fixture(), at = Date.now(), expiresAt = at + 60000;
  await withClock(at, async () => {
    const grant = await f.create(expiresAt), session = await f.login(grant.token);
    assert.equal(session.body.expiresAt, expiresAt); assert.equal(session.body.sessionExpiresAt, expiresAt);
    assert.match(session.setCookie, /Max-Age=60(?:;|$)/);
    const status = await f.request('status', { cookie: session.cookie }); assert.equal((await status.json()).expiresAt, expiresAt);
    const response = await f.request('open', { cookie: session.cookie }); assert.equal(response.status, 200);
    assert.equal(Number(response.headers.get('x-vault-expires-at')), expiresAt);
    assert.equal(Number(response.headers.get('x-vault-session-expires-at')), expiresAt);
    await withClock(expiresAt, async () => {
      assert.equal((await f.request('session', { body: JSON.stringify({ linkToken: grant.token }) })).status, 401);
      for (const action of ['status', 'open']) assert.ok([401, 403].includes((await f.request(action, { cookie: session.cookie })).status));
    });
  });
});

test('shortening a document deadline also limits live links and existing link sessions', async () => {
  const f = await fixture(), at = Date.now(), grant = await f.create(), session = await f.login(grant.token), shortened = at + 60000;
  await withClock(at, async () => {
    const response = await f.request('expiry', { access: true, subject: f.env.VAULT_OWNER_SUB,
      body: JSON.stringify({ expectedExpiresAt: f.expiresAt, expiresAt: shortened }) }); assert.equal(response.status, 200);
    const status = await f.request('status', { cookie: session.cookie }); assert.equal(status.status, 200);
    const value = await status.json(); assert.equal(value.expiresAt, shortened); assert.ok(value.sessionExpiresAt <= shortened);
    const fresh = await f.login(grant.token); assert.equal(fresh.body.expiresAt, shortened);
  });
  await withClock(shortened, async () => {
    for (const action of ['status', 'open']) assert.ok([401, 403].includes((await f.request(action, { cookie: session.cookie })).status));
    assert.equal((await f.request('session', { body: JSON.stringify({ linkToken: grant.token }) })).status, 403);
  });
});

test('document revocation denies every existing or new link session', async () => {
  const f = await fixture(), grant = await f.create(), session = await f.login(grant.token);
  assert.equal((await f.request('revoke', { access: true, subject: f.env.VAULT_OWNER_SUB })).status, 200);
  f.restart();
  for (const action of ['status', 'open']) assert.ok([401, 403].includes((await f.request(action, { cookie: session.cookie })).status));
  assert.ok([401, 403].includes((await f.request('session', { body: JSON.stringify({ linkToken: grant.token }) })).status));
  assert.equal((await f.request('links', { access: true, subject: f.env.VAULT_OWNER_SUB, method: 'POST',
    body: JSON.stringify({ action: 'create', expectedRevision: 1, expiresAt: f.expiresAt }) })).status, 403);
});

test('ciphertext replacement invalidates old URL credentials and sessions', async () => {
  const f = await fixture(), grant = await f.create(), session = await f.login(grant.token);
  f.record = await sealDocument({ id: f.id, bytes: f.pdf, subjects: [], authMode: 'password', password: PASSWORD,
    expiresAt: f.expiresAt, recipientName: f.recipientName }, f.wrappingKey); f.pinRecord(); f.restart();
  const reads = f.reads;
  assert.equal((await f.request('session', { body: JSON.stringify({ linkToken: grant.token }) })).status, 401); assert.equal(f.reads, reads);
  for (const action of ['status', 'open']) assert.ok([401, 403].includes((await f.request(action, { cookie: session.cookie })).status));
  const value = await (await f.request('links', { access: true, subject: f.env.VAULT_OWNER_SUB })).json();
  assert.equal(value.revision, 0); assert.deepEqual(value.links, []);
  const next = await f.create(); assert.notEqual(next.token, grant.token);
  assert.equal((await f.request('open', { cookie: (await f.login(next.token)).cookie })).status, 200);
});

test('a URL credential or copied grant cannot authenticate another document', async () => {
  const first = await fixture(), grant = await first.create(), copied = await first.state(), second = await fixture();
  const response = await second.request('session', { body: JSON.stringify({ linkToken: grant.token }) }); assert.equal(response.status, 401);
  copied.documentId = second.id; await second.writeState(copied);
  assert.equal((await second.request('session', { body: JSON.stringify({ linkToken: grant.token }) })).status, 401);
  assert.equal(second.reads, 0); assert.equal(second.calls.length, 0);
});

test('a link credential cannot authenticate any owner endpoint', async () => {
  const f = await fixture(), grant = await f.create(), session = await f.login(grant.token);
  for (const action of ['links', 'metadata', 'logs', 'recipients', 'status', 'expiry', 'revoke', 'retry-notifications']) {
    assert.equal((await f.request(action, { access: true, cookie: session.cookie })).status, 401);
    assert.equal((await f.request(action, { access: true, cookie: session.cookie, subject: f.subject })).status, 403);
  }
});

test('same-document tabs cannot replace another grant context through the shared browser cookie', async () => {
  const f = await fixture(), first = await f.create(), second = await f.create(), firstSession = await f.login(first.token),
    secondSession = await f.login(second.token), passwordSession = await f.login();
  const before = await f.state(), reads = f.reads;
  for (const action of ['status', 'open']) {
    const wrongGrant = await f.request(action, { cookie: secondSession.cookie, linkContext: first.link.id });
    assert.equal(wrongGrant.status, 401); privateResponse(wrongGrant); assert.doesNotMatch(await wrongGrant.text(), /SYNTHETIC_LINK_DOCUMENT/);
    const missingGrant = await f.request(action, { cookie: firstSession.cookie, linkContext: null }); assert.equal(missingGrant.status, 401);
    const wrongMode = await f.request(action, { cookie: passwordSession.cookie, linkContext: first.link.id }); assert.equal(wrongMode.status, 401);
  }
  const wrongLogout = await f.request('session', { method: 'DELETE', cookie: secondSession.cookie, linkContext: first.link.id });
  assert.equal(wrongLogout.status, 401); assert.equal(wrongLogout.headers.get('set-cookie'), null);
  assert.equal(f.reads, reads); assert.deepEqual(await f.state(), before);
  assert.equal((await f.request('status', { cookie: firstSession.cookie })).status, 200);
  assert.equal((await f.request('status', { cookie: secondSession.cookie })).status, 200);
  assert.equal((await f.request('status', { cookie: passwordSession.cookie })).status, 200);
  assert.equal((await stop(f, first.link.id, 2)).status, 200);
  assert.equal((await f.request('open', { cookie: secondSession.cookie, linkContext: first.link.id })).status, 401);
  assert.equal((await f.request('open', { cookie: secondSession.cookie })).status, 200);
});

test('Access-only documents cannot issue or accept password-free links', async () => {
  const f = await fixture({ authMode: 'access' });
  const metadata = await f.request('links', { access: true, subject: f.env.VAULT_OWNER_SUB }); assert.equal(metadata.status, 200);
  assert.equal((await metadata.json()).enabled, false);
  const create = await f.request('links', { access: true, subject: f.env.VAULT_OWNER_SUB, method: 'POST',
    body: JSON.stringify({ action: 'create', expectedRevision: 0, expiresAt: f.expiresAt }) }); assert.equal(create.status, 403);
  assert.equal((await f.request('session', { body: JSON.stringify({ linkToken: 'a'.repeat(64) }) })).status, 401);
  assert.equal((await f.request('open', { access: true, subject: f.subject })).status, 200);
});

test('link creation enforces document deadline, immutable recipient and revision conflicts', async () => {
  const f = await fixture(), first = await f.create();
  for (const body of [{ action: 'create', expectedRevision: 1, expiresAt: f.expiresAt + 1 },
    { action: 'create', expectedRevision: 1, expiresAt: Date.now() },
    { action: 'create', expectedRevision: 1, expiresAt: f.expiresAt, recipientName: 'Forged recipient' }]) {
    const response = await f.request('links', { access: true, subject: f.env.VAULT_OWNER_SUB, method: 'POST', body: JSON.stringify(body) });
    assert.equal(response.status, 400);
  }
  assert.equal((await f.request('links', { access: true, subject: f.env.VAULT_OWNER_SUB, method: 'POST',
    body: JSON.stringify({ action: 'create', expectedRevision: 0, expiresAt: f.expiresAt }) })).status, 409);
  assert.equal((await stop(f, first.link.id, 0)).status, 409);
  assert.deepEqual((await f.state()).readerLinks.entries.map(entry => entry.id), [first.link.id]);
});

test('the owner inventory stays bounded and stopped links free capacity', async () => {
  const f = await fixture(); let first;
  for (let revision = 0; revision < MAX_READER_LINKS; revision++) {
    const grant = await f.create(f.expiresAt, revision); if (!first) first = grant;
  }
  assert.equal((await f.request('links', { access: true, subject: f.env.VAULT_OWNER_SUB, method: 'POST',
    body: JSON.stringify({ action: 'create', expectedRevision: MAX_READER_LINKS, expiresAt: f.expiresAt }) })).status, 429);
  assert.equal((await stop(f, first.link.id, MAX_READER_LINKS)).status, 200);
  await f.create(f.expiresAt, MAX_READER_LINKS + 1);
  const state = await f.state(); assert.equal(state.readerLinks.entries.length, MAX_READER_LINKS);
  assert.ok(!state.readerLinks.entries.some(entry => entry.id === first.link.id));
});

test('links require the existing reader switch and dummy pin and cannot bypass either', async () => {
  const f = await fixture(), grant = await f.create();
  for (const request of [{ id: crypto.randomUUID(), body: JSON.stringify({ linkToken: grant.token }) },
    { query: '?link=' + grant.token, body: JSON.stringify({ linkToken: grant.token }) },
    { headers: { origin: 'https://other.example.test' }, body: JSON.stringify({ linkToken: grant.token }) },
    { headers: { 'sec-fetch-site': 'cross-site' }, body: JSON.stringify({ linkToken: grant.token }) }]) {
    assert.equal((await f.request('session', request)).status, 403);
  }
  const reads = f.reads; f.env.PASSWORD_READER_ENABLED = '0';
  assert.equal((await f.request('session', { body: JSON.stringify({ linkToken: grant.token }) })).status, 403);
  assert.equal(f.reads, reads);
});

test('a slow link exchange cannot block individual owner revocation or issue a late session', async () => {
  const f = await fixture(), grant = await f.create(), entered = deferred(), release = deferred(); let blocked = false;
  f.recordHandler = async () => { if (!blocked) { blocked = true; entered.resolve(); await release.promise; } };
  const pending = f.request('session', { body: JSON.stringify({ linkToken: grant.token }) }); await entered.promise;
  try {
    const revoked = await within(stop(f, grant.link.id, 1)); assert.ok(revoked, 'Owner revocation must not wait for the reader R2 request');
    assert.equal(revoked.status, 200);
  } finally { release.resolve(); }
  const response = await pending; assert.equal(response.status, 401); assert.equal(response.headers.get('set-cookie'), null);
  const state = await f.state(); assert.equal(state.sessions.length, 0); assert.equal(state.events.length, 0); assert.equal(state.jobs.length, 0);
});

test('individual revocation during a slow PDF read suppresses plaintext and notifications', async () => {
  const f = await fixture(), grant = await f.create(), session = await f.login(grant.token), entered = deferred(), release = deferred(); let blocked = false;
  f.recordHandler = async () => { if (!blocked) { blocked = true; entered.resolve(); await release.promise; } };
  const pending = f.request('open', { cookie: session.cookie }); await entered.promise;
  try {
    const revoked = await within(stop(f, grant.link.id, 1)); assert.ok(revoked, 'Owner revocation must remain available during document I/O');
    assert.equal(revoked.status, 200);
  } finally { release.resolve(); }
  const response = await pending; assert.equal(response.status, 401); assert.doesNotMatch(await response.text(), /SYNTHETIC_LINK_DOCUMENT/);
  const state = await f.state(); assert.equal(state.sessions.length, 0); assert.equal(state.events.length, 0); assert.equal(state.jobs.length, 0);
});

test('a link deadline crossed during R2 access cannot issue a session or release PDF bytes', async () => {
  const f = await fixture(), at = Date.now(), expiresAt = at + 60000;
  await withClock(at, async () => {
    const grant = await f.create(expiresAt), entered = deferred(), release = deferred(); let blocked = false;
    f.recordHandler = async () => { if (!blocked) { blocked = true; entered.resolve(); await release.promise; } };
    const pending = f.request('session', { body: JSON.stringify({ linkToken: grant.token }) }); await entered.promise;
    await withClock(expiresAt, async () => {
      release.resolve(); const response = await pending; assert.equal(response.status, 401);
      assert.equal(response.headers.get('set-cookie'), null); assert.doesNotMatch(await response.text(), /SYNTHETIC_LINK_DOCUMENT/);
    });
    const state = await f.state(); assert.equal(state.sessions.length, 0); assert.equal(state.events.length, 0); assert.equal(state.jobs.length, 0);
  });
});
