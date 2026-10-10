import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { generateKeyPair, exportJWK, SignJWT } from 'jose';
import worker, { VaultDocument } from '../src/worker.js';
import { newKey, importKey, sealDocument, openJSON, sealJSON, utf8 } from '../src/crypto.js';

const originalFetch = globalThis.fetch;
after(() => { globalThis.fetch = originalFetch; });
const pair = await generateKeyPair('RS256', { extractable: true });
const jwk = { ...await exportJWK(pair.publicKey), kid: 'management-fixture', use: 'sig', alg: 'RS256' };
const PASSWORD = 'synthetic management password';
let fixtureNumber = 0;

class Storage {
  constructor() { this.map = new Map(); this.writes = 0; this.failWrite = false; this.afterCommit = null; }
  async get(key) { return structuredClone(this.map.get(key)); }
  async transaction(operation) {
    const draft = new Map(structuredClone([...this.map]));
    const result = await operation({
      get: async key => structuredClone(draft.get(key)),
      put: async (key, value) => { if (this.failWrite) throw new Error('synthetic_failure'); this.writes++; draft.set(key, structuredClone(value)); },
      delete: async key => draft.delete(key),
      list: async options => new Map([...draft].filter(([key]) => key.startsWith(options.prefix) && (!options.end || key < options.end))
        .sort(([a], [b]) => a.localeCompare(b)).slice(0, options.limit)),
      setAlarm: async () => {}, deleteAlarm: async () => {},
    });
    this.map = draft;
    if (this.afterCommit) await this.afterCommit();
    return result;
  }
}

// Synthetic, local records only. Bucket writes and external notifications fail the fixture.
async function fixture({ authMode = 'access', expiresAt = Date.now() + 600000, recipientName = 'Synthetic Recipient' } = {}) {
  const id = crypto.randomUUID(), reader = 'synthetic-reader', pdf = utf8('%PDF-1.4\nSYNTHETIC_MANAGEMENT_BODY\n');
  const env = { PUBLIC_ORIGIN: 'https://vault.example.test', ACCESS_ISSUER: `https://management-${++fixtureNumber}.cloudflareaccess.com`,
    ACCESS_AUDIENCE: 'synthetic-management-audience', VAULT_OWNER_SUB: 'synthetic-owner',
    VAULT_WRAP_KEY: newKey(), VAULT_AUDIT_KEY: newKey(), PASSWORD_READER_ENABLED: '1',
    WEBHOOK_URL: 'https://notify.example.test/synthetic' };
  const wrap = await importKey(env.VAULT_WRAP_KEY), audit = await importKey(env.VAULT_AUDIT_KEY);
  let record = await sealDocument({ id, bytes: pdf, expiresAt, ...(recipientName === null ? {} : { recipientName }), authMode,
    subjects: authMode === 'access' ? [reader] : [], ...(authMode === 'password' ? { password: PASSWORD } : {}) }, wrap);
  function pin() { env.DUMMY_DOCUMENT_ID = id; env.DUMMY_RECORD_SHA256 = createHash('sha256').update(JSON.stringify(record)).digest('hex'); }
  pin();
  let reads = 0, notifications = 0, bucketWrites = 0;
  env.VAULT_DOCUMENTS = {
    async get(name) { reads++; assert.equal(name, `${id}.sealed.json`); const body = utf8(JSON.stringify(record)); return { size: body.length, body: new Response(body).body }; },
    async put() { bucketWrites++; throw new Error('unexpected_bucket_write'); },
  };
  globalThis.fetch = async url => {
    if (String(url) === `${env.ACCESS_ISSUER}/cdn-cgi/access/certs`) return Response.json({ keys: [jwk] });
    notifications++; throw new Error('unexpected_notification');
  };
  const storage = new Storage(), ctx = { storage, id: { toString: () => `management-${id}` } }, context = `journal:v1:management-${id}`;
  let instance = new VaultDocument(ctx, env);
  env.VAULT = { idFromName: name => { assert.equal(name, id); return name; }, get: () => instance };
  async function token(subject) {
    return new SignJWT({ sub: subject, iss: env.ACCESS_ISSUER, aud: env.ACCESS_AUDIENCE,
      iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + 600 })
      .setProtectedHeader({ alg: 'RS256', kid: 'management-fixture' }).sign(pair.privateKey);
  }
  async function request(action = 'metadata', options = {}) {
    const passwordPath = options.password === true, method = options.method ?? (['metadata', 'status'].includes(action) ? 'GET' : 'POST');
    const subject = Object.hasOwn(options, 'subject') ? options.subject : passwordPath ? null : env.VAULT_OWNER_SUB;
    const headers = { origin: env.PUBLIC_ORIGIN, 'content-type': 'application/json', 'cf-connecting-ip': '192.0.2.45',
      ...(subject ? { 'cf-access-jwt-assertion': await token(subject) } : {}), ...(options.cookie ? { cookie: options.cookie } : {}), ...options.headers };
    const body = options.body ?? JSON.stringify(action === 'session' ? { password: PASSWORD } : action === 'open' ? { requestId: crypto.randomUUID() } : {});
    const req = new Request(`${env.PUBLIC_ORIGIN}${passwordPath ? '/p' : '/v1/documents'}/${options.id ?? id}/${action}${options.query ?? ''}`, {
      method, headers, ...(['GET', 'HEAD'].includes(method) ? {} : { body }) });
    return options.direct ? instance.fetch(req) : worker.fetch(req, env);
  }
  async function metadata() { const response = await request(); assert.equal(response.status, 200); return response.json(); }
  async function change(expires, expected = expiresAt, options = {}) {
    return request('expiry', { body: JSON.stringify({ expiresAt: expires, expectedExpiresAt: expected }), ...options });
  }
  async function login() { const response = await request('session', { password: true }); assert.equal(response.status, 200); return { cookie: response.headers.get('set-cookie').split(';')[0], value: await response.json() }; }
  return { env, id, reader, pdf, expiresAt, recipientName, storage, request, metadata, change, login, context,
    async state() { return openJSON(await storage.get('encrypted-journal'), audit, context); },
    async writeState(value) { storage.map.set('encrypted-journal', await sealJSON(value, audit, context)); },
    async alterPolicy(change) { const policy = await openJSON(record.policy, wrap, `policy:v2:${id}`); change(policy); record.policy = await sealJSON(policy, wrap, `policy:v2:${id}`); pin(); },
    restart() { instance = new VaultDocument(ctx, env); }, pin,
    get instance() { return instance; }, get record() { return record; }, get reads() { return reads; },
    get bucketWrites() { return bucketWrites; }, get notifications() { return notifications; },
  };
}

async function withClock(at, operation) {
  const original = Date.now; Date.now = () => at;
  try { return await operation(); } finally { Date.now = original; }
}
function emptyHistory(state) { assert.deepEqual([state.events, state.jobs, state.requests], [[], [], []]); }

test('owner metadata reads only the pinned policy and returns no password, keys or PDF content', async () => {
  const f = await fixture();
  f.record.document.ciphertext = 'not valid document ciphertext'; f.record.wrappedKey.ciphertext = 'not valid wrapped key'; f.pin();
  const response = await f.request(), value = await response.json();
  assert.equal(response.status, 200);
  assert.deepEqual(value, { id: f.id, mime: 'application/pdf', size: f.pdf.length, authMode: 'access', recipientName: f.recipientName,
    expiresAt: f.expiresAt, sealedExpiresAt: f.expiresAt, revoked: false, pending: 0, failed: 0, providerAccepted: 0 });
  for (const secret of [PASSWORD, f.env.VAULT_WRAP_KEY, f.env.VAULT_AUDIT_KEY, 'SYNTHETIC_MANAGEMENT_BODY', 'passwordVerifier', 'ciphertext', f.reader]) assert.ok(!JSON.stringify(value).includes(secret));
  assert.match(response.headers.get('cache-control'), /no-store/); assert.equal(response.headers.get('access-control-allow-origin'), null);
  assert.equal(f.storage.writes, 0); assert.equal(f.bucketWrites, 0); assert.equal(f.notifications, 0);
});

test('metadata returns a nullable recipient for an existing unnamed document', async () => {
  const f = await fixture({ recipientName: null }); assert.equal((await f.metadata()).recipientName, null);
});

for (const action of ['metadata', 'expiry']) test(`${action} permits only the signed owner identity`, async () => {
  const f = await fixture({ authMode: 'password' }), session = await f.login(), before = f.reads;
  let keyReads = 0;
  for (const name of ['VAULT_WRAP_KEY', 'VAULT_AUDIT_KEY']) {
    const value = f.env[name]; Object.defineProperty(f.env, name, { get() { keyReads++; return value; } });
  }
  const body = JSON.stringify({ expiresAt: f.expiresAt - 60000, expectedExpiresAt: f.expiresAt });
  for (const direct of [false, true]) {
    for (const options of [{ subject: null }, { subject: f.reader }, { subject: null, cookie: session.cookie },
      { subject: null, headers: { 'cf-access-authenticated-user-email': 'owner@example.test', 'x-vault-owner-sub': f.env.VAULT_OWNER_SUB } },
      { subject: null, headers: { 'cf-access-jwt-assertion': 'synthetic forged token' } }]) {
      const response = await f.request(action, { ...options, direct, body });
      assert.equal(response.status, options.subject === f.reader ? 403 : 401);
    }
  }
  assert.equal(f.reads, before); emptyHistory(await f.state());
  assert.equal(keyReads, 0);
  assert.equal(f.notifications, 0); assert.equal(f.bucketWrites, 0);
});

test('owner management remains separate from disabled password viewing', async () => {
  const f = await fixture({ authMode: 'password' }); f.env.PASSWORD_READER_ENABLED = '0';
  assert.equal((await f.metadata()).authMode, 'password');
  assert.equal((await f.change(f.expiresAt - 60000)).status, 200);
  for (const action of ['metadata', 'expiry']) assert.equal((await f.request(action, { password: true, subject: f.env.VAULT_OWNER_SUB })).status, 403);
});

for (const [name, options, status] of [
  ['GET mutation', { method: 'GET' }, 405], ['DELETE mutation', { method: 'DELETE' }, 405],
  ['wrong origin', { headers: { origin: 'https://other.example.test' } }, 403],
  ['missing origin', { headers: { origin: '' } }, 403], ['not JSON', { headers: { 'content-type': 'text/plain' } }, 403],
  ['query', { query: '?expiresAt=123' }, 403], ['other document', { id: crypto.randomUUID() }, 403],
  ['oversize', { body: 'x'.repeat(129) }, 400], ['malformed JSON', { body: '{' }, 400],
  ['array', { body: '[]' }, 400], ['missing fields', { body: '{}' }, 400],
  ['unexpected field', { body: '{"expiresAt":1,"expectedExpiresAt":2,"other":3}' }, 400],
  ['string date', { body: '{"expiresAt":"1800000000000","expectedExpiresAt":1800000000000}' }, 400],
  ['fractional date', { body: '{"expiresAt":1800000000000.5,"expectedExpiresAt":1800000000000}' }, 400],
  ['unsafe date', { body: '{"expiresAt":9007199254740992,"expectedExpiresAt":1800000000000}' }, 400],
]) test(`expiry rejects ${name} without reading or changing stored policy`, async () => {
  const f = await fixture();
  assert.equal((await f.change(f.expiresAt - 60000, f.expiresAt, options)).status, status);
  assert.equal(f.reads, 0); assert.equal(f.storage.writes, 0); assert.equal(f.notifications, 0); assert.equal(f.bucketWrites, 0);
});

test('metadata rejects POST and both management operations retain the dummy ciphertext pin', async () => {
  const f = await fixture(); assert.equal((await f.request('metadata', { method: 'POST' })).status, 405);
  f.record.document.ciphertext += 'modified';
  for (const direct of [false, true]) {
    assert.equal((await f.request('metadata', { direct })).status, 403);
    assert.equal((await f.change(f.expiresAt - 60000, f.expiresAt, { direct })).status, 403);
  }
  assert.equal(f.storage.writes, 0); assert.equal(f.notifications, 0);
});

test('owner deadline changes are encrypted, survive restart and keep the sealed maximum immutable', async () => {
  const f = await fixture(), shortened = f.expiresAt - 60000, sealedBefore = JSON.stringify(f.record);
  const response = await f.change(shortened); assert.equal(response.status, 200);
  const value = await response.json(); assert.equal(value.expiresAt, shortened); assert.equal(value.sealedExpiresAt, f.expiresAt);
  const state = await f.state(); assert.deepEqual(state.deadline, { recordDigest: f.env.DUMMY_RECORD_SHA256, expiresAt: shortened });
  emptyHistory(state);
  const persisted = JSON.stringify([...f.storage.map]);
  for (const privateValue of [f.id, f.env.DUMMY_RECORD_SHA256, String(shortened), f.recipientName, PASSWORD, f.env.VAULT_WRAP_KEY, f.env.VAULT_AUDIT_KEY, 'SYNTHETIC_MANAGEMENT_BODY']) assert.ok(!persisted.includes(privateValue));
  f.restart(); assert.equal((await f.metadata()).expiresAt, shortened); assert.equal(JSON.stringify(f.record), sealedBefore);
  assert.equal(f.bucketWrites, 0); assert.equal(f.notifications, 0);
  const restored = await f.change(f.expiresAt, shortened); assert.equal(restored.status, 200); assert.equal((await restored.json()).expiresAt, f.expiresAt);
});

test('a stale deadline update fails without overwriting the newer owner decision', async () => {
  const f = await fixture(), first = f.expiresAt - 60000, second = f.expiresAt - 120000;
  const responses = await Promise.all([f.change(first), f.change(second)]);
  assert.deepEqual(responses.map(r => r.status).sort(), [200, 409]);
  const current = (await f.metadata()).expiresAt; assert.ok([first, second].includes(current));
  const before = structuredClone([...f.storage.map]);
  const stale = await f.change(f.expiresAt, f.expiresAt); assert.equal(stale.status, 409);
  assert.deepEqual(await stale.json(), { error: 'expiry_changed' }); assert.deepEqual([...f.storage.map], before);
});

test('past, current and beyond-sealed deadlines cannot be stored', async () => {
  const f = await fixture();
  for (const expires of [Date.now() - 1, Date.now(), f.expiresAt + 1]) {
    const response = await f.change(expires); assert.equal(response.status, 400); assert.deepEqual(await response.json(), { error: 'invalid_expiry' });
  }
  assert.equal(f.storage.writes, 0); assert.equal((await f.metadata()).expiresAt, f.expiresAt);
});

test('owner may restore an elapsed shortening only while the sealed permission remains live', async () => {
  const f = await fixture(), short = Date.now() + 30000;
  assert.equal((await f.change(short)).status, 200);
  await withClock(short + 1, async () => { assert.equal((await f.change(f.expiresAt, short)).status, 200); });
  await withClock(f.expiresAt, async () => {
    assert.equal((await f.metadata()).expiresAt, f.expiresAt);
    assert.equal((await f.change(f.expiresAt + 1000)).status, 403);
  });
});

test('restoring an elapsed password deadline does not resurrect its previous sessions', async () => {
  const f = await fixture({ authMode: 'password' }), short = Date.now() + 30000, previous = await f.login();
  assert.equal((await f.change(short)).status, 200);
  await withClock(short + 1, async () => {
    assert.equal((await f.change(f.expiresAt, short)).status, 200);
    assert.equal((await f.request('status', { password: true, cookie: previous.cookie })).status, 401);
    const fresh = await f.login(); assert.ok(fresh.value.sessionExpiresAt > short); assert.equal(fresh.value.expiresAt, f.expiresAt);
  });
});

test('owner cannot reopen a revoked document by changing its deadline', async () => {
  const f = await fixture(); assert.equal((await f.request('revoke')).status, 200);
  const before = structuredClone([...f.storage.map]);
  assert.equal((await f.change(f.expiresAt - 60000)).status, 403); assert.deepEqual([...f.storage.map], before);
  assert.equal((await f.metadata()).revoked, true);
});

test('a sealed revoked policy also prevents owner deadline changes', async () => {
  const f = await fixture(); await f.alterPolicy(policy => { policy.revoked = true; });
  assert.equal((await f.change(f.expiresAt - 60000)).status, 403); assert.equal((await f.metadata()).revoked, true); assert.equal(f.storage.writes, 0);
});

test('failed deadline persistence leaves the previous effective deadline and sessions unchanged', async () => {
  const f = await fixture({ authMode: 'password' }), session = await f.login(), before = structuredClone([...f.storage.map]);
  f.storage.failWrite = true; assert.equal((await f.change(Date.now() + 30000)).status, 503);
  assert.deepEqual([...f.storage.map], before); f.storage.failWrite = false; f.restart();
  assert.equal((await f.metadata()).expiresAt, f.expiresAt);
  const status = await f.request('status', { password: true, cookie: session.cookie }); assert.equal(status.status, 200);
  assert.equal((await status.json()).sessionExpiresAt, session.value.sessionExpiresAt);
});

for (const authMode of ['access', 'password']) test(`${authMode} retrieval honors the shortened deadline across restart`, async () => {
  const f = await fixture({ authMode }), short = Date.now() + 30000;
  const previous = authMode === 'password' ? await f.login() : null;
  assert.equal((await f.change(short)).status, 200); f.restart();
  const credentials = authMode === 'password' ? { password: true, cookie: previous.cookie } : { subject: f.reader };
  const opened = await f.request('open', credentials); assert.equal(opened.status, 200); assert.deepEqual(new Uint8Array(await opened.arrayBuffer()), f.pdf);
  assert.equal(Number(opened.headers.get('x-vault-expires-at')), short);
  if (previous) {
    assert.equal(Number(opened.headers.get('x-vault-session-expires-at')), short);
    const status = await f.request('status', credentials); assert.deepEqual(await status.json(), { expiresAt: short, sessionExpiresAt: short });
    const minted = await f.login(); assert.equal(minted.value.expiresAt, short); assert.equal(minted.value.sessionExpiresAt, short);
    assert.equal((await f.change(f.expiresAt, short)).status, 200);
    const oldStatus = await f.request('status', credentials); assert.equal((await oldStatus.json()).sessionExpiresAt, short);
    assert.equal((await f.change(short, f.expiresAt)).status, 200);
  }
  await withClock(short, async () => {
    for (const action of previous ? ['open', 'status', 'session'] : ['open']) {
      const denied = await f.request(action, credentials); assert.ok([401, 403].includes(denied.status));
      assert.doesNotMatch(await denied.text(), /SYNTHETIC_MANAGEMENT_BODY/);
    }
  });
  assert.equal(f.bucketWrites, 0); assert.equal(f.notifications, 0);
});

for (const authMode of ['access', 'password']) test(`${authMode} deadline crossing the final audit commit suppresses plaintext`, async () => {
  const f = await fixture({ authMode }), short = Date.now() + 30000;
  const previous = authMode === 'password' ? await f.login() : null;
  assert.equal((await f.change(short)).status, 200);
  const before = Date.now;
  f.storage.afterCommit = async () => { const state = await f.state(); if (state.events.some(event => event.outcome === 'decrypted')) Date.now = () => short; };
  try {
    const response = await f.request('open', previous ? { password: true, cookie: previous.cookie } : { subject: f.reader });
    assert.equal(response.status, 403); assert.doesNotMatch(await response.text(), /SYNTHETIC_MANAGEMENT_BODY/);
  } finally { Date.now = before; }
});

for (const [label, deadline] of [
  ['bad digest', { recordDigest: 'bad', expiresAt: 1800000000000 }], ['string time', { recordDigest: 'a'.repeat(64), expiresAt: '1800000000000' }],
  ['extra property', { recordDigest: 'a'.repeat(64), expiresAt: 1800000000000, other: true }], ['null', null],
]) test(`invalid stored deadline fails closed (${label})`, async () => {
  const f = await fixture(); await f.change(f.expiresAt - 60000); const state = await f.state(); state.deadline = deadline; await f.writeState(state);
  for (const action of ['metadata', 'open']) assert.equal((await f.request(action, { subject: action === 'open' ? f.reader : f.env.VAULT_OWNER_SUB })).status, 503);
});

test('a stored deadline is bound to the current ciphertext digest and sealed maximum', async () => {
  const f = await fixture(); await f.change(f.expiresAt - 60000); const state = await f.state();
  state.deadline.recordDigest = 'a'.repeat(64); await f.writeState(state); assert.equal((await f.request()).status, 503);
  state.deadline.recordDigest = f.env.DUMMY_RECORD_SHA256; state.deadline.expiresAt = f.expiresAt + 1; await f.writeState(state); assert.equal((await f.request()).status, 503);
});

test('owner metadata reports existing delivery counters without changing the legacy status response', async () => {
  const f = await fixture(); await f.change(f.expiresAt - 60000); const state = await f.state();
  state.archivedAccepted = 2; state.jobs = [{ state: 'pending' }, { state: 'failed' }, { state: 'accepted' }]; await f.writeState(state);
  const writes = f.storage.writes, metadata = await f.metadata();
  assert.deepEqual([metadata.pending, metadata.failed, metadata.providerAccepted], [1, 1, 3]);
  const status = await f.request('status'); assert.deepEqual(await status.json(), { revoked: false, pending: 1, failed: 1, providerAccepted: 3 });
  assert.equal(f.storage.writes, writes); assert.equal(f.notifications, 0);
});
