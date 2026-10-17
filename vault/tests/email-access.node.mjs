import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { generateKeyPair, exportJWK, SignJWT } from 'jose';
import worker, { VaultDocument } from '../src/worker.js';
import { newKey, importKey, sealDocument, readPolicy, openJSON, sealJSON, utf8 } from '../src/crypto.js';

// Every PDF, identity, key, storage operation and provider response is synthetic.
const originalFetch = globalThis.fetch;
after(() => { globalThis.fetch = originalFetch; });
const pair = await generateKeyPair('RS256', { extractable: true });
const otherPair = await generateKeyPair('RS256', { extractable: true });
const jwk = { ...await exportJWK(pair.publicKey), kid: 'email-access-fixture', use: 'sig', alg: 'RS256' };
const EMAIL = 'Reviewer@example.test', SUBJECT = 'synthetic-email-reader';
let fixtureNumber = 0;

function list(map, options) {
  const entries = [...map].filter(([key]) => key.startsWith(options.prefix) &&
    (!options.start || key >= options.start) && (!options.startAfter || key > options.startAfter) && (!options.end || key < options.end))
    .sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0);
  if (options.reverse) entries.reverse();
  return new Map(entries.slice(0, options.limit));
}
class Storage {
  constructor() { this.map = new Map(); this.tail = Promise.resolve(); this.alarmAt = null; }
  async get(key) { return structuredClone(this.map.get(key)); }
  async list(options) { return list(this.map, options); }
  async setAlarm(at) { this.alarmAt = at; }
  transaction(operation) {
    const next = this.tail.then(async () => {
      const draft = new Map(structuredClone([...this.map])); let alarmAt = this.alarmAt;
      const result = await operation({
        get: async key => structuredClone(draft.get(key)), list: async options => list(draft, options),
        put: async (key, value) => { draft.set(key, structuredClone(value)); }, delete: async key => draft.delete(key),
        setAlarm: async at => { alarmAt = at; }, deleteAlarm: async () => { alarmAt = null; },
      });
      this.map = draft; this.alarmAt = alarmAt; return result;
    });
    this.tail = next.catch(() => {}); return next;
  }
}
async function fixture({ authMode = 'email', allowedEmails = [EMAIL], expiresAt = Date.now() + 600000 } = {}) {
  const id = crypto.randomUUID(), pdf = utf8('%PDF-1.4\nSYNTHETIC_EMAIL_DOCUMENT\n');
  const env = {
    PUBLIC_ORIGIN: 'https://vault.example.test', ACCESS_ISSUER: `https://email-access-${++fixtureNumber}.cloudflareaccess.com`,
    ACCESS_AUDIENCE: 'synthetic-admin-audience', READER_ACCESS_AUDIENCE: 'synthetic-reader-audience',
    EMAIL_READER_ENABLED: '1', PASSWORD_READER_ENABLED: '1', VAULT_OWNER_SUB: 'synthetic-owner',
    VAULT_WRAP_KEY: newKey(), VAULT_AUDIT_KEY: newKey(), WEBHOOK_URL: 'https://notify.example.test/synthetic-email',
  };
  const wrappingKey = await importKey(env.VAULT_WRAP_KEY), auditKey = await importKey(env.VAULT_AUDIT_KEY);
  let record = await sealDocument({ id, bytes: pdf, subjects: authMode === 'access' ? [SUBJECT] : [], authMode, expiresAt,
    recipientName: 'Synthetic Recipient', ...(authMode === 'email' ? { allowedEmails } : {}),
    ...(authMode === 'password' ? { password: 'synthetic fallback password' } : {}) }, wrappingKey);
  const pin = () => { env.DUMMY_DOCUMENT_ID = id; env.DUMMY_RECORD_SHA256 = createHash('sha256').update(JSON.stringify(record)).digest('hex'); };
  pin();
  const storage = new Storage(), context = `journal:v1:email-object-${id}`, ctx = { storage, id: { toString: () => `email-object-${id}` } };
  let instance = new VaultDocument(ctx, env), reads = 0;
  const calls = [];
  env.VAULT_DOCUMENTS = { async get(name) {
    reads++; assert.equal(name, `${id}.sealed.json`);
    const bytes = utf8(JSON.stringify(record)); return { size: bytes.length, body: new Response(bytes).body };
  } };
  env.VAULT = { idFromName: value => { assert.equal(value, id); return value; }, get: () => instance };
  globalThis.fetch = async (url, options) => {
    if (String(url) === `${env.ACCESS_ISSUER}/cdn-cgi/access/certs`) return Response.json({ keys: [jwk] });
    assert.equal(String(url), env.WEBHOOK_URL); calls.push(JSON.parse(options.body)); return new Response('synthetic accepted', { status: 202 });
  };
  async function token(claims = {}, key = pair.privateKey) {
    const now = Math.floor(Date.now() / 1000);
    const payload = { sub: SUBJECT, email: EMAIL, type: 'app', iss: env.ACCESS_ISSUER,
      aud: env.READER_ACCESS_AUDIENCE, iat: now, exp: now + 600, ...claims };
    for (const name of Object.keys(payload)) if (payload[name] === undefined) delete payload[name];
    return new SignJWT(payload).setProtectedHeader({ alg: 'RS256', kid: 'email-access-fixture' }).sign(key);
  }
  async function request(action = 'open', options = {}) {
    const prefix = options.prefix || '/e';
    const method = options.method || (['status', 'metadata', 'logs', 'links', 'recipients'].includes(action) ? 'GET' : 'POST');
    const jwt = Object.hasOwn(options, 'jwt') ? options.jwt : await token(options.claims);
    const headers = { origin: env.PUBLIC_ORIGIN, 'content-type': 'application/json', 'cf-connecting-ip': '192.0.2.42',
      ...(jwt ? { 'cf-access-jwt-assertion': jwt } : {}), ...options.headers };
    const body = options.body ?? JSON.stringify(action === 'open'
      ? { requestId: options.requestId || crypto.randomUUID(), purpose: options.purpose || 'view' } : {});
    const url = options.url || `${env.PUBLIC_ORIGIN}${prefix}/${options.id || id}/${action}${options.query || ''}`;
    const req = new Request(url, { method, headers, ...(['GET', 'HEAD'].includes(method) ? {} : { body }) });
    return options.direct ? instance.fetch(req) : worker.fetch(req, env);
  }
  async function owner(action = 'logs', options = {}) {
    return request(action, { prefix: '/v1/documents', ...options,
      jwt: await token({ sub: env.VAULT_OWNER_SUB, aud: env.ACCESS_AUDIENCE, email: undefined, type: undefined }) });
  }
  async function state() { const box = await storage.get('encrypted-journal'); return box ? openJSON(box, auditKey, context) : null; }
  async function writeState(value) { storage.map.set('encrypted-journal', await sealJSON(value, auditKey, context)); }
  return { id, pdf, env, expiresAt, storage, context, wrappingKey, auditKey, request, owner, token, state, writeState, calls,
    get reads() { return reads; }, get record() { return record; },
    async replacePolicy(change) { const policy = await openJSON(record.policy, wrappingKey, `policy:v2:${id}`);
      change(policy); record = { ...record, policy: await sealJSON(policy, wrappingKey, `policy:v2:${id}`) }; pin(); },
    restart() { instance = new VaultDocument(ctx, env); }, alarm() { return instance.alarm(); } };
}
function privateResponse(response) {
  assert.match(response.headers.get('cache-control'), /no-store/);
  assert.equal(response.headers.get('cdn-cache-control'), 'no-store');
  assert.equal(response.headers.get('referrer-policy'), 'no-referrer');
  assert.notEqual(response.headers.get('access-control-allow-origin'), '*');
}
async function denied(response, statuses = [401, 403]) {
  assert.ok(statuses.includes(response.status), `Expected denial, received ${response.status}: ${await response.clone().text()}`);
  privateResponse(response); assert.notEqual(response.headers.get('content-type'), 'application/pdf');
  assert.equal(response.headers.get('x-vault-event'), null);
  assert.doesNotMatch(await response.text(), /SYNTHETIC_EMAIL_DOCUMENT|Reviewer@example\.test/);
}
async function withClock(at, operation) {
  const original = Date.now; Date.now = () => at;
  try { return await operation(); } finally { Date.now = original; }
}

test('email policy is encrypted and reader status authenticates without recording an acquisition', async () => {
  const f = await fixture(), policy = await readPolicy(f.record, f.id, f.wrappingKey);
  assert.equal(policy.authMode, 'email'); assert.deepEqual(policy.allowedEmails, [EMAIL]); assert.deepEqual(policy.subjects, []);
  assert.equal(Object.hasOwn(policy, 'passwordVerifier'), false); assert.ok(!JSON.stringify(f.record).includes(EMAIL));
  const jwt = await f.token(), claims = JSON.parse(Buffer.from(jwt.split('.')[1], 'base64url').toString());
  const response = await f.request('status', { jwt }); assert.equal(response.status, 200); privateResponse(response);
  assert.deepEqual(await response.json(), { expiresAt: f.expiresAt, sessionExpiresAt: claims.exp * 1000, verifiedEmail: EMAIL });
  assert.equal(await f.state(), null); assert.equal(f.calls.length, 0);
});

for (const purpose of ['view', 'download']) test(`signed allowed email obtains synthetic PDF and records ${purpose}`, async () => {
  const f = await fixture(), response = await f.request('open', { purpose });
  assert.equal(response.status, 200); privateResponse(response);
  assert.deepEqual(new Uint8Array(await response.arrayBuffer()), f.pdf);
  const state = await f.state(), event = state.events[0];
  assert.equal(event.subject, SUBJECT); assert.equal(event.verifiedEmail, EMAIL); assert.equal(event.purpose, purpose);
  assert.equal(event.outcome, 'decrypted'); assert.equal(event.id, response.headers.get('x-vault-event'));
  const logs = await f.owner(); assert.equal(logs.status, 200);
  const visible = (await logs.json()).events[0];
  assert.equal(visible.verifiedEmail, EMAIL); assert.equal(visible.purpose, purpose); assert.equal(visible.subject, SUBJECT);
  for (const secret of [EMAIL, SUBJECT, 'SYNTHETIC_EMAIL_DOCUMENT', f.env.VAULT_WRAP_KEY, f.env.VAULT_AUDIT_KEY]) {
    assert.ok(!JSON.stringify([...f.storage.map]).includes(secret));
  }
  await withClock(Date.now() + 1000, () => f.alarm()); assert.equal(f.calls.length, 1);
  const sent = f.calls[0]; assert.equal(sent.kind, 'vault.decryption');
  assert.deepEqual(sent.event, { id: event.id, outcome: 'decrypted' });
  assert.ok(!JSON.stringify(sent).includes(EMAIL)); assert.ok(!JSON.stringify(sent).includes(SUBJECT));
  assert.equal(Object.hasOwn(sent.event, 'purpose'), false);
});

test('email comparison normalizes the domain but keeps local-part case and aliases distinct', async () => {
  const f = await fixture({ allowedEmails: [EMAIL, 'Second@example.test'] });
  for (const email of ['Reviewer@EXAMPLE.TEST', 'Second@example.test']) {
    const response = await f.request('open', { claims: { email } }); assert.equal(response.status, 200);
    const state = await f.state(); assert.equal(state.events.at(-1).verifiedEmail, email.replace(/@.*/, '@example.test'));
  }
  for (const email of ['reviewer@example.test', 'Reviewer+alias@example.test', 'Third@example.test']) await denied(await f.request('open', { claims: { email } }));
  assert.equal((await f.state()).events.length, 2);
});

for (const [name, claims] of [
  ['missing email', { email: undefined }], ['malformed email', { email: 'not-an-email' }],
  ['missing subject', { sub: undefined }], ['missing application type', { type: undefined }],
  ['service type', { type: 'service' }], ['wrong audience', { aud: 'unrelated-audience' }],
  ['administrator audience', { aud: 'synthetic-admin-audience' }],
  ['wrong issuer', { iss: 'https://other.cloudflareaccess.com' }],
  ['expired token', { iat: 100, exp: 200 }], ['missing expiry', { exp: undefined }],
  ['unallowed email', { email: 'stranger@example.test' }],
]) test(`email route rejects ${name} without PDF release or audit acquisition`, async () => {
  const f = await fixture(); await denied(await f.request('open', { claims }));
  assert.equal(await f.state(), null); assert.equal(f.calls.length, 0);
});

for (const direct of [false, true]) test(`forged and unsigned identities cannot use email routes (${direct ? 'DO' : 'Worker'})`, async () => {
  const f = await fixture();
  for (const jwt of [null, 'not-a-jwt', await f.token({}, otherPair.privateKey)]) {
    for (const action of ['status', 'open']) await denied(await f.request(action, { jwt, direct,
      headers: { 'cf-access-authenticated-user-email': EMAIL, 'x-vault-owner-sub': f.env.VAULT_OWNER_SUB } }));
  }
  assert.equal(await f.state(), null); assert.equal(f.calls.length, 0);
});

for (const [name, value] of [['disabled', '0'], ['missing', undefined], ['nonexact', 'true']]) test(`email feature ${name} denies signed readers`, async () => {
  const f = await fixture(); f.env.EMAIL_READER_ENABLED = value;
  await denied(await f.request('open'), [401, 403, 503]); await denied(await f.request('status'), [401, 403, 503]);
  assert.equal(await f.state(), null); assert.equal(f.reads, 0);
});

test('email reader and administrator audiences cannot be configured identically', async () => {
  const f = await fixture(); f.env.READER_ACCESS_AUDIENCE = f.env.ACCESS_AUDIENCE;
  await denied(await f.request('open'), [401, 403, 503]); assert.equal(await f.state(), null);
});

test('email-reader token cannot access administrator APIs even when its subject matches the owner', async () => {
  const f = await fixture(), jwt = await f.token({ sub: f.env.VAULT_OWNER_SUB });
  for (const action of ['status', 'metadata', 'logs', 'recipients', 'links', 'revoke']) {
    await denied(await f.request(action, { prefix: '/v1/documents', jwt }));
  }
  for (const path of ['/v1/admin', '/v1/management']) await denied(await worker.fetch(new Request(f.env.PUBLIC_ORIGIN + path,
    { headers: { 'cf-access-jwt-assertion': jwt } }), f.env));
  assert.equal(f.reads, 0); assert.equal(await f.state(), null);
});

test('password, secret-URL and legacy Access paths cannot obtain an email document', async () => {
  const f = await fixture();
  await denied(await f.request('session', { prefix: '/p', jwt: null, body: JSON.stringify({ password: 'synthetic fallback password' }) }));
  await denied(await f.request('session', { prefix: '/p', jwt: null, body: JSON.stringify({ linkToken: 'ab'.repeat(32) }) }));
  await denied(await f.request('open', { prefix: '/p', body: JSON.stringify({ requestId: crypto.randomUUID() }) }));
  await denied(await f.owner('open', { body: JSON.stringify({ requestId: crypto.randomUUID() }) }));
  assert.equal(await f.state(), null); assert.equal(f.calls.length, 0);
});

for (const authMode of ['access', 'password', 'link']) test(`email route cannot bypass an existing ${authMode} document policy`, async () => {
  const f = await fixture({ authMode }); await denied(await f.request('status')); await denied(await f.request('open'));
  assert.equal(await f.state(), null); assert.equal(f.calls.length, 0);
});

for (const [name, options, statuses] of [
  ['missing purpose', { body: JSON.stringify({ requestId: crypto.randomUUID() }) }, [400]],
  ['unsupported purpose', { purpose: 'print' }, [400]],
  ['extra field', { body: JSON.stringify({ requestId: crypto.randomUUID(), purpose: 'view', verifiedEmail: EMAIL }) }, [400]],
  ['wrong origin', { headers: { origin: 'https://other.example.test' } }, [403]],
  ['wrong content type', { headers: { 'content-type': 'text/plain' } }, [403]],
  ['GET open', { method: 'GET' }, [405]], ['HEAD open', { method: 'HEAD' }, [405]],
  ['Range', { headers: { range: 'bytes=0-20' } }, [400]],
  ['query parameters', { query: '?email=Reviewer' }, [403]],
  ['another document', { id: crypto.randomUUID() }, [403]],
]) test(`email acquisition rejects ${name}`, async () => {
  const f = await fixture(); await denied(await f.request('open', options), statuses);
  assert.equal(await f.state(), null); assert.equal(f.calls.length, 0);
});

test('request replay is rejected across a restart while new view and download remain separate events', async () => {
  const f = await fixture(), requestId = crypto.randomUUID();
  assert.equal((await f.request('open', { requestId })).status, 200); f.restart();
  await denied(await f.request('open', { requestId, purpose: 'download' }), [409]);
  assert.equal((await f.request('open', { purpose: 'download' })).status, 200);
  assert.deepEqual((await f.state()).events.map(event => event.purpose), ['view', 'download']);
});

test('document expiry rejects both email status and new acquisitions with an otherwise valid JWT', async () => {
  const f = await fixture({ expiresAt: Date.now() + 60000 }), jwt = await f.token();
  assert.equal((await f.request('open', { jwt })).status, 200);
  const state = await f.state();
  await withClock(f.expiresAt + 1, async () => {
    await denied(await f.request('status', { jwt })); await denied(await f.request('open', { jwt }));
  });
  assert.deepEqual(await f.state(), state);
});

test('owner revocation remains permanent for email readers across a restart', async () => {
  const f = await fixture(), jwt = await f.token();
  assert.equal((await f.request('open', { jwt })).status, 200);
  assert.equal((await f.owner('revoke')).status, 200); f.restart();
  const state = await f.state(); assert.equal(state.revoked, true);
  await denied(await f.request('status', { jwt })); await denied(await f.request('open', { jwt }));
  assert.deepEqual(await f.state(), state);
  const response = await f.owner('metadata'); assert.equal(response.status, 200); assert.equal((await response.json()).revoked, true);
});

test('encrypted automatic archives preserve verified email and purpose without changing legacy log events', async () => {
  const f = await fixture(); assert.equal((await f.request('open', { purpose: 'download' })).status, 200);
  await withClock(Date.now() + 1000, () => f.alarm());
  const state = await f.state(), recorded = state.events[0], now = Date.now();
  for (let i = 0; i < 198; i++) state.events.push({ id: crypto.randomUUID(), documentId: f.id,
    subject: 'shared-password', at: now - 500 - i, outcome: 'decrypted' });
  await f.writeState(state);
  assert.equal((await f.request('open')).status, 200);
  const archiveName = `audit:${recorded.id}`; assert.ok(f.storage.map.has(archiveName), 'Completed event must be compacted into an encrypted archive');
  const saved = await openJSON(await f.storage.get(archiveName), f.auditKey, `${f.context}:${archiveName}`);
  assert.equal(saved.event.verifiedEmail, EMAIL); assert.equal(saved.event.purpose, 'download');
  f.restart();
  const seen = []; let cursor = null;
  do {
    const response = await f.owner('logs', cursor ? { method: 'POST', body: JSON.stringify({ cursor }) } : {});
    assert.equal(response.status, 200); const page = await response.json();
    assert.equal(page.retentionDays, 30); seen.push(...page.events); cursor = page.nextCursor;
    assert.ok(seen.length <= 200);
  } while (cursor);
  assert.equal(seen.length, 200);
  const archivedEvent = seen.find(event => event.id === recorded.id);
  assert.equal(archivedEvent.verifiedEmail, EMAIL); assert.equal(archivedEvent.purpose, 'download');
  for (const legacy of seen.filter(event => event.subject === 'shared-password')) {
    assert.deepEqual(Object.keys(legacy).sort(), ['at', 'id', 'notifications', 'outcome', 'subject']);
  }
  for (const secret of [EMAIL, SUBJECT, 'SYNTHETIC_EMAIL_DOCUMENT']) assert.ok(!JSON.stringify([...f.storage.map]).includes(secret));
});

for (const overrides of [{ verifiedEmail: EMAIL }, { purpose: 'view' }, { verifiedEmail: 'invalid', purpose: 'view' },
  { verifiedEmail: EMAIL, purpose: 'print' }]) test(`owner logs fail closed for malformed email audit fields ${JSON.stringify(overrides)}`, async () => {
  const f = await fixture(); assert.equal((await f.request('open')).status, 200);
  const state = await f.state(); delete state.events[0].verifiedEmail; delete state.events[0].purpose;
  Object.assign(state.events[0], overrides); await f.writeState(state);
  const response = await f.owner('logs'); assert.equal(response.status, 503); assert.deepEqual(await response.json(), { error: 'unavailable' });
});
