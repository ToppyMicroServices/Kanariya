import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { generateKeyPair, exportJWK, SignJWT } from 'jose';
import { VaultRegistrations, registrationBody, MAX_REGISTRATIONS, MAX_REGISTRATION_BODY } from '../src/registration.js';
import { MAX_PDF_BYTES, newKey, utf8, b64, importKey, openJSON, readPolicy, decryptDocument, sealJSON } from '../src/crypto.js';

const originalFetch = globalThis.fetch;
after(() => { globalThis.fetch = originalFetch; });
const pair = await generateKeyPair('RS256', { extractable: true });
const jwk = { ...await exportJWK(pair.publicKey), kid: 'registration-fixture', use: 'sig', alg: 'RS256' };
let fixtureNumber = 0;

class Storage {
  constructor() { this.map = new Map(); this.writes = 0; this.failWrite = false; this.failAt = 0; }
  async get(key) { return structuredClone(this.map.get(key)); }
  async transaction(operation) {
    const draft = new Map(structuredClone([...this.map]));
    const result = await operation({ get: async key => structuredClone(draft.get(key)),
      put: async (key, value) => { if (this.failWrite || this.failAt === this.writes + 1) throw new Error('synthetic_storage_failure'); this.writes++; draft.set(key, structuredClone(value)); } });
    this.map = draft; return result;
  }
}

async function fixture() {
  const storage = new Storage(), owner = 'synthetic-private-registration-owner';
  const env = { PUBLIC_ORIGIN: 'https://vault.example.test', ACCESS_ISSUER: `https://registration-${++fixtureNumber}.cloudflareaccess.com`,
    ACCESS_AUDIENCE: 'registration-fixture', VAULT_OWNER_SUB: owner, VAULT_WRAP_KEY: newKey(), VAULT_AUDIT_KEY: newKey(),
    DUMMY_DOCUMENT_ID: crypto.randomUUID(), DUMMY_RECORD_SHA256: 'a'.repeat(64), PASSWORD_READER_ENABLED: '1' };
  const wrap = await importKey(env.VAULT_WRAP_KEY), audit = await importKey(env.VAULT_AUDIT_KEY);
  const ctx = { storage, id: { toString: () => 'owner-registration:v1' } }, context = 'registration:v1:owner-registration:v1';
  let instance = new VaultRegistrations(ctx, env), reads = 0, writes = 0, notifications = 0;
  const objects = new Map([[`${env.DUMMY_DOCUMENT_ID}.sealed.json`, utf8('SYNTHETIC_EXISTING_PUBLIC_RECORD')]]);
  let putFailure = false, readFailure = false, alteredReadback = false, afterRead = null;
  env.VAULT_DOCUMENTS = {
    async put(name, value, options) {
      writes++; assert.match(name, /^staging\/[0-9a-f-]{36}\.sealed\.json$/);
      assert.equal(options.onlyIf.get('if-none-match'), '*');
      assert.equal(options.httpMetadata.contentType, 'application/json');
      assert.match(options.httpMetadata.cacheControl, /no-store/);
      assert.equal(Object.hasOwn(options, 'customMetadata'), false);
      assert.equal(Buffer.from(options.sha256).toString('hex'), createHash('sha256').update(value).digest('hex'));
      if (putFailure) throw new Error('synthetic_sensitive_provider_failure');
      if (objects.has(name)) return null;
      objects.set(name, new Uint8Array(value)); return { key: name, size: value.byteLength };
    },
    async get(name) {
      reads++; assert.match(name, /^staging\/[0-9a-f-]{36}\.sealed\.json$/);
      if (readFailure) throw new Error('synthetic_sensitive_provider_failure');
      const body = new Uint8Array(objects.get(name)); if (alteredReadback) body[body.length - 1] ^= 1;
      if (afterRead) await afterRead();
      return { size: body.byteLength, body: new Response(body).body };
    },
    async delete() { throw new Error('unexpected_delete'); }, async list() { throw new Error('unexpected_bucket_list'); },
  };
  globalThis.fetch = async url => {
    if (String(url) === `${env.ACCESS_ISSUER}/cdn-cgi/access/certs`) return Response.json({ keys: [jwk] });
    notifications++; throw new Error('unexpected_outbound');
  };
  const pdf = utf8('%PDF-1.4\nSYNTHETIC_PRIVATE_REGISTRATION_CONTENT\n');
  function input(changes = {}) { return { id: crypto.randomUUID(), pdfBase64: b64(pdf), fileName: 'Synthetic private CV.pdf',
    expiresAt: Date.now() + 600000, replaceOf: null, expectedRevision: 0, ...changes }; }
  async function token(subject) {
    return new SignJWT({ sub: subject, iss: env.ACCESS_ISSUER, aud: env.ACCESS_AUDIENCE,
      iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + 600 })
      .setProtectedHeader({ alg: 'RS256', kid: 'registration-fixture' }).sign(pair.privateKey);
  }
  async function makeRequest(options = {}) {
    const subject = Object.hasOwn(options, 'subject') ? options.subject : owner;
    const method = options.method ?? 'POST';
    const headers = { origin: env.PUBLIC_ORIGIN, 'content-type': 'application/json',
      ...(subject ? { 'cf-access-jwt-assertion': await token(subject) } : {}), ...options.headers };
    return new Request(env.PUBLIC_ORIGIN + (options.path ?? '/v1/registrations'), { method, headers,
      ...(['GET', 'HEAD'].includes(method) ? {} : { body: options.raw ?? JSON.stringify(options.input ?? input()), ...(options.stream ? { duplex: 'half' } : {}) }) });
  }
  async function request(options = {}) { return instance.fetch(await makeRequest(options)); }
  async function list() { const response = await request({ method: 'GET' }); assert.equal(response.status, 200); return response.json(); }
  async function state() { const box = await storage.get('encrypted-registration'); return box ? openJSON(box, audit, context) : { version: 1, revision: 0, documents: [], reservations: [] }; }
  async function writeState(value) { storage.map.set('encrypted-registration', await sealJSON(value, audit, context)); }
  return { env, owner, storage, objects, pdf, input, request, list, state, writeState, makeRequest, wrap, audit, context,
    get instance() { return instance; }, restart() { instance = new VaultRegistrations(ctx, env); },
    get reads() { return reads; }, get writes() { return writes; }, get notifications() { return notifications; },
    set putFailure(value) { putFailure = value; }, set readFailure(value) { readFailure = value; },
    set alteredReadback(value) { alteredReadback = value; }, set afterRead(value) { afterRead = value; } };
}

test('owner registration stores only encrypted PDF and metadata with a private exact response', async () => {
  const f = await fixture(), pinBefore = [f.env.DUMMY_DOCUMENT_ID, f.env.DUMMY_RECORD_SHA256], input = f.input();
  assert.deepEqual(await f.list(), { revision: 0, documents: [], pending: 0 });
  const response = await f.request({ input }); assert.equal(response.status, 201);
  const result = await response.json(); assert.equal(result.revision, 2); assert.equal(result.documents.length, 1); assert.equal(result.pending, 0);
  assert.deepEqual(result.documents[0], { id: input.id, createdAt: result.documents[0].createdAt,
    expiresAt: input.expiresAt, size: f.pdf.length, replaceOf: null, status: 'private', fileName: input.fileName });
  assert.match(response.headers.get('cache-control'), /no-store/); assert.equal(response.headers.get('access-control-allow-origin'), null);
  const stored = f.objects.get(`staging/${input.id}.sealed.json`), record = JSON.parse(Buffer.from(stored).toString()), policy = await readPolicy(record, input.id, f.wrap);
  assert.deepEqual(policy.subjects, [f.owner]); assert.equal(policy.authMode, 'access');
  assert.equal(Object.hasOwn(policy, 'passwordVerifier'), false); assert.equal(Object.hasOwn(policy, 'recipientName'), false);
  assert.deepEqual(await decryptDocument(record, f.wrap, policy), f.pdf);
  const saved = await f.state(); assert.equal(saved.documents[0].recordSha256, createHash('sha256').update(stored).digest('hex'));
  for (const persisted of [JSON.stringify([...f.storage.map]), Buffer.from(stored).toString()]) {
    for (const secret of [input.fileName, f.owner, f.env.VAULT_WRAP_KEY, f.env.VAULT_AUDIT_KEY, 'SYNTHETIC_PRIVATE_REGISTRATION_CONTENT']) assert.ok(!persisted.includes(secret));
  }
  for (const secret of ['ciphertext', 'recordSha256', f.owner, f.env.VAULT_WRAP_KEY, f.env.VAULT_AUDIT_KEY, 'staging/', 'SYNTHETIC_PRIVATE_REGISTRATION_CONTENT']) assert.ok(!JSON.stringify(result).includes(secret));
  f.restart(); assert.deepEqual(await f.list(), result);
  assert.deepEqual([f.env.DUMMY_DOCUMENT_ID, f.env.DUMMY_RECORD_SHA256], pinBefore);
  assert.equal(Buffer.from(f.objects.get(`${pinBefore[0]}.sealed.json`)).toString(), 'SYNTHETIC_EXISTING_PUBLIC_RECORD');
  assert.equal(f.notifications, 0);
});

test('a replacement candidate names only the current pinned document and remains private', async () => {
  const f = await fixture(), input = f.input({ replaceOf: f.env.DUMMY_DOCUMENT_ID });
  const response = await f.request({ input }); assert.equal(response.status, 201);
  assert.equal((await response.json()).documents[0].replaceOf, f.env.DUMMY_DOCUMENT_ID);
  assert.equal((await f.state()).documents[0].status, 'private');
  assert.equal(f.objects.size, 2); assert.equal(f.notifications, 0);
});

test('the exact one MiB PDF boundary fits the separate upload and ciphertext limits', async () => {
  const f = await fixture(), bytes = new Uint8Array(MAX_PDF_BYTES);
  bytes.set(utf8('%PDF-1.4\nSYNTHETIC_MAXIMUM_PRIVATE_UPLOAD\n'));
  const input = f.input({ pdfBase64: b64(bytes), fileName: ' 最大ダミー.pdf ' });
  const response = await f.request({ input }); assert.equal(response.status, 201);
  const document = (await response.json()).documents[0];
  assert.equal(document.size, MAX_PDF_BYTES); assert.equal(document.fileName, '最大ダミー.pdf');
  const record = JSON.parse(Buffer.from(f.objects.get(`staging/${input.id}.sealed.json`)).toString());
  const policy = await readPolicy(record, input.id, f.wrap);
  assert.deepEqual(await decryptDocument(record, f.wrap, policy), bytes);
  assert.equal(f.notifications, 0);
});

test('anonymous, password-cookie, forged header and non-owner requests never read bodies, keys or storage', async () => {
  const f = await fixture(); let keyReads = 0, storageReads = 0, bodyReads = 0;
  for (const key of ['VAULT_WRAP_KEY', 'VAULT_AUDIT_KEY']) {
    const value = f.env[key]; Object.defineProperty(f.env, key, { get() { keyReads++; return value; } });
  }
  f.storage.get = async () => { storageReads++; throw new Error('unauthorized_storage_read'); };
  for (const method of ['GET', 'POST']) {
    for (const options of [{ subject: null }, { subject: 'synthetic-other-reader' },
      { subject: null, headers: { cookie: '__Secure-vault-fake=synthetic', 'cf-access-authenticated-user-email': 'owner@example.test' } },
      { subject: null, headers: { 'cf-access-jwt-assertion': 'forged token', 'x-vault-owner-sub': f.owner } }]) {
      const request = await f.makeRequest({ method, ...options });
      const guarded = new Proxy(request, { get(target, name) { if (name === 'body') { bodyReads++; throw new Error('unauthorized_body_read'); } return Reflect.get(target, name, target); } });
      assert.equal((await f.instance.fetch(guarded)).status, options.subject === 'synthetic-other-reader' ? 403 : 401);
    }
  }
  assert.deepEqual([keyReads, storageReads, bodyReads, f.reads, f.writes, f.storage.writes, f.notifications], [0, 0, 0, 0, 0, 0, 0]);
});

for (const [label, options, status] of [
  ['wrong origin', { headers: { origin: 'https://other.example.test' } }, 403],
  ['missing origin', { headers: { origin: '' } }, 403],
  ['wrong type', { headers: { 'content-type': 'text/plain' } }, 403],
  ['JSON type with parameters', { headers: { 'content-type': 'application/json; charset=utf-8' } }, 403],
  ['cross-site', { headers: { 'sec-fetch-site': 'cross-site' } }, 403],
  ['same-site', { headers: { 'sec-fetch-site': 'same-site' } }, 403],
  ['wrong path', { path: '/v1/registrations/open' }, 403],
  ['query', { path: '/v1/registrations?id=unapproved' }, 403],
  ['DELETE', { method: 'DELETE' }, 405],
  ['PUT', { method: 'PUT' }, 405],
  ['malformed JSON', { raw: '{' }, 400], ['array', { raw: '[]' }, 400], ['empty object', { raw: '{}' }, 400],
  ['oversized declared body', { headers: { 'content-length': String(MAX_REGISTRATION_BODY + 1) } }, 400],
  ['malformed declared body', { headers: { 'content-length': 'not-a-size' } }, 400],
  ['oversized actual body', { raw: 'x'.repeat(MAX_REGISTRATION_BODY + 1) }, 400],
]) test(`registration rejects ${label} before storage or keys`, async () => {
  const f = await fixture(); let keyReads = 0;
  for (const key of ['VAULT_WRAP_KEY', 'VAULT_AUDIT_KEY']) {
    const value = f.env[key]; Object.defineProperty(f.env, key, { get() { keyReads++; return value; } });
  }
  assert.equal((await f.request(options)).status, status);
  assert.deepEqual([keyReads, f.reads, f.writes, f.storage.writes, f.notifications], [0, 0, 0, 0, 0]);
});

for (const [label, change] of [
  ['wrong ID', { id: 'not-an-id' }], ['extra field', { password: 'must-not-be-accepted' }],
  ['missing field', { replaceOf: undefined }], ['wrong replacement', { replaceOf: crypto.randomUUID() }],
  ['non-UUID replacement', { replaceOf: 'other' }], ['past deadline', { expiresAt: 1 }],
  ['fractional deadline', { expiresAt: 1800000000000.5 }], ['string deadline', { expiresAt: '1800000000000' }],
  ['invalid Date maximum', { expiresAt: 8640000000000001 }], ['negative revision', { expectedRevision: -1 }],
  ['fractional revision', { expectedRevision: 0.5 }], ['string revision', { expectedRevision: '0' }],
  ['bad base64', { pdfBase64: '<not base64>' }], ['empty PDF', { pdfBase64: '' }],
  ['non-PDF content', { pdfBase64: b64(utf8('not-a-pdf')) }],
  ['oversized decoded PDF', { pdfBase64: b64(new Uint8Array(MAX_PDF_BYTES + 1)) }],
  ['empty name', { fileName: ' ' }], ['long name', { fileName: 'x'.repeat(121) }],
  ['control in name', { fileName: 'bad\nname.pdf' }], ['path in name', { fileName: '/private/source.pdf' }],
  ['backslash in name', { fileName: 'private\\source.pdf' }], ['bidi in name', { fileName: 'bad\u202ename.pdf' }],
  ['non-string name', { fileName: null }], ['malformed Unicode name', { fileName: '\ud800.pdf' }],
]) test(`registration rejects ${label}`, async () => {
  const f = await fixture(); assert.equal((await f.request({ input: f.input(change) })).status, 400);
  assert.deepEqual([f.reads, f.writes, f.storage.writes, f.notifications], [0, 0, 0, 0]);
});

test('the current public document ID cannot be reused for a private upload', async () => {
  const f = await fixture(); assert.equal((await f.request({ input: f.input({ id: f.env.DUMMY_DOCUMENT_ID }) })).status, 400);
  assert.equal(f.writes, 0); assert.equal(f.storage.writes, 0);
});

test('stale revision, duplicate IDs and concurrent updates fail before new R2 writes', async () => {
  const f = await fixture(), first = f.input(); assert.equal((await f.request({ input: first })).status, 201);
  const before = f.writes;
  assert.equal((await f.request({ input: first })).status, 409);
  assert.deepEqual(await (await f.request({ input: first })).json(), { error: 'registration_exists' });
  assert.equal((await f.request({ input: f.input() })).status, 409); assert.equal(f.writes, before);
  const results = await Promise.all([f.request({ input: f.input({ expectedRevision: 2 }) }), f.request({ input: f.input({ expectedRevision: 2 }) })]);
  assert.deepEqual(results.map(response => response.status).sort(), [201, 409]);
  assert.equal(f.writes, before + 1); assert.equal((await f.list()).revision, 4);
});

test('an existing immutable staging object cannot be overwritten or admitted as a different upload', async () => {
  const f = await fixture(), input = f.input(), original = utf8('SYNTHETIC_EXISTING_PRIVATE_OBJECT');
  f.objects.set(`staging/${input.id}.sealed.json`, original);
  const response = await f.request({ input }); assert.equal(response.status, 409);
  assert.deepEqual(await response.json(), { error: 'registration_exists' });
  assert.deepEqual(f.objects.get(`staging/${input.id}.sealed.json`), original);
  assert.equal(f.storage.writes, 1); assert.equal(f.reads, 0);
  assert.deepEqual(await f.list(), { revision: 1, documents: [], pending: 1 });
});

for (const problem of ['putFailure', 'readFailure', 'alteredReadback']) test(`R2 ${problem} leaves no admitted document and returns a fixed error`, async () => {
  const f = await fixture(); f[problem] = true;
  const response = await f.request(); assert.equal(response.status, 503); assert.deepEqual(await response.json(), { error: 'unavailable' });
  assert.equal(f.storage.writes, 1); assert.deepEqual(await f.list(), { revision: 1, documents: [], pending: 1 });
  assert.equal(f.notifications, 0);
});

test('an R2 object stays private when the registry changes before its final CAS', async () => {
  const f = await fixture(); let other;
  f.afterRead = async () => {
    const registered = f.input(); other = { id: registered.id, createdAt: Date.now(), expiresAt: registered.expiresAt,
      size: f.pdf.length, replaceOf: null, status: 'private', fileName: registered.fileName, recordSha256: 'b'.repeat(64) };
    const state = await f.state(); state.documents.push(other); state.revision += 2; await f.writeState(state);
  };
  const input = f.input(), response = await f.request({ input });
  assert.equal(response.status, 409); assert.deepEqual(await response.json(), { error: 'registration_changed' });
  assert.ok(f.objects.has(`staging/${input.id}.sealed.json`));
  const list = await f.list(); assert.equal(list.documents.length, 1); assert.equal(list.documents[0].id, other.id);
  assert.equal(list.documents.some(document => document.id === input.id), false);
  assert.equal(f.notifications, 0);
});

test('failed encrypted completion cannot publish or list the uploaded candidate', async () => {
  const f = await fixture(), input = f.input(); f.storage.failAt = 2;
  const response = await f.request({ input }); assert.equal(response.status, 503);
  assert.deepEqual(await response.json(), { error: 'unavailable' });
  assert.ok(f.objects.has(`staging/${input.id}.sealed.json`)); assert.deepEqual(await f.list(), { revision: 1, documents: [], pending: 1 });
  assert.equal(f.storage.writes, 1); f.restart(); assert.equal((await f.state()).reservations[0].id, input.id);
  assert.equal(f.env.DUMMY_RECORD_SHA256, 'a'.repeat(64)); assert.equal(f.notifications, 0);
});

test('a failed durable reservation cannot reach R2 or leave a private metadata entry', async () => {
  const f = await fixture(), input = f.input(); f.storage.failWrite = true;
  const response = await f.request({ input }); assert.equal(response.status, 503);
  assert.deepEqual(await response.json(), { error: 'unavailable' });
  assert.deepEqual([f.reads, f.writes, f.storage.writes], [0, 0, 0]);
  assert.equal(f.objects.size, 1); assert.deepEqual(await f.list(), { revision: 0, documents: [], pending: 0 });
  assert.equal(f.notifications, 0);
});

test('a reserved ID cannot be reused after an uncertain object write, even after restart', async () => {
  const f = await fixture(), input = f.input(); f.readFailure = true;
  assert.equal((await f.request({ input })).status, 503);
  const before = f.writes; f.restart(); f.readFailure = false;
  const response = await f.request({ input: { ...input, expectedRevision: 1 } }); assert.equal(response.status, 409);
  assert.deepEqual(await response.json(), { error: 'registration_exists' });
  assert.equal(f.writes, before); assert.deepEqual(await f.list(), { revision: 1, documents: [], pending: 1 });
  const state = await f.state(); assert.equal(state.reservations[0].id, input.id);
  for (const sensitive of [input.id, input.fileName, f.owner, f.env.VAULT_WRAP_KEY, f.env.VAULT_AUDIT_KEY,
    String(input.expiresAt), 'SYNTHETIC_PRIVATE_REGISTRATION_CONTENT']) assert.ok(!JSON.stringify([...f.storage.map]).includes(sensitive));
  assert.equal(f.notifications, 0);
});

for (const problem of ['putFailure', 'readFailure', 'alteredReadback', 'completionFailure']) test(`${problem} consumes durable slots and stays capped across restart`, async () => {
  const f = await fixture();
  if (problem === 'completionFailure') f.afterRead = async () => { f.storage.failWrite = true; };
  else f[problem] = true;
  for (let index = 0; index < MAX_REGISTRATIONS; index++) {
    f.storage.failWrite = false;
    const input = f.input({ expectedRevision: index }), response = await f.request({ input });
    assert.equal(response.status, 503); assert.deepEqual(await response.json(), { error: 'unavailable' });
    assert.deepEqual(await f.list(), { revision: index + 1, documents: [], pending: index + 1 });
    if (index % 3 === 0) f.restart();
  }
  f.restart(); f.storage.failWrite = false;
  const before = f.writes;
  const blocked = await f.request({ input: f.input({ expectedRevision: MAX_REGISTRATIONS }) });
  assert.equal(blocked.status, 429); assert.deepEqual(await blocked.json(), { error: 'registration_limit' });
  assert.equal(f.writes, before); assert.equal(before, MAX_REGISTRATIONS);
  assert.deepEqual(await f.list(), { revision: MAX_REGISTRATIONS, documents: [], pending: MAX_REGISTRATIONS });
  assert.equal(f.notifications, 0);
});

test('completed and incomplete candidates share the same twenty-slot capacity', async () => {
  const f = await fixture();
  assert.equal((await f.request()).status, 201);
  f.putFailure = true;
  for (let index = 0; index < MAX_REGISTRATIONS - 1; index++) {
    assert.equal((await f.request({ input: f.input({ expectedRevision: index + 2 }) })).status, 503);
  }
  const list = await f.list(); assert.equal(list.revision, MAX_REGISTRATIONS + 1);
  assert.equal(list.documents.length, 1); assert.equal(list.pending, MAX_REGISTRATIONS - 1);
  const before = f.writes;
  assert.equal((await f.request({ input: f.input({ expectedRevision: list.revision }) })).status, 429);
  assert.equal(f.writes, before);
});

test('a deadline that passes during R2 readback cannot enter the registry', async () => {
  const f = await fixture(), input = f.input(), originalNow = Date.now;
  f.afterRead = async () => { Date.now = () => input.expiresAt; };
  try {
    const response = await f.request({ input }); assert.equal(response.status, 400);
    assert.ok(f.objects.has(`staging/${input.id}.sealed.json`)); assert.equal(f.storage.writes, 1);
    assert.deepEqual(await f.list(), { revision: 1, documents: [], pending: 1 });
    assert.equal(f.notifications, 0);
  } finally { Date.now = originalNow; }
});

test('the candidate count is bounded before further encryption or bucket writes', async () => {
  const f = await fixture(), documents = Array.from({ length: MAX_REGISTRATIONS }, () => {
    const input = f.input(); return { id: input.id, createdAt: Date.now(), expiresAt: input.expiresAt,
      size: f.pdf.length, replaceOf: null, status: 'private', fileName: input.fileName, recordSha256: 'b'.repeat(64) };
  });
  await f.writeState({ version: 1, revision: 2 * MAX_REGISTRATIONS, documents, reservations: [] });
  const response = await f.request({ input: f.input({ expectedRevision: 2 * MAX_REGISTRATIONS }) });
  assert.equal(response.status, 429); assert.deepEqual(await response.json(), { error: 'registration_limit' });
  assert.equal(f.writes, 0); assert.equal(f.storage.writes, 0);
});

for (const change of [state => { state.version = 2; }, state => { state.revision++; },
  state => { state.documents[0].status = 'public'; }, state => { state.documents[0].recordSha256 = 'not-a-hash'; },
  state => { state.documents.push(state.documents[0]); state.revision += 2; }]) test('malformed authenticated registry fails closed', async () => {
  const f = await fixture(); assert.equal((await f.request()).status, 201);
  const state = await f.state(); change(state); await f.writeState(state);
  const writes = f.writes;
  for (const method of ['GET', 'POST']) assert.equal((await f.request({ method, input: f.input({ expectedRevision: 2 }) })).status, 503);
  assert.equal(f.writes, writes);
});

for (const change of [state => { delete state.reservations; }, state => { state.reservations = {}; },
  state => { state.reservations[0].status = 'private'; }, state => { state.reservations[0].recordSha256 = 'not-a-hash'; },
  state => { state.reservations[0].other = true; }, state => { state.documents.push({ ...state.reservations[0], status: 'private' }); state.revision += 2; }])
test('malformed reservation state cannot admit more objects or leak candidate metadata', async () => {
  const f = await fixture(); f.putFailure = true;
  assert.equal((await f.request()).status, 503); const state = await f.state(); change(state); await f.writeState(state);
  const before = f.writes;
  for (const method of ['GET', 'POST']) {
    const response = await f.request({ method, input: f.input({ expectedRevision: 1 }) }); assert.equal(response.status, 503);
    assert.deepEqual(await response.json(), { error: 'unavailable' });
  }
  assert.equal(f.writes, before);
});

test('registration needs separate encryption keys and cannot expose key import errors', async () => {
  const f = await fixture(); f.env.VAULT_AUDIT_KEY = f.env.VAULT_WRAP_KEY;
  const response = await f.request(); assert.equal(response.status, 503); assert.deepEqual(await response.json(), { error: 'unavailable' });
  assert.equal(f.writes, 0); assert.equal(f.storage.writes, 0);
});

test('owner upload reader rejects a stalled stream without waiting for cancellation', async () => {
  let cancelled = false;
  const stream = new ReadableStream({ pull: () => new Promise(() => {}), cancel() { cancelled = true; return new Promise(() => {}); } });
  const request = new Request('https://vault.example.test/v1/registrations', { method: 'POST', body: stream, duplex: 'half' });
  await assert.rejects(registrationBody(request, 10), error => error.status === 408 && error.code === 'request_timeout');
  assert.equal(cancelled, true);
});
