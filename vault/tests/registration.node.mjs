import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { generateKeyPair, exportJWK, SignJWT } from 'jose';
import { VaultRegistrations, registrationBody, MAX_REGISTRATIONS, MAX_REGISTRATION_BODY } from '../src/registration.js';
import { MAX_PDF_BYTES, newKey, utf8, b64, importKey, openJSON, readPolicy, decryptDocument, sealJSON, sealDocument } from '../src/crypto.js';

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
  let instance = new VaultRegistrations(ctx, env), reads = 0, writes = 0, notifications = 0, metadataReads = 0;
  const objects = new Map([[`${env.DUMMY_DOCUMENT_ID}.sealed.json`, utf8('SYNTHETIC_EXISTING_PUBLIC_RECORD')]]);
  let putFailure = false, readFailure = false, alteredReadback = false, afterRead = null;
  env.VAULT_DOCUMENTS = {
    async put(name, value, options) {
      writes++; assert.match(name, /^(?:staging\/)?[0-9a-f-]{36}\.sealed\.json$/);
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
      reads++; assert.match(name, /^(?:staging\/)?[0-9a-f-]{36}\.sealed\.json$/);
      if (readFailure) throw new Error('synthetic_sensitive_provider_failure');
      if (!objects.has(name)) return null;
      const body = new Uint8Array(objects.get(name)); if (alteredReadback) body[body.length - 1] ^= 1;
      if (afterRead) await afterRead();
      return { size: body.byteLength, body: new Response(body).body };
    },
    async delete() { throw new Error('unexpected_delete'); }, async list() { throw new Error('unexpected_bucket_list'); },
  };
  let metadata = { id: env.DUMMY_DOCUMENT_ID, authMode: 'password', expiresAt: Date.now() + 600000, revoked: false };
  env.VAULT = { idFromName: id => { assert.equal(id, env.DUMMY_DOCUMENT_ID); return id; }, get: () => ({
    async fetch(request) { metadataReads++; assert.equal(request.method, 'GET'); assert.equal(new URL(request.url).pathname, `/v1/documents/${env.DUMMY_DOCUMENT_ID}/metadata`); return Response.json(metadata); }
  }) };
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
    get metadataReads() { return metadataReads; }, get metadata() { return metadata; }, set metadata(value) { metadata = value; },
    set putFailure(value) { putFailure = value; }, set readFailure(value) { readFailure = value; },
    set alteredReadback(value) { alteredReadback = value; }, set afterRead(value) { afterRead = value; } };
}

function preparedInput(f, changes = {}) {
  return f.input({ recipient: { type: 'organization', organizationName: '株式会社ダミー', personName: '採用担当' },
    watermarkEnabled: true, sourceSha256: 'b'.repeat(64),
    preparedSha256: createHash('sha256').update(f.pdf).digest('hex'), preparationVersion: 1, ...changes });
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

test('browser preparation metadata stays encrypted and owner-visible without publishing or asserting a PDF transform', async () => {
  const f = await fixture(), pinBefore = [f.env.DUMMY_DOCUMENT_ID, f.env.DUMMY_RECORD_SHA256];
  const input = preparedInput(f, { recipient: { type: 'organization', organizationName: ' 株式会社ダミー ', personName: ' 担当e\u0301 ' } });
  const response = await f.request({ input }); assert.equal(response.status, 201);
  const result = await response.json(), recipient = { type: 'organization', organizationName: '株式会社ダミー', personName: '担当é' };
  assert.deepEqual(result.documents[0], { id: input.id, createdAt: result.documents[0].createdAt, expiresAt: input.expiresAt,
    size: f.pdf.length, replaceOf: null, status: 'private', fileName: input.fileName,
    recipient, watermarkEnabled: true, sourceSha256: input.sourceSha256, preparedSha256: input.preparedSha256, preparationVersion: 1 });
  assert.equal(result.revision, 2); assert.equal(result.pending, 0);
  const stored = f.objects.get(`staging/${input.id}.sealed.json`), record = JSON.parse(Buffer.from(stored).toString());
  const policy = await readPolicy(record, input.id, f.wrap);
  assert.equal(policy.recipientName, '株式会社ダミー 担当é');
  assert.deepEqual(policy.subjects, [f.owner]); assert.equal(policy.authMode, 'access');
  // These synthetic header bytes intentionally have no watermark or validated
  // PDF structure. The upload API checks the received digest, not either claim.
  assert.deepEqual(await decryptDocument(record, f.wrap, policy), f.pdf);
  assert.equal(Object.hasOwn(policy, 'watermarkEnabled'), false);
  assert.deepEqual((await f.state()).documents[0].recipient, recipient);
  for (const persisted of [JSON.stringify([...f.storage.map]), Buffer.from(stored).toString()]) {
    for (const sensitive of [recipient.organizationName, recipient.personName, policy.recipientName, input.sourceSha256,
      input.preparedSha256, input.fileName, 'recipient', 'watermarkEnabled', 'SYNTHETIC_PRIVATE_REGISTRATION_CONTENT']) assert.ok(!persisted.includes(sensitive));
  }
  f.restart(); assert.deepEqual(await f.list(), result);
  assert.deepEqual([f.env.DUMMY_DOCUMENT_ID, f.env.DUMMY_RECORD_SHA256], pinBefore);
  assert.equal(Buffer.from(f.objects.get(`${pinBefore[0]}.sealed.json`)).toString(), 'SYNTHETIC_EXISTING_PUBLIC_RECORD');
  assert.equal(f.notifications, 0);
});

for (const recipient of [
  { type: 'organization', organizationName: '株式会社ダミー', personName: null },
  { type: 'person', organizationName: null, personName: '個人ダミー' },
]) test(`prepared ${recipient.type} metadata supports an explicit disabled watermark`, async () => {
  const f = await fixture(), input = preparedInput(f, { recipient, watermarkEnabled: false });
  const response = await f.request({ input }); assert.equal(response.status, 201);
  const summary = (await response.json()).documents[0];
  assert.deepEqual(summary.recipient, recipient); assert.equal(summary.watermarkEnabled, false);
  const record = JSON.parse(Buffer.from(f.objects.get(`staging/${input.id}.sealed.json`)).toString());
  const policy = await readPolicy(record, input.id, f.wrap);
  assert.equal(policy.recipientName, recipient.organizationName ?? recipient.personName);
  assert.deepEqual(await decryptDocument(record, f.wrap, policy), f.pdf); assert.equal(f.notifications, 0);
});

test('legacy v1 rows coexist with prepared candidates and acquire no preparation claims', async () => {
  const f = await fixture(), legacy = f.input(); assert.equal((await f.request({ input: legacy })).status, 201);
  const before = await f.list(), saved = (await f.state()).documents[0];
  assert.equal(Object.keys(saved).length, 8);
  for (const field of ['recipient', 'watermarkEnabled', 'sourceSha256', 'preparedSha256', 'preparationVersion']) {
    assert.equal(Object.hasOwn(saved, field), false); assert.equal(Object.hasOwn(before.documents[0], field), false);
  }
  f.restart(); assert.deepEqual(await f.list(), before);
  const response = await f.request({ input: preparedInput(f, { expectedRevision: 2 }) }); assert.equal(response.status, 201);
  const result = await response.json(); assert.deepEqual(result.documents[0], before.documents[0]);
  assert.equal(result.revision, 4); assert.equal(result.documents[1].preparationVersion, 1);
  f.restart(); assert.deepEqual(await f.list(), result); assert.equal(f.notifications, 0);
});

for (const field of ['recipient', 'watermarkEnabled', 'sourceSha256', 'preparedSha256', 'preparationVersion']) {
  test(`preparation fields must be supplied together: missing ${field}`, async () => {
    const f = await fixture(), input = preparedInput(f); delete input[field];
    assert.equal((await f.request({ input })).status, 400);
    assert.deepEqual([f.reads, f.writes, f.storage.writes, f.notifications], [0, 0, 0, 0]);
  });
  test(`legacy uploads reject the isolated preparation field ${field}`, async () => {
    const f = await fixture(), metadata = preparedInput(f), input = f.input({ [field]: metadata[field] });
    assert.equal((await f.request({ input })).status, 400);
    assert.deepEqual([f.reads, f.writes, f.storage.writes, f.notifications], [0, 0, 0, 0]);
  });
}

for (const [label, changes] of [
  ['recipient array', { recipient: [] }], ['recipient null', { recipient: null }],
  ['unknown recipient type', { recipient: { type: 'company', organizationName: '会社', personName: null } }],
  ['missing recipient field', { recipient: { type: 'organization', organizationName: '会社' } }],
  ['extra recipient field', { recipient: { type: 'organization', organizationName: '会社', personName: null, email: 'forged@example.test' } }],
  ['organization without a name', { recipient: { type: 'organization', organizationName: null, personName: '担当' } }],
  ['person without a name', { recipient: { type: 'person', organizationName: null, personName: null } }],
  ['person with an organization', { recipient: { type: 'person', organizationName: '会社', personName: '担当' } }],
  ['empty organization name', { recipient: { type: 'organization', organizationName: ' ', personName: null } }],
  ['path in recipient', { recipient: { type: 'person', organizationName: null, personName: '../dummy' } }],
  ['bidi in recipient', { recipient: { type: 'person', organizationName: null, personName: 'dummy\u202e' } }],
  ['malformed Unicode recipient', { recipient: { type: 'person', organizationName: null, personName: '\ud800' } }],
  ['long combined recipient', { recipient: { type: 'organization', organizationName: '界'.repeat(40), personName: '界'.repeat(21) } }],
  ['watermark string', { watermarkEnabled: 'true' }], ['watermark null', { watermarkEnabled: null }],
  ['unknown preparation version', { preparationVersion: 2 }], ['string preparation version', { preparationVersion: '1' }],
  ['invalid source hash', { sourceSha256: 'not-a-hash' }], ['uppercase source hash', { sourceSha256: 'A'.repeat(64) }],
  ['non-string source hash', { sourceSha256: null }], ['invalid prepared hash', { preparedSha256: 'not-a-hash' }],
  ['non-string prepared hash', { preparedSha256: ['a'.repeat(64)] }], ['wrong received PDF digest', { preparedSha256: 'c'.repeat(64) }],
]) test(`prepared registration rejects ${label} before keys or persistence`, async () => {
  const f = await fixture(); let keyReads = 0;
  for (const key of ['VAULT_WRAP_KEY', 'VAULT_AUDIT_KEY']) {
    const value = f.env[key]; Object.defineProperty(f.env, key, { get() { keyReads++; return value; } });
  }
  const response = await f.request({ input: preparedInput(f, changes) }); assert.equal(response.status, 400);
  assert.deepEqual(await response.json(), { error: 'invalid_request' });
  assert.deepEqual([keyReads, f.reads, f.writes, f.storage.writes, f.notifications], [0, 0, 0, 0, 0]);
});

test('the combined recipient accepts the exact 180 UTF-8 byte boundary', async () => {
  const f = await fixture(), recipient = { type: 'organization', organizationName: '界'.repeat(40), personName: 'x'.repeat(59) };
  const response = await f.request({ input: preparedInput(f, { recipient }) }); assert.equal(response.status, 201);
  assert.deepEqual((await response.json()).documents[0].recipient, recipient);
});

test('an incomplete prepared upload retains only encrypted metadata and a durable private reservation', async () => {
  const f = await fixture(), input = preparedInput(f); f.readFailure = true;
  assert.equal((await f.request({ input })).status, 503); f.restart();
  assert.deepEqual(await f.list(), { revision: 1, documents: [], pending: 1 });
  const reservation = (await f.state()).reservations[0];
  for (const field of ['recipient', 'watermarkEnabled', 'sourceSha256', 'preparedSha256', 'preparationVersion']) assert.deepEqual(reservation[field], input[field]);
  for (const sensitive of [input.recipient.organizationName, input.recipient.personName, input.sourceSha256, input.preparedSha256]) {
    assert.ok(!JSON.stringify([...f.storage.map]).includes(sensitive));
  }
  const before = f.writes;
  assert.equal((await f.request({ input: { ...input, expectedRevision: 1 } })).status, 409);
  assert.equal(f.writes, before); assert.equal(f.notifications, 0);
});

for (const pending of [false, true]) for (const [label, change] of [
  ['partial preparation', entry => { delete entry.sourceSha256; }],
  ['extra metadata', entry => { entry.preparationComplete = true; }],
  ['extra recipient field', entry => { entry.recipient.email = 'private@example.test'; }],
  ['unnormalized recipient', entry => { entry.recipient.organizationName = ' 株式会社ダミー'; }],
  ['unknown version', entry => { entry.preparationVersion = 2; }],
  ['invalid hash', entry => { entry.preparedSha256 = null; }],
]) test(`malformed ${pending ? 'pending' : 'completed'} preparation state rejects ${label} without exposing metadata`, async () => {
  const f = await fixture(); f.readFailure = pending;
  assert.equal((await f.request({ input: preparedInput(f) })).status, pending ? 503 : 201);
  const state = await f.state(); change((pending ? state.reservations : state.documents)[0]); await f.writeState(state);
  const before = [f.reads, f.writes, f.storage.writes];
  for (const method of ['GET', 'POST']) {
    const response = await f.request({ method, input: f.input({ expectedRevision: pending ? 1 : 2 }) });
    assert.equal(response.status, 503); assert.deepEqual(await response.json(), { error: 'unavailable' });
  }
  assert.deepEqual([f.reads, f.writes, f.storage.writes], before); assert.equal(f.notifications, 0);
});

test('a legacy row with a partial preparation extension fails closed instead of acquiring preparation status', async () => {
  const f = await fixture(); assert.equal((await f.request()).status, 201);
  const state = await f.state(); state.documents[0].watermarkEnabled = true; await f.writeState(state);
  const response = await f.request({ method: 'GET' }); assert.equal(response.status, 503);
  assert.deepEqual(await response.json(), { error: 'unavailable' });
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

async function replacementFixture(mode = 'password', policyChanges = {}) {
  const f = await fixture(), currentId = f.env.DUMMY_DOCUMENT_ID;
  const currentRecord = await sealDocument({ id: currentId, bytes: utf8('%PDF-1.4\nSYNTHETIC_CURRENT_DOCUMENT'),
    subjects: mode === 'password' ? [] : [f.owner, 'synthetic-approved-access-reader'],
    expiresAt: Date.now() + 1200000, authMode: mode, ...(mode === 'password' ? { password: 'synthetic-dummy-password' } : {}) }, f.wrap);
  if (Object.keys(policyChanges).length) {
    const policy = { ...await readPolicy(currentRecord, currentId, f.wrap), ...policyChanges };
    currentRecord.policy = await sealJSON(policy, f.wrap, `policy:v2:${currentId}`);
  }
  const currentBytes = utf8(JSON.stringify(currentRecord));
  f.objects.set(`${currentId}.sealed.json`, currentBytes);
  f.env.DUMMY_RECORD_SHA256 = createHash('sha256').update(currentBytes).digest('hex');
  const policy = await readPolicy(currentRecord, currentId, f.wrap);
  f.metadata = { id: currentId, authMode: mode, expiresAt: policy.expiresAt, revoked: false };
  const candidate = preparedInput(f, { replaceOf: currentId });
  assert.equal((await f.request({ input: candidate })).status, 201);
  const path = `/v1/registrations/${candidate.id}/replacement`;
  const replacementInput = { expectedRevision: 2, currentDocumentId: currentId };
  return Object.assign(f, { candidate, currentRecord, currentBytes, path, replacementInput,
    prepare: options => f.request({ path, input: replacementInput, ...options }),
    review: options => f.request({ path, method: 'GET', ...options }) });
}

test('private replacement preserves the shared password and candidate PDF without changing live pins or notifying', async () => {
  const f = await replacementFixture(), pin = [f.env.DUMMY_DOCUMENT_ID, f.env.DUMMY_RECORD_SHA256];
  const candidateRecord = JSON.parse(Buffer.from(f.objects.get(`staging/${f.candidate.id}.sealed.json`)).toString());
  const response = await f.prepare(); assert.equal(response.status, 201);
  const result = await response.json(), m = result.replacement;
  assert.deepEqual(Object.keys(m).sort(), ['version', 'status', 'id', 'currentDocumentId', 'currentRecordSha256', 'recordSha256',
    'preparedSha256', 'sourceSha256', 'recipient', 'recipientName', 'watermarkEnabled', 'expiresAt', 'authMode', 'registryRevision', 'createdAt'].sort());
  assert.equal(m.status, 'prepared_not_active'); assert.equal(m.id, f.candidate.id);
  assert.equal(m.currentDocumentId, pin[0]); assert.equal(m.currentRecordSha256, pin[1]);
  assert.equal(m.preparedSha256, f.candidate.preparedSha256); assert.equal(m.sourceSha256, f.candidate.sourceSha256);
  assert.equal(m.authMode, 'password'); assert.equal(m.expiresAt, f.candidate.expiresAt);
  assert.equal(m.recipientName, '株式会社ダミー 採用担当'); assert.equal(m.watermarkEnabled, true); assert.equal(m.registryRevision, 2);
  const canonical = f.objects.get(`${m.id}.sealed.json`), finalRecord = JSON.parse(Buffer.from(canonical).toString());
  assert.equal(createHash('sha256').update(canonical).digest('hex'), m.recordSha256);
  assert.deepEqual(finalRecord.document, candidateRecord.document); assert.deepEqual(finalRecord.wrappedKey, candidateRecord.wrappedKey);
  const currentPolicy = await readPolicy(f.currentRecord, pin[0], f.wrap), finalPolicy = await readPolicy(finalRecord, m.id, f.wrap);
  assert.deepEqual(finalPolicy.subjects, []); assert.deepEqual(finalPolicy.passwordVerifier, currentPolicy.passwordVerifier);
  assert.equal(finalPolicy.recipientName, m.recipientName); assert.equal(finalPolicy.expiresAt, m.expiresAt);
  assert.deepEqual(await decryptDocument(finalRecord, f.wrap, finalPolicy), f.pdf);
  assert.deepEqual(f.objects.get(`${pin[0]}.sealed.json`), f.currentBytes); assert.deepEqual([f.env.DUMMY_DOCUMENT_ID, f.env.DUMMY_RECORD_SHA256], pin);
  const receiptBox = await f.storage.get(`encrypted-replacement:${m.id}`);
  const receipt = await openJSON(receiptBox, f.audit, `${f.context}:replacement:v1:${m.id}`);
  assert.ok(utf8(JSON.stringify(receipt)).byteLength <= 64 * 1024); assert.equal(Object.hasOwn(receipt, 'record'), false);
  for (const persisted of [JSON.stringify([...f.storage.map]), Buffer.from(canonical).toString(), JSON.stringify(result)]) {
    for (const secret of [f.owner, f.env.VAULT_WRAP_KEY, f.env.VAULT_AUDIT_KEY, 'synthetic-dummy-password', 'SYNTHETIC_PRIVATE_REGISTRATION_CONTENT',
      currentPolicy.passwordVerifier.hash]) assert.ok(!persisted.includes(secret));
  }
  for (const secret of ['株式会社ダミー', '採用担当', 'passwordVerifier', 'authMode']) assert.ok(!JSON.stringify([...f.storage.map]).includes(secret));
  const writes = [f.writes, f.storage.writes];
  f.restart(); const reviewed = await f.review(); assert.equal(reviewed.status, 200); assert.deepEqual(await reviewed.json(), result);
  assert.deepEqual([f.writes, f.storage.writes], writes);
  const repeated = await f.prepare(); assert.equal(repeated.status, 200); assert.deepEqual(await repeated.json(), result);
  assert.deepEqual([f.writes, f.storage.writes], writes); assert.equal(f.notifications, 0);
});

test('replacement keeps the exact existing Access reader subjects and does not add the owner to a password grant', async () => {
  const f = await replacementFixture('access'); assert.equal((await f.prepare()).status, 201);
  const record = JSON.parse(Buffer.from(f.objects.get(`${f.candidate.id}.sealed.json`)).toString()), policy = await readPolicy(record, f.candidate.id, f.wrap);
  assert.equal(policy.authMode, 'access'); assert.deepEqual(policy.subjects, [f.owner, 'synthetic-approved-access-reader']);
  assert.equal(Object.hasOwn(policy, 'passwordVerifier'), false); assert.equal(f.notifications, 0);
});

test('unprepared owner review does not reserve, write or publish a candidate', async () => {
  const f = await replacementFixture(), before = [f.writes, f.storage.writes];
  assert.deepEqual(await (await f.review()).json(), { replacement: null });
  assert.deepEqual([f.writes, f.storage.writes], before); assert.equal(f.objects.has(`${f.candidate.id}.sealed.json`), false);
  assert.equal(f.storage.map.has(`encrypted-replacement:${f.candidate.id}`), false); assert.equal(f.notifications, 0);
});

for (const method of ['GET', 'POST']) for (const subject of [null, 'synthetic-other-reader'])
test(`replacement ${method} rejects ${subject ? 'another Access reader' : 'anonymous'} before body, keys and storage`, async () => {
  const f = await replacementFixture(); let keys = 0, storageReads = 0;
  const previous = [f.reads, f.writes, f.storage.writes, f.metadataReads];
  for (const name of ['VAULT_WRAP_KEY', 'VAULT_AUDIT_KEY']) { const value = f.env[name]; Object.defineProperty(f.env, name, { get() { keys++; return value; } }); }
  const get = f.storage.get.bind(f.storage); f.storage.get = async key => { storageReads++; return get(key); };
  const request = await f.makeRequest({ path: f.path, method, subject, input: f.replacementInput });
  const guarded = new Proxy(request, { get(target, key) { if (key === 'body') throw new Error('unauthorized_body_read'); return Reflect.get(target, key, target); } });
  assert.equal((await f.instance.fetch(guarded)).status, subject ? 403 : 401);
  assert.equal(keys, 0); assert.equal(storageReads, 0); assert.deepEqual([f.reads, f.writes, f.storage.writes, f.metadataReads], previous);
});

for (const [label, options, status] of [
  ['wrong origin', { headers: { origin: 'https://other.example.test' } }, 403],
  ['cross-site', { headers: { 'sec-fetch-site': 'cross-site' } }, 403],
  ['wrong type', { headers: { 'content-type': 'text/plain' } }, 403],
  ['query', { path: '/v1/registrations/11111111-1111-4111-8111-111111111111/replacement?key=other' }, 403],
  ['oversized body', { raw: 'x'.repeat(2049) }, 400],
  ['extra field', { input: { expectedRevision: 2, currentDocumentId: '11111111-1111-4111-8111-111111111111', authMode: 'password' } }, 400],
  ['negative revision', { input: { expectedRevision: -1, currentDocumentId: '11111111-1111-4111-8111-111111111111' } }, 400],
  ['missing current ID', { input: { expectedRevision: 2 } }, 400],
  ['non-UUID current ID', { input: { expectedRevision: 2, currentDocumentId: 'other' } }, 400],
  ['wrong current ID', { input: { expectedRevision: 2, currentDocumentId: '11111111-1111-4111-8111-111111111111' } }, 409],
]) test(`replacement rejects ${label} before encryption, R2 and metadata reads`, async () => {
  const f = await replacementFixture(), before = [f.reads, f.writes, f.storage.writes, f.metadataReads]; let keys = 0;
  for (const name of ['VAULT_WRAP_KEY', 'VAULT_AUDIT_KEY']) { const value = f.env[name]; Object.defineProperty(f.env, name, { get() { keys++; return value; } }); }
  assert.equal((await f.prepare(options)).status, status); assert.equal(keys, 0);
  assert.deepEqual([f.reads, f.writes, f.storage.writes, f.metadataReads], before);
});

test('a stale replacement revision fails before reading either encrypted PDF', async () => {
  const f = await replacementFixture(), before = [f.reads, f.writes, f.storage.writes];
  const response = await f.prepare({ input: { ...f.replacementInput, expectedRevision: 0 } }); assert.equal(response.status, 409);
  assert.deepEqual(await response.json(), { error: 'registration_changed' }); assert.deepEqual([f.reads, f.writes, f.storage.writes], before);
});

for (const change of [entry => { for (const field of ['recipient', 'watermarkEnabled', 'sourceSha256', 'preparedSha256', 'preparationVersion']) delete entry[field]; },
  entry => { entry.replaceOf = null; }, entry => { entry.expiresAt = 1; }])
test('ineligible or expired candidates cannot create a replacement receipt or object', async () => {
  const f = await replacementFixture(), state = await f.state(); change(state.documents[0]); await f.writeState(state);
  const before = [f.writes, f.storage.writes]; const response = await f.prepare(); assert.ok([403, 409].includes(response.status));
  assert.deepEqual([f.writes, f.storage.writes], before); assert.equal(f.storage.map.has(`encrypted-replacement:${f.candidate.id}`), false);
});

for (const object of ['current', 'candidate']) test(`a changed ${object} encrypted record cannot be prepared`, async () => {
  const f = await replacementFixture(), key = object === 'current' ? `${f.env.DUMMY_DOCUMENT_ID}.sealed.json` : `staging/${f.candidate.id}.sealed.json`;
  const body = f.objects.get(key); body[body.length - 1] ^= 1;
  const before = [f.writes, f.storage.writes]; const response = await f.prepare(); assert.equal(response.status, 409);
  assert.deepEqual(await response.json(), { error: 'replacement_changed' }); assert.deepEqual([f.writes, f.storage.writes], before);
});

test('the actual candidate plaintext must match its prepared PDF hash', async () => {
  const f = await replacementFixture(), state = await f.state(); state.documents[0].preparedSha256 = 'c'.repeat(64); await f.writeState(state);
  const before = [f.writes, f.storage.writes]; assert.equal((await f.prepare()).status, 409);
  assert.deepEqual([f.writes, f.storage.writes], before); assert.equal(f.notifications, 0);
});

for (const changes of [{ subjects: ['synthetic-other-reader'] }, { revoked: true }, { recipientName: '別の開示先' }, { expiresAt: Date.now() + 3600000 }])
test('candidate policy must match the registered owner-only prepared candidate', async () => {
  const f = await replacementFixture(), key = `staging/${f.candidate.id}.sealed.json`, record = JSON.parse(Buffer.from(f.objects.get(key)).toString());
  const policy = { ...await readPolicy(record, f.candidate.id, f.wrap), ...changes };
  record.policy = await sealJSON(policy, f.wrap, `policy:v2:${f.candidate.id}`);
  const bytes = utf8(JSON.stringify(record)); f.objects.set(key, bytes);
  const state = await f.state(); state.documents[0].recordSha256 = createHash('sha256').update(bytes).digest('hex'); await f.writeState(state);
  const before = [f.writes, f.storage.writes]; assert.equal((await f.prepare()).status, 403); assert.deepEqual([f.writes, f.storage.writes], before);
});

for (const changes of [{ revoked: true }, { expiresAt: 1 }]) test('revoked or expired sealed reader grants cannot be copied', async () => {
  const f = await replacementFixture('password', changes), before = [f.writes, f.storage.writes];
  assert.equal((await f.prepare()).status, 403); assert.deepEqual([f.writes, f.storage.writes], before);
});

for (const changes of [{ revoked: true }, { expiresAt: 1 }, { id: crypto.randomUUID() }, { authMode: 'access' }])
test('effective owner metadata must still allow the current reader grant', async () => {
  const f = await replacementFixture(); f.metadata = { ...f.metadata, ...changes }; const before = [f.writes, f.storage.writes];
  assert.equal((await f.prepare()).status, 403); assert.deepEqual([f.writes, f.storage.writes], before);
});

test('canonical collision cannot overwrite another record or produce a successful review manifest', async () => {
  const f = await replacementFixture(), key = `${f.candidate.id}.sealed.json`, original = utf8('SYNTHETIC_COLLIDING_ENCRYPTED_OBJECT');
  f.objects.set(key, original); const before = f.writes;
  assert.equal((await f.prepare()).status, 409); assert.deepEqual(f.objects.get(key), original); assert.equal(f.writes, before);
  assert.equal((await f.review()).status, 409); assert.equal(f.notifications, 0);
});

test('uncertain canonical writes retain one encrypted receipt and recover with the same immutable bytes', async () => {
  const f = await replacementFixture(); f.putFailure = true; assert.equal((await f.prepare()).status, 503);
  const box = await f.storage.get(`encrypted-replacement:${f.candidate.id}`), receipt = await openJSON(box, f.audit, `${f.context}:replacement:v1:${f.candidate.id}`);
  assert.ok(receipt.recordSha256); assert.deepEqual(await (await f.review()).json(), { replacement: null });
  const durableWrites = f.storage.writes; f.restart(); f.putFailure = false;
  const response = await f.prepare(); assert.equal(response.status, 200); assert.equal((await response.json()).replacement.recordSha256, receipt.recordSha256);
  assert.equal(f.storage.writes, durableWrites); assert.equal(f.notifications, 0);
});

test('failed durable receipt reservation performs no canonical R2 write', async () => {
  const f = await replacementFixture(); f.storage.failWrite = true; const before = f.writes;
  assert.equal((await f.prepare()).status, 503); assert.equal(f.writes, before); assert.equal(f.objects.has(`${f.candidate.id}.sealed.json`), false);
});

test('the registration CAS is checked after encrypted source reads and before preparing a canonical object', async () => {
  const f = await replacementFixture(); let changed = false;
  f.afterRead = async () => { if (changed) return; changed = true; const state = await f.state();
    const extra = f.input(); state.documents.push({ id: extra.id, createdAt: Date.now(), expiresAt: extra.expiresAt,
      size: f.pdf.length, replaceOf: null, status: 'private', fileName: extra.fileName, recordSha256: 'b'.repeat(64) }); state.revision += 2; await f.writeState(state); };
  const before = [f.writes, f.storage.writes]; assert.equal((await f.prepare()).status, 409); assert.deepEqual([f.writes, f.storage.writes], before);
  assert.equal(f.objects.has(`${f.candidate.id}.sealed.json`), false);
});

test('pin drift during preparation cannot reserve or write a new record', async () => {
  const f = await replacementFixture(); let changed = false;
  f.afterRead = async () => { if (changed) return; changed = true; f.env.DUMMY_RECORD_SHA256 = 'd'.repeat(64); };
  const before = [f.writes, f.storage.writes]; assert.equal((await f.prepare()).status, 409); assert.deepEqual([f.writes, f.storage.writes], before);
});

test('registry historical rows survive actual pin rotation without allowing arbitrary replacement targets', async () => {
  const f = await replacementFixture(), response = await f.prepare(); assert.equal(response.status, 201);
  const manifest = (await response.json()).replacement;
  f.env.DUMMY_DOCUMENT_ID = manifest.id; f.env.DUMMY_RECORD_SHA256 = manifest.recordSha256; f.restart();
  const list = await f.list(); assert.equal(list.documents[0].id, manifest.id); assert.equal(list.documents[0].replaceOf, manifest.currentDocumentId);
  assert.equal((await f.prepare()).status, 409);
  const input = f.input({ expectedRevision: 2, replaceOf: manifest.currentDocumentId }); assert.equal((await f.request({ input })).status, 400);
  const valid = f.input({ expectedRevision: 2, replaceOf: manifest.id }); assert.equal((await f.request({ input: valid })).status, 201);
  assert.equal((await f.list()).documents.length, 2); assert.equal(f.notifications, 0);
});

test('an uncertain receipt can resume after another registration advances the registry', async () => {
  const f = await replacementFixture(); f.putFailure = true; assert.equal((await f.prepare()).status, 503);
  const receipt = await openJSON(await f.storage.get(`encrypted-replacement:${f.candidate.id}`), f.audit, `${f.context}:replacement:v1:${f.candidate.id}`);
  f.putFailure = false; assert.equal((await f.request({ input: f.input({ expectedRevision: 2 }) })).status, 201);
  const before = f.storage.writes;
  const resumed = await f.prepare({ input: { ...f.replacementInput, expectedRevision: 4 } }); assert.equal(resumed.status, 200);
  assert.equal((await resumed.json()).replacement.recordSha256, receipt.recordSha256); assert.equal(f.storage.writes, before);
  const writes = f.writes; const repeated = await f.prepare({ input: { ...f.replacementInput, expectedRevision: 4 } });
  assert.equal(repeated.status, 200); assert.equal(f.writes, writes); assert.equal(f.notifications, 0);
});

test('one MiB replacement keeps its receipt small and the canonical PDF encrypted', async () => {
  const f = await replacementFixture(), bytes = new Uint8Array(MAX_PDF_BYTES).fill(65); bytes.set(utf8('%PDF-'));
  const record = await sealDocument({ id: f.candidate.id, bytes, subjects: [f.owner], expiresAt: f.candidate.expiresAt,
    authMode: 'access', recipientName: '株式会社ダミー 採用担当' }, f.wrap), encrypted = utf8(JSON.stringify(record));
  f.objects.set(`staging/${f.candidate.id}.sealed.json`, encrypted);
  const state = await f.state(); state.documents[0].size = bytes.byteLength;
  state.documents[0].recordSha256 = createHash('sha256').update(encrypted).digest('hex');
  state.documents[0].preparedSha256 = createHash('sha256').update(bytes).digest('hex'); await f.writeState(state);
  const response = await f.prepare(); assert.equal(response.status, 201);
  const box = await f.storage.get(`encrypted-replacement:${f.candidate.id}`); assert.ok(utf8(JSON.stringify(box)).byteLength < 4096);
  const manifest = (await response.json()).replacement;
  const final = JSON.parse(Buffer.from(f.objects.get(`${f.candidate.id}.sealed.json`)).toString()), policy = await readPolicy(final, f.candidate.id, f.wrap);
  assert.deepEqual(await decryptDocument(final, f.wrap, policy), bytes); assert.equal(manifest.preparedSha256, state.documents[0].preparedSha256);
  assert.equal(f.notifications, 0);
});

for (const resource of ['R2 response', 'R2 body', 'metadata response', 'metadata body'])
test(`replacement ${resource} has a five-second deadline and does not prepare after timeout`, async t => {
  const f = await replacementFixture(), originalTimer = globalThis.setTimeout, armed = [];
  t.mock.method(globalThis, 'setTimeout', (callback, delay, ...args) => { armed.push(delay); return originalTimer(callback, delay === 5000 ? 10 : delay, ...args); });
  let cancelled = false;
  const stalledBody = () => new ReadableStream({ pull: () => new Promise(() => {}), cancel() { cancelled = true; return new Promise(() => {}); } });
  if (resource === 'R2 response') f.env.VAULT_DOCUMENTS.get = () => new Promise(() => {});
  if (resource === 'R2 body') f.env.VAULT_DOCUMENTS.get = async () => ({ size: 100, body: stalledBody() });
  if (resource === 'metadata response') f.env.VAULT.get = () => ({ fetch: () => new Promise(() => {}) });
  if (resource === 'metadata body') f.env.VAULT.get = () => ({ fetch: async () => new Response(stalledBody()) });
  const before = [f.writes, f.storage.writes];
  try {
    const response = await f.prepare(); assert.equal(response.status, 408); assert.deepEqual(await response.json(), { error: 'request_timeout' });
    assert.ok(armed.includes(5000)); assert.deepEqual([f.writes, f.storage.writes], before);
    if (resource.endsWith('body')) assert.equal(cancelled, true);
  } finally { t.mock.restoreAll(); }
});

test('oversized owner metadata fails before a durable receipt or canonical write', async () => {
  const f = await replacementFixture(); f.env.VAULT.get = () => ({ fetch: async () => Response.json({ ...f.metadata, extra: 'x'.repeat(4096) }) });
  const before = [f.writes, f.storage.writes]; assert.equal((await f.prepare()).status, 400); assert.deepEqual([f.writes, f.storage.writes], before);
});

test('a malformed encrypted receipt fails closed and cannot be regenerated or overwritten', async () => {
  const f = await replacementFixture(); assert.equal((await f.prepare()).status, 201);
  const key = `encrypted-replacement:${f.candidate.id}`, context = `${f.context}:replacement:v1:${f.candidate.id}`;
  const receipt = await openJSON(await f.storage.get(key), f.audit, context); receipt.password = 'synthetic-forbidden-secret';
  f.storage.map.set(key, await sealJSON(receipt, f.audit, context)); const before = [f.writes, f.storage.writes];
  for (const method of ['GET', 'POST']) { const response = await f.prepare({ method }); assert.equal(response.status, 503); assert.deepEqual(await response.json(), { error: 'unavailable' }); }
  assert.deepEqual([f.writes, f.storage.writes], before); assert.equal(f.notifications, 0);
});
