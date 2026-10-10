import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPair, exportJWK, SignJWT } from 'jose';
import worker, { VaultDocument } from '../src/worker.js';
import { newKey, importKey, openJSON, sealJSON } from '../src/crypto.js';
import { MAX_RECIPIENT_REQUEST_BYTES } from '../src/contacts.js';

const originalFetch = globalThis.fetch;
after(() => { globalThis.fetch = originalFetch; });
const pair = await generateKeyPair('RS256', { extractable: true });
const jwk = { ...await exportJWK(pair.publicKey), kid: 'owner-contacts-test', use: 'sig', alg: 'RS256' };
let fixtureNumber = 0;

class Storage {
  constructor() { this.map = new Map(); this.reads = 0; this.writes = 0; this.failWrite = false; }
  async get(key) { this.reads++; return structuredClone(this.map.get(key)); }
  async transaction(operation) {
    const draft = new Map(structuredClone([...this.map]));
    const result = await operation({
      get: async key => { this.reads++; return structuredClone(draft.get(key)); },
      put: async (key, value) => { if (this.failWrite) throw new Error('synthetic_write_failure'); this.writes++; draft.set(key, structuredClone(value)); },
      delete: async key => draft.delete(key),
      list: async options => new Map([...draft].filter(([key]) => key.startsWith(options.prefix) && (!options.end || key < options.end))
        .sort(([a], [b]) => a.localeCompare(b)).slice(0, options.limit)),
      setAlarm: async () => {}, deleteAlarm: async () => {},
    });
    this.map = draft;
    return result;
  }
}

async function fixture() {
  const id = crypto.randomUUID(), digest = 'a'.repeat(64), owner = 'synthetic-contact-owner', reader = 'synthetic-contact-reader';
  const auditKey = newKey(), wrapKey = newKey(), audit = await importKey(auditKey);
  let keyReads = 0, bucketReads = 0, bucketWrites = 0, notifications = 0;
  const env = { PUBLIC_ORIGIN: 'https://vault.example.test', ACCESS_ISSUER: `https://owner-contacts-${++fixtureNumber}.cloudflareaccess.com`,
    ACCESS_AUDIENCE: 'synthetic-contacts', VAULT_OWNER_SUB: owner, DUMMY_DOCUMENT_ID: id, DUMMY_RECORD_SHA256: digest, PASSWORD_READER_ENABLED: '1' };
  for (const [name, value] of [['VAULT_WRAP_KEY', wrapKey], ['VAULT_AUDIT_KEY', auditKey]]) {
    Object.defineProperty(env, name, { get() { keyReads++; return value; } });
  }
  env.VAULT_DOCUMENTS = {
    async get() { bucketReads++; throw new Error('contacts_must_not_read_pdf'); },
    async put() { bucketWrites++; throw new Error('contacts_must_not_write_pdf'); },
  };
  globalThis.fetch = async url => {
    if (String(url) === `${env.ACCESS_ISSUER}/cdn-cgi/access/certs`) return Response.json({ keys: [jwk] });
    notifications++; throw new Error('contacts_must_not_notify');
  };
  const storage = new Storage(), ctx = { storage, id: { toString: () => `contacts-${id}` } }, context = `journal:v1:contacts-${id}`;
  let instance = new VaultDocument(ctx, env);
  env.VAULT = { idFromName: name => { assert.equal(name, id); return name; }, get: () => instance };
  async function token(subject) {
    return new SignJWT({ sub: subject }).setIssuer(env.ACCESS_ISSUER).setAudience(env.ACCESS_AUDIENCE)
      .setIssuedAt().setExpirationTime('10m').setProtectedHeader({ alg: 'RS256', kid: jwk.kid }).sign(pair.privateKey);
  }
  async function request(options = {}) {
    const method = options.method ?? 'GET', subject = Object.hasOwn(options, 'subject') ? options.subject : owner;
    const headers = { origin: env.PUBLIC_ORIGIN, 'content-type': 'application/json',
      ...(subject ? { 'cf-access-jwt-assertion': await token(subject) } : {}), ...options.headers };
    const req = new Request(`${options.origin ?? env.PUBLIC_ORIGIN}/v1/documents/${options.id ?? id}/${options.action ?? 'recipients'}${options.query ?? ''}`,
      { method, headers, ...(['GET', 'HEAD'].includes(method) ? {} : { body: options.body ?? JSON.stringify(options.input ?? {}) }) });
    let bodyReaders = 0;
    if (options.forbidBody) Object.defineProperty(req, 'body', { value: { getReader() { bodyReaders++; throw new Error('body_before_authorization'); } } });
    const response = await (options.direct ? instance.fetch(req) : worker.fetch(req, env));
    return { response, bodyReaders };
  }
  return { id, digest, owner, reader, env, storage, auditKey, wrapKey, context, request,
    async read() { const { response } = await request(); assert.equal(response.status, 200); return response.json(); },
    async save(input, options = {}) { return (await request({ method: 'POST', input, ...options })).response; },
    async state() { return openJSON(storage.map.get('encrypted-journal'), audit, context); },
    async writeState(value) { storage.map.set('encrypted-journal', await sealJSON(value, audit, context)); },
    restart() { instance = new VaultDocument(ctx, env); },
    get keyReads() { return keyReads; }, get bucketReads() { return bucketReads; }, get bucketWrites() { return bucketWrites; }, get notifications() { return notifications; },
  };
}

test('owner contacts start empty and never read a PDF or send notifications', async () => {
  const f = await fixture();
  const { response } = await f.request();
  assert.equal(response.status, 200); assert.deepEqual(await response.json(), { revision: 0, emails: [] });
  assert.match(response.headers.get('cache-control'), /no-store/);
  assert.equal(response.headers.get('access-control-allow-origin'), null);
  assert.equal(f.storage.writes, 0); assert.equal(f.bucketReads, 0); assert.equal(f.bucketWrites, 0); assert.equal(f.notifications, 0);
});

test('recipient GET and POST reject unsigned, forged and reader identities before body, keys or storage', async () => {
  const f = await fixture();
  for (const direct of [false, true]) for (const method of ['GET', 'POST']) {
    for (const [options, status] of [
      [{ subject: null }, 401], [{ subject: f.reader }, 403],
      [{ subject: null, headers: { 'cf-access-authenticated-user-email': 'owner@example.test', 'x-vault-owner-sub': f.owner } }, 401],
      [{ subject: null, headers: { 'cf-access-jwt-assertion': 'forged token', cookie: '__Secure-vault-fake=synthetic' } }, 401],
    ]) {
      const { response, bodyReaders } = await f.request({ ...options, direct, method, forbidBody: method === 'POST' });
      assert.equal(response.status, status); assert.equal(bodyReaders, 0);
    }
  }
  assert.equal(f.keyReads, 0); assert.equal(f.storage.reads, 0); assert.equal(f.storage.writes, 0);
  assert.equal(f.bucketReads, 0); assert.equal(f.bucketWrites, 0); assert.equal(f.notifications, 0);
});

test('contacts persist only inside the encrypted journal and remain metadata after restart', async () => {
  const f = await fixture(), emails = ['Reader@EXAMPLE.TEST', 'other@example.test'];
  const response = await f.save({ expectedRevision: 0, emails });
  assert.equal(response.status, 200); assert.deepEqual(await response.json(), { revision: 1, emails: ['Reader@example.test', 'other@example.test'] });
  const state = await f.state();
  assert.deepEqual(state.recipientContacts, { recordDigest: f.digest, revision: 1, emails: ['Reader@example.test', 'other@example.test'] });
  assert.deepEqual([state.events, state.requests, state.jobs, state.sessions], [[], [], [], []]);
  const persisted = JSON.stringify([...f.storage.map]);
  for (const value of ['Reader@example.test', 'other@example.test', f.digest, f.id, f.owner, f.auditKey, f.wrapKey]) assert.ok(!persisted.includes(value));
  assert.deepEqual([...f.storage.map.keys()], ['encrypted-journal']);
  f.restart(); assert.deepEqual(await f.read(), { revision: 1, emails: ['Reader@example.test', 'other@example.test'] });
  assert.equal(f.bucketReads, 0); assert.equal(f.bucketWrites, 0); assert.equal(f.notifications, 0);
});

test('only authenticated owner contact requests can exceed the ordinary 2048-byte limit', async () => {
  const f = await fixture();
  const emails = Array.from({ length: 50 }, (_, index) => `${String(index).padStart(2, '0')}${'a'.repeat(62)}@${'b'.repeat(63)}.${'c'.repeat(63)}.${'d'.repeat(61)}`);
  const input = { expectedRevision: 0, emails }, body = JSON.stringify(input);
  assert.ok(body.length > 12000 && body.length < MAX_RECIPIENT_REQUEST_BYTES);
  const response = await f.save(input); assert.equal(response.status, 200); assert.equal((await response.json()).emails.length, 50);
  const denied = await f.request({ method: 'POST', subject: f.reader, body, forbidBody: true });
  assert.equal(denied.response.status, 403); assert.equal(denied.bodyReaders, 0);
  for (const action of ['expiry', 'logs', 'open']) {
    const { response: ordinary } = await f.request({ method: 'POST', action, body });
    assert.equal(ordinary.status, 400, action); assert.deepEqual(await ordinary.json(), { error: 'invalid_request' });
  }
  assert.equal((await f.read()).revision, 1); assert.equal(f.bucketReads, 0);
});

test('contacts reject declared or actual oversized bodies without changing the journal', async () => {
  const f = await fixture();
  for (const options of [{ headers: { 'content-length': String(MAX_RECIPIENT_REQUEST_BYTES + 1) }, forbidBody: true },
    { body: 'x'.repeat(MAX_RECIPIENT_REQUEST_BYTES + 1) }]) {
    const { response, bodyReaders } = await f.request({ method: 'POST', ...options });
    assert.equal(response.status, 400); assert.equal(bodyReaders, 0);
  }
  assert.equal(f.storage.writes, 0); assert.equal(f.bucketReads, 0);
});

test('concurrent contact updates use compare-and-set and never overwrite a newer decision', async () => {
  const f = await fixture();
  const responses = await Promise.all([f.save({ expectedRevision: 0, emails: ['first@example.test'] }), f.save({ expectedRevision: 0, emails: ['second@example.test'] })]);
  assert.deepEqual(responses.map(response => response.status).sort(), [200, 409]);
  const current = await f.read(); assert.equal(current.revision, 1);
  const before = structuredClone([...f.storage.map]);
  assert.equal((await f.save({ expectedRevision: 0, emails: [] })).status, 409); assert.deepEqual([...f.storage.map], before);
  f.restart(); assert.deepEqual(await f.read(), current);
  assert.equal((await f.save({ expectedRevision: 1, emails: [] })).status, 200); assert.deepEqual(await f.read(), { revision: 2, emails: [] });
});

test('invalid contact input cannot create plaintext or a partial encrypted update', async () => {
  const f = await fixture();
  for (const input of [{ expectedRevision: 0, emails: ['reader@example.test', 'reader@EXAMPLE.TEST'] },
    { expectedRevision: 0, emails: ['reader@example.test\r\nBcc:bad@example.test'] },
    { expectedRevision: 0, emails: ['reader@example.test'], grants: true },
    { expectedRevision: '0', emails: [] }, { expectedRevision: 0, emails: Array(51).fill('a@example.test') }]) {
    const response = await f.save(input); assert.equal(response.status, 400);
    assert.deepEqual(await response.json(), { error: 'invalid_recipients' });
  }
  assert.equal(f.storage.writes, 0); assert.deepEqual(await f.read(), { revision: 0, emails: [] });
});

test('contact mutation rejects CSRF, invalid routes and methods before reading a body', async () => {
  const f = await fixture();
  for (const options of [{ headers: { origin: 'https://other.example.test' } }, { headers: { origin: '' } },
    { headers: { 'content-type': 'text/plain' } }, { id: crypto.randomUUID() }, { query: '?other=1' },
    { origin: 'https://other.example.test' }, { method: 'DELETE' }]) {
    for (const direct of [false, true]) {
      const { response, bodyReaders } = await f.request({ method: 'POST', forbidBody: true, ...options, direct });
      assert.equal(response.status, 403); assert.equal(bodyReaders, 0);
    }
  }
  assert.equal(f.keyReads, 0); assert.equal(f.storage.reads, 0); assert.equal(f.storage.writes, 0);
});

test('contacts remain bound to the exact ciphertext digest and fail closed on malformed stored state', async () => {
  const f = await fixture();
  assert.equal((await f.save({ expectedRevision: 0, emails: ['reader@example.test'] })).status, 200);
  const valid = await f.state(), before = structuredClone([...f.storage.map]);
  f.env.DUMMY_RECORD_SHA256 = 'b'.repeat(64);
  assert.equal((await f.request()).response.status, 503); assert.equal((await f.save({ expectedRevision: 1, emails: [] })).status, 503);
  assert.deepEqual([...f.storage.map], before);
  f.env.DUMMY_RECORD_SHA256 = f.digest;
  await f.writeState({ ...valid, recipientContacts: { ...valid.recipientContacts, emails: ['reader@EXAMPLE.TEST'] } });
  assert.equal((await f.request()).response.status, 503); assert.equal((await f.save({ expectedRevision: 1, emails: [] })).status, 503);
});

test('failed encrypted storage writes do not report a successful contact change', async () => {
  const f = await fixture(); f.storage.failWrite = true;
  const response = await f.save({ expectedRevision: 0, emails: ['reader@example.test'] });
  assert.equal(response.status, 503); assert.deepEqual(await response.json(), { error: 'unavailable' });
  assert.deepEqual(await f.read(), { revision: 0, emails: [] }); assert.equal(f.storage.map.size, 0);
});
