import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPair, exportJWK, SignJWT } from 'jose';
import { handleCanary, CANARY_ORIGIN } from '../src/canary-management.js';
import { failure } from '../src/http.js';

const originalFetch = globalThis.fetch;
after(() => { globalThis.fetch = originalFetch; });
const pair = await generateKeyPair('RS256', { extractable: true });
const jwk = { ...await exportJWK(pair.publicKey), kid: 'canary-management-test', use: 'sig', alg: 'RS256' };
const id = 'f025a92a-082d-4eaf-9b78-9ed396b9bb85', token = 'kr_' + 'a'.repeat(64);
let fixtureNumber = 0;
function fixture({ configured = true } = {}) {
  const env = { PUBLIC_ORIGIN: 'https://vault.example.test', ACCESS_ISSUER: `https://canary-management-${++fixtureNumber}.cloudflareaccess.com`,
    ACCESS_AUDIENCE: 'canary-owner-fixture', VAULT_OWNER_SUB: 'owner', DUMMY_DOCUMENT_ID: id, DUMMY_RECORD_SHA256: 'b'.repeat(64) };
  const calls = [], deadlineReads = [], expiresAt = Date.now() + 600000;
  let bindingReads = 0, sideEffects = 0;
  const current = { token, state: 'active', expiresAt, hitCount: 0, lastSeenAt: null };
  const binding = Object.fromEntries(['status', 'create', 'revoke', 'events'].map(method => [method, async (...args) => {
    calls.push({ method, args });
    return { status: method === 'create' ? 201 : 200, value: method === 'events' ? { documentId: id, events: [] } : { documentId: id,
      canary: method === 'revoke' ? { ...current, state: 'revoked' } : method === 'create' ? { ...current, expiresAt: args[1] } : current } };
  }]));
  Object.defineProperty(env, 'CANARY_ADMIN', { configurable: true, get() { bindingReads++; return configured ? binding : undefined; } });
  for (const name of ['VAULT_WRAP_KEY', 'VAULT_AUDIT_KEY', 'VAULT_DOCUMENTS', 'VAULT']) {
    Object.defineProperty(env, name, { get() { sideEffects++; throw new Error('must_not_access_storage_or_keys'); } });
  }
  globalThis.fetch = async url => {
    assert.equal(String(url), `${env.ACCESS_ISSUER}/cdn-cgi/access/certs`);
    return Response.json({ keys: [jwk] });
  };
  async function signed(subject) {
    return new SignJWT({ sub: subject }).setIssuer(env.ACCESS_ISSUER).setAudience(env.ACCESS_AUDIENCE)
      .setIssuedAt().setExpirationTime('5m').setProtectedHeader({ alg: 'RS256', kid: jwk.kid }).sign(pair.privateKey);
  }
  async function request(options = {}) {
    const method = options.method ?? 'GET', subject = Object.hasOwn(options, 'subject') ? options.subject : 'owner';
    const request = new Request(`${options.origin ?? env.PUBLIC_ORIGIN}/v1/documents/${options.id ?? id}/${options.logs ? 'canary-logs' : 'canary'}${options.query ?? ''}`, {
      method, headers: { origin: env.PUBLIC_ORIGIN, 'content-type': 'application/json',
        ...(subject ? { 'cf-access-jwt-assertion': await signed(subject) } : {}), ...options.headers },
      ...(['GET', 'HEAD'].includes(method) ? {} : { body: options.body ?? JSON.stringify({ action: options.action ?? 'create' }) }),
    });
    let bodyReaders = 0;
    if (options.forbidBody) Object.defineProperty(request, 'body', { value: { getReader() { bodyReaders++; throw new Error('body_before_authorization'); } } });
    let response;
    try { response = await handleCanary(request, env, { id: options.id ?? id, getExpiresAt: async () => { deadlineReads.push(true); return options.expiresAt ?? expiresAt; } }); }
    catch (error) { response = failure(error); }
    return { response, bodyReaders };
  }
  return { env, binding, calls, deadlineReads, expiresAt, current, request,
    get bindingReads() { return bindingReads; }, get sideEffects() { return sideEffects; } };
}

test('missing optional binding leaves owner Canary inactive with no storage or notifications', async () => {
  const f = fixture({ configured: false });
  const status = await f.request(); assert.equal(status.response.status, 200);
  assert.deepEqual(await status.response.json(), { configured: false, documentId: id, canary: null });
  const logs = await f.request({ logs: true }); assert.deepEqual(await logs.response.json(), { configured: false, documentId: id, events: [] });
  const mutation = await f.request({ method: 'POST', forbidBody: true });
  assert.equal(mutation.response.status, 503); assert.equal(mutation.bodyReaders, 0);
  assert.deepEqual(f.calls, []); assert.deepEqual(f.deadlineReads, []); assert.equal(f.sideEffects, 0);
});

test('unsigned, forged and reader identities cannot touch the binding or read request bodies', async () => {
  const f = fixture();
  for (const [options, status] of [[{ subject: null }, 401], [{ subject: 'reader' }, 403],
    [{ subject: null, headers: { 'cf-access-authenticated-user-email': 'owner@example.test' } }, 401],
    [{ subject: null, headers: { 'cf-access-jwt-assertion': 'forged', cookie: 'password-cookie=synthetic' } }, 401]]) {
    for (const method of ['GET', 'POST']) {
      const result = await f.request({ ...options, method, forbidBody: method === 'POST' });
      assert.equal(result.response.status, status); assert.equal(result.bodyReaders, 0);
    }
  }
  assert.equal(f.bindingReads, 0); assert.equal(f.sideEffects, 0); assert.deepEqual(f.calls, []);
});

test('creation reads the effective document deadline only after owner action validation', async () => {
  const f = fixture();
  const status = await f.request(); assert.equal(status.response.status, 200); assert.deepEqual(f.deadlineReads, []);
  const response = (await f.request({ method: 'POST' })).response; assert.equal(response.status, 201);
  assert.deepEqual(f.calls.at(-1), { method: 'create', args: [id, f.expiresAt] }); assert.equal(f.deadlineReads.length, 1);
  const value = await response.json(); assert.equal(value.canary.url, `${CANARY_ORIGIN}/canary/${token}`);
  const revoked = (await f.request({ method: 'POST', action: 'revoke' })).response; assert.equal(revoked.status, 200);
  assert.equal((await revoked.json()).canary.state, 'revoked'); assert.equal(f.deadlineReads.length, 1);
  assert.equal(f.sideEffects, 0); assert.match(response.headers.get('cache-control'), /no-store/);
  assert.equal(response.headers.get('access-control-allow-origin'), null);
});

test('closed or expired document deadlines cannot create a Canary', async () => {
  const f = fixture();
  for (const expiresAt of [Date.now() - 1, 8640000000000001]) {
    assert.equal((await f.request({ method: 'POST', expiresAt })).response.status, 403);
  }
  assert.deepEqual(f.calls, []);
});

test('wrong origin, scope, query and CSRF reject before body or binding access', async () => {
  const f = fixture();
  for (const options of [{ id: crypto.randomUUID() }, { origin: 'https://elsewhere.example' }, { query: '?other=1' },
    { headers: { origin: 'https://elsewhere.example' } }, { headers: { origin: '' } },
    { headers: { 'content-type': 'text/plain' } }, { headers: { 'sec-fetch-site': 'cross-site' } }]) {
    const result = await f.request({ method: 'POST', forbidBody: true, ...options });
    assert.equal(result.response.status, 403); assert.equal(result.bodyReaders, 0);
  }
  assert.equal(f.bindingReads, 0); assert.deepEqual(f.calls, []); assert.deepEqual(f.deadlineReads, []);
});

test('Canary mutations reject extra data, arbitrary actions and oversized input', async () => {
  const f = fixture();
  for (const body of ['{}', '[]', '{', '{"action":"test"}', '{"action":"create","expiresAt":1800000000000}', 'x'.repeat(129)]) {
    assert.equal((await f.request({ method: 'POST', body })).response.status, 400);
  }
  assert.deepEqual(f.calls, []); assert.deepEqual(f.deadlineReads, []);
  assert.equal((await f.request({ logs: true, method: 'POST' })).response.status, 405);
});

test('document-scoped logs accept bounded fixed evidence only', async () => {
  const f = fixture();
  f.binding.events = async documentId => ({ status: 200, value: { documentId, events: [{ id: 'c'.repeat(32), at: Date.now(),
    outcome: 'url_requested', notifications: [{ type: 'email', state: 'accepted' }] }] } });
  const response = (await f.request({ logs: true })).response; assert.equal(response.status, 200);
  const value = await response.json(); assert.equal(value.events.length, 1); assert.equal(value.events[0].outcome, 'url_requested');
  assert.equal(value.events[0].source, null);
  f.binding.events = async documentId => ({ status: 200, value: { documentId, events: Array(51).fill(value.events[0]) } });
  assert.equal((await f.request({ logs: true })).response.status, 503);
  f.binding.events = async documentId => ({ status: 200, value: { documentId, events: [{ ...value.events[0], readerEmail: 'private@example.test' }] } });
  assert.equal((await f.request({ logs: true })).response.status, 503);
});

test('owner logs accept bounded source evidence and normalize legacy records without source', async () => {
  const f = fixture(), base = { id: 'c'.repeat(32), at: Date.now(), outcome: 'url_requested', notifications: [] };
  for (const source of [null,
    { ip: '198.51.100.9', country: 'JP', asn: 64500, network: 'Example network', refererHost: 'careers.example.test' },
    { ip: '2001:db8::9', country: '', asn: null, network: '', refererHost: '' },
    { ip: '::ffff:192.0.2.9', country: 'US', asn: 4294967295, network: 'Example network', refererHost: '[2001:db8::9]' },
  ]) {
    f.binding.events = async documentId => ({ status: 200, value: { documentId, events: [{ ...base, source }] } });
    const response = (await f.request({ logs: true })).response; assert.equal(response.status, 200);
    assert.deepEqual((await response.json()).events[0].source, source);
  }
  f.binding.events = async documentId => ({ status: 200, value: { documentId, events: [base] } });
  assert.equal((await (await f.request({ logs: true })).response.json()).events[0].source, null);
  assert.deepEqual(f.deadlineReads, []); assert.equal(f.sideEffects, 0);
});

test('malformed or expanded source evidence fails closed rather than exposing extra private data', async () => {
  const f = fixture(), base = { id: 'c'.repeat(32), at: Date.now(), outcome: 'url_requested', notifications: [] };
  const source = { ip: '198.51.100.9', country: 'JP', asn: 64500, network: 'Example network', refererHost: 'careers.example.test' };
  const invalid = [undefined, {}, [], { ...source, email: 'private@example.test' }, { ...source, ip: '' },
    { ...source, ip: '198.51.100.999' }, { ...source, ip: '0198.51.100.9' }, { ...source, ip: '2001:db8::9%en0' },
    { ...source, ip: 'a'.repeat(46) }, { ...source, country: 'Japan' }, { ...source, country: 'jp' },
    { ...source, asn: 0 }, { ...source, asn: -1 }, { ...source, asn: 4294967296 }, { ...source, asn: '64500' },
    { ...source, network: 'x'.repeat(161) }, { ...source, network: 'name\nPRIVATE' }, { ...source, network: 'name\u0085PRIVATE' },
    { ...source, refererHost: 'https://careers.example.test/private' }, { ...source, refererHost: 'careers.example.test/private' },
    { ...source, refererHost: 'careers.example.test:443' }, { ...source, refererHost: 'user:secret@careers.example.test' },
    { ...source, refererHost: 'careers.example.test?email=private@example.test' }, { ...source, refererHost: 'x'.repeat(254) },
    { ...source, refererHost: 'Careers.example.test' }, { ...source, refererHost: 'careers.example.test\nPRIVATE' },
  ];
  for (const value of invalid) {
    f.binding.events = async documentId => ({ status: 200, value: { documentId, events: [{ ...base, source: value }] } });
    const response = (await f.request({ logs: true })).response;
    assert.equal(response.status, 503); assert.deepEqual(await response.json(), { error: 'unavailable' });
  }
});

test('source-bearing logs remain owner-only and pinned to the dummy document', async () => {
  const f = fixture();
  for (const [options, status] of [[{ subject: 'reader' }, 403], [{ subject: null }, 401], [{ id: crypto.randomUUID() }, 403]]) {
    const response = (await f.request({ logs: true, ...options })).response;
    assert.equal(response.status, status); assert.doesNotMatch(await response.text(), /source|198\.51\.100/);
  }
  assert.equal(f.bindingReads, 0); assert.deepEqual(f.calls, []); assert.equal(f.sideEffects, 0);
});

test('unexpected upstream routes, identities and response data fail closed', async () => {
  const f = fixture();
  for (const value of [{ documentId: crypto.randomUUID(), canary: null }, { documentId: id, canary: { ...f.current, token: '../other' } },
    { documentId: id, canary: { ...f.current, email: 'private@example.test' } }]) {
    f.binding.status = async () => ({ status: 200, value });
    assert.equal((await f.request()).response.status, 503);
  }
  f.binding.create = async () => ({ status: 409, value: { error: 'canary_exists' } });
  const conflict = (await f.request({ method: 'POST' })).response; assert.equal(conflict.status, 409);
  assert.deepEqual(await conflict.json(), { error: 'canary_exists' });
});
