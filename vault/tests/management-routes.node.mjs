import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPair, exportJWK, SignJWT } from 'jose';
import worker from '../src/worker.js';
import * as admin from '../src/admin.js';
import { HEADERS } from '../src/http.js';

const originalFetch = globalThis.fetch;
after(() => { globalThis.fetch = originalFetch; });
const pair = await generateKeyPair('RS256', { extractable: true });
const jwk = { ...await exportJWK(pair.publicKey), kid: 'owner-page-fixture', use: 'sig', alg: 'RS256' };
const env = {
  PUBLIC_ORIGIN: 'https://vault.example.test', ACCESS_ISSUER: 'https://management-page-fixture.cloudflareaccess.com',
  ACCESS_AUDIENCE: 'owner-page-fixture', VAULT_OWNER_SUB: 'synthetic-owner',
  DUMMY_DOCUMENT_ID: crypto.randomUUID(), DUMMY_RECORD_SHA256: 'a'.repeat(64), PASSWORD_READER_ENABLED: '0',
};
for (const name of ['VAULT_DOCUMENTS', 'VAULT_WRAP_KEY', 'VAULT_AUDIT_KEY', 'VAULT']) {
  Object.defineProperty(env, name, { get() { throw new Error('page_must_not_access_document_or_keys'); } });
}
globalThis.fetch = async url => {
  assert.equal(String(url), `${env.ACCESS_ISSUER}/cdn-cgi/access/certs`);
  return Response.json({ keys: [jwk] });
};
async function token(subject) {
  return new SignJWT({ sub: subject, iss: env.ACCESS_ISSUER, aud: env.ACCESS_AUDIENCE,
    iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + 600 })
    .setProtectedHeader({ alg: 'RS256', kid: 'owner-page-fixture' }).sign(pair.privateKey);
}
async function request(path, subject, options = {}) {
  const headers = subject ? { 'cf-access-jwt-assertion': await token(subject) } : {};
  return worker.fetch(new Request(env.PUBLIC_ORIGIN + path, { method: options.method ?? 'GET',
    headers: { ...headers, ...options.headers } }), env);
}
const surfaces = ['/v1/admin', '/v1/admin/assets/admin.js', '/v1/admin/assets/admin.css', '/v1/admin/assets/management.js', '/v1/management'];

test('owner administration surfaces reject anonymous, password-cookie and non-owner identities', async () => {
  for (const path of [...surfaces, '/v1/registrations']) {
    assert.equal((await request(path)).status, 401, path);
    assert.equal((await request(path, null, { headers: { cookie: '__Host-fake=synthetic',
      'cf-access-authenticated-user-email': 'owner@example.test' } })).status, 401, path);
    assert.equal((await request(path, 'synthetic-reader')).status, 403, path);
  }
});

test('owner page and assets return exact UI with private headers and no document access', async () => {
  for (const [path, expected, type] of [
    ['/v1/admin', admin.html, 'text/html; charset=utf-8'],
    ['/v1/admin/assets/admin.js', admin.js, 'text/javascript; charset=utf-8'],
    ['/v1/admin/assets/admin.css', admin.css, 'text/css; charset=utf-8'],
    ['/v1/admin/assets/management.js', admin.managementJs, 'text/javascript; charset=utf-8'],
  ]) {
    const response = await request(path, env.VAULT_OWNER_SUB);
    assert.equal(response.status, 200); assert.equal(await response.text(), expected);
    assert.equal(response.headers.get('content-type'), type);
    for (const [name, value] of Object.entries(HEADERS)) assert.equal(response.headers.get(name), value);
  }
});

test('owner bootstrap exposes only the pinned document ID without reading records or keys', async () => {
  const response = await request('/v1/management', env.VAULT_OWNER_SUB);
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), { documentId: env.DUMMY_DOCUMENT_ID });
});

test('owner page routes reject mutation methods, query strings and lookalike paths', async () => {
  for (const path of surfaces) {
    assert.equal((await request(path, env.VAULT_OWNER_SUB, { method: 'POST' })).status, 405);
    assert.equal((await request(path + '?document=other', env.VAULT_OWNER_SUB)).status, 403);
  }
  for (const path of ['/v1/admin/', '/v1/admin/assets/missing.js', '/v1/management/']) {
    assert.equal((await request(path, env.VAULT_OWNER_SUB)).status, 404);
  }
});
