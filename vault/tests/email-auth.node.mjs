import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPair, exportJWK, SignJWT } from 'jose';
import { identity, emailIdentity, emailReaderConfiguration } from '../src/auth.js';

const originalFetch = globalThis.fetch;
after(() => { globalThis.fetch = originalFetch; });
const pair = await generateKeyPair('RS256', { extractable: true });
const jwk = { ...await exportJWK(pair.publicKey), kid: 'email-auth-fixture', use: 'sig', alg: 'RS256' };
let fixtureNumber = 0;
function fixture() {
  const env = { ACCESS_ISSUER: `https://email-auth-${++fixtureNumber}.cloudflareaccess.com`,
    ACCESS_AUDIENCE: 'synthetic-owner-audience', EMAIL_READER_ENABLED: '1', READER_ACCESS_AUDIENCE: 'synthetic-reader-audience' };
  let fetches = 0;
  globalThis.fetch = async url => {
    assert.equal(String(url), `${env.ACCESS_ISSUER}/cdn-cgi/access/certs`); fetches++;
    return Response.json({ keys: [jwk] });
  };
  const now = Math.floor(Date.now() / 1000);
  async function token(changes = {}) {
    return new SignJWT({ sub: 'synthetic-reader-subject', email: 'Recipient@EXAMPLE.TEST', type: 'app',
      iss: env.ACCESS_ISSUER, aud: env.READER_ACCESS_AUDIENCE, iat: now, exp: now + 600, ...changes })
      .setProtectedHeader({ alg: 'RS256', kid: jwk.kid }).sign(pair.privateKey);
  }
  const request = jwt => new Request('https://vault.example.test/r/synthetic', {
    headers: { ...(jwt ? { 'cf-access-jwt-assertion': jwt } : {}),
      'cf-access-authenticated-user-email': 'forged@example.test', 'x-vault-owner-sub': 'forged-owner' },
  });
  return { env, now, token, request, get fetches() { return fetches; } };
}

test('email identity comes only from the signed recipient application token', async () => {
  const f = fixture(), jwt = await f.token();
  assert.deepEqual(await emailIdentity(f.request(jwt), f.env), {
    subject: 'synthetic-reader-subject', email: 'Recipient@example.test', expiresAt: (f.now + 600) * 1000,
  });
  assert.equal(f.fetches, 1);
});

test('reader tokens do not authenticate as administrator and owner tokens do not authenticate as email readers', async () => {
  const f = fixture();
  await assert.rejects(identity(f.request(await f.token()), f.env));
  await assert.rejects(emailIdentity(f.request(await f.token({ aud: f.env.ACCESS_AUDIENCE })), f.env));
  const legacy = await f.token({ aud: f.env.ACCESS_AUDIENCE, email: undefined, type: undefined });
  assert.equal(await identity(f.request(legacy), f.env), 'synthetic-reader-subject');
});

for (const [label, changes] of [
  ['missing flag', { EMAIL_READER_ENABLED: undefined }], ['disabled flag', { EMAIL_READER_ENABLED: '0' }],
  ['numeric flag', { EMAIL_READER_ENABLED: 1 }], ['missing audience', { READER_ACCESS_AUDIENCE: undefined }],
  ['empty audience', { READER_ACCESS_AUDIENCE: '' }], ['placeholder audience', { READER_ACCESS_AUDIENCE: 'unconfigured' }],
  ['overlong audience', { READER_ACCESS_AUDIENCE: 'a'.repeat(257) }], ['padded audience', { READER_ACCESS_AUDIENCE: ' reader ' }],
  ['owner audience', { READER_ACCESS_AUDIENCE: 'synthetic-owner-audience' }], ['bad issuer', { ACCESS_ISSUER: 'https://untrusted.example.test' }],
]) test(`email reader configuration rejects ${label} before network access`, async () => {
  const f = fixture(), env = { ...f.env, ...changes };
  assert.throws(() => emailReaderConfiguration(env), /auth_configuration/);
  await assert.rejects(emailIdentity(f.request(await f.token()), env), /auth_configuration/);
  assert.equal(f.fetches, 0);
});

for (const [label, changes] of [
  ['missing email', { email: undefined }], ['empty email', { email: '' }], ['non-string email', { email: [] }],
  ['malformed email', { email: 'missing-at-sign' }], ['header injection email', { email: 'a@example.test\r\nX-Test: bad' }],
  ['unicode email', { email: '利用者@example.test' }], ['missing type', { type: undefined }], ['non-app type', { type: 'service' }],
  ['service common name', { common_name: 'synthetic-service.access' }], ['service token id', { service_token_id: 'synthetic-service' }],
  ['wrong issuer', { iss: 'https://wrong.cloudflareaccess.com' }], ['wrong audience', { aud: 'unrelated' }],
  ['missing subject', { sub: undefined }], ['empty subject', { sub: '' }], ['overlong subject', { sub: 'a'.repeat(257) }],
  ['missing expiry', { exp: undefined }], ['expired token', { exp: 1 }], ['missing issued-at', { iat: undefined }],
  ['negative issued-at', { iat: -1 }], ['future issued-at', { iat: Math.floor(Date.now() / 1000) + 120 }],
  ['fractional expiry', { exp: Math.floor(Date.now() / 1000) + 600.5 }], ['unsafe expiry', { exp: Number.MAX_SAFE_INTEGER }],
  ['future not-before', { nbf: Math.floor(Date.now() / 1000) + 120 }],
]) test(`email identity rejects ${label}`, async () => {
  const f = fixture();
  await assert.rejects(emailIdentity(f.request(await f.token(changes)), f.env));
});

test('unsigned identity and a modified signature cannot identify an account', async () => {
  const f = fixture();
  await assert.rejects(emailIdentity(f.request(null), f.env));
  assert.equal(f.fetches, 0);
  const parts = (await f.token()).split('.');
  parts[2] = (parts[2][0] === 'A' ? 'B' : 'A') + parts[2].slice(1);
  await assert.rejects(emailIdentity(f.request(parts.join('.')), f.env));
});

test('OTP policy is not inferred from an unsupported JWT AMR claim', async () => {
  const f = fixture();
  assert.equal((await emailIdentity(f.request(await f.token()), f.env)).email, 'Recipient@example.test');
});
