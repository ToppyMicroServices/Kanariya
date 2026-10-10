import test from 'node:test';
import assert from 'node:assert/strict';
import { HEADERS, json, failure, Denied } from '../src/http.js';
import worker from '../src/worker.js';

test('Vault enforces same-origin CSP and host-only HSTS on JSON and denials', () => {
  for (const response of [json({ ok: true }), failure(new Denied(401, 'not_authenticated')),
    failure(new Denied()), failure(new Error('synthetic failure'))]) {
    assert.equal(response.headers.get('strict-transport-security'), 'max-age=86400');
    assert.equal(response.headers.get('content-security-policy'), HEADERS['content-security-policy']);
    assert.equal(response.headers.get('content-security-policy-report-only'), null);
    assert.doesNotMatch(response.headers.get('content-security-policy'), /unsafe-inline|unsafe-eval|blob:|https:|data:/);
    assert.match(response.headers.get('content-security-policy'), /worker-src 'self'/);
  }
});

test('Vault does not send HSTS over a rejected plaintext connection', async () => {
  const response = await worker.fetch(new Request('http://fixture.test/v1/admin'), { PUBLIC_ORIGIN: 'https://fixture.test' });
  assert.equal(response.status, 403);
  assert.equal(response.headers.get('strict-transport-security'), null);
  assert.equal(response.headers.get('content-security-policy'), HEADERS['content-security-policy']);
});
