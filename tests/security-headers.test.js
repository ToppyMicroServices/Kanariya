import { describe, it, expect } from 'vitest';
import worker from '../src/worker.js';

describe('security headers on public and private response paths', () => {
  it.each([
    ['GET', '/canary/invalid/extra', {}, 204],
    ['OPTIONS', '/canary/invalid/extra', {}, 204],
    ['OPTIONS', '/admin/tokens', {}, 204],
    ['GET', '/admin/tokens', {}, 403],
    ['GET', '/admin/tokens', { ADMIN_KEY: 'synthetic' }, 503],
    ['GET', '/admin/sign?token=invalid/extra', { ADMIN_KEY: 'synthetic' }, 400],
    ['GET', '/unmatched', {}, 404],
    ['POST', '/canary/invalid/extra', {}, 405],
    ['GET', '/admin/tokens', { ADMIN_KEY: 'synthetic', KANARI_STORE: {
      idFromName: name => name, get: () => ({ fetch: async () => Response.json({ tokens: [] }) }),
    } }, 200],
    ['GET', '/admin/export?token=synthetic', { ADMIN_KEY: 'synthetic', KANARI_STORE: {
      idFromName: name => name, get: () => ({ fetch: async () => Response.json({ error: 'denied' }, { status: 403 }) }),
    } }, 403],
  ])('%s %s carries enforced CSP and host-only HSTS (%s)', async (method, path, env, status) => {
    const response = await worker.fetch(new Request(`https://fixture.test${path}`, {
      method, headers: { authorization: 'Bearer synthetic' },
    }), env);
    expect(response.status).toBe(status);
    expect(response.headers.get('content-security-policy')).toBe("default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'");
    expect(response.headers.get('content-security-policy-report-only')).toBeNull();
    expect(response.headers.get('strict-transport-security')).toBe('max-age=86400');
    expect(response.headers.get('access-control-allow-origin')).toBe('*');
    expect(response.headers.get('cache-control')).toBe('no-store');
    if (status === 204) expect(await response.text()).toBe('');
  });
});
