import { afterEach, expect, it, vi } from 'vitest';
import worker from '../src/worker.js';
import { CanaryManagement } from '../src/canary-management.js';
import { setup, admin, hits } from './helpers.js';

const id = 'f025a92a-082d-4eaf-9b78-9ed396b9bb85', other = '72de62a9-a3cc-4015-9913-d8c67e08f1bb';
const future = () => Date.now() + 86400000;
const bridge = s => new CanaryManagement({}, s.env);
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals(); });

it('keeps the private entrypoint narrow and never asks for or exposes ADMIN_KEY', async () => {
  const s = setup(), rpc = bridge(s);
  for (const name of ['fetch', 'operation', 'test', 'sign', 'export', 'list']) expect(typeof rpc[name]).not.toBe('function');
  Object.defineProperty(s.env, 'ADMIN_KEY', { get() { throw new Error('must_not_read_admin_secret'); } });
  expect(await rpc.status(id)).toEqual({ status: 200, value: { documentId: id, canary: null } });
  expect((await rpc.create(id, future())).status).toBe(201);
  expect((await rpc.revoke(id)).status).toBe(200); expect((await rpc.events(id)).status).toBe(200);
});

it('keeps every internal management route unreachable through public fetch', async () => {
  const s = setup();
  for (const method of ['GET', 'POST']) for (const action of ['status', 'create', 'revoke', 'events']) {
    const request = new Request(`https://kanariya.toppymicros.com/internal/vault-canary/${action}`, {
      method, headers: { authorization: 'Bearer test-admin', 'content-type': 'application/json' },
      ...(method === 'POST' ? { body: JSON.stringify({ documentId: id, expiresAt: future() }) } : {}),
    });
    expect((await worker.fetch(request, s.env)).status).toBe(404);
  }
  expect((await worker.fetch(admin('/admin/tokens', { key: 'wrong' }), s.env)).status).toBe(403);
  expect(s.object.rows('SELECT * FROM tokens')).toEqual([]);
});

it('rejects non-UUID scopes, invalid deadlines and reserved ordinary-token metadata', async () => {
  const s = setup(), rpc = bridge(s);
  for (const invalid of ['../admin/tokens', '<script>', id.toUpperCase(), undefined, {}]) expect((await rpc.status(invalid)).status).toBe(400);
  for (const expiry of [null, Date.now(), Infinity, '1800000000000', 8640000000000001]) expect((await rpc.create(id, expiry)).status).toBe(400);
  const reserved = await worker.fetch(admin('/admin/tokens', { method: 'POST', data: { name: id, src: 'vault-management-v1' } }), s.env);
  expect(reserved.status).toBe(400); expect(s.object.rows('SELECT * FROM tokens')).toEqual([]);
});

it('creates at most one active token per document and preserves the exact bounded deadline', async () => {
  const s = setup(), rpc = bridge(s), expiresAt = future();
  const responses = await Promise.all(Array.from({ length: 10 }, () => rpc.create(id, expiresAt)));
  expect(responses.filter(result => result.status === 201)).toHaveLength(1);
  expect(responses.filter(result => result.status === 409)).toHaveLength(9);
  const item = (await rpc.status(id)).value.canary;
  expect(item).toEqual({ token: expect.stringMatching(/^kr_[a-f0-9]{64}$/), state: 'active', expiresAt, hitCount: 0, lastSeenAt: null });
  expect(s.object.rows('SELECT name,location,src FROM tokens')).toEqual([{ name: id, location: '', src: 'vault-management-v1' }]);
  s.restart(); expect((await bridge(s).status(id)).value.canary).toEqual(item);
  expect((await rpc.status(other)).value.canary).toBeNull();
});

it('retains the current token when replacement happens in the same millisecond and revokes only its scope', async () => {
  const now = Date.now(); vi.spyOn(Date, 'now').mockReturnValue(now);
  const s = setup(), rpc = bridge(s);
  const first = (await rpc.create(id, future())).value.canary;
  const sibling = (await rpc.create(other, future())).value.canary;
  expect((await rpc.revoke(id)).value.canary.state).toBe('revoked');
  const replacement = (await rpc.create(id, future())).value.canary;
  expect(replacement.token).not.toBe(first.token); expect((await rpc.status(id)).value.canary.token).toBe(replacement.token);
  expect((await rpc.status(other)).value.canary).toEqual(sibling);
});

it('stores document Canary hits with opaque identifiers and fixed data only', async () => {
  const s = setup({ WEBHOOK_URL: 'https://fixture.test/synthetic-notify' }), rpc = bridge(s);
  const token = (await rpc.create(id, future())).value.canary.token;
  const request = new Request(`https://kanariya.toppymicros.com/canary/${token}?src=PRIVATE_EMAIL@example.test`, {
    headers: { 'cf-connecting-ip': '198.51.100.9', 'user-agent': 'PRIVATE_USER_AGENT', referer: 'https://private.example.test/PRIVATE_CV', authorization: 'PRIVATE_BEARER' },
  });
  Object.defineProperty(request, 'cf', { value: { country: 'PRIVATE_COUNTRY', asn: 12345 } });
  expect((await worker.fetch(request, s.env)).status).toBe(204);
  expect(hits(s, token)).toEqual([{ kind: 'vault.canary', id: expect.stringMatching(/^[a-f0-9]{32}$/), ts: expect.any(String), documentId: id }]);
  const persisted = JSON.stringify(['tokens', 'events', 'deliveries', 'guards'].flatMap(table => s.object.rows(`SELECT * FROM ${table}`)));
  for (const secret of ['198.51.100.9', 'PRIVATE_', '12345', 'referer', 'ipHash', 'user-agent']) expect(persisted).not.toContain(secret);
  const status = (await rpc.status(id)).value.canary; expect(status.hitCount).toBe(1); expect(status.lastSeenAt).toBeTypeOf('number');
  const notify = vi.fn(async () => new Response(null, { status: 200 })); vi.stubGlobal('fetch', notify);
  await s.object.alarm(); expect(notify).toHaveBeenCalledTimes(1);
  const sent = JSON.parse(notify.mock.calls[0][1].body);
  expect(sent.event).toEqual(hits(s, token)[0]); expect(JSON.stringify(sent)).not.toContain('PRIVATE_');
  expect((await rpc.events(id)).value.events[0].notifications).toEqual([{ type: 'webhook', state: 'accepted' }]);
});

it('does not offer a document-token notification test or add hits on status/create/revoke/events', async () => {
  const s = setup(), rpc = bridge(s), token = (await rpc.create(id, future())).value.canary.token;
  await rpc.status(id); await rpc.events(id);
  const test = await worker.fetch(admin(`/admin/tokens/${token}/test`, { method: 'POST' }), s.env);
  expect(test.status).toBe(404); expect(hits(s, token)).toEqual([]);
  await rpc.revoke(id); await worker.fetch(new Request(`https://kanariya.toppymicros.com/canary/${token}`), s.env);
  expect(hits(s, token)).toEqual([]); expect(s.object.rows('SELECT * FROM deliveries')).toEqual([]);
});

it('returns at most fifty events for only the requested document across replaced tokens', async () => {
  const now = Date.now(); const clock = vi.spyOn(Date, 'now').mockReturnValue(now);
  const s = setup({ RATE_LIMIT_MAX: '0' }), rpc = bridge(s), token = (await rpc.create(id, future())).value.canary.token;
  for (let index = 0; index < 55; index++) {
    clock.mockReturnValue(now + index); await worker.fetch(new Request(`https://kanariya.toppymicros.com/canary/${token}`), s.env);
  }
  const sibling = (await rpc.create(other, future())).value.canary.token;
  await worker.fetch(new Request(`https://kanariya.toppymicros.com/canary/${sibling}`), s.env);
  const page = (await rpc.events(id)).value;
  expect(page.events).toHaveLength(50); expect(page.events[0].at).toBe(now + 54);
  expect(page.events.every(event => event.outcome === 'url_requested')).toBe(true);
  expect((await rpc.events(other)).value.events).toHaveLength(1);
});

it('respects the existing installation inventory cap without removing another token', async () => {
  const s = setup({ TOKEN_MAX_ITEMS: '1' });
  const ordinary = await worker.fetch(admin('/admin/tokens', { method: 'POST', data: { name: 'Ordinary existing placement' } }), s.env);
  expect(ordinary.status).toBe(201); expect((await bridge(s).create(id, future())).status).toBe(409);
  expect(s.object.rows('SELECT * FROM tokens')).toHaveLength(1);
});
