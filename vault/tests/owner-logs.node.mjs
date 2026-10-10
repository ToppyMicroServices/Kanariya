import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPair, exportJWK, SignJWT } from 'jose';
import worker, { VaultDocument } from '../src/worker.js';
import { newKey, importKey, sealJSON, openJSON } from '../src/crypto.js';

const DAY = 86400000, originalFetch = globalThis.fetch;
after(() => { globalThis.fetch = originalFetch; });
const pair = await generateKeyPair('RS256', { extractable: true });
const jwk = { ...await exportJWK(pair.publicKey), kid: 'owner-logs-fixture', use: 'sig', alg: 'RS256' };
let fixtureNumber = 0;
class Storage {
  constructor() { this.map = new Map(); this.reads = []; this.lists = []; }
  async get(key) { this.reads.push(key); return structuredClone(this.map.get(key)); }
  async list(options) {
    if (options.start && options.end && options.start >= options.end) throw new Error('invalid_log_list_range');
    this.lists.push(structuredClone(options));
    const entries = [...this.map].filter(([key]) => key.startsWith(options.prefix) && (!options.start || key >= options.start) && (!options.end || key < options.end))
      .sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0);
    if (options.reverse) entries.reverse();
    return new Map(entries.slice(0, options.limit));
  }
  async transaction() { throw new Error('unexpected_log_write'); }
  async put() { throw new Error('unexpected_log_write'); }
  async delete() { throw new Error('unexpected_log_write'); }
  async setAlarm() { throw new Error('unexpected_log_write'); }
}
async function fixture() {
  const id = crypto.randomUUID(), env = { PUBLIC_ORIGIN: 'https://vault.example.test',
    ACCESS_ISSUER: `https://owner-logs-${++fixtureNumber}.cloudflareaccess.com`, ACCESS_AUDIENCE: 'synthetic-owner-logs',
    VAULT_OWNER_SUB: 'synthetic-owner', VAULT_WRAP_KEY: newKey(), VAULT_AUDIT_KEY: newKey(),
    DUMMY_DOCUMENT_ID: id, DUMMY_RECORD_SHA256: 'ab'.repeat(32), PASSWORD_READER_ENABLED: '1' };
  const key = await importKey(env.VAULT_AUDIT_KEY), storage = new Storage();
  const ctx = { storage, id: { toString: () => `owner-logs-${id}` } }, context = `journal:v1:owner-logs-${id}`;
  let instance = new VaultDocument(ctx, env), notifications = 0;
  Object.defineProperty(env, 'VAULT_DOCUMENTS', { get() { throw new Error('logs_must_not_access_pdf'); } });
  env.VAULT = { idFromName: name => { assert.equal(name, id); return name; }, get: () => instance };
  globalThis.fetch = async url => {
    if (String(url) === `${env.ACCESS_ISSUER}/cdn-cgi/access/certs`) return Response.json({ keys: [jwk] });
    notifications++; throw new Error('unexpected_notification');
  };
  async function request(options = {}) {
    const subject = Object.hasOwn(options, 'subject') ? options.subject : env.VAULT_OWNER_SUB;
    const jwt = subject ? await new SignJWT({ sub: subject, iss: env.ACCESS_ISSUER, aud: env.ACCESS_AUDIENCE,
      iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + 600 })
      .setProtectedHeader({ alg: 'RS256', kid: 'owner-logs-fixture' }).sign(pair.privateKey) : null;
    const method = options.method ?? (options.cursor ? 'POST' : 'GET');
    const req = new Request(`${env.PUBLIC_ORIGIN}${options.password ? '/p' : '/v1/documents'}/${options.id ?? id}/logs${options.query ?? ''}`, {
      method, headers: { origin: env.PUBLIC_ORIGIN, 'content-type': 'application/json',
        ...(jwt ? { 'cf-access-jwt-assertion': jwt } : {}), ...options.headers },
      ...(['GET', 'HEAD'].includes(method) ? {} : { body: options.body ?? JSON.stringify({ cursor: options.cursor }) }) });
    return options.direct ? instance.fetch(req) : worker.fetch(req, env);
  }
  function event(at = Date.now() - 1000, overrides = {}) {
    return { id: crypto.randomUUID(), documentId: id, subject: 'shared-password', at, outcome: 'decrypted', ...overrides };
  }
  const state = (events = [], jobs = []) => ({ version: 1, documentId: id, revoked: false, events, jobs,
    requests: [], sessions: [], readerUsage: [], archivedAccepted: 0 });
  async function write(events, jobs, overrides = {}) { storage.map.set('encrypted-journal', await sealJSON({ ...state(events, jobs), ...overrides }, key, context)); }
  async function archive(event, jobs = [], overrides = {}) {
    const name = `audit:${event.id}`, expiresAt = event.at + 30 * DAY;
    storage.map.set(name, await sealJSON({ event, jobs, expiresAt, ...overrides }, key, `${context}:${name}`));
    storage.map.set(`expiry:${String(expiresAt).padStart(13, '0')}:${name}`, name);
  }
  async function replay(at) {
    const name = `replay:${crypto.randomUUID()}`;
    storage.map.set(name, 'synthetic replay must never be decrypted by logs');
    storage.map.set(`expiry:${String(at + 30 * DAY).padStart(13, '0')}:${name}`, name);
  }
  async function cursor(value) {
    const box = await sealJSON(value, key, `${context}:logs:v1:${id}:${env.DUMMY_RECORD_SHA256}`);
    return `${box.nonce}.${box.ciphertext}`;
  }
  return { id, env, storage, key, context, request, event, write, archive, replay, cursor,
    restart() { instance = new VaultDocument(ctx, env); }, get notifications() { return notifications; } };
}
function job(event, overrides = {}) {
  return { eventId: event.id, target: { type: 'email', fingerprint: 'secret fingerprint', address: 'private@example.test' },
    state: 'accepted', attempts: 1, at: event.at, outcome: event.outcome, nextAt: event.at + 1000, error: null, httpStatus: null, ...overrides };
}
async function page(f, options) { const response = await f.request(options); assert.equal(response.status, 200); return response.json(); }
async function withClock(at, operation) { const before = Date.now; Date.now = () => at; try { return await operation(); } finally { Date.now = before; } }

test('owner logs return a no-store empty page without PDF access, decryption, storage writes or notifications', async () => {
  const f = await fixture(), response = await f.request();
  assert.equal(response.status, 200); assert.deepEqual(await response.json(), { events: [], nextCursor: null, retentionDays: 30 });
  assert.match(response.headers.get('cache-control'), /no-store/); assert.equal(response.headers.get('access-control-allow-origin'), null);
  assert.equal(f.notifications, 0); assert.equal(f.storage.map.size, 0);
  assert.deepEqual(f.storage.reads, ['encrypted-journal']); assert.equal(f.storage.lists[0].limit, 100);
});

test('owner logs expose only existing event and provider outcome fields', async () => {
  const f = await fixture(), at = Date.now() - 5000;
  const first = f.event(at, { subject: 'synthetic-access-subject', outcome: 'requested', email: 'private@example.test', ip: 'private IP', userAgent: 'private UA' });
  const second = f.event(at + 1000), third = f.event(at + 2000, { outcome: 'failed' });
  await f.write([first, second], [job(first, { state: 'pending', attempts: 0 }), job(second)]);
  await f.archive(third, [job(third, { state: 'failed', attempts: 8, error: 'http_error', httpStatus: 503,
    lease: 'private lease', actor: 'private actor', target: { type: 'webhook', url: 'https://private.example.test/token' } })]);
  const value = await page(f);
  assert.deepEqual(value.events, [
    { id: third.id, at: third.at, subject: 'shared-password', outcome: 'failed', notifications: [{ type: 'webhook', state: 'failed', attempts: 8, error: 'http_error', httpStatus: 503 }] },
    { id: second.id, at: second.at, subject: 'shared-password', outcome: 'decrypted', notifications: [{ type: 'email', state: 'accepted', attempts: 1, error: null, httpStatus: null }] },
    { id: first.id, at: first.at, subject: first.subject, outcome: 'requested', notifications: [{ type: 'email', state: 'pending', attempts: 0, error: null, httpStatus: null }] },
  ]);
  for (const secret of ['private', 'fingerprint', 'lease', 'actor', 'purpose', 'ciphertext', 'view', 'download', f.env.VAULT_WRAP_KEY, f.env.VAULT_AUDIT_KEY]) assert.ok(!JSON.stringify(value).includes(secret));
  assert.equal(f.notifications, 0);
});

for (const direct of [false, true]) test(`logs reject unsigned, reader and forged owner identities before storage/key access (${direct ? 'DO' : 'Worker'})`, async () => {
  const f = await fixture(); let keyReads = 0;
  for (const name of ['VAULT_WRAP_KEY', 'VAULT_AUDIT_KEY']) Object.defineProperty(f.env, name, { get() { keyReads++; throw new Error('unexpected_key_read'); } });
  for (const options of [{ subject: null }, { subject: 'synthetic-reader' },
    { subject: null, headers: { cookie: 'synthetic password session', 'cf-access-authenticated-user-email': 'owner@example.test' } },
    { subject: null, headers: { 'cf-access-jwt-assertion': 'forged', 'x-vault-owner-sub': f.env.VAULT_OWNER_SUB } }]) {
    assert.equal((await f.request({ ...options, direct })).status, options.subject === 'synthetic-reader' ? 403 : 401);
  }
  assert.equal(keyReads, 0); assert.deepEqual(f.storage.reads, []); assert.deepEqual(f.storage.lists, []);
});

for (const [name, options, status] of [
  ['password route', { password: true }, 403], ['other document', { id: crypto.randomUUID() }, 403],
  ['query', { query: '?cursor=arbitrary' }, 403], ['unsupported method', { method: 'DELETE' }, 405],
  ['missing POST origin', { method: 'POST', headers: { origin: '' } }, 403],
  ['wrong POST origin', { method: 'POST', headers: { origin: 'https://other.example.test' } }, 403],
  ['not JSON', { method: 'POST', headers: { 'content-type': 'text/plain' } }, 403],
  ['empty POST', { method: 'POST', body: '{}' }, 400], ['array', { method: 'POST', body: '[]' }, 400],
  ['unexpected POST field', { method: 'POST', body: '{"cursor":"x","extra":1}' }, 400],
  ['numeric cursor', { method: 'POST', body: '{"cursor":1}' }, 400], ['oversized cursor', { cursor: 'x'.repeat(1025) }, 400],
  ['plaintext storage key cursor', { cursor: 'encrypted-journal' }, 400], ['malformed body', { method: 'POST', body: '{' }, 400],
]) test(`logs reject ${name} without stored changes`, async () => {
  const f = await fixture(); assert.equal((await f.request(options)).status, status); assert.equal(f.storage.map.size, 0); assert.equal(f.notifications, 0);
});

test('logs merge active and archived history with stable newest-first pagination, including equal timestamps and replay-only windows', async () => {
  const f = await fixture(), now = Date.now(), events = Array.from({ length: 260 }, (_, i) => f.event(now - 1000 - Math.floor(i / 2) * 1000));
  await f.write(events.slice(0, 60), events.slice(0, 60).map(e => job(e)));
  for (const event of events.slice(60)) await f.archive(event, [job(event)]);
  for (let i = 0; i < 120; i++) await f.replay(now - 40000 - i);
  const seen = []; let cursor, pages = 0;
  do {
    const reads = f.storage.reads.length, lists = f.storage.lists.length, value = await page(f, cursor ? { cursor } : {});
    assert.ok(value.events.length <= 50); assert.ok(f.storage.reads.length - reads <= 101); assert.equal(f.storage.lists.length - lists, 1);
    assert.equal(f.storage.lists.at(-1).limit, 100); assert.equal(f.storage.lists.at(-1).reverse, true);
    seen.push(...value.events.map(e => e.id)); cursor = value.nextCursor; assert.ok(!cursor || cursor.length <= 1024);
    assert.ok(++pages < 12);
  } while (cursor);
  const expected = events.toSorted((a, b) => b.at - a.at || (a.id < b.id ? 1 : -1)).map(e => e.id);
  assert.deepEqual(seen, expected); assert.equal(new Set(seen).size, events.length); assert.equal(f.notifications, 0);
});

test('a replay-only archive window advances its cursor without skipping older active evidence', async () => {
  const f = await fixture(), now = Date.now(), oldest = f.event(now - 100000);
  await f.write([oldest], []); for (let i = 0; i < 100; i++) await f.replay(now - 1000 - i);
  const first = await page(f); assert.deepEqual(first.events, []); assert.ok(first.nextCursor);
  const second = await page(f, { cursor: first.nextCursor }); assert.deepEqual(second.events.map(e => e.id), [oldest.id]); assert.equal(second.nextCursor, null);
});

test('moving active events into archives between pages does not duplicate or lose history', async () => {
  const f = await fixture(), now = Date.now(), events = Array.from({ length: 80 }, (_, i) => f.event(now - 1000 - i));
  await f.write(events, []); const first = await page(f); assert.equal(first.events.length, 50);
  for (const event of events) await f.archive(event); await f.write([], []); f.restart();
  const second = await page(f, { cursor: first.nextCursor }); assert.equal(second.events.length, 30); assert.equal(second.nextCursor, null);
  assert.deepEqual([...first.events, ...second.events].map(e => e.id), events.map(e => e.id));
});

test('a cursor excludes events created after its snapshot and expires after ten minutes', async () => {
  const f = await fixture(), now = Date.now(), events = Array.from({ length: 60 }, (_, i) => f.event(now - 1000 - i));
  await f.write(events, []);
  const first = await withClock(now, () => page(f));
  await f.write([...events, f.event(now + 1)], []);
  const second = await withClock(now + 2, () => page(f, { cursor: first.nextCursor }));
  assert.deepEqual(second.events.map(e => e.id), events.slice(50).map(e => e.id));
  assert.equal((await withClock(now + 600000, () => f.request({ cursor: first.nextCursor }))).status, 400);
});

test('retention filtering removes active and archived history at thirty days without deleting stored evidence', async () => {
  const f = await fixture(), now = Date.now(), old = f.event(now - 30 * DAY), recent = f.event(now - 30 * DAY + 1), oldArchive = f.event(now - 31 * DAY);
  await f.write([old, recent], []); await f.archive(oldArchive); const before = structuredClone([...f.storage.map]);
  const value = await withClock(now, () => page(f)); assert.deepEqual(value.events.map(e => e.id), [recent.id]);
  assert.deepEqual([...f.storage.map], before);
});

test('an older page that expires during pagination returns an empty final page without an invalid storage range', async () => {
  const f = await fixture(), now = Date.now(), events = Array.from({ length: 60 }, () => f.event(now - 30 * DAY + 1));
  await f.write(events, []); const first = await withClock(now, () => page(f)); assert.equal(first.events.length, 50); assert.ok(first.nextCursor);
  const lists = f.storage.lists.length, second = await withClock(now + 2, () => page(f, { cursor: first.nextCursor }));
  assert.deepEqual(second, { events: [], nextCursor: null, retentionDays: 30 }); assert.equal(f.storage.lists.length, lists);
});

test('revoked documents retain owner audit access and return no permission or secret-bearing policy', async () => {
  const f = await fixture(), event = f.event(); await f.write([event], [], { revoked: true });
  assert.equal((await page(f)).events[0].id, event.id);
});

test('cursor authentication binds pagination to the document, ciphertext pin and Durable Object context', async () => {
  const f = await fixture(), events = Array.from({ length: 60 }, (_, i) => f.event(Date.now() - 1000 - i)); await f.write(events, []);
  const first = await page(f), second = await fixture(); second.env.VAULT_AUDIT_KEY = f.env.VAULT_AUDIT_KEY;
  assert.equal((await second.request({ cursor: first.nextCursor })).status, 400);
  const [nonce, ciphertext] = first.nextCursor.split('.');
  const altered = `${nonce}.${ciphertext[0] === 'A' ? 'B' : 'A'}${ciphertext.slice(1)}`;
  assert.equal((await f.request({ cursor: altered })).status, 400);
  f.env.DUMMY_RECORD_SHA256 = 'cd'.repeat(32); assert.equal((await f.request({ cursor: first.nextCursor })).status, 400);
});

test('authenticated but malformed cursor payloads cannot request arbitrary storage keys or future history', async () => {
  const f = await fixture(), now = Date.now(), valid = { version: 1, snapshotAt: now, before: `expiry:${String(now + 30 * DAY).padStart(13, '0')}:audit:${crypto.randomUUID()}` };
  for (const value of [{ ...valid, before: 'encrypted-journal' }, { ...valid, version: 2 }, { ...valid, snapshotAt: now + 1 },
    { ...valid, before: `expiry:${String(now + 30 * DAY + 1).padStart(13, '0')}:audit:${crypto.randomUUID()}` },
    { ...valid, before: `expiry:${String(now + 30 * DAY).padStart(13, '0')}:audit:../private-key` }, { ...valid, extra: true }]) {
    const token = await f.cursor(value); assert.equal((await withClock(now, () => f.request({ cursor: token }))).status, 400);
  }
  assert.deepEqual(f.storage.reads, []); assert.deepEqual(f.storage.lists, []);
});

for (const condition of ['unrecognized outcome', 'other document', 'invalid notification type', 'invalid notification state', 'tampered archive', 'index points to arbitrary key', 'archive expiry mismatch'])
  test(`logs fail closed on ${condition} without changing storage`, async () => {
    const f = await fixture(), event = f.event(), jobs = [job(event)];
    if (condition === 'unrecognized outcome') event.outcome = 'download';
    if (condition === 'other document') event.documentId = crypto.randomUUID();
    if (condition === 'invalid notification type') jobs[0].target.type = 'custom-private';
    if (condition === 'invalid notification state') jobs[0].state = 'delivered';
    if (condition.startsWith('archive') || condition === 'tampered archive' || condition === 'index points to arbitrary key') {
      await f.archive(event, jobs, condition === 'archive expiry mismatch' ? { expiresAt: event.at + 30 * DAY + 1 } : {});
      if (condition === 'tampered archive') f.storage.map.get(`audit:${event.id}`).ciphertext = 'invalid';
      if (condition === 'index points to arbitrary key') f.storage.map.set([...f.storage.map.keys()].find(k => k.startsWith('expiry:')), 'encrypted-journal');
    } else await f.write([event], jobs);
    const before = structuredClone([...f.storage.map]), response = await f.request();
    assert.equal(response.status, 503); assert.deepEqual(await response.json(), { error: 'unavailable' }); assert.deepEqual([...f.storage.map], before); assert.equal(f.notifications, 0);
  });

test('unrecognized provider text is not exposed as a notification error', async () => {
  const f = await fixture(), event = f.event(); await f.write([event], [job(event, { error: 'private provider secret', httpStatus: 'private status' })]);
  assert.deepEqual((await page(f)).events[0].notifications[0], { type: 'email', state: 'accepted', attempts: 1, error: null, httpStatus: null });
});

test('pagination cursors contain only authenticated ciphertext and log reads leave journal plaintext encrypted', async () => {
  const f = await fixture(), events = Array.from({ length: 60 }, (_, i) => f.event(Date.now() - 1000 - i)); await f.write(events, []);
  const before = structuredClone([...f.storage.map]), value = await page(f);
  for (const privateValue of [f.id, events[49].id, 'shared-password', f.env.DUMMY_RECORD_SHA256, f.env.VAULT_AUDIT_KEY]) assert.ok(!value.nextCursor.includes(privateValue));
  assert.deepEqual([...f.storage.map], before);
  const stored = JSON.stringify([...f.storage.map]); assert.ok(!stored.includes('shared-password')); assert.ok(!stored.includes(events[0].id));
  assert.equal((await openJSON(f.storage.map.get('encrypted-journal'), f.key, f.context)).events.length, 60);
});
