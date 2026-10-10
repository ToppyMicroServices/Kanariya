import test from 'node:test';
import assert from 'node:assert/strict';
import { Denied } from '../src/http.js';
import { hashToken } from '../src/password.js';
import { MAX_READER_LINKS, readLinks, listLinks, createLink, revokeLink, getLiveLink } from '../src/links.js';

const digest = 'a'.repeat(64), otherDigest = 'b'.repeat(64), now = 1791727200000, expiry = now + 600000;
const invalid = error => error instanceof Denied && error.status === 400 && error.code === 'invalid_links';
const changed = error => error instanceof Denied && error.status === 409 && error.code === 'links_changed';
const unauthorized = error => error instanceof Denied && error.status === 401 && error.code === 'unauthenticated';
const input = (expectedRevision = 0, expiresAt = expiry) => ({ action: 'create', expectedRevision, expiresAt });
const revoke = (linkId, expectedRevision) => ({ action: 'revoke', linkId, expectedRevision });

test('old journals have no links and reading does not initialize credentials', () => {
  const state = { sessions: [], events: [] }, before = structuredClone(state);
  assert.deepEqual(readLinks(state, digest), { version: 1, recordDigest: digest, revision: 0, entries: [] });
  assert.deepEqual(listLinks(state, digest), { revision: 0, links: [] });
  assert.deepEqual(state, before);
});

test('a new link exposes its random credential once and stores only its digest', async () => {
  const state = { sessions: [], events: [] }, result = await createLink(state, digest, input(), expiry, now);
  assert.match(result.urlToken, /^[0-9a-f]{64}$/);
  assert.equal(state.readerLinks.entries[0].hash, await hashToken(result.urlToken));
  assert.ok(!JSON.stringify(state).includes(result.urlToken));
  assert.deepEqual(result.link, { id: state.readerLinks.entries[0].id, createdAt: now, expiresAt: expiry, revoked: false });
  assert.deepEqual(listLinks(state, digest), { revision: 1, links: [result.link] });
  assert.ok(!JSON.stringify(listLinks(state, digest)).includes(state.readerLinks.entries[0].hash));
  assert.equal(result.revision, 1); assert.deepEqual(state.sessions, []); assert.deepEqual(state.events, []);
});

test('public links and decrypted reads return independent objects', async () => {
  const state = {}, result = await createLink(state, digest, input(), expiry, now), id = result.link.id;
  result.link.id = crypto.randomUUID(); result.link.revoked = true;
  const read = readLinks(state, digest); read.entries[0].revoked = true;
  const listed = listLinks(state, digest); listed.links[0].expiresAt = now;
  const live = getLiveLink(state, digest, id, now); live.revoked = true;
  assert.equal(state.readerLinks.entries[0].revoked, false);
  assert.equal(state.readerLinks.entries[0].expiresAt, expiry);
  assert.equal(getLiveLink(state, digest, id, now).id, id);
});

test('a ciphertext replacement invalidates old links without carrying credentials forward', async () => {
  const state = {}, original = await createLink(state, digest, input(), expiry, now), before = structuredClone(state);
  assert.deepEqual(readLinks(state, otherDigest), { version: 1, recordDigest: otherDigest, revision: 0, entries: [] });
  assert.deepEqual(listLinks(state, otherDigest), { revision: 0, links: [] });
  assert.throws(() => getLiveLink(state, otherDigest, original.link.id, now), unauthorized);
  assert.deepEqual(state, before);
  const next = await createLink(state, otherDigest, input(), expiry, now);
  assert.equal(next.revision, 1); assert.equal(state.readerLinks.recordDigest, otherDigest);
  assert.equal(state.readerLinks.entries.length, 1); assert.notEqual(next.urlToken, original.urlToken);
});

test('link expiry must be in the future and cannot exceed the document deadline', async () => {
  for (const expiresAt of [null, undefined, 0, -1, now, now - 1, expiry + 1, Number.MAX_SAFE_INTEGER + 1, 8640000000000001, 1.5, String(expiry)]) {
    const state = {};
    await assert.rejects(createLink(state, digest, { ...input(), expiresAt }, expiry, now), invalid);
    assert.deepEqual(state, {});
  }
  assert.equal((await createLink({}, digest, input(), expiry, now)).link.expiresAt, expiry);
  for (const clock of [null, 0, 1.5, Infinity, Number.MAX_SAFE_INTEGER + 1]) {
    await assert.rejects(createLink({}, digest, input(), expiry, clock), invalid);
  }
  for (const deadline of [null, 0, 1.5, now, Infinity, Number.MAX_SAFE_INTEGER + 1]) {
    await assert.rejects(createLink({}, digest, input(), deadline, now), invalid);
  }
});

test('create rejects malformed payloads and extra fields without mutation', async () => {
  for (const value of [null, [], 'invalid', {}, { expiresAt: expiry }, { expectedRevision: 0, expiresAt: expiry },
    { ...input(), action: 'revoke' }, { ...input(), extra: true }, { ...input(), expectedRevision: -1 },
    { ...input(), expectedRevision: 1.5 }, { ...input(), expectedRevision: '0' },
    { ...input(), expectedRevision: Number.MAX_SAFE_INTEGER + 1 }]) {
    const state = {};
    await assert.rejects(createLink(state, digest, value, expiry, now), invalid);
    assert.deepEqual(state, {});
  }
});

test('stale revisions cannot create or revoke a current link', async () => {
  const state = {}, result = await createLink(state, digest, input(), expiry, now), before = structuredClone(state);
  await assert.rejects(createLink(state, digest, input(), expiry, now), changed);
  assert.throws(() => revokeLink(state, digest, revoke(result.link.id, 0)), changed);
  assert.deepEqual(state, before);
  assert.equal((await createLink(state, digest, input(1), expiry, now)).revision, 2);
});

test('individual revocation removes all of its sessions while preserving other readers', async () => {
  const state = {}, first = await createLink(state, digest, input(), expiry, now), second = await createLink(state, digest, input(1), expiry, now);
  state.sessions = [{ hash: '1'.repeat(64), linkId: first.link.id }, { hash: '2'.repeat(64), linkId: first.link.id },
    { hash: '3'.repeat(64), linkId: second.link.id }, { hash: '4'.repeat(64) }];
  const result = revokeLink(state, digest, revoke(first.link.id, 2));
  assert.equal(result.revision, 3); assert.equal(result.links[0].revoked, true);
  assert.deepEqual(state.sessions, [{ hash: '3'.repeat(64), linkId: second.link.id }, { hash: '4'.repeat(64) }]);
  assert.throws(() => getLiveLink(state, digest, first.link.id, now), unauthorized);
  assert.equal(getLiveLink(state, digest, second.link.id, now).id, second.link.id);
  assert.equal(revokeLink(state, digest, revoke(first.link.id, 3)).revision, 3);
});

test('revocation rejects invalid or unknown identifiers and cannot change the journal', async () => {
  const state = {}, result = await createLink(state, digest, input(), expiry, now), before = structuredClone(state);
  for (const value of [null, [], {}, { action: 'revoke' }, { ...revoke(result.link.id, 1), extra: true },
    { ...revoke(result.link.id, 1), action: 'create' }, revoke('invalid', 1), revoke(result.link.id, -1)]) {
    assert.throws(() => revokeLink(state, digest, value), invalid); assert.deepEqual(state, before);
  }
  assert.throws(() => revokeLink(state, digest, revoke(crypto.randomUUID(), 1)), error => error instanceof Denied && error.status === 404);
  assert.deepEqual(state, before);
});

test('twenty live links fill the bounded grant inventory', async () => {
  const state = {};
  for (let revision = 0; revision < MAX_READER_LINKS; revision++) await createLink(state, digest, input(revision), expiry, now);
  const before = structuredClone(state);
  await assert.rejects(createLink(state, digest, input(MAX_READER_LINKS), expiry, now), error => error instanceof Denied && error.status === 429 && error.code === 'link_limit');
  assert.deepEqual(state, before); assert.equal(state.readerLinks.entries.length, MAX_READER_LINKS);
});

test('revoked grants remain visible until capacity requires their removal', async () => {
  const state = {}, first = await createLink(state, digest, input(), expiry, now);
  revokeLink(state, digest, revoke(first.link.id, 1));
  for (let revision = 2; revision <= MAX_READER_LINKS; revision++) await createLink(state, digest, input(revision), expiry, now);
  assert.equal(state.readerLinks.entries.length, MAX_READER_LINKS);
  assert.equal(state.readerLinks.entries[0].id, first.link.id);
  const last = await createLink(state, digest, input(MAX_READER_LINKS + 1), expiry, now);
  assert.equal(last.revision, MAX_READER_LINKS + 2); assert.equal(state.readerLinks.entries.length, MAX_READER_LINKS);
  assert.ok(!state.readerLinks.entries.some(entry => entry.id === first.link.id));
});

test('expired grants free bounded capacity but remain unusable before pruning', async () => {
  const state = {};
  for (let revision = 0; revision < MAX_READER_LINKS; revision++) await createLink(state, digest, input(revision, now + 1), expiry, now);
  const expired = state.readerLinks.entries[0].id;
  assert.throws(() => getLiveLink(state, digest, expired, now + 1), unauthorized);
  await createLink(state, digest, input(MAX_READER_LINKS), expiry, now + 1);
  assert.equal(state.readerLinks.entries.length, 1); assert.ok(!state.readerLinks.entries.some(entry => entry.id === expired));
});

test('missing, malformed, expired and revoked live grants fail closed', async () => {
  const state = {}, result = await createLink(state, digest, input(), expiry, now);
  for (const id of [undefined, null, '', 'invalid', crypto.randomUUID()]) assert.throws(() => getLiveLink(state, digest, id, now), unauthorized);
  for (const at of [0, null, 1.5, Infinity, expiry, expiry + 1]) assert.throws(() => getLiveLink(state, digest, result.link.id, at), unauthorized);
  revokeLink(state, digest, revoke(result.link.id, 1));
  assert.throws(() => getLiveLink(state, digest, result.link.id, now), unauthorized);
});

test('malformed decrypted boxes cannot be ignored even after ciphertext replacement', async () => {
  const canonicalEntry = { id: crypto.randomUUID(), hash: 'c'.repeat(64), createdAt: now, expiresAt: expiry, revoked: false };
  const canonical = { version: 1, recordDigest: digest, revision: 1, entries: [canonicalEntry] };
  const badEntries = [null, [], {}, { ...canonicalEntry, extra: true }, { ...canonicalEntry, id: 'invalid' },
    { ...canonicalEntry, hash: 'C'.repeat(64) }, { ...canonicalEntry, createdAt: 0 }, { ...canonicalEntry, createdAt: 1.5 },
    { ...canonicalEntry, expiresAt: now }, { ...canonicalEntry, expiresAt: Infinity }, { ...canonicalEntry, revoked: 1 }];
  const boxes = [null, [], {}, { ...canonical, version: 2 }, { ...canonical, extra: true },
    { ...canonical, recordDigest: 'invalid' }, { ...canonical, revision: 0 }, { ...canonical, revision: 1.5 },
    { ...canonical, revision: Number.MAX_SAFE_INTEGER + 1 }, { ...canonical, entries: null },
    { ...canonical, entries: new Array(1) }, { ...canonical, entries: [canonicalEntry, canonicalEntry] },
    { ...canonical, entries: [canonicalEntry, { ...canonicalEntry, id: crypto.randomUUID() }] },
    { ...canonical, entries: Array.from({ length: MAX_READER_LINKS + 1 }, () => ({ ...canonicalEntry, id: crypto.randomUUID() })) },
    ...badEntries.map(entry => ({ ...canonical, entries: [entry] }))];
  for (const box of boxes) {
    const state = { readerLinks: box }, before = structuredClone(state);
    assert.throws(() => readLinks(state, digest), /invalid_journal/);
    assert.throws(() => readLinks(state, otherDigest), /invalid_journal/);
    await assert.rejects(createLink(state, digest, input(), expiry, now), /invalid_journal/);
    assert.deepEqual(state, before);
  }
});

test('invalid journal or digest arguments cannot initialize grants', async () => {
  for (const state of [null, [], 'invalid']) assert.throws(() => readLinks(state, digest), /invalid_journal/);
  for (const value of [null, '', 'a'.repeat(63), 'A'.repeat(64), 'g'.repeat(64), { toString: () => digest }]) {
    const state = {};
    assert.throws(() => readLinks(state, value), /invalid_journal/);
    await assert.rejects(createLink(state, value, input(), expiry, now), /invalid_journal/);
    assert.deepEqual(state, {});
  }
});

test('revision exhaustion cannot wrap or mutate a grant decision', async () => {
  const state = {}; await createLink(state, digest, input(), expiry, now);
  state.readerLinks.revision = Number.MAX_SAFE_INTEGER;
  const before = structuredClone(state);
  await assert.rejects(createLink(state, digest, input(Number.MAX_SAFE_INTEGER), expiry, now), /invalid_journal/);
  assert.throws(() => revokeLink(state, digest, revoke(state.readerLinks.entries[0].id, Number.MAX_SAFE_INTEGER)), /invalid_journal/);
  assert.deepEqual(state, before);
});
