import test from 'node:test';
import assert from 'node:assert/strict';
import { Denied } from '../src/http.js';
import { MAX_RECIPIENT_CONTACTS, MAX_RECIPIENT_EMAIL_BYTES, MAX_RECIPIENT_REQUEST_BYTES,
  normalizeContactEmail, readContacts, setContacts } from '../src/contacts.js';

const digest = 'a'.repeat(64), otherDigest = 'b'.repeat(64);
const invalidInput = error => error instanceof Denied && error.status === 400 && error.code === 'invalid_recipients';
const conflict = error => error instanceof Denied && error.status === 409 && error.code === 'recipients_changed';

test('contact addresses retain local-part case and normalize only the domain', () => {
  assert.equal(normalizeContactEmail(' Reader.Name+cv@EXAMPLE.Test '), 'Reader.Name+cv@example.test');
  assert.equal(normalizeContactEmail("a!#$%&'*+/=?^_`{|}~-@example.test"), "a!#$%&'*+/=?^_`{|}~-@example.test");
  assert.equal(normalizeContactEmail('reader@xn--bcher-kva.example'), 'reader@xn--bcher-kva.example');
});

test('contact addresses reject malformed, non-ASCII, control and display-name inputs', () => {
  for (const email of [undefined, null, 0, [], {}, '', ' ', 'reader', '@example.test', 'reader@',
    'reader@@example.test', '.reader@example.test', 'reader.@example.test', 'read..er@example.test',
    'read er@example.test', 'reader@example..test', 'reader@-example.test', 'reader@example-.test',
    'reader@example.test.', 'reader@_example.test', 'reader@[192.0.2.1]', '"reader"@example.test',
    'Reader <reader@example.test>', 'reader@example.test\r\nBcc:other@example.test', '\treader@example.test',
    'reader@exämple.test', '読者@example.test', '\u00a0reader@example.test', 'reader@example.test\u202e',
    'reader@' + 'a'.repeat(64) + '.test', 'a'.repeat(65) + '@example.test']) {
    assert.throws(() => normalizeContactEmail(email), invalidInput, String(email));
  }
});

test('address and request limits are bounded in ASCII bytes', () => {
  const email = 'a'.repeat(64) + '@' + ['b'.repeat(63), 'c'.repeat(63), 'd'.repeat(61)].join('.');
  assert.equal(email.length, MAX_RECIPIENT_EMAIL_BYTES);
  assert.equal(normalizeContactEmail(email), email);
  assert.throws(() => normalizeContactEmail(email + 'd'), invalidInput);
  assert.throws(() => normalizeContactEmail('  ' + email + '  '), invalidInput);
  const maximum = Array.from({ length: MAX_RECIPIENT_CONTACTS }, (_, index) => `${String(index).padStart(2, '0')}${email.slice(2)}`);
  assert.ok(Buffer.byteLength(JSON.stringify({ expectedRevision: Number.MAX_SAFE_INTEGER, emails: maximum })) < MAX_RECIPIENT_REQUEST_BYTES);
});

test('old journal records read as an empty contact list without mutation', () => {
  const state = { version: 1, events: [] }, before = structuredClone(state);
  assert.deepEqual(readContacts(state, digest), { revision: 0, emails: [] });
  assert.deepEqual(state, before);
  const empty = readContacts(state, digest); empty.emails.push('untrusted@example.test');
  assert.deepEqual(readContacts(state, digest), { revision: 0, emails: [] });
});

test('contact changes bind to the current ciphertext and return independent copies', () => {
  const state = { events: [{ id: 'synthetic-event' }] };
  const input = { expectedRevision: 0, emails: ['Reader@EXAMPLE.TEST', 'reader@example.test'] };
  const result = setContacts(state, digest, input);
  assert.deepEqual(result, { revision: 1, emails: ['Reader@example.test', 'reader@example.test'] });
  assert.deepEqual(state.recipientContacts, { recordDigest: digest, ...result });
  assert.deepEqual(state.events, [{ id: 'synthetic-event' }]);
  input.emails[0] = 'input-change@example.test'; result.emails[0] = 'result-change@example.test';
  const read = readContacts(state, digest); read.emails[0] = 'read-change@example.test';
  assert.equal(state.recipientContacts.emails[0], 'Reader@example.test');
  assert.deepEqual(setContacts(state, digest, { expectedRevision: 1, emails: [] }), { revision: 2, emails: [] });
});

test('duplicate normalized addresses and oversized lists cannot change the journal', () => {
  for (const emails of [['reader@example.test', 'reader@EXAMPLE.TEST'], ['reader@example.test', ' reader@example.test '],
    Array.from({ length: MAX_RECIPIENT_CONTACTS + 1 }, (_, index) => `reader${index}@example.test`)]) {
    const state = {};
    assert.throws(() => setContacts(state, digest, { expectedRevision: 0, emails }), invalidInput);
    assert.deepEqual(state, {});
  }
  const state = {}, emails = Array.from({ length: MAX_RECIPIENT_CONTACTS }, (_, index) => `reader${index}@example.test`);
  assert.deepEqual(setContacts(state, digest, { expectedRevision: 0, emails }), { revision: 1, emails });
});

test('a stale revision cannot overwrite the current recipient decision', () => {
  const state = {};
  setContacts(state, digest, { expectedRevision: 0, emails: ['first@example.test'] });
  const before = structuredClone(state);
  assert.throws(() => setContacts(state, digest, { expectedRevision: 0, emails: ['stale@example.test'] }), conflict);
  assert.deepEqual(state, before);
  assert.equal(setContacts(state, digest, { expectedRevision: 1, emails: ['next@example.test'] }).revision, 2);
});

test('contact mutations reject extra fields and invalid revisions or lists', () => {
  for (const input of [null, [], 'invalid', {}, { emails: [] }, { expectedRevision: 0 },
    { expectedRevision: 0, emails: [], extra: true }, { expectedRevision: -1, emails: [] },
    { expectedRevision: 1.5, emails: [] }, { expectedRevision: '0', emails: [] },
    { expectedRevision: Number.MAX_SAFE_INTEGER + 1, emails: [] }, { expectedRevision: 0, emails: null },
    { expectedRevision: 0, emails: new Array(1) },
    { expectedRevision: 0, emails: ['reader@example.test', 'malformed'] }]) {
    const state = {};
    assert.throws(() => setContacts(state, digest, input), invalidInput);
    assert.deepEqual(state, {});
  }
});

test('malformed stored contacts and ciphertext mismatches fail closed', () => {
  const canonical = { recordDigest: digest, revision: 1, emails: ['reader@example.test'] };
  for (const contacts of [null, [], {}, { ...canonical, extra: true }, { ...canonical, recordDigest: otherDigest },
    { ...canonical, revision: 0 }, { ...canonical, revision: -1 }, { ...canonical, revision: 1.5 },
    { ...canonical, revision: Number.MAX_SAFE_INTEGER + 1 }, { ...canonical, emails: null },
    { ...canonical, emails: new Array(1) },
    { ...canonical, emails: ['reader@EXAMPLE.TEST'] }, { ...canonical, emails: [' reader@example.test'] },
    { ...canonical, emails: ['reader@example.test', 'reader@example.test'] }]) {
    const state = { recipientContacts: contacts }, before = structuredClone(state);
    assert.throws(() => readContacts(state, digest), /invalid_journal/);
    assert.throws(() => setContacts(state, digest, { expectedRevision: 1, emails: [] }), /invalid_journal/);
    assert.deepEqual(state, before);
  }
  const state = { recipientContacts: canonical };
  assert.throws(() => readContacts(state, otherDigest), /invalid_journal/);
  assert.throws(() => setContacts(state, otherDigest, { expectedRevision: 1, emails: [] }), /invalid_journal/);
});

test('invalid journal or digest arguments cannot initialize recipient contacts', () => {
  for (const state of [null, [], 'invalid']) assert.throws(() => readContacts(state, digest), /invalid_journal/);
  for (const invalidDigest of [null, '', 'a'.repeat(63), 'A'.repeat(64), 'g'.repeat(64), { toString: () => digest }]) {
    const state = {};
    assert.throws(() => readContacts(state, invalidDigest), /invalid_journal/);
    assert.throws(() => setContacts(state, invalidDigest, { expectedRevision: 0, emails: [] }), /invalid_journal/);
    assert.deepEqual(state, {});
  }
});

test('revision exhaustion cannot wrap the journal revision', () => {
  const state = { recipientContacts: { recordDigest: digest, revision: Number.MAX_SAFE_INTEGER, emails: [] } };
  const before = structuredClone(state);
  assert.throws(() => setContacts(state, digest, { expectedRevision: Number.MAX_SAFE_INTEGER, emails: [] }), /invalid_journal/);
  assert.deepEqual(state, before);
});

test('serialized contacts preserve revision and addresses without creating grants', () => {
  const state = { version: 1, sessions: [], events: [] };
  setContacts(state, digest, { expectedRevision: 0, emails: ['Reader@example.test'] });
  const restarted = JSON.parse(JSON.stringify(state));
  assert.deepEqual(readContacts(restarted, digest), { revision: 1, emails: ['Reader@example.test'] });
  assert.deepEqual(Object.keys(restarted).sort(), ['events', 'recipientContacts', 'sessions', 'version']);
});
