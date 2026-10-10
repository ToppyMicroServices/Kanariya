import { Denied } from './http.js';
import { randomToken, hashToken } from './password.js';

export const MAX_READER_LINKS = 20;
const DIGEST = /^[0-9a-f]{64}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const exact = (value, keys) => !!value && typeof value === 'object' && !Array.isArray(value) &&
  Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
const timestamp = value => Number.isSafeInteger(value) && value > 0 && value <= 8640000000000000;
const publicLink = ({ id, createdAt, expiresAt, revoked }) => ({ id, createdAt, expiresAt, revoked });

// This box lives inside the encrypted journal. Even after decrypting that
// journal, only the digest of a reader's URL credential remains available.
export function readLinks(state, digest) {
  if (!state || typeof state !== 'object' || Array.isArray(state) || typeof digest !== 'string' || !DIGEST.test(digest)) throw new Error('invalid_journal');
  const empty = () => ({ version: 1, recordDigest: digest, revision: 0, entries: [] });
  if (!Object.hasOwn(state, 'readerLinks')) return empty();
  const box = state.readerLinks;
  if (!exact(box, ['version', 'recordDigest', 'revision', 'entries']) || box.version !== 1 ||
      typeof box.recordDigest !== 'string' || !DIGEST.test(box.recordDigest) ||
      !Number.isSafeInteger(box.revision) || box.revision < 1 || !Array.isArray(box.entries) ||
      box.entries.length > MAX_READER_LINKS) throw new Error('invalid_journal');
  const ids = new Set(), hashes = new Set();
  for (const entry of box.entries) {
    if (!exact(entry, ['id', 'hash', 'createdAt', 'expiresAt', 'revoked']) ||
        typeof entry.id !== 'string' || !UUID.test(entry.id) || typeof entry.hash !== 'string' || !DIGEST.test(entry.hash) ||
        !timestamp(entry.createdAt) || !timestamp(entry.expiresAt) || entry.expiresAt <= entry.createdAt ||
        typeof entry.revoked !== 'boolean' || ids.has(entry.id) || hashes.has(entry.hash)) throw new Error('invalid_journal');
    ids.add(entry.id); hashes.add(entry.hash);
  }
  // Replacing the sealed document invalidates every old link. Never carry a
  // credential across ciphertext versions, even when the document ID is reused.
  return box.recordDigest === digest ? structuredClone(box) : empty();
}

export function listLinks(state, digest) {
  const box = readLinks(state, digest);
  return { revision: box.revision, links: box.entries.map(publicLink) };
}

function revision(input, current, keys, action) {
  if (!exact(input, keys) || input.action !== action || !Number.isSafeInteger(input.expectedRevision) || input.expectedRevision < 0) {
    throw new Denied(400, 'invalid_links');
  }
  if (input.expectedRevision !== current.revision) throw new Denied(409, 'links_changed');
  if (current.revision === Number.MAX_SAFE_INTEGER) throw new Error('invalid_journal');
}

export async function createLink(state, digest, input, documentExpiresAt, now = Date.now()) {
  const box = readLinks(state, digest);
  revision(input, box, ['action', 'expiresAt', 'expectedRevision'], 'create');
  if (!timestamp(now) || !timestamp(documentExpiresAt) || !timestamp(input.expiresAt) ||
      input.expiresAt <= now || input.expiresAt > documentExpiresAt) throw new Denied(400, 'invalid_links');
  if (box.entries.length >= MAX_READER_LINKS) box.entries = box.entries.filter(entry => !entry.revoked && entry.expiresAt > now);
  if (box.entries.length >= MAX_READER_LINKS) throw new Denied(429, 'link_limit');
  const urlToken = randomToken(), entry = { id: crypto.randomUUID(), hash: await hashToken(urlToken),
    createdAt: now, expiresAt: input.expiresAt, revoked: false };
  box.entries.push(entry); box.revision++;
  state.readerLinks = box;
  return { revision: box.revision, link: publicLink(entry), urlToken };
}

export function revokeLink(state, digest, input) {
  const box = readLinks(state, digest);
  revision(input, box, ['action', 'linkId', 'expectedRevision'], 'revoke');
  if (typeof input.linkId !== 'string' || !UUID.test(input.linkId)) throw new Denied(400, 'invalid_links');
  const link = box.entries.find(entry => entry.id === input.linkId);
  if (!link) throw new Denied(404, 'link_not_found');
  if (!link.revoked) { link.revoked = true; box.revision++; }
  if (state.sessions !== undefined) {
    if (!Array.isArray(state.sessions)) throw new Error('invalid_journal');
    state.sessions = state.sessions.filter(session => session.linkId !== link.id);
  }
  state.readerLinks = box;
  return listLinks(state, digest);
}

export function getLiveLink(state, digest, linkId, now = Date.now()) {
  const box = readLinks(state, digest);
  const entry = box.entries.find(link => link.id === linkId);
  if (!timestamp(now) || typeof linkId !== 'string' || !UUID.test(linkId) || !entry || entry.revoked || entry.expiresAt <= now) {
    throw new Denied(401, 'unauthenticated');
  }
  return entry;
}
