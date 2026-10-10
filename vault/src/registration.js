import { identity } from './auth.js';
import { UUID, MAX_PDF_BYTES, MAX_RECORD_BYTES, importKey, sealDocument, sealJSON, openJSON,
  unb64, utf8, parseJSON, boundedBody } from './crypto.js';
import { Denied, failure, json, origin, dummyPin } from './http.js';

export const MAX_REGISTRATIONS = 20;
export const MAX_REGISTRATION_BODY = 1536 * 1024;
const STATE_KEY = 'encrypted-registration';
const FIELDS = ['id', 'pdfBase64', 'fileName', 'expiresAt', 'replaceOf', 'expectedRevision'];
const RECORD_FIELDS = ['id', 'createdAt', 'expiresAt', 'size', 'replaceOf', 'status', 'fileName', 'recordSha256'];
const SHA256 = /^[0-9a-f]{64}$/;
const unsafeName = /[\u0000-\u001f\u007f-\u009f\u061c\u200e\u200f\u2028\u2029\u202a-\u202e\u2066-\u2069\\/]/u;
const timestamp = value => Number.isSafeInteger(value) && value > 0 && value <= 8640000000000000;
const exactKeys = (value, keys) => value && typeof value === 'object' && !Array.isArray(value) &&
  Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));

function fileName(value) {
  if (typeof value !== 'string' || !value.isWellFormed() || unsafeName.test(value)) throw new Denied(400, 'invalid_request');
  const normalized = value.normalize('NFC').trim();
  if (!normalized || normalized.length > 120) throw new Denied(400, 'invalid_request');
  return normalized;
}

// Uploads use an owner-only bounded reader. Raising the public password/body
// limits to accept PDF files would undo the existing unauthenticated safeguards.
export async function registrationBody(request, timeoutMs = 10000) {
  const declared = request.headers.get('content-length');
  if (declared && (!/^\d+$/.test(declared) || Number(declared) > MAX_REGISTRATION_BODY)) throw new Denied(400, 'invalid_request');
  if (!request.body) throw new Denied(400, 'invalid_request');
  const reader = request.body.getReader(), chunks = [];
  let length = 0, timer;
  const deadline = new Promise((_, reject) => { timer = setTimeout(() => reject(new Denied(408, 'request_timeout')), timeoutMs); });
  try {
    while (true) {
      const { done, value } = await Promise.race([reader.read(), deadline]);
      if (done) break;
      length += value.byteLength;
      if (length > MAX_REGISTRATION_BODY) throw new Denied(400, 'invalid_request');
      chunks.push(value);
    }
    const bytes = new Uint8Array(length);
    let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
    try { return parseJSON(bytes); }
    catch { throw new Denied(400, 'invalid_request'); }
    finally { bytes.fill(0); }
  } catch (error) {
    // Do not wait for a source that ignores cancellation.
    void reader.cancel().catch(() => {});
    throw error;
  } finally {
    clearTimeout(timer); reader.releaseLock();
    for (const chunk of chunks) chunk.fill(0);
  }
}

function summary(state) {
  return { revision: state.revision, documents: state.documents.map(({ recordSha256, ...document }) => document),
    pending: state.reservations.length };
}

// This registry stores private candidates only. It has no activation, document
// download or notification path, and never changes the current dummy pin.
export class VaultRegistrations {
  constructor(ctx, env) {
    this.ctx = ctx; this.env = env; this.tail = Promise.resolve();
    this.context = `registration:v1:${ctx.id.toString()}`;
  }
  serial(operation) {
    const next = this.tail.then(operation, operation);
    this.tail = next.catch(() => {}); return next;
  }
  async keys() {
    const wrap = this.env.VAULT_WRAP_KEY, audit = this.env.VAULT_AUDIT_KEY;
    if (!wrap || wrap === audit) throw new Error('configuration');
    return { wrap: await importKey(wrap), audit: await importKey(audit) };
  }
  async state(storage, audit, pin) {
    const box = await storage.get(STATE_KEY);
    if (!box) return { version: 1, revision: 0, documents: [], reservations: [] };
    const state = await openJSON(box, audit, this.context);
    if (!exactKeys(state, ['version', 'revision', 'documents', 'reservations']) || state.version !== 1 ||
        !Number.isSafeInteger(state.revision) || state.revision < 0 || !Array.isArray(state.documents) || !Array.isArray(state.reservations) ||
        state.documents.length + state.reservations.length > MAX_REGISTRATIONS ||
        state.revision !== 2 * state.documents.length + state.reservations.length) throw new Error('invalid_registry');
    const ids = new Set();
    for (const [entries, status] of [[state.documents, 'private'], [state.reservations, 'pending']]) for (const entry of entries) {
      if (!exactKeys(entry, RECORD_FIELDS) || !UUID.test(entry.id) || entry.id === pin.id || ids.has(entry.id) ||
          !timestamp(entry.createdAt) || !timestamp(entry.expiresAt) || !Number.isSafeInteger(entry.size) ||
          entry.size < 5 || entry.size > MAX_PDF_BYTES || !(entry.replaceOf === null || entry.replaceOf === pin.id) ||
          entry.status !== status || !SHA256.test(entry.recordSha256)) throw new Error('invalid_registry');
      try { if (fileName(entry.fileName) !== entry.fileName) throw new Error(); }
      catch { throw new Error('invalid_registry'); }
      ids.add(entry.id);
    }
    return state;
  }
  check(state, input) {
    if ([...state.documents, ...state.reservations].some(document => document.id === input.id)) throw new Denied(409, 'registration_exists');
    if (state.revision !== input.expectedRevision) throw new Denied(409, 'registration_changed');
    if (state.documents.length + state.reservations.length >= MAX_REGISTRATIONS) throw new Denied(429, 'registration_limit');
  }
  async fetch(request) {
    let input, bytes;
    try {
      const url = new URL(request.url);
      if (url.origin !== origin(this.env) || url.search || url.pathname !== '/v1/registrations') throw new Denied();
      let subject;
      try { subject = await identity(request, this.env); } catch { throw new Denied(401, 'unauthenticated'); }
      if (typeof this.env.VAULT_OWNER_SUB !== 'string' || !this.env.VAULT_OWNER_SUB || this.env.VAULT_OWNER_SUB.length > 256) throw new Error('configuration');
      if (subject !== this.env.VAULT_OWNER_SUB) throw new Denied();
      if (!['GET', 'POST'].includes(request.method)) throw new Denied(405, 'method_not_allowed');
      const pin = dummyPin(this.env);
      if (request.method === 'GET') {
        const keys = await this.keys();
        return await this.serial(async () => json(summary(await this.state(this.ctx.storage, keys.audit, pin))));
      }
      if (request.headers.get('origin') !== url.origin || request.headers.get('content-type') !== 'application/json' ||
          ['cross-site', 'same-site'].includes(request.headers.get('sec-fetch-site'))) throw new Denied();
      input = await registrationBody(request);
      if (!exactKeys(input, FIELDS) || !UUID.test(input.id) || input.id === pin.id ||
          !timestamp(input.expiresAt) || input.expiresAt <= Date.now() ||
          !(input.replaceOf === null || input.replaceOf === pin.id) ||
          !Number.isSafeInteger(input.expectedRevision) || input.expectedRevision < 0) throw new Denied(400, 'invalid_request');
      input.fileName = fileName(input.fileName);
      try { bytes = unb64(input.pdfBase64, MAX_PDF_BYTES); }
      catch { throw new Denied(400, 'invalid_request'); }
      input.pdfBase64 = '';
      if (bytes.length < 5 || String.fromCharCode(...bytes.subarray(0, 5)) !== '%PDF-') throw new Denied(400, 'invalid_pdf');
      const keys = await this.keys();
      return await this.serial(async () => {
        const before = await this.state(this.ctx.storage, keys.audit, pin);
        this.check(before, input);
        if (input.expiresAt <= Date.now()) throw new Denied(400, 'invalid_request');
        const record = await sealDocument({ id: input.id, bytes, subjects: [subject],
          expiresAt: input.expiresAt, authMode: 'access' }, keys.wrap);
        bytes.fill(0);
        const serialized = utf8(JSON.stringify(record));
        const digestBytes = await crypto.subtle.digest('SHA-256', serialized);
        const digest = Array.from(new Uint8Array(digestBytes), b => b.toString(16).padStart(2, '0')).join('');
        const reservation = { id: input.id, createdAt: Date.now(), expiresAt: input.expiresAt, size: bytes.byteLength,
          replaceOf: input.replaceOf, status: 'pending', fileName: input.fileName, recordSha256: digest };
        // Every possible R2 write consumes a durable encrypted slot first.
        // Failed or uncertain operations retain it; retries cannot create an
        // unlimited set of unlisted ciphertext objects.
        const reservedRevision = await this.ctx.storage.transaction(async tx => {
          const latest = await this.state(tx, keys.audit, pin);
          this.check(latest, input);
          if (input.expiresAt <= Date.now()) throw new Denied(400, 'invalid_request');
          latest.reservations.push(reservation); latest.revision++;
          await tx.put(STATE_KEY, await sealJSON(latest, keys.audit, this.context));
          return latest.revision;
        });
        const name = `staging/${input.id}.sealed.json`;
        const stored = await this.env.VAULT_DOCUMENTS.put(name, serialized, { sha256: digestBytes,
          onlyIf: new Headers({ 'if-none-match': '*' }),
          httpMetadata: { contentType: 'application/json', cacheControl: 'private, no-store' } });
        if (!stored) throw new Denied(409, 'registration_exists');
        const object = await this.env.VAULT_DOCUMENTS.get(name);
        if (!object || !Number.isSafeInteger(object.size) || object.size !== serialized.byteLength || object.size > MAX_RECORD_BYTES) throw new Error('registration_readback');
        const readback = await boundedBody(new Response(object.body), MAX_RECORD_BYTES);
        const actual = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', readback)), b => b.toString(16).padStart(2, '0')).join('');
        if (actual !== digest) throw new Error('registration_readback');
        const result = await this.ctx.storage.transaction(async tx => {
          const latest = await this.state(tx, keys.audit, pin);
          if (latest.revision !== reservedRevision) throw new Denied(409, 'registration_changed');
          const index = latest.reservations.findIndex(entry => entry.id === input.id && entry.recordSha256 === digest);
          if (index < 0 || latest.documents.some(entry => entry.id === input.id)) throw new Error('registration_reservation');
          if (input.expiresAt <= Date.now()) throw new Denied(400, 'invalid_request');
          latest.documents.push({ ...latest.reservations[index], status: 'private' });
          latest.reservations.splice(index, 1); latest.revision++;
          await tx.put(STATE_KEY, await sealJSON(latest, keys.audit, this.context));
          return summary(latest);
        });
        return json(result, 201);
      });
    } catch (error) { return failure(error); }
    finally { bytes?.fill(0); if (input && typeof input === 'object') input.pdfBase64 = ''; }
  }
}
