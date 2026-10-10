import { identity } from './auth.js';
import { UUID, MAX_PDF_BYTES, MAX_RECORD_BYTES, importKey, sealDocument, sealJSON, openJSON,
  readPolicy, decryptDocument, validatePolicy, unb64, utf8, parseJSON, boundedBody } from './crypto.js';
import { Denied, failure, json, origin, dummyPin, requestBody } from './http.js';
import { normalizeRecipientName } from './recipient.js';

export const MAX_REGISTRATIONS = 20;
export const MAX_REGISTRATION_BODY = 1536 * 1024;
const STATE_KEY = 'encrypted-registration';
const FIELDS = ['id', 'pdfBase64', 'fileName', 'expiresAt', 'replaceOf', 'expectedRevision'];
const RECORD_FIELDS = ['id', 'createdAt', 'expiresAt', 'size', 'replaceOf', 'status', 'fileName', 'recordSha256'];
const PREPARATION_FIELDS = ['recipient', 'watermarkEnabled', 'sourceSha256', 'preparedSha256', 'preparationVersion'];
const PREPARED_FIELDS = [...FIELDS, ...PREPARATION_FIELDS];
const PREPARED_RECORD_FIELDS = [...RECORD_FIELDS, ...PREPARATION_FIELDS];
const RECIPIENT_FIELDS = ['type', 'organizationName', 'personName'];
const REPLACEMENT_ROUTE = /^\/v1\/registrations\/([0-9a-f-]{36})\/replacement$/;
const REPLACEMENT_FIELDS = ['expectedRevision', 'currentDocumentId'];
const RECEIPT_FIELDS = ['version', 'id', 'currentDocumentId', 'currentRecordSha256', 'candidateRecordSha256',
  'recordSha256', 'registryRevision', 'createdAt', 'policy'];
const SHA256 = /^[0-9a-f]{64}$/;
const unsafeName = /[\u0000-\u001f\u007f-\u009f\u061c\u200e\u200f\u2028\u2029\u202a-\u202e\u2066-\u2069\\/]/u;
const timestamp = value => Number.isSafeInteger(value) && value > 0 && value <= 8640000000000000;
const exactKeys = (value, keys) => value && typeof value === 'object' && !Array.isArray(value) &&
  Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
const sha256 = async bytes => Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)), b => b.toString(16).padStart(2, '0')).join('');
async function replacementWait(operation) {
  let timer;
  try { return await Promise.race([operation, new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Denied(408, 'request_timeout')), 5000);
  })]); } finally { clearTimeout(timer); }
}
async function replacementBytes(response, url, max) {
  const ready = await requestBody(new Request(url, { method: 'POST', headers: response.headers, body: response.body, duplex: 'half' }), 5000, max);
  return boundedBody(new Response(ready.body), max);
}

function fileName(value) {
  if (typeof value !== 'string' || !value.isWellFormed() || unsafeName.test(value)) throw new Denied(400, 'invalid_request');
  const normalized = value.normalize('NFC').trim();
  if (!normalized || normalized.length > 120) throw new Denied(400, 'invalid_request');
  return normalized;
}

function preparation(value) {
  const recipient = value.recipient;
  if (!exactKeys(recipient, RECIPIENT_FIELDS) || !['organization', 'person'].includes(recipient.type) ||
      typeof value.watermarkEnabled !== 'boolean' || value.preparationVersion !== 1 ||
      typeof value.sourceSha256 !== 'string' || !SHA256.test(value.sourceSha256) ||
      typeof value.preparedSha256 !== 'string' || !SHA256.test(value.preparedSha256) ||
      (recipient.type === 'organization' && recipient.organizationName === null) ||
      (recipient.type === 'person' && (recipient.organizationName !== null || recipient.personName === null))) throw new Error('invalid_preparation');
  const normalized = { type: recipient.type,
    organizationName: recipient.organizationName === null ? null : normalizeRecipientName(recipient.organizationName),
    personName: recipient.personName === null ? null : normalizeRecipientName(recipient.personName) };
  const recipientName = normalizeRecipientName([normalized.organizationName, normalized.personName].filter(name => name !== null).join(' '));
  return { recipientName, metadata: { recipient: normalized, watermarkEnabled: value.watermarkEnabled,
    sourceSha256: value.sourceSha256, preparedSha256: value.preparedSha256, preparationVersion: 1 } };
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

// Candidates and replacement receipts remain private. Preparing a canonical
// record never changes the exact pin that admits public document requests.
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
      const prepared = exactKeys(entry, PREPARED_RECORD_FIELDS);
      if ((!exactKeys(entry, RECORD_FIELDS) && !prepared) || !UUID.test(entry.id) || ids.has(entry.id) ||
          !timestamp(entry.createdAt) || !timestamp(entry.expiresAt) || !Number.isSafeInteger(entry.size) ||
          entry.size < 5 || entry.size > MAX_PDF_BYTES || !(entry.replaceOf === null || UUID.test(entry.replaceOf) && entry.replaceOf !== entry.id) ||
          entry.status !== status || !SHA256.test(entry.recordSha256)) throw new Error('invalid_registry');
      try {
        if (fileName(entry.fileName) !== entry.fileName) throw new Error();
        if (prepared) {
          const { metadata } = preparation(entry);
          if (RECIPIENT_FIELDS.some(key => entry.recipient[key] !== metadata.recipient[key])) throw new Error();
        }
      }
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
  samePin(pin) {
    const current = dummyPin(this.env);
    if (current.id !== pin.id || current.digest !== pin.digest) throw new Denied(409, 'replacement_changed');
  }
  async record(name, digest, optional = false) {
    const object = await replacementWait(this.env.VAULT_DOCUMENTS.get(name));
    if (!object) { if (optional) return null; throw new Denied(409, 'replacement_changed'); }
    if (!Number.isSafeInteger(object.size) || object.size < 1 || object.size > MAX_RECORD_BYTES) throw new Error('invalid_replacement_record');
    const bytes = await replacementBytes(new Response(object.body), origin(this.env), MAX_RECORD_BYTES);
    try {
      if (bytes.byteLength !== object.size || await sha256(bytes) !== digest) throw new Denied(409, 'replacement_changed');
      return parseJSON(bytes);
    } finally { bytes.fill(0); }
  }
  async receipt(storage, audit, entry, state) {
    const box = await storage.get(`encrypted-replacement:${entry.id}`);
    if (!box) return null;
    const value = await openJSON(box, audit, `${this.context}:replacement:v1:${entry.id}`);
    if (!exactKeys(value, RECEIPT_FIELDS) || value.version !== 1 || value.id !== entry.id ||
        value.currentDocumentId !== entry.replaceOf || !UUID.test(value.currentDocumentId) || value.currentDocumentId === value.id ||
        !SHA256.test(value.currentRecordSha256) || value.candidateRecordSha256 !== entry.recordSha256 ||
        !SHA256.test(value.recordSha256) || !Number.isSafeInteger(value.registryRevision) || value.registryRevision < 2 ||
        value.registryRevision > state.revision || !timestamp(value.createdAt) || value.createdAt < entry.createdAt ||
        !exactKeys(value.policy, ['nonce', 'ciphertext']) || utf8(JSON.stringify(value)).byteLength > 64 * 1024) throw new Error('invalid_replacement_receipt');
    return value;
  }
  manifest(receipt, entry, policy) {
    const prepared = preparation(entry);
    return { version: 1, status: 'prepared_not_active', id: entry.id,
      currentDocumentId: receipt.currentDocumentId, currentRecordSha256: receipt.currentRecordSha256,
      recordSha256: receipt.recordSha256, preparedSha256: entry.preparedSha256, sourceSha256: entry.sourceSha256,
      recipient: prepared.metadata.recipient, recipientName: prepared.recipientName, watermarkEnabled: entry.watermarkEnabled,
      expiresAt: entry.expiresAt, authMode: policy.authMode ?? 'access', registryRevision: receipt.registryRevision, createdAt: receipt.createdAt };
  }
  async replacement(request, id, subject, pin) {
    let input = null, plaintext;
    if (request.method === 'POST') {
      const ready = await requestBody(request, 5000, 2048);
      try { input = parseJSON(await boundedBody(new Response(ready.body), 2048)); }
      catch { throw new Denied(400, 'invalid_request'); }
      if (!exactKeys(input, REPLACEMENT_FIELDS) || !Number.isSafeInteger(input.expectedRevision) || input.expectedRevision < 0 ||
          !UUID.test(input.currentDocumentId)) throw new Denied(400, 'invalid_request');
      if (input.currentDocumentId !== pin.id) throw new Denied(409, 'replacement_changed');
    }
    const keys = await this.keys();
    try {
      return await this.serial(async () => {
        this.samePin(pin);
        const state = await this.state(this.ctx.storage, keys.audit, pin);
        const entry = state.documents.find(row => row.id === id);
        if (!entry || !exactKeys(entry, PREPARED_RECORD_FIELDS) || entry.replaceOf !== pin.id || id === pin.id) throw new Denied(409, 'replacement_changed');
        if (input && input.expectedRevision !== state.revision) throw new Denied(409, 'registration_changed');
        if (entry.expiresAt <= Date.now()) throw new Denied();
        const candidate = await this.record(`staging/${id}.sealed.json`, entry.recordSha256);
        const current = await this.record(`${pin.id}.sealed.json`, pin.digest);
        this.samePin(pin);
        const candidatePolicy = await readPolicy(candidate, id, keys.wrap), currentPolicy = await readPolicy(current, pin.id, keys.wrap);
        const prepared = preparation(entry), mode = currentPolicy.authMode ?? 'access';
        if ((candidatePolicy.authMode ?? 'access') !== 'access' || candidatePolicy.subjects.length !== 1 || candidatePolicy.subjects[0] !== subject ||
            candidatePolicy.revoked || candidatePolicy.size !== entry.size || candidatePolicy.expiresAt !== entry.expiresAt ||
            candidatePolicy.recipientName !== prepared.recipientName || currentPolicy.revoked || currentPolicy.expiresAt <= Date.now()) throw new Denied();
        const metadataRequest = new Request(`${origin(this.env)}/v1/documents/${pin.id}/metadata`, { headers: request.headers });
        const metadataResponse = await replacementWait(this.env.VAULT.get(this.env.VAULT.idFromName(pin.id)).fetch(metadataRequest));
        if (!metadataResponse.ok) throw new Denied();
        const metadataBytes = await replacementBytes(metadataResponse, origin(this.env), 4096);
        let metadata;
        try { metadata = parseJSON(metadataBytes); } finally { metadataBytes.fill(0); }
        if (metadata.id !== pin.id || metadata.authMode !== mode || metadata.revoked !== false || !timestamp(metadata.expiresAt) ||
            metadata.expiresAt <= Date.now() || metadata.expiresAt > currentPolicy.expiresAt) throw new Denied();
        plaintext = await decryptDocument(candidate, keys.wrap, candidatePolicy);
        if (await sha256(plaintext) !== entry.preparedSha256) throw new Denied(409, 'replacement_changed');
        plaintext.fill(0); plaintext = null;
        this.samePin(pin);
        let receipt = await this.receipt(this.ctx.storage, keys.audit, entry, state);
        if (receipt && (receipt.currentDocumentId !== pin.id || receipt.currentRecordSha256 !== pin.digest)) throw new Denied(409, 'replacement_changed');
        const policy = validatePolicy({ mime: candidatePolicy.mime, size: candidatePolicy.size, subjects: [...currentPolicy.subjects],
          expiresAt: entry.expiresAt, revoked: false, authMode: mode, recipientName: prepared.recipientName,
          ...(mode === 'password' ? { passwordVerifier: currentPolicy.passwordVerifier } : {}) });
        let created = false;
        if (!receipt) {
          if (!input) return json({ replacement: null });
          const record = { version: 2, id, policy: await sealJSON(policy, keys.wrap, `policy:v2:${id}`),
            wrappedKey: candidate.wrappedKey, document: candidate.document };
          receipt = { version: 1, id, currentDocumentId: pin.id, currentRecordSha256: pin.digest,
            candidateRecordSha256: entry.recordSha256, recordSha256: await sha256(utf8(JSON.stringify(record))),
            registryRevision: state.revision, createdAt: Date.now(), policy: record.policy };
          if (utf8(JSON.stringify(receipt)).byteLength > 64 * 1024) throw new Error('replacement_receipt_limit');
          await this.ctx.storage.transaction(async tx => {
            this.samePin(pin);
            const latest = await this.state(tx, keys.audit, pin);
            if (latest.revision !== input.expectedRevision) throw new Denied(409, 'registration_changed');
            if (await tx.get(`encrypted-replacement:${id}`)) throw new Denied(409, 'replacement_changed');
            if (entry.expiresAt <= Date.now()) throw new Denied();
            await tx.put(`encrypted-replacement:${id}`, await sealJSON(receipt, keys.audit, `${this.context}:replacement:v1:${id}`));
          });
          created = true;
        }
        const record = { version: 2, id, policy: receipt.policy, wrappedKey: candidate.wrappedKey, document: candidate.document };
        if (await sha256(utf8(JSON.stringify(record))) !== receipt.recordSha256) throw new Error('invalid_replacement_receipt');
        const preparedPolicy = await readPolicy(record, id, keys.wrap);
        if (JSON.stringify(preparedPolicy) !== JSON.stringify(policy)) throw new Denied(409, 'replacement_changed');
        let final = await this.record(`${id}.sealed.json`, receipt.recordSha256, true);
        if (input && !final) {
          this.samePin(pin);
          const latest = await this.state(this.ctx.storage, keys.audit, pin);
          if (latest.revision !== input.expectedRevision) throw new Denied(409, 'registration_changed');
          if (entry.expiresAt <= Date.now()) throw new Denied();
          const bytes = utf8(JSON.stringify(record));
          try {
            await this.env.VAULT_DOCUMENTS.put(`${id}.sealed.json`, bytes, { sha256: new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)),
              onlyIf: new Headers({ 'if-none-match': '*' }), httpMetadata: { contentType: 'application/json', cacheControl: 'private, no-store' } });
          } finally { bytes.fill(0); }
          final = await this.record(`${id}.sealed.json`, receipt.recordSha256);
        }
        this.samePin(pin);
        const latest = await this.state(this.ctx.storage, keys.audit, pin);
        if (input && latest.revision !== input.expectedRevision) throw new Denied(409, 'registration_changed');
        if (entry.expiresAt <= Date.now() || currentPolicy.expiresAt <= Date.now() || metadata.expiresAt <= Date.now()) throw new Denied();
        return json({ replacement: final ? this.manifest(receipt, entry, preparedPolicy) : null }, created ? 201 : 200);
      });
    } finally { plaintext?.fill(0); }
  }
  async fetch(request) {
    let input, bytes;
    try {
      const url = new URL(request.url);
      const replacement = REPLACEMENT_ROUTE.exec(url.pathname);
      if (url.origin !== origin(this.env) || url.search || (url.pathname !== '/v1/registrations' && (!replacement || !UUID.test(replacement[1])))) throw new Denied();
      let subject;
      try { subject = await identity(request, this.env); } catch { throw new Denied(401, 'unauthenticated'); }
      if (typeof this.env.VAULT_OWNER_SUB !== 'string' || !this.env.VAULT_OWNER_SUB || this.env.VAULT_OWNER_SUB.length > 256) throw new Error('configuration');
      if (subject !== this.env.VAULT_OWNER_SUB) throw new Denied();
      if (!['GET', 'POST'].includes(request.method)) throw new Denied(405, 'method_not_allowed');
      const pin = dummyPin(this.env);
      if (request.method === 'POST' && (request.headers.get('origin') !== url.origin || request.headers.get('content-type') !== 'application/json' ||
          ['cross-site', 'same-site'].includes(request.headers.get('sec-fetch-site')))) throw new Denied();
      if (replacement) return await this.replacement(request, replacement[1], subject, pin);
      if (request.method === 'GET') {
        const keys = await this.keys();
        return await this.serial(async () => json(summary(await this.state(this.ctx.storage, keys.audit, pin))));
      }
      if (request.headers.get('origin') !== url.origin || request.headers.get('content-type') !== 'application/json' ||
          ['cross-site', 'same-site'].includes(request.headers.get('sec-fetch-site'))) throw new Denied();
      input = await registrationBody(request);
      const hasPreparation = exactKeys(input, PREPARED_FIELDS);
      if ((!exactKeys(input, FIELDS) && !hasPreparation) || !UUID.test(input.id) || input.id === pin.id ||
          !timestamp(input.expiresAt) || input.expiresAt <= Date.now() ||
          !(input.replaceOf === null || input.replaceOf === pin.id) ||
          !Number.isSafeInteger(input.expectedRevision) || input.expectedRevision < 0) throw new Denied(400, 'invalid_request');
      input.fileName = fileName(input.fileName);
      let prepared = null;
      if (hasPreparation) {
        try { prepared = preparation(input); }
        catch { throw new Denied(400, 'invalid_request'); }
      }
      try { bytes = unb64(input.pdfBase64, MAX_PDF_BYTES); }
      catch { throw new Denied(400, 'invalid_request'); }
      input.pdfBase64 = '';
      if (bytes.length < 5 || String.fromCharCode(...bytes.subarray(0, 5)) !== '%PDF-') throw new Denied(400, 'invalid_pdf');
      // The owner's preparation metadata is not proof of PDF structure or a
      // watermark. Only the digest of the uploaded PDF can be checked here.
      if (prepared) {
        const actual = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)), b => b.toString(16).padStart(2, '0')).join('');
        if (actual !== prepared.metadata.preparedSha256) throw new Denied(400, 'invalid_request');
      }
      const keys = await this.keys();
      return await this.serial(async () => {
        const before = await this.state(this.ctx.storage, keys.audit, pin);
        this.check(before, input);
        if (input.expiresAt <= Date.now()) throw new Denied(400, 'invalid_request');
        const record = await sealDocument({ id: input.id, bytes, subjects: [subject],
          expiresAt: input.expiresAt, authMode: 'access', ...(prepared ? { recipientName: prepared.recipientName } : {}) }, keys.wrap);
        bytes.fill(0);
        const serialized = utf8(JSON.stringify(record));
        const digestBytes = await crypto.subtle.digest('SHA-256', serialized);
        const digest = Array.from(new Uint8Array(digestBytes), b => b.toString(16).padStart(2, '0')).join('');
        const reservation = { id: input.id, createdAt: Date.now(), expiresAt: input.expiresAt, size: bytes.byteLength,
          replaceOf: input.replaceOf, status: 'pending', fileName: input.fileName, recordSha256: digest,
          ...(prepared?.metadata ?? {}) };
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
