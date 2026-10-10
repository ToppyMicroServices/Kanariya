import { identity, accessConfiguration } from './auth.js';
import { UUID, MAX_RECORD_BYTES, importKey, openJSON, sealJSON, readPolicy, decryptDocument, boundedBody, parseJSON } from './crypto.js';
import { requireNotificationTargets, deliverNotification } from '../../src/notifications.js';
import { ACCESS_ROUTE, PASSWORD_ROUTE, HEADERS, json, Denied, failure, origin, dummyPin, passwordEnabled, requestBody } from './http.js';
import { passwordValid, verifyPassword, randomToken, hashToken, readSession, sessionCookie,
  SESSION_MS, MAX_SESSIONS } from './password.js';
import { recipientHeaders } from './recipient.js';
import { PasswordAdmission } from './admission.js';
const DAY = 86400000;

export class VaultDocument {
  constructor(ctx, env) {
    this.ctx = ctx; this.env = env; this.tail = Promise.resolve(); this.alarmRunning = null;
    this.context = `journal:v1:${ctx.id.toString()}`;
    this.admission = new PasswordAdmission(ctx.storage, env, this.context);
  }
  // Requests and durable state changes are serialized. Network notification delivery
  // intentionally happens outside this queue so owner revocation remains available.
  serial(operation) {
    const next = this.tail.then(operation, operation);
    this.tail = next.catch(() => {}); return next;
  }
  async keys() {
    if (!this.env.VAULT_WRAP_KEY || this.env.VAULT_WRAP_KEY === this.env.VAULT_AUDIT_KEY || (typeof this.env.VAULT_OWNER_SUB !== "string" || !this.env.VAULT_OWNER_SUB || this.env.VAULT_OWNER_SUB.length > 256)) throw new Error('configuration');
    return { wrap: await importKey(this.env.VAULT_WRAP_KEY), audit: await importKey(this.env.VAULT_AUDIT_KEY) };
  }
  async state(storage, key) {
    const box = await storage.get('encrypted-journal');
    if (!box) return { version: 1, documentId: null, revoked: false, requests: [], events: [], jobs: [], sessions: [], readerUsage: [], archivedAccepted: 0 };
    const state = await openJSON(box, key, this.context);
    if (state.version !== 1 || !Array.isArray(state.jobs) || !Array.isArray(state.events) || !Array.isArray(state.requests)) throw new Error('invalid_journal');
    state.sessions ??= [];
    if (!Array.isArray(state.sessions)) throw new Error('invalid_journal');
    state.readerUsage ??= []; state.archivedAccepted ??= 0;
    if (!Array.isArray(state.readerUsage) || !Number.isSafeInteger(state.archivedAccepted)) throw new Error('invalid_journal');
    return state;
  }
  async archive(tx, key, type, id, value, at) {
    const name = `${type}:${id}`, expiresAt = at + 30 * DAY;
    await tx.put(name, await sealJSON({ ...value, expiresAt }, key, `${this.context}:${name}`));
    await tx.put(`expiry:${String(expiresAt).padStart(13, '0')}:${name}`, name);
  }
  async compact(tx, state, key) {
    // Preserve recent evidence in separate authenticated records instead of
    // allowing the 30-day history to fill the active notification/session box.
    if (state.events.length < 200 && state.requests.length < 200 && state.jobs.length < 400) return;
    const removable = state.events.filter(e => !state.jobs.some(j => j.eventId === e.id && j.state !== 'accepted')).slice(0, -10);
    const ids = new Set(removable.map(e => e.id));
    for (const event of removable) {
      const jobs = state.jobs.filter(j => j.eventId === event.id);
      await this.archive(tx, key, 'audit', event.id, { event, jobs }, event.at);
      state.archivedAccepted += jobs.length;
    }
    state.events = state.events.filter(e => !ids.has(e.id));
    state.jobs = state.jobs.filter(j => !ids.has(j.eventId));
    const oldRequests = state.requests.filter(r => r.at <= Date.now() - 60000);
    for (const request of oldRequests) await this.archive(tx, key, 'replay', request.requestId, { request }, request.at);
    state.requests = state.requests.filter(r => r.at > Date.now() - 60000);
  }
  async cleanup(tx, now, state, key) {
    const expired = await tx.list({ prefix: 'expiry:', end: `expiry:${String(now + 1).padStart(13, '0')}:`, limit: 100 });
    for (const [index, name] of expired) {
      if (name.startsWith('audit:')) {
        const box = await tx.get(name);
        if (box) state.archivedAccepted -= (await openJSON(box, key, `${this.context}:${name}`)).jobs.length;
      }
      await tx.delete(name); await tx.delete(index);
    }
  }
  async mutate(id, key, change) {
    return this.ctx.storage.transaction(async tx => {
      const state = await this.state(tx, key);
      if (state.documentId && state.documentId !== id) throw new Error('identity_mismatch');
      state.documentId = id;
      const now = Date.now();
      state.events = state.events.filter(e => e.at > now - 30 * DAY);
      state.requests = state.requests.filter(e => e.at > now - 30 * DAY);
      state.jobs = state.jobs.filter(j => j.state !== 'accepted' || j.at > now - 30 * DAY);
      state.sessions = state.sessions.filter(s => s.expiresAt > now);
      state.readerUsage = state.readerUsage.filter(r => r.day === Math.floor(now / DAY));
      const result = await change(state, tx);
      await this.compact(tx, state, key);
      await this.cleanup(tx, now, state, key);
      await tx.put('encrypted-journal', await sealJSON(state, key, this.context));
      const times = state.jobs.filter(j => j.state === 'pending').map(j => j.nextAt);
      const expiry = await tx.list({ prefix: 'expiry:', limit: 1 });
      if (expiry.size) times.push(Number([...expiry.keys()][0].split(':')[1]));
      if (times.length) await tx.setAlarm(Math.max(Date.now() + 1, Math.min(...times)));
      else await tx.deleteAlarm();
      return result;
    });
  }
  async record(id, digest) {
    const object = await this.env.VAULT_DOCUMENTS.get(`${id}.sealed.json`);
    if (!object || object.size > MAX_RECORD_BYTES) throw new Denied();
    const bytes = await boundedBody(new Response(object.body), MAX_RECORD_BYTES);
    const actual = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)), b => b.toString(16).padStart(2, '0')).join('');
    // Exact ciphertext admission precedes document-key import and policy decryption.
    if (actual !== digest) throw new Denied();
    return parseJSON(bytes);
  }
  async fetch(request) {
    try {
      const ready = await requestBody(request);
      const prepared = await this.passwordPreflight(ready);
      if (prepared instanceof Response) return prepared;
      return await this.serial(async () => {
        try { return await this.handle(ready, prepared); } catch (error) { return failure(error); }
      });
    } catch (error) { return failure(error); }
  }
  async passwordPreflight(request) {
    const url = new URL(request.url);
    if (!url.pathname.startsWith('/p/')) return null;
    const match = PASSWORD_ROUTE.exec(url.pathname), pin = dummyPin(this.env);
    if (url.origin !== origin(this.env) || url.search || !match || !UUID.test(match[1]) || match[1] !== pin.id) throw new Denied();
    passwordEnabled(this.env); accessConfiguration(this.env);
    if (typeof this.env.VAULT_OWNER_SUB !== 'string' || !this.env.VAULT_OWNER_SUB || this.env.VAULT_OWNER_SUB.length > 256) throw new Error('configuration');
    const [, id, action] = match;
    if (!(action === 'status' ? ['GET'] : action === 'session' ? ['POST', 'DELETE'] : ['POST']).includes(request.method)) throw new Denied(405, 'method_not_allowed');
    if (['cross-site', 'same-site'].includes(request.headers.get('sec-fetch-site')) ||
        (action !== 'status' && (request.headers.get('origin') !== url.origin || request.headers.get('content-type') !== 'application/json'))) throw new Denied();
    const input = action === 'status' ? null : await this.input(request.clone(), action === 'session' ? 2048 : 128);
    if (action === 'session' && (!input || Array.isArray(input) || typeof input !== 'object' ||
        (request.method === 'POST' ? Object.keys(input).length !== 1 || !passwordValid(input.password) : Object.keys(input).length))) throw new Denied(400, 'invalid_request');
    if (action === 'open' && (!input || Object.keys(input).length !== 1 || !UUID.test(input.requestId))) throw new Denied(400, 'invalid_request');
    const token = readSession(request, id), logout = action === 'session' && request.method === 'DELETE';
    if (!token && logout) return json({ accepted: true }, 200, { 'set-cookie': sessionCookie(id, '', 0) });
    if (!token && action !== 'session') throw new Denied(401, 'unauthenticated');
    if (action === 'open') await requireNotificationTargets(this.env);
    const source = this.admission.source(request);
    await this.admission.take(source, action === 'session' && request.method === 'POST' ? 'login' : 'request');
    if (action !== 'session' || logout) {
      const result = await this.serial(async () => {
        const audit = await importKey(this.env.VAULT_AUDIT_KEY), state = await this.state(this.ctx.storage, audit);
        const hash = await hashToken(token);
        const session = state.sessions.find(s => s.hash === hash && s.recordDigest === pin.digest && s.expiresAt > Date.now());
        if (logout) {
          if (session) await this.mutate(id, audit, latest => { latest.sessions = latest.sessions.filter(s => s.hash !== hash); });
          return json({ accepted: true }, 200, { 'set-cookie': sessionCookie(id, '', 0) });
        }
        if (state.revoked) throw new Denied();
        if (!session) throw new Denied(401, 'unauthenticated');
        return null;
      });
      if (result) return result;
    }
    // R2 I/O cannot occupy the owner mutation queue. Authorization, expiry,
    // revocation and the unchanged pin are checked again in handle().
    return { source, digest: pin.digest, record: await this.record(id, pin.digest) };
  }
  live(policy, state, session = null) {
    if (policy.revoked || state.revoked || policy.expiresAt <= Date.now()) throw new Denied();
    if (session && session.expiresAt <= Date.now()) throw new Denied(401, 'unauthenticated');
  }
  async input(request, max = 128) {
    try { return parseJSON(await boundedBody(request, max)); }
    catch { throw new Denied(400, 'invalid_request'); }
  }
  async owner(request, id, action, subject) {
    if (subject !== this.env.VAULT_OWNER_SUB) throw new Denied();
    const keys = await this.keys();
    if (action === 'status') {
      const state = await this.state(this.ctx.storage, keys.audit);
      return json({ revoked: state.revoked, pending: state.jobs.filter(j => j.state === 'pending').length,
        failed: state.jobs.filter(j => j.state === 'failed').length,
        providerAccepted: state.archivedAccepted + state.jobs.filter(j => j.state === 'accepted').length });
    }
    const input = await this.input(request, 16);
    if (!input || Array.isArray(input) || typeof input !== 'object' || Object.keys(input).length) throw new Denied(400, 'invalid_request');
    const targets = action === 'retry-notifications' ? await requireNotificationTargets(this.env) : [];
    await this.mutate(id, keys.audit, state => {
      if (action === 'revoke') { state.revoked = true; state.sessions = []; }
      else for (const job of state.jobs.filter(j => j.state === 'failed')) {
        const target = targets.find(t => t.type === job.target.type);
        if (target) { job.target = target; job.state = 'pending'; job.attempts = 0; job.nextAt = Date.now(); delete job.lease; }
      }
    });
    return json({ accepted: true });
  }
  async handle(request, prepared = null) {
    const url = new URL(request.url), passwordPath = url.pathname.startsWith('/p/');
    const match = (passwordPath ? PASSWORD_ROUTE : ACCESS_ROUTE).exec(url.pathname);
    if (url.origin !== origin(this.env) || url.search || !match || !UUID.test(match[1])) throw new Denied();
    const [, id, action] = match, pin = dummyPin(this.env);
    if (id !== pin.id) throw new Denied();
    if (passwordPath) {
      passwordEnabled(this.env); accessConfiguration(this.env);
      if (!prepared) throw new Denied();
    }
    const methods = action === 'status' ? ['GET'] : passwordPath && action === 'session' ? ['POST', 'DELETE'] : ['POST'];
    if (!methods.includes(request.method)) throw new Denied(405, 'method_not_allowed');
    if (action !== 'status' && (request.headers.get('origin') !== origin(this.env) ||
        request.headers.get('content-type') !== 'application/json')) throw new Denied();
    if (passwordPath && ['cross-site', 'same-site'].includes(request.headers.get('sec-fetch-site'))) throw new Denied();
    let subject;
    if (!passwordPath) {
      try { subject = await identity(request, this.env); } catch { throw new Denied(401, 'unauthenticated'); }
      if (action !== 'open') return this.owner(request, id, action, subject);
    }
    let input, token;
    if (action === 'open') {
      input = await this.input(request);
      if (!input || Object.keys(input).length !== 1 || !UUID.test(input.requestId)) throw new Denied(400, 'invalid_request');
    } else if (action === 'session') {
      input = await this.input(request, 2048);
      if (!input || Array.isArray(input) || typeof input !== 'object') throw new Denied(400, 'invalid_request');
      if (request.method === 'POST' && (Object.keys(input).length !== 1 || !passwordValid(input.password))) throw new Denied(400, 'invalid_request');
      if (request.method === 'DELETE' && Object.keys(input).length) throw new Denied(400, 'invalid_request');
    }
    if (passwordPath) {
      token = readSession(request, id);
      if (action !== 'session' && !token) throw new Denied(401, 'unauthenticated');
    }
    // Notification validation still precedes storage/key access for all opens.
    const targets = action === 'open' ? await requireNotificationTargets(this.env) : [];
    if (prepared && prepared.digest !== pin.digest) throw new Denied();
    const record = prepared ? prepared.record : await this.record(id, pin.digest), keys = await this.keys();
    const policy = await readPolicy(record, id, keys.wrap);
    if ((policy.authMode ?? 'access') !== (passwordPath ? 'password' : 'access')) throw new Denied();
    let state = await this.state(this.ctx.storage, keys.audit), session = null;
    if (passwordPath && action === 'session') {
      if (request.method === 'DELETE') {
        const hash = token ? await hashToken(token) : null;
        await this.mutate(id, keys.audit, latest => { latest.sessions = latest.sessions.filter(s => s.hash !== hash); });
        return json({ accepted: true }, 200, { 'set-cookie': sessionCookie(id, '', 0) });
      }
      this.live(policy, state);
      // The independent source budget was committed before R2 and scrypt.
      if (!verifyPassword(input.password, policy.passwordVerifier)) throw new Denied(401, 'unauthenticated');
      input.password = '';
      const raw = randomToken(), hash = await hashToken(raw);
      const expiresAt = Math.min(policy.expiresAt, Date.now() + SESSION_MS);
      await this.mutate(id, keys.audit, latest => {
        this.live(policy, latest);
        latest.sessions = latest.sessions.filter(s => s.recordDigest === pin.digest);
        if (latest.sessions.length >= MAX_SESSIONS) throw new Denied(429, 'session_limit');
        latest.sessions.push({ hash, expiresAt, recordDigest: pin.digest });
      });
      this.live(policy, { revoked: false }, { expiresAt });
      return json({ expiresAt: policy.expiresAt, sessionExpiresAt: expiresAt }, 200,
        { 'set-cookie': sessionCookie(id, raw, Math.max(0, Math.floor((expiresAt - Date.now()) / 1000))) });
    }
    this.live(policy, state);
    if (passwordPath) {
      const hash = await hashToken(token);
      session = state.sessions.find(s => s.hash === hash && s.recordDigest === pin.digest && s.expiresAt > Date.now());
      if (!session) throw new Denied(401, 'unauthenticated');
      subject = 'shared-password'; // No claim of individual identity for a shared credential.
      if (action === 'status') return json({ expiresAt: policy.expiresAt, sessionExpiresAt: session.expiresAt });
    } else if (!policy.subjects.includes(subject)) throw new Denied();
    if (request.headers.has('range') || request.headers.has('if-range')) throw new Denied(400, 'range_not_supported');
    const eventId = crypto.randomUUID();
    const actor = passwordPath ? `source:${prepared.source}` : `access:${subject}`;
    await this.mutate(id, keys.audit, async (latest, tx) => {
      this.live(policy, latest, session);
      if (latest.requests.some(r => r.requestId === input.requestId)) throw new Denied(409, 'request_already_used');
      const archived = await tx.get(`replay:${input.requestId}`);
      if (archived && (await openJSON(archived, keys.audit, `${this.context}:replay:${input.requestId}`)).expiresAt > Date.now()) throw new Denied(409, 'request_already_used');
      if (latest.jobs.some(j => j.state === 'failed') || latest.jobs.filter(j => j.state === 'pending').length + targets.length > 100) throw new Error('audit_capacity');
      if (latest.jobs.filter(j => j.state === 'pending' && j.actor === actor).length + targets.length > 10) throw new Denied(429, 'rate_limited');
      if (latest.requests.filter(r => (r.actor ?? `access:${r.subject}`) === actor && r.at > Date.now() - 60000).length >= 10) throw new Denied(429, 'rate_limited');
      let usage = latest.readerUsage.find(r => r.actor === actor);
      if ((usage?.count || 0) >= 100 || (!usage && latest.readerUsage.length >= 1024)) throw new Denied(429, 'rate_limited');
      if (!usage) { usage = { actor, day: Math.floor(Date.now() / DAY), count: 0 }; latest.readerUsage.push(usage); }
      usage.count++;
      const at = Date.now();
      latest.requests.push({ requestId: input.requestId, subject, actor, at });
      latest.events.push({ id: eventId, subject, documentId: id, at, outcome: 'requested' });
      for (const target of targets) latest.jobs.push({ eventId, actor, target, at, state: 'pending', attempts: 0, outcome: 'unknown', nextAt: at + 10000 });
    });
    let bytes;
    try { bytes = await decryptDocument(record, keys.wrap, policy); }
    catch { await this.finish(id, keys.audit, eventId, 'failed'); throw new Error('decryption_failed'); }
    try {
      // Suppress late plaintext. A completed decryption audit does not claim
      // delivery; a deadline crossing during the commit may still deny release.
      this.live(policy, state, session);
      await this.finish(id, keys.audit, eventId, 'decrypted');
      this.live(policy, state, session);
    } catch (error) { bytes.fill(0); throw error; }
    return new Response(bytes, { headers: { ...HEADERS, 'content-type': 'application/pdf',
      ...recipientHeaders(policy), 'x-vault-event': eventId,
      'x-vault-expires-at': String(policy.expiresAt),
      ...(session ? { 'x-vault-session-expires-at': String(session.expiresAt) } : {}) } });
  }
  async finish(id, key, eventId, outcome) {
    return this.mutate(id, key, state => {
      const event = state.events.find(e => e.id === eventId);
      if (!event || event.outcome !== 'requested') throw new Error('event_state');
      event.outcome = outcome;
      for (const job of state.jobs.filter(j => j.eventId === eventId)) { job.outcome = outcome; job.nextAt = Date.now() + 1; }
    });
  }
  alarm() {
    if (!this.alarmRunning) this.alarmRunning = this.deliverDue().finally(() => { this.alarmRunning = null; });
    return this.alarmRunning;
  }
  async deliverDue() {
    try {
      const keys = await this.keys();
      for (let index = 0; index < 10; index++) {
        // Persist a short lease before the external call. On a crash it becomes
        // due again; provider idempotency keys remain unchanged (at-least-once).
        const claim = await this.serial(async () => {
          const state = await this.state(this.ctx.storage, keys.audit);
          if (!state.documentId) return null;
          return this.mutate(state.documentId, keys.audit, latest => {
            const job = latest.jobs.find(j => j.state === 'pending' && j.nextAt <= Date.now());
            if (!job) return null;
            job.lease = crypto.randomUUID(); job.nextAt = Date.now() + 60000;
            return { id: state.documentId, job: structuredClone(job) };
          });
        });
        if (!claim) break;
        const { id, job: due } = claim;
        const result = await deliverNotification(this.env, due.target,
          { kind: 'vault.decryption', id: due.eventId, outcome: due.outcome }, `${due.eventId}:${due.target.type}`);
        await this.serial(() => this.mutate(id, keys.audit, latest => {
          const job = latest.jobs.find(j => j.eventId === due.eventId && j.target.type === due.target.type);
          if (!job || job.state !== 'pending' || job.lease !== due.lease) return;
          delete job.lease; job.attempts++;
          job.state = result.ok ? 'accepted' : (result.retryable && job.attempts < 8 ? 'pending' : 'failed');
          job.error = result.error; job.httpStatus = result.httpStatus;
          job.nextAt = Date.now() + (result.retryAfterMs ?? Math.min(3600000, 1000 * 2 ** job.attempts));
        }));
      }
    } catch {
      console.error('vault_alarm_failed');
      await this.serial(() => this.ctx.storage.setAlarm(Date.now() + 300000));
    }
  }
}
