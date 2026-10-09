import { identity, accessConfiguration } from './auth.js';
import { UUID, MAX_RECORD_BYTES, importKey, openJSON, sealJSON, readPolicy, decryptDocument, boundedBody, parseJSON } from './crypto.js';
import { requireNotificationTargets, deliverNotification } from '../../src/notifications.js';
import { ACCESS_ROUTE, PASSWORD_ROUTE, HEADERS, json, Denied, failure, origin, dummyPin, passwordEnabled, requestBody } from './http.js';
import { passwordValid, verifyPassword, randomToken, hashToken, readSession, sessionCookie,
  SESSION_MS, ATTEMPT_WINDOW_MS, MAX_ATTEMPTS, MAX_SESSIONS } from './password.js';
import { recipientHeaders } from './recipient.js';
const DAY = 86400000;

export class VaultDocument {
  constructor(ctx, env) {
    this.ctx = ctx; this.env = env; this.tail = Promise.resolve(); this.alarmRunning = null;
    this.context = `journal:v1:${ctx.id.toString()}`;
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
    if (!box) return { version: 1, documentId: null, revoked: false, requests: [], events: [], jobs: [], sessions: [], passwordRate: null };
    const state = await openJSON(box, key, this.context);
    if (state.version !== 1 || !Array.isArray(state.jobs) || !Array.isArray(state.events) || !Array.isArray(state.requests)) throw new Error('invalid_journal');
    state.sessions ??= [];
    if (!Array.isArray(state.sessions)) throw new Error('invalid_journal');
    return state;
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
      const result = await change(state);
      await tx.put('encrypted-journal', await sealJSON(state, key, this.context));
      const times = state.jobs.filter(j => j.state === 'pending').map(j => j.nextAt);
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
    // Exact ciphertext admission precedes key import and policy decryption.
    if (actual !== digest) throw new Denied();
    return parseJSON(bytes);
  }
  async fetch(request) {
    try {
      const ready = await requestBody(request);
      return await this.serial(async () => {
        try { return await this.handle(ready); } catch (error) { return failure(error); }
      });
    } catch (error) { return failure(error); }
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
        providerAccepted: state.jobs.filter(j => j.state === 'accepted').length });
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
  async handle(request) {
    const url = new URL(request.url), passwordPath = url.pathname.startsWith('/p/');
    const match = (passwordPath ? PASSWORD_ROUTE : ACCESS_ROUTE).exec(url.pathname);
    if (url.origin !== origin(this.env) || url.search || !match || !UUID.test(match[1])) throw new Denied();
    const [, id, action] = match, pin = dummyPin(this.env);
    if (id !== pin.id) throw new Denied();
    if (passwordPath) { passwordEnabled(this.env); accessConfiguration(this.env); }
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
    const record = await this.record(id, pin.digest), keys = await this.keys();
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
      // Commit the attempt before doing expensive work, including successful tries.
      await this.mutate(id, keys.audit, latest => {
        this.live(policy, latest);
        if (!latest.passwordRate || Date.now() >= latest.passwordRate.start + ATTEMPT_WINDOW_MS) latest.passwordRate = { start: Date.now(), count: 0 };
        if (latest.passwordRate.count >= MAX_ATTEMPTS) throw new Denied(429, 'rate_limited');
        latest.passwordRate.count++;
      });
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
    await this.mutate(id, keys.audit, latest => {
      this.live(policy, latest, session);
      if (latest.requests.some(r => r.requestId === input.requestId)) throw new Denied(409, 'request_already_used');
      if (latest.jobs.some(j => j.state === 'failed') || latest.jobs.filter(j => j.state === 'pending').length + targets.length > 100 ||
          latest.events.length >= 500 || latest.requests.length >= 500 || latest.jobs.length + targets.length > 1000) throw new Error('audit_capacity');
      if (latest.requests.filter(r => r.subject === subject && r.at > Date.now() - 60000).length >= 10) throw new Denied(429, 'rate_limited');
      const at = Date.now();
      latest.requests.push({ requestId: input.requestId, subject, at });
      latest.events.push({ id: eventId, subject, documentId: id, at, outcome: 'requested' });
      for (const target of targets) latest.jobs.push({ eventId, target, at, state: 'pending', attempts: 0, outcome: 'unknown', nextAt: at + 10000 });
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
