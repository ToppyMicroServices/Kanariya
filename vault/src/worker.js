import { identity } from "./auth.js";
import { UUID, MAX_RECORD_BYTES, importKey, openJSON, sealJSON, readPolicy, decryptDocument, boundedBody, parseJSON } from "./crypto.js";
import { requireNotificationTargets, deliverNotification } from "../../src/notifications.js";
import * as viewer from "./viewer.js";
import { pdfjsAssets } from "./pdfjs-assets.generated.js";

const DAY = 86400000;
const ROUTE = /^\/v1\/documents\/([0-9a-f-]{36})\/(open|revoke|status|retry-notifications)$/;
const HEADERS = {
  "cache-control": "private, no-store, max-age=0", "cdn-cache-control": "no-store", "pragma": "no-cache",
  "referrer-policy": "no-referrer", "x-content-type-options": "nosniff", "x-frame-options": "SAMEORIGIN",
  "content-security-policy": "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; worker-src 'self'; frame-ancestors 'self'; base-uri 'none'; form-action 'none'",
  "permissions-policy": "camera=(), microphone=(), geolocation=()",
};
function json(value, status = 200) { return new Response(JSON.stringify(value), { status, headers: { ...HEADERS, "content-type": "application/json" } }); }
class Denied extends Error { constructor(status = 403, code = "not_allowed") { super(code); this.status = status; this.code = code; } }
function failure(error) { return error instanceof Denied ? json({ error: error.code }, error.status) : json({ error: "unavailable" }, 503); }
function origin(env) {
  const url = new URL(env.PUBLIC_ORIGIN);
  if (url.protocol !== "https:" || url.origin !== env.PUBLIC_ORIGIN || url.hostname.endsWith(".invalid")) throw new Error("configuration");
  return url.origin;
}
function dummyPin(env) {
  if (typeof env.DUMMY_DOCUMENT_ID !== "string" || !UUID.test(env.DUMMY_DOCUMENT_ID) ||
      typeof env.DUMMY_RECORD_SHA256 !== "string" || !/^[0-9a-f]{64}$/.test(env.DUMMY_RECORD_SHA256)) throw new Error("configuration");
  return { id: env.DUMMY_DOCUMENT_ID, digest: env.DUMMY_RECORD_SHA256 };
}
export default {
  async fetch(request, env) {
    try {
      const url = new URL(request.url);
      if (url.origin !== origin(env) || url.search) return json({ error: "not_allowed" }, 403);
      const pin = dummyPin(env);
      const match = ROUTE.exec(url.pathname);
      if (match && UUID.test(match[1])) {
        if (match[1] !== pin.id) throw new Denied();
        return env.VAULT.get(env.VAULT.idFromName(match[1])).fetch(request);
      }
      if (request.method !== "GET") return json({ error: "not_found" }, 404);
      const asset = Object.hasOwn(pdfjsAssets, url.pathname) ? pdfjsAssets[url.pathname] : null;
      if (!asset && !["/", "/viewer.js", "/viewer.css"].includes(url.pathname)) return json({ error: "not_found" }, 404);
      try { await identity(request, env); } catch { return json({ error: "unauthenticated" }, 401); }
      if (asset) {
        const body = asset.encoding === "base64" ? Uint8Array.from(atob(asset.data), char => char.charCodeAt(0)) : asset.data;
        return new Response(body, { headers: { ...HEADERS, "content-type": asset.mime } });
      }
      const [body, mime] = url.pathname === "/" ? [viewer.html, "text/html; charset=utf-8"] :
        url.pathname === "/viewer.js" ? [viewer.js, "text/javascript; charset=utf-8"] : [viewer.css, "text/css; charset=utf-8"];
      return new Response(body, { headers: { ...HEADERS, "content-type": mime } });
    } catch (error) { return failure(error); }
  },
};

export class VaultDocument {
  constructor(ctx, env) {
    this.ctx = ctx; this.env = env; this.tail = Promise.resolve();
    this.context = `journal:v1:${ctx.id.toString()}`;
  }
  // Include fetch and alarms in the same in-isolate critical section. Durable
  // storage transactions protect commits; no plaintext is persisted on failure.
  serial(operation) {
    const next = this.tail.then(operation, operation);
    this.tail = next.catch(() => {}); return next;
  }
  async keys() {
    if (!this.env.VAULT_WRAP_KEY || this.env.VAULT_WRAP_KEY === this.env.VAULT_AUDIT_KEY || !this.env.VAULT_OWNER_SUB) throw new Error("configuration");
    return { wrap: await importKey(this.env.VAULT_WRAP_KEY), audit: await importKey(this.env.VAULT_AUDIT_KEY) };
  }
  async state(storage, key) {
    const box = await storage.get("encrypted-journal");
    if (!box) return { version: 1, documentId: null, revoked: false, requests: [], events: [], jobs: [] };
    const state = await openJSON(box, key, this.context);
    if (state.version !== 1 || !Array.isArray(state.jobs) || !Array.isArray(state.events) || !Array.isArray(state.requests)) throw new Error("invalid_journal");
    return state;
  }
  async mutate(id, key, change) {
    return this.ctx.storage.transaction(async tx => {
      const state = await this.state(tx, key);
      if (state.documentId && state.documentId !== id) throw new Error("identity_mismatch");
      state.documentId = id;
      const now = Date.now();
      state.events = state.events.filter(e => e.at > now - 30 * DAY);
      state.requests = state.requests.filter(e => e.at > now - 30 * DAY);
      state.jobs = state.jobs.filter(j => j.state !== "accepted" || j.at > now - 30 * DAY);
      const result = await change(state);
      await tx.put("encrypted-journal", await sealJSON(state, key, this.context));
      const times = state.jobs.filter(j => j.state === "pending").map(j => j.nextAt);
      if (times.length) await tx.setAlarm(Math.max(Date.now() + 1, Math.min(...times)));
      else await tx.deleteAlarm();
      return result;
    });
  }
  async record(id, digest) {
    const object = await this.env.VAULT_DOCUMENTS.get(`${id}.sealed.json`);
    if (!object || object.size > MAX_RECORD_BYTES) throw new Denied();
    const bytes = await boundedBody(new Response(object.body), MAX_RECORD_BYTES);
    const actual = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)), b => b.toString(16).padStart(2, "0")).join("");
    // Compare the exact uploaded bytes before importing keys or decrypting even
    // the policy. A same-name replacement cannot activate another document.
    if (actual !== digest) throw new Denied();
    return parseJSON(bytes);
  }
  fetch(request) { return this.serial(async () => {
    try { return await this.handle(request); } catch (error) { return failure(error); }
  }); }
  async handle(request) {
    const url = new URL(request.url), match = ROUTE.exec(url.pathname);
    if (url.origin !== origin(this.env) || url.search || !match || !UUID.test(match[1])) throw new Denied();
    const [, id, action] = match;
    const pin = dummyPin(this.env);
    if (id !== pin.id) throw new Denied();
    if (request.method !== (action === "status" ? "GET" : "POST")) throw new Denied(405, "method_not_allowed");
    if (action !== "status" && (request.headers.get("origin") !== origin(this.env) ||
        request.headers.get("content-type") !== "application/json")) throw new Denied();
    let subject;
    try { subject = await identity(request, this.env); } catch { throw new Denied(401, "unauthenticated"); }
    if (action !== "open") {
      if (subject !== this.env.VAULT_OWNER_SUB) throw new Denied();
      const keys = await this.keys();
      if (action === "status") {
        const state = await this.state(this.ctx.storage, keys.audit);
        return json({ revoked: state.revoked, pending: state.jobs.filter(j => j.state === "pending").length,
          failed: state.jobs.filter(j => j.state === "failed").length,
          providerAccepted: state.jobs.filter(j => j.state === "accepted").length });
      }
      const input = parseJSON(await boundedBody(request, 16));
      if (!input || Object.keys(input).length) throw new Denied(400, "invalid_request");
      const targets = action === "retry-notifications" ? await requireNotificationTargets(this.env) : [];
      await this.mutate(id, keys.audit, state => {
        if (action === "revoke") state.revoked = true;
        else for (const job of state.jobs.filter(j => j.state === "failed")) {
          // Rebind only after this explicit owner operation, never during an alarm.
          const target = targets.find(t => t.type === job.target.type);
          if (target) { job.target = target; job.state = "pending"; job.attempts = 0; job.nextAt = Date.now(); }
        }
      });
      return json({ accepted: true });
    }
    let input;
    try { input = parseJSON(await boundedBody(request, 128)); } catch { throw new Denied(400, "invalid_request"); }
    if (!input || Object.keys(input).length !== 1 || !UUID.test(input.requestId)) throw new Denied(400, "invalid_request");
    const targets = await requireNotificationTargets(this.env);
    const record = await this.record(id, pin.digest);
    const keys = await this.keys();
    const policy = await readPolicy(record, id, keys.wrap);
    if (policy.revoked || policy.expiresAt <= Date.now() || !policy.subjects.includes(subject)) throw new Denied();
    const eventId = crypto.randomUUID();
    await this.mutate(id, keys.audit, state => {
      if (state.revoked) throw new Denied();
      if (state.requests.some(r => r.requestId === input.requestId)) throw new Denied(409, "request_already_used");
      if (state.jobs.some(j => j.state === "failed") || state.jobs.filter(j => j.state === "pending").length + targets.length > 100 ||
          state.events.length >= 500 || state.requests.length >= 500 || state.jobs.length + targets.length > 1000) throw new Error("audit_capacity");
      if (state.requests.filter(r => r.subject === subject && r.at > Date.now() - 60000).length >= 10) throw new Denied(429, "rate_limited");
      const at = Date.now();
      state.requests.push({ requestId: input.requestId, subject, at });
      state.events.push({ id: eventId, subject, documentId: id, at, outcome: "requested" });
      for (const target of targets) state.jobs.push({ eventId, target, at, state: "pending", attempts: 0, outcome: "unknown", nextAt: at + 10000 });
    });
    let bytes;
    try { bytes = await decryptDocument(record, keys.wrap, policy); }
    catch {
      await this.finish(id, keys.audit, eventId, "failed");
      throw new Error("decryption_failed");
    }
    try { await this.finish(id, keys.audit, eventId, "decrypted"); }
    catch (error) { bytes.fill(0); throw error; }
    // This confirms a durable audit + outbox commit, not inbox delivery or reading.
    return new Response(bytes, { headers: { ...HEADERS, "content-type": "application/pdf",
      "content-disposition": 'inline; filename="protected-document.pdf"', "x-vault-event": eventId } });
  }
  async finish(id, key, eventId, outcome) {
    return this.mutate(id, key, state => {
      const event = state.events.find(e => e.id === eventId);
      if (!event || event.outcome !== "requested") throw new Error("event_state");
      event.outcome = outcome;
      for (const job of state.jobs.filter(j => j.eventId === eventId)) { job.outcome = outcome; job.nextAt = Date.now() + 1; }
    });
  }
  alarm() { return this.serial(async () => {
    try {
      const keys = await this.keys(), state = await this.state(this.ctx.storage, keys.audit);
      if (!state.documentId) return;
      for (const due of state.jobs.filter(j => j.state === "pending" && j.nextAt <= Date.now()).slice(0, 10)) {
        const result = await deliverNotification(this.env, due.target,
          { kind: "vault.decryption", id: due.eventId, outcome: due.outcome }, `${due.eventId}:${due.target.type}`);
        await this.mutate(state.documentId, keys.audit, latest => {
          const job = latest.jobs.find(j => j.eventId === due.eventId && j.target.type === due.target.type);
          if (!job || job.state !== "pending") throw new Error("job_state");
          job.attempts++;
          job.state = result.ok ? "accepted" : (result.retryable && job.attempts < 8 ? "pending" : "failed");
          job.error = result.error; job.httpStatus = result.httpStatus;
          job.nextAt = Date.now() + (result.retryAfterMs ?? Math.min(3600000, 1000 * 2 ** job.attempts));
        });
      }
      // Alarms are at least once. A provider may accept a duplicate after a crash.
      await this.mutate(state.documentId, keys.audit, () => {});
    } catch {
      console.error("vault_alarm_failed");
      await this.ctx.storage.setAlarm(Date.now() + 300000);
    }
  }); }
}
