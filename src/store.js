import { notificationTargets, deliverNotification, notificationEvent } from "./notifications.js";
import { sealSource, openSource } from './access-source.js';

const TOKEN = /^[A-Za-z0-9_-]{1,512}$/;
const MANAGED = /^kr_[a-f0-9]{64}$/;
const DOCUMENT_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const DOCUMENT_CANARY_SOURCE = 'vault-management-v1';
const HOUR = 3_600_000;
const DAY = 24 * HOUR;
const json = (value, status = 200) => new Response(JSON.stringify(value), { status, headers: { "content-type": "application/json" } });
const setting = (env, key, fallback, min, max) => {
  const n = Number(env[key] ?? fallback);
  return Number.isFinite(n) ? Math.min(max, Math.max(min, Math.floor(n))) : fallback;
};
const randomHex = (bytes) => [...crypto.getRandomValues(new Uint8Array(bytes))].map(b => b.toString(16).padStart(2, "0")).join("");

async function readJson(request) {
  const reader = request.body?.getReader();
  if (!reader) throw new Error("Invalid JSON");
  let size = 0;
  const chunks = [];
  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    size += value.length;
    if (size > 8192) { await reader.cancel(); throw new Error("Request too large"); }
    chunks.push(value);
  }
  const data = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) { data.set(chunk, offset); offset += chunk.length; }
  return JSON.parse(new TextDecoder().decode(data));
}

// One object per installation. SQLite transactions own token state, evidence and outbox.
// External notification requests are deliberately outside storage transactions.
export class KanariyaStore {
  constructor(ctx, env) {
    this.storage = ctx.storage;
    this.sql = ctx.storage.sql;
    this.env = env;
    this.sql.exec(`
      CREATE TABLE IF NOT EXISTS tokens (
        token TEXT PRIMARY KEY, name TEXT NOT NULL, location TEXT NOT NULL, src TEXT NOT NULL,
        created_at INTEGER NOT NULL, expires_at INTEGER, revoked_at INTEGER,
        last_seen_at INTEGER, hit_count INTEGER NOT NULL DEFAULT 0, last_test_at INTEGER
      );
      CREATE TABLE IF NOT EXISTS events (
        id TEXT PRIMARY KEY, token TEXT NOT NULL, ts INTEGER NOT NULL,
        body TEXT NOT NULL, expires_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS events_token_time ON events(token, ts DESC);
      CREATE INDEX IF NOT EXISTS events_expiry ON events(expires_at);
      CREATE TABLE IF NOT EXISTS deliveries (
        id TEXT PRIMARY KEY, event_id TEXT NOT NULL, type TEXT NOT NULL, fingerprint TEXT NOT NULL,
        state TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, next_at INTEGER,
        http_status INTEGER, error TEXT, updated_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS deliveries_due ON deliveries(state, next_at);
      CREATE INDEX IF NOT EXISTS deliveries_event ON deliveries(event_id);
      CREATE TABLE IF NOT EXISTS guards (key TEXT PRIMARY KEY, count INTEGER NOT NULL, expires_at INTEGER NOT NULL);
      CREATE INDEX IF NOT EXISTS guards_expiry ON guards(expires_at);
      CREATE TABLE IF NOT EXISTS vault_canary_heads (document_id TEXT PRIMARY KEY, token TEXT NOT NULL UNIQUE);
    `);
  }
  rows(query, ...args) { return [...this.sql.exec(query, ...args)]; }
  one(query, ...args) { return this.rows(query, ...args)[0]; }
  removeExpired(now) {
    this.sql.exec("DELETE FROM deliveries WHERE event_id IN (SELECT id FROM events WHERE expires_at<=?)", now);
    this.sql.exec("DELETE FROM events WHERE expires_at<=?", now);
    this.sql.exec("DELETE FROM guards WHERE expires_at<=?", now);
  }
  tokenView(row, origin) {
    const iso = value => value === null ? null : new Date(value).toISOString();
    return {
      token: row.token, name: row.name, location: row.location, src: row.src,
      createdAt: iso(row.created_at), expiresAt: iso(row.expires_at), revokedAt: iso(row.revoked_at),
      lastSeenAt: iso(row.last_seen_at), hitCount: row.hit_count, lastTestAt: iso(row.last_test_at),
      state: row.revoked_at !== null ? "revoked" : row.expires_at !== null && row.expires_at <= Date.now() ? "expired" : "active",
      url: `${origin}/canary/${row.token}`,
    };
  }
  deliveryView(row) {
    return { id: row.id, type: row.type, state: row.state, attempts: row.attempts,
      httpStatus: row.http_status, error: row.error,
      nextAttemptAt: row.next_at === null ? null : new Date(row.next_at).toISOString(),
      updatedAt: new Date(row.updated_at).toISOString() };
  }
  async wakeAt(time) {
    const current = await this.storage.getAlarm();
    if (current === null || time < current) await this.storage.setAlarm(time);
  }
  async fetch(request) {
    const url = new URL(request.url);
    const path = url.pathname;
    if (/^\/internal\/vault-canary\/(status|create|revoke|events)$/.test(path)) return this.documentCanary(request);
    if (path === "/internal/hit" && request.method === "POST") {
      const data = await readJson(request);
      return json(await this.record(data));
    }
    if (path === "/admin/tokens") {
      if (request.method === "GET") {
        return json({ tokens: this.rows("SELECT * FROM tokens ORDER BY created_at DESC, token").map(t => this.tokenView(t, url.origin)),
          notifications: (await notificationTargets(this.env)).map(t => t.type) });
      }
      if (request.method !== "POST") return json({ error: "Method not allowed" }, 405);
      let data;
      try { data = await readJson(request); } catch { return json({ error: "Invalid JSON or request too large" }, 400); }
      if (!data || Array.isArray(data) || typeof data !== "object") return json({ error: "Invalid token metadata" }, 400);
      for (const [key, max] of [["name", 120], ["location", 240], ["src", 512]]) {
        if (data[key] !== undefined && (typeof data[key] !== "string" || data[key].length > max)) return json({ error: `Invalid ${key}` }, 400);
      }
      if (!data.name?.trim()) return json({ error: "Name is required" }, 400);
      if (data.src === DOCUMENT_CANARY_SOURCE) return json({ error: 'Reserved source' }, 400);
      const now = Date.now();
      const expires = data.expiresAt === undefined ? now + 90 * DAY : data.expiresAt === null ? null : typeof data.expiresAt === "string" ? Date.parse(data.expiresAt) : NaN;
      if (expires !== null && (!Number.isFinite(expires) || expires <= now)) return json({ error: "Expiry must be in the future or null" }, 400);
      const token = `kr_${randomHex(32)}`;
      return this.storage.transaction(async () => {
        const cap = setting(this.env, "TOKEN_MAX_ITEMS", 1000, 1, 10000);
        if (this.one("SELECT COUNT(*) AS n FROM tokens").n >= cap) return json({ error: "Token inventory is full" }, 409);
        this.sql.exec("INSERT INTO tokens(token,name,location,src,created_at,expires_at) VALUES(?,?,?,?,?,?)", token, data.name.trim(), data.location || "", data.src || "", now, expires);
        return json(this.tokenView(this.one("SELECT * FROM tokens WHERE token=?", token), url.origin), 201);
      });
    }
    const match = path.match(/^\/admin\/tokens\/(kr_[a-f0-9]{64})\/(revoke|test)$/);
    if (match) {
      if (request.method !== "POST") return json({ error: "Method not allowed" }, 405);
      const [, token, action] = match;
      if (action === "revoke") return this.storage.transaction(async () => {
        this.sql.exec("UPDATE tokens SET revoked_at=COALESCE(revoked_at,?) WHERE token=?", Date.now(), token);
        const row = this.one("SELECT * FROM tokens WHERE token=?", token);
        return row ? json(this.tokenView(row, url.origin)) : json({ error: "Token not found" }, 404);
      });
      const result = await this.record({ registered: true, event: {
        id: randomHex(16), ts: new Date().toISOString(), token, test: true, src: "",
        ipHash: "", country: "", asn: "", ua: "Kanariya admin test", referer: "",
      } });
      if (!result.accepted) return json({ error: result.reason }, result.reason === "test_rate_limit" ? 429 : result.reason === "event_capacity" ? 409 : 404);
      return json({ eventId: result.eventId, test: true, deliveries: result.deliveries });
    }
    if (path === "/admin/export") {
      if (request.method !== "GET") return json({ error: "Method not allowed" }, 405);
      const token = url.searchParams.get("token") || "";
      if (!TOKEN.test(token)) return json({ error: "Invalid token" }, 400);
      const limit = setting(this.env, "EXPORT_MAX_ITEMS", 1000, 1, 1000);
      return json(this.rows("SELECT * FROM events WHERE token=? AND expires_at>? ORDER BY ts DESC,id DESC LIMIT ?", token, Date.now(), limit).map(row => ({
        ...notificationEvent(JSON.parse(row.body)), deliveries: this.rows("SELECT * FROM deliveries WHERE event_id=? ORDER BY type", row.id).map(d => this.deliveryView(d)),
      })));
    }
    return json({ error: "Not found" }, 404);
  }
  documentCanaryView(row) {
    if (!row) return null;
    return { token: row.token, state: row.revoked_at !== null ? 'revoked' : row.expires_at <= Date.now() ? 'expired' : 'active',
      expiresAt: row.expires_at, hitCount: row.hit_count, lastSeenAt: row.last_seen_at };
  }
  async documentCanary(request) {
    if (request.method !== 'POST') return json({ error: 'method_not_allowed' }, 405);
    let input;
    try { input = await readJson(request); } catch { return json({ error: 'invalid_request' }, 400); }
    const action = new URL(request.url).pathname.split('/').at(-1), create = action === 'create';
    if (!input || Array.isArray(input) || typeof input !== 'object' ||
        Object.keys(input).length !== (create ? 2 : 1) || typeof input.documentId !== 'string' || !DOCUMENT_ID.test(input.documentId) ||
        (create && (!Number.isSafeInteger(input.expiresAt) || input.expiresAt <= Date.now() || input.expiresAt > 8640000000000000))) {
      return json({ error: 'invalid_request' }, 400);
    }
    const id = input.documentId;
    const current = () => this.one('SELECT t.* FROM tokens t JOIN vault_canary_heads h ON h.token=t.token WHERE h.document_id=? AND t.src=? AND t.name=?', id, DOCUMENT_CANARY_SOURCE, id);
    if (action === 'status') return json({ documentId: id, canary: this.documentCanaryView(current()) });
    if (action === 'events') {
      const rows = this.rows('SELECT e.* FROM events e JOIN tokens t ON t.token=e.token WHERE t.src=? AND t.name=? AND e.expires_at>? ORDER BY e.ts DESC,e.id DESC LIMIT 50',
        DOCUMENT_CANARY_SOURCE, id, Date.now());
      return json({ documentId: id, events: await Promise.all(rows.map(async row => ({ id: row.id, at: row.ts,
        source: await openSource(this.env, JSON.parse(row.body).sourceBox, { ...JSON.parse(row.body), token: row.token }),
        outcome: 'url_requested', notifications: this.rows('SELECT type,state FROM deliveries WHERE event_id=? ORDER BY type', row.id)
          .map(({ type, state }) => ({ type, state })) }))) });
    }
    return this.storage.transaction(async () => {
      const row = current();
      if (action === 'revoke') {
        this.sql.exec('UPDATE tokens SET revoked_at=COALESCE(revoked_at,?) WHERE src=? AND name=?', Date.now(), DOCUMENT_CANARY_SOURCE, id);
        return json({ documentId: id, canary: this.documentCanaryView(row ? current() : null) });
      }
      if (this.one('SELECT 1 FROM tokens WHERE src=? AND name=? AND revoked_at IS NULL AND expires_at>? LIMIT 1', DOCUMENT_CANARY_SOURCE, id, Date.now())) {
        return json({ error: 'canary_exists' }, 409);
      }
      if (input.expiresAt <= Date.now()) return json({ error: 'invalid_request' }, 400);
      if (this.one('SELECT COUNT(*) AS n FROM tokens').n >= setting(this.env, 'TOKEN_MAX_ITEMS', 1000, 1, 10000)) return json({ error: 'canary_capacity' }, 409);
      const token = `kr_${randomHex(32)}`;
      this.sql.exec('INSERT INTO tokens(token,name,location,src,created_at,expires_at) VALUES(?,?,?,?,?,?)', token, id, '', DOCUMENT_CANARY_SOURCE, Date.now(), input.expiresAt);
      this.sql.exec('INSERT OR REPLACE INTO vault_canary_heads(document_id,token) VALUES(?,?)', id, token);
      return json({ documentId: id, canary: this.documentCanaryView(this.one('SELECT * FROM tokens WHERE token=?', token)) }, 201);
    });
  }
  async record({ event, registered, nonce = "", nonceExpiresAt = 0, source = null }) {
    const targets = await notificationTargets(this.env);
    return this.storage.transaction(async () => {
      const now = Date.now();
      let token;
      if (registered) {
        if (!MANAGED.test(event.token)) return { accepted: false, reason: "invalid" };
        token = this.one("SELECT * FROM tokens WHERE token=?", event.token);
        if (!token) return { accepted: false, reason: "unknown" };
        if (event.test && token.src === DOCUMENT_CANARY_SOURCE) return { accepted: false, reason: 'document_canary_test_disabled' };
        if (!event.test && (token.revoked_at !== null || (token.expires_at !== null && token.expires_at <= now))) return { accepted: false, reason: "inactive" };
        if (event.test && token.last_test_at !== null && token.last_test_at + 10000 > now) return { accepted: false, reason: "test_rate_limit" };
        // Placement is trusted registry metadata; a visitor cannot relabel the alert.
        event = token.src === DOCUMENT_CANARY_SOURCE && DOCUMENT_ID.test(token.name) ?
          { kind: 'vault.canary', id: event.id, ts: event.ts, token: event.token, test: false, documentId: token.name, ipHash: '' } :
          { ...event, src: token.src, name: token.name, location: token.location };
      }
      // Admission never evicts unexpired evidence, including another token's outbox.
      // Check both caps before writing nonce, rate or notification guards.
      this.removeExpired(now);
      const tokenCap = setting(this.env, "EVENT_MAX_ITEMS_PER_TOKEN", 1000, 1, 10000);
      const cap = setting(this.env, "EVENT_MAX_ITEMS", 10000, 1, 100000);
      if (this.one("SELECT COUNT(*) AS n FROM events WHERE token=?", event.token).n >= tokenCap ||
          this.one("SELECT COUNT(*) AS n FROM events").n >= cap) return { accepted: false, reason: "event_capacity" };
      if (nonce) {
        const key = JSON.stringify(["nonce", event.token, nonce]);
        if (this.one("SELECT 1 FROM guards WHERE key=? AND expires_at>?", key, now)) return { accepted: false, reason: "replay" };
      }
      if (!event.test) {
        const window = setting(this.env, "RATE_LIMIT_WINDOW_SECONDS", 60, 0, 86400);
        const max = setting(this.env, "RATE_LIMIT_MAX", 60, 0, 100000);
        if (window && max) {
          const key = JSON.stringify(["rate", event.token, event.ipHash, Math.floor(now / (window * 1000))]);
          const count = this.one("SELECT count FROM guards WHERE key=? AND expires_at>?", key, now)?.count || 0;
          if (count >= max) return { accepted: false, reason: "rate_limit" };
          this.sql.exec("INSERT OR REPLACE INTO guards VALUES(?,?,?)", key, count + 1, now + window * 1000);
        }
      }
      // New keys omit UA; an absent IP hash shares one token bucket without raw IP.
      const dedupeKey = JSON.stringify(["dedupe", event.token, event.ipHash || ""]);
      const cooldownKey = JSON.stringify(["notify", event.token]);
      // The indexed comma-to-hyphen range matches old keys with a fourth UA item.
      // Preserve every live old guard's expiry even when the visitor changes UA.
      const legacyDedupeBase = dedupeKey.slice(0, -1);
      const suppressed = !event.test && (this.one("SELECT 1 FROM guards WHERE key=? AND expires_at>?", dedupeKey, now) ||
        this.one("SELECT 1 FROM guards WHERE key=? AND expires_at>?", cooldownKey, now) ||
        this.one("SELECT 1 FROM guards WHERE key>=? AND key<? AND expires_at>? LIMIT 1", `${legacyDedupeBase},`, `${legacyDedupeBase}-`, now));
      const ttl = setting(this.env, "EVENT_TTL_SECONDS", 2592000, 60, 31536000);
      const body = event.kind === 'vault.canary' ? { kind: event.kind, id: event.id, ts: event.ts, documentId: event.documentId } : event;
      if (event.kind === 'vault.canary') {
        const box = await sealSource(this.env, source, event);
        if (box) body.sourceBox = box;
      }
      this.sql.exec("INSERT INTO events VALUES(?,?,?,?,?)", event.id, event.token, now, JSON.stringify(body), now + ttl * 1000);
      if (nonce) this.sql.exec("INSERT OR REPLACE INTO guards VALUES(?,?,?)", JSON.stringify(["nonce", event.token, nonce]), 1, nonceExpiresAt);
      if (token) {
        if (event.test) this.sql.exec("UPDATE tokens SET last_test_at=? WHERE token=?", now, event.token);
        else this.sql.exec("UPDATE tokens SET last_seen_at=?,hit_count=hit_count+1 WHERE token=?", now, event.token);
      }
      if (!suppressed && targets.length) {
        if (!event.test) {
          this.sql.exec("INSERT OR REPLACE INTO guards VALUES(?,?,?)", dedupeKey, 1, now + setting(this.env, "DEDUPE_TTL_SECONDS", 1800, 1, 86400) * 1000);
          this.sql.exec("INSERT OR REPLACE INTO guards VALUES(?,?,?)", cooldownKey, 1, now + setting(this.env, "NOTIFY_TOKEN_COOLDOWN_SECONDS", 60, 1, 86400) * 1000);
        }
        let queued = this.one("SELECT COUNT(*) AS n FROM deliveries WHERE state IN ('pending','retrying')").n;
        for (const target of targets) {
          const full = queued >= setting(this.env, "NOTIFY_QUEUE_MAX", 10000, 1, 100000);
          this.sql.exec("INSERT INTO deliveries(id,event_id,type,fingerprint,state,next_at,error,updated_at) VALUES(?,?,?,?,?,?,?,?)",
            `${event.id}:${target.type}`, event.id, target.type, target.fingerprint,
            full ? "failed" : "pending", full ? null : now, full ? "queue_full" : null, now);
          if (!full) queued++;
        }
      }
      // The alarm and durable outbox commit together; no waitUntil-only delivery gap.
      await this.wakeAt(now + ((!suppressed && targets.length) ? 100 : HOUR));
      return { accepted: true, eventId: event.id, deliveries: this.rows("SELECT * FROM deliveries WHERE event_id=? ORDER BY type", event.id).map(d => this.deliveryView(d)) };
    });
  }
  async alarm() {
    // Persist a recovery wake-up before external I/O. A crash can duplicate a send,
    // but it cannot leave a claimed delivery permanently stranded.
    await this.storage.setAlarm(Date.now() + 60000);
    const due = this.rows("SELECT d.*,e.body,e.expires_at FROM deliveries d JOIN events e ON e.id=d.event_id WHERE d.state IN ('pending','retrying') AND d.next_at<=? ORDER BY d.next_at,d.id LIMIT 20", Date.now());
    for (const row of due) {
      const max = setting(this.env, "NOTIFY_MAX_ATTEMPTS", 6, 1, 10);
      if (row.expires_at <= Date.now() || row.attempts >= max) {
        this.sql.exec("UPDATE deliveries SET state='failed',next_at=NULL,error=?,updated_at=? WHERE id=?", row.expires_at <= Date.now() ? "event_expired" : "attempts_exhausted", Date.now(), row.id);
        continue;
      }
      const attempt = row.attempts + 1;
      this.sql.exec("UPDATE deliveries SET state='retrying',attempts=?,next_at=?,updated_at=? WHERE id=?", attempt, Date.now() + 60000, Date.now(), row.id);
      const result = await deliverNotification(this.env, { type: row.type, fingerprint: row.fingerprint }, JSON.parse(row.body), row.id);
      const retry = !result.ok && result.retryable && attempt < max;
      const backoff = Math.min(3600000, setting(this.env, "NOTIFY_RETRY_BASE_SECONDS", 30, 1, 3600) * 1000 * 2 ** (attempt - 1));
      const next = retry ? Date.now() + Math.max(backoff, result.retryAfterMs || 0) : null;
      this.sql.exec("UPDATE deliveries SET state=?,next_at=?,http_status=?,error=?,updated_at=? WHERE id=?",
        result.ok ? "accepted" : retry ? "retrying" : "failed", next, result.httpStatus ?? null, result.error ?? null, Date.now(), row.id);
    }
    await this.storage.transaction(async () => {
      const now = Date.now();
      this.removeExpired(now);
      const next = this.one("SELECT MIN(next_at) AS at FROM deliveries WHERE state IN ('pending','retrying')")?.at;
      const expiry = this.one("SELECT MIN(expires_at) AS at FROM events")?.at;
      const guardExpiry = this.one("SELECT MIN(expires_at) AS at FROM guards")?.at;
      // Include writes that arrived while provider requests were in flight.
      const times = [next, expiry, guardExpiry].filter(t => t !== null && t !== undefined);
      if (times.length) await this.storage.setAlarm(Math.max(now + 100, Math.min(now + HOUR, ...times)));
      else await this.storage.deleteAlarm();
    });
  }
}
