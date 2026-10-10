import test, { after } from "node:test";
import assert from "node:assert/strict";
import cryptoNode, { createHash } from "node:crypto";
import { syncBuiltinESMExports } from "node:module";
import { generateKeyPair, exportJWK, SignJWT } from "jose";
import worker, { VaultDocument } from "../src/worker.js";
import { newKey, importKey, sealDocument, readPolicy, openJSON, sealJSON, utf8 } from "../src/crypto.js";

function list(map, options) {
  return new Map([...map].filter(([key]) => key.startsWith(options.prefix) && (!options.end || key < options.end))
    .sort(([a], [b]) => a.localeCompare(b)).slice(0, options.limit));
}

// Isolated dummy fixtures: no account, remote bucket, or notification service is used.
const originalFetch = globalThis.fetch;
after(() => { globalThis.fetch = originalFetch; });
const pair = await generateKeyPair("RS256", { extractable: true });
const jwk = { ...await exportJWK(pair.publicKey), kid: "password-fixture", use: "sig", alg: "RS256" };
const PASSWORD = "synthetic reader password";
let fixtureNumber = 0;
class Storage {
  constructor() { this.map = new Map(); this.alarmAt = null; this.writes = 0; this.failAt = Infinity; this.afterCommit = null; this.tail = Promise.resolve(); }
  async get(key) { return structuredClone(this.map.get(key)); }
  async setAlarm(at) { this.alarmAt = at; }
  transaction(fn) {
    const next = this.tail.then(() => this.runTransaction(fn)); this.tail = next.catch(() => {}); return next;
  }
  async runTransaction(fn) {
    const draft = new Map(structuredClone([...this.map])); let alarm = this.alarmAt;
    const result = await fn({
      get: async key => structuredClone(draft.get(key)),
      list: async options => list(draft, options), delete: async key => draft.delete(key),
      put: async (key, value) => { if (++this.writes === this.failAt) throw new Error("synthetic_failure"); draft.set(key, structuredClone(value)); },
      setAlarm: async at => { alarm = at; }, deleteAlarm: async () => { alarm = null; },
    });
    this.map = draft; this.alarmAt = alarm;
    if (this.afterCommit) await this.afterCommit();
    return result;
  }
}
async function fixture({ authMode = "password", expiresAt = Date.now() + 600000, recipientName } = {}) {
  const id = crypto.randomUUID(), subject = "synthetic-access-reader", pdf = utf8("%PDF-1.4\nSYNTHETIC_PASSWORD_BODY\n");
  const env = { PUBLIC_ORIGIN: "https://vault.example.test", ACCESS_ISSUER: `https://password-fixture-${++fixtureNumber}.cloudflareaccess.com`,
    ACCESS_AUDIENCE: "synthetic-audience", VAULT_WRAP_KEY: newKey(), VAULT_AUDIT_KEY: newKey(), VAULT_OWNER_SUB: "synthetic-owner",
    PASSWORD_READER_ENABLED: "1", WEBHOOK_URL: "https://notify.example.test/synthetic-path" };
  const wrappingKey = await importKey(env.VAULT_WRAP_KEY), auditKey = await importKey(env.VAULT_AUDIT_KEY);
  let record = await sealDocument({ id, bytes: pdf, expiresAt, subjects: authMode === "password" ? [] : [subject],
    ...(authMode === undefined ? {} : { authMode }), ...(authMode === "password" ? { password: PASSWORD } : {}),
    ...(recipientName === undefined ? {} : { recipientName }) }, wrappingKey);
  const pinRecord = () => { env.DUMMY_DOCUMENT_ID = id; env.DUMMY_RECORD_SHA256 = createHash("sha256").update(JSON.stringify(record)).digest("hex"); };
  pinRecord();
  let reads = 0, jwksReads = 0, providerStatus = 202, providerHandler, recordHandler;
  const calls = [], storage = new Storage(), ctx = { storage, id: { toString: () => `password-object-${id}` } };
  const context = `journal:v1:password-object-${id}`;
  let instance = new VaultDocument(ctx, env);
  env.VAULT_DOCUMENTS = { async get(name) { reads++; assert.equal(name, `${id}.sealed.json`);
    if (recordHandler) await recordHandler();
    if (!record) return null; const bytes = utf8(JSON.stringify(record)); return { size: bytes.length, body: new Response(bytes).body }; } };
  env.VAULT = { idFromName: value => { assert.equal(value, id); return value; }, get: () => instance };
  globalThis.fetch = async (url, options) => {
    if (String(url) === `${env.ACCESS_ISSUER}/cdn-cgi/access/certs`) { jwksReads++; return Response.json({ keys: [jwk] }); }
    assert.equal(String(url), env.WEBHOOK_URL); calls.push({ url, options, payload: JSON.parse(options.body) });
    if (providerHandler) return providerHandler(url, options);
    return new Response("synthetic provider response", { status: providerStatus });
  };
  async function token(sub = subject) {
    return new SignJWT({ sub, iss: env.ACCESS_ISSUER, aud: env.ACCESS_AUDIENCE, iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + 600 })
      .setProtectedHeader({ alg: "RS256", kid: "password-fixture" }).sign(pair.privateKey);
  }
  async function request(action = "session", options = {}) {
    const ownerRoute = options.access === true;
    const method = options.method || (action === "status" ? "GET" : "POST");
    const headers = { origin: env.PUBLIC_ORIGIN, "content-type": "application/json", "cf-connecting-ip": "192.0.2.1", ...(options.cookie ? { cookie: options.cookie } : {}),
      ...(options.subject ? { "cf-access-jwt-assertion": await token(options.subject) } : {}), ...options.headers };
    const body = options.body ?? JSON.stringify(action === "session" && method === "POST" ? { password: PASSWORD } :
      action === "open" ? { requestId: options.requestId || crypto.randomUUID() } : {});
    const url = `${env.PUBLIC_ORIGIN}${ownerRoute ? "/v1/documents" : "/p"}/${options.id || id}/${action}${options.query || ""}`;
    const req = new Request(options.url || url, { method, headers, ...(["GET", "HEAD"].includes(method) ? {} : { body }) });
    return options.direct ? instance.fetch(req) : worker.fetch(req, env);
  }
  async function login(options) {
    const response = await request("session", options); assert.equal(response.status, 200);
    const setCookie = response.headers.get("set-cookie"); assert.ok(setCookie);
    return { cookie: setCookie.split(";")[0], setCookie, response, body: await response.json() };
  }
  async function state() { return openJSON(await storage.get("encrypted-journal"), auditKey, context); }
  async function admission() { return openJSON(await storage.get("encrypted-admission"), auditKey, `admission:${context}`); }
  async function replacePolicy(change) {
    const policy = await openJSON(record.policy, wrappingKey, `policy:v2:${id}`); change(policy);
    record.policy = await sealJSON(policy, wrappingKey, `policy:v2:${id}`); pinRecord();
  }
  return { env, id, subject, pdf, expiresAt, wrappingKey, auditKey, context, storage, token, request, login, state, admission, replacePolicy, pinRecord, calls,
    get reads() { return reads; }, get jwksReads() { return jwksReads; }, get record() { return record; }, set record(value) { record = value; },
    set providerHandler(value) { providerHandler = value; }, set providerStatus(value) { providerStatus = value; },
    set recordHandler(value) { recordHandler = value; },
    restart() { instance = new VaultDocument(ctx, env); }, alarm() { return instance.alarm(); },
    async writeState(value) { storage.map.set("encrypted-journal", await sealJSON(value, auditKey, context)); },
  };
}
function privateResponse(response) {
  assert.match(response.headers.get("cache-control"), /no-store/);
  assert.equal(response.headers.get("cdn-cache-control"), "no-store");
  assert.notEqual(response.headers.get("access-control-allow-origin"), "*");
}
function keyReads(env) {
  let count = 0;
  for (const name of ["VAULT_WRAP_KEY", "VAULT_AUDIT_KEY"]) {
    const value = env[name]; Object.defineProperty(env, name, { get() { count++; return value; } });
  }
  return () => count;
}
async function withClock(at, operation) {
  const original = Date.now; Date.now = () => at;
  try { return await operation(); } finally { Date.now = original; }
}
function deferred() { let resolve; const promise = new Promise(r => { resolve = r; }); return { promise, resolve }; }
async function within(promise, ms = 1000) {
  let timer;
  try { return await Promise.race([promise, new Promise(resolve => { timer = setTimeout(() => resolve(null), ms); })]); }
  finally { clearTimeout(timer); }
}

test("password PDF naming is owner-bound, private until authentication, and denied after revocation", async () => {
  const recipientName = "株式会社テスト 採用担当", f = await fixture({ recipientName });
  const anonymous = await f.request("open");
  assert.equal(anonymous.status, 401); assert.equal(anonymous.headers.get("x-vault-download-filename"), null);
  const session = await f.login(); assert.ok(!JSON.stringify(session.body).includes(recipientName));
  const response = await f.request("open", { cookie: session.cookie });
  assert.equal(response.status, 200); assert.deepEqual(new Uint8Array(await response.arrayBuffer()), f.pdf);
  assert.equal(decodeURIComponent(response.headers.get("x-vault-download-filename")), `CV_${recipientName}.pdf`);
  assert.equal(decodeURIComponent(response.headers.get("content-disposition").split("filename*=UTF-8''")[1]), `CV_${recipientName}.pdf`);
  assert.ok(!JSON.stringify(f.record).includes(recipientName)); assert.ok(!JSON.stringify(await f.state()).includes(recipientName));
  const forged = await f.request("open", { cookie: session.cookie, body: JSON.stringify({ requestId: crypto.randomUUID(), recipientName: "Other recipient" }) });
  assert.equal(forged.status, 400);
  assert.equal((await f.request("revoke", { access: true, subject: f.env.VAULT_OWNER_SUB })).status, 200);
  const revoked = await f.request("open", { cookie: session.cookie });
  assert.equal(revoked.status, 403); assert.equal(revoked.headers.get("x-vault-download-filename"), null);
});

test("password session and PDF open work without any reader JWT and set bounded secure cookies", async () => {
  const f = await fixture(), startedAt = Date.now(), session = await f.login();
  assert.match(session.setCookie, new RegExp(`^__Secure-vault-${f.id}=[^;]+;`));
  assert.match(session.setCookie, new RegExp(`(?:^|;\\s*)Path=/p/${f.id}/(?:;|$)`));
  for (const attribute of ["Secure", "HttpOnly", "SameSite=Strict"]) assert.match(session.setCookie, new RegExp(`(?:^|;\\s*)${attribute}(?:;|$)`, "i"));
  assert.doesNotMatch(session.setCookie, /(?:^|;\s*)Domain=/i);
  const maxAge = /(?:^|;\s*)Max-Age=(\d+)(?:;|$)/i.exec(session.setCookie);
  assert.ok(maxAge); assert.ok(Number(maxAge[1]) > 0 && Number(maxAge[1]) <= 300);
  assert.equal(session.body.expiresAt, f.expiresAt);
  assert.ok(session.body.sessionExpiresAt > startedAt && session.body.sessionExpiresAt <= Date.now() + 300000);
  assert.ok(session.body.sessionExpiresAt <= session.body.expiresAt);
  const response = await f.request("open", { cookie: session.cookie });
  assert.equal(response.status, 200); assert.deepEqual(new Uint8Array(await response.arrayBuffer()), f.pdf);
  assert.equal(response.headers.get("content-type"), "application/pdf");
  assert.equal(response.headers.get("x-vault-download-filename"), null);
  assert.equal(Number(response.headers.get("x-vault-expires-at")), f.expiresAt);
  assert.equal(Number(response.headers.get("x-vault-session-expires-at")), session.body.sessionExpiresAt);
  privateResponse(session.response); privateResponse(response); assert.equal(f.jwksReads, 0);
  assert.equal((await f.state()).events[0].outcome, "decrypted"); assert.ok(f.storage.alarmAt); assert.equal(f.calls.length, 0);
});
test("password status is authenticated, has current timestamps, and contains no body or verifier", async () => {
  const f = await fixture();
  const denied = await f.request("status"); assert.ok([401, 403].includes(denied.status)); privateResponse(denied);
  const { cookie, body } = await f.login(), response = await f.request("status", { cookie });
  assert.equal(response.status, 200); privateResponse(response);
  const value = await response.json(); assert.equal(value.expiresAt, f.expiresAt); assert.equal(value.sessionExpiresAt, body.sessionExpiresAt);
  assert.doesNotMatch(JSON.stringify(value), /SYNTHETIC_PASSWORD_BODY|scrypt|password|ciphertext/);
});
test("session token is encrypted durably, survives restart, and logout invalidates it durably", async () => {
  const f = await fixture(), { cookie } = await f.login(), rawToken = cookie.slice(cookie.indexOf("=") + 1);
  const persisted = JSON.stringify([...f.storage.map]), state = JSON.stringify(await f.state());
  for (const secret of [PASSWORD, rawToken, "SYNTHETIC_PASSWORD_BODY", f.env.VAULT_WRAP_KEY, f.env.VAULT_AUDIT_KEY]) assert.ok(!persisted.includes(secret));
  assert.ok(!state.includes(rawToken)); assert.ok(!state.includes(PASSWORD));
  f.restart(); assert.equal((await f.request("open", { cookie })).status, 200);
  const logout = await f.request("session", { method: "DELETE", cookie }); assert.equal(logout.status, 200);
  assert.match(logout.headers.get("set-cookie"), /(?:^|;\s*)Max-Age=0(?:;|$)/i); privateResponse(logout);
  f.restart(); assert.ok([401, 403].includes((await f.request("open", { cookie })).status));
  assert.ok([401, 403].includes((await f.request("status", { cookie })).status));
});
test("wrong password, malformed token, and unrelated document cookie cannot release content", async () => {
  const f = await fixture();
  const wrong = await f.request("session", { body: JSON.stringify({ password: "synthetic wrong password" }) });
  assert.equal(wrong.status, 401); assert.equal(wrong.headers.get("set-cookie"), null); privateResponse(wrong);
  const { cookie } = await f.login(), otherName = cookie.replace(f.id, crypto.randomUUID());
  for (const candidate of [otherName, `__Secure-vault-${f.id}=wrong`, cookie.slice(0, -1) + (cookie.endsWith("a") ? "b" : "a")]) {
    const response = await f.request("open", { cookie: candidate }); assert.ok([401, 403].includes(response.status)); privateResponse(response);
  }
  assert.equal((await f.state()).events.length, 0);
});
test("a cookie and copied session journal cannot authenticate another document", async () => {
  const first = await fixture(), { cookie } = await first.login(), copiedState = await first.state();
  const second = await fixture();
  copiedState.documentId = second.id; await second.writeState(copiedState);
  const response = await second.request("open", { cookie: cookie.replace(first.id, second.id) });
  assert.ok([401, 403].includes(response.status)); assert.doesNotMatch(await response.text(), /SYNTHETIC_PASSWORD_BODY/);
});
test("same-ID re-sealing and re-pinning invalidates an existing password session", async () => {
  const f = await fixture(), { cookie } = await f.login();
  f.record = await sealDocument({ id: f.id, bytes: f.pdf, subjects: [], authMode: "password", password: PASSWORD, expiresAt: f.expiresAt }, f.wrappingKey);
  f.pinRecord();
  assert.ok([401, 403].includes((await f.request("status", { cookie })).status));
  assert.ok([401, 403].includes((await f.request("open", { cookie })).status));
});
test("password sessions cannot authenticate any owner operation", async () => {
  const f = await fixture(), { cookie } = await f.login();
  for (const action of ["status", "revoke", "retry-notifications"]) {
    assert.equal((await f.request(action, { access: true, cookie })).status, 401);
    assert.equal((await f.request(action, { access: true, cookie, subject: f.subject })).status, 403);
    assert.equal((await f.request(action, { access: true, cookie, headers: { "cf-access-authenticated-user-email": "synthetic-owner@example.test" } })).status, 401);
  }
  assert.equal((await f.request("status", { access: true, subject: f.env.VAULT_OWNER_SUB })).status, 200);
});
test("owner revocation denies live and restarted password sessions", async () => {
  const f = await fixture(), { cookie } = await f.login();
  assert.equal((await f.request("revoke", { access: true, subject: f.env.VAULT_OWNER_SUB })).status, 200);
  for (const restart of [false, true]) {
    if (restart) f.restart();
    for (const action of ["status", "open", "session"]) assert.equal((await f.request(action, { cookie })).status, 403);
  }
});
test("Access and password routes cannot be confused, even with valid credentials for both", async () => {
  const password = await fixture();
  for (const subject of [password.subject, password.env.VAULT_OWNER_SUB]) {
    assert.equal((await password.request("open", { access: true, subject })).status, 403);
  }
  const access = await fixture({ authMode: "access" });
  assert.equal((await access.request("session", { subject: access.subject })).status, 403);
  assert.equal((await access.request("open", { subject: access.subject })).status, 401);
  assert.equal((await access.request("status", { subject: access.env.VAULT_OWNER_SUB })).status, 401);
  assert.equal((await access.request("open", { access: true, subject: access.subject })).status, 200);
});
for (const enabled of [undefined, "0", true, 1, "true"]) test(`password reader requires the exact opt-in value (${String(enabled)})`, async () => {
  const f = await fixture(); f.env.PASSWORD_READER_ENABLED = enabled; const observe = keyReads(f.env);
  for (const direct of [false, true]) for (const action of ["session", "status", "open"]) {
    const response = await f.request(action, { direct }); assert.equal(response.status, 403); privateResponse(response);
  }
  assert.equal(observe(), 0); assert.equal(f.reads, 0); assert.equal(f.storage.map.size, 0);
});
for (const direct of [false, true]) test(`password routes reject unknown and malformed IDs before storage or key use (${direct ? "object" : "worker"})`, async () => {
  const f = await fixture(), observe = keyReads(f.env);
  for (const id of [crypto.randomUUID(), "not-a-document", f.id.toUpperCase(), "00000000-0000-0000-0000-000000000000"]) {
    const response = await f.request("session", { id, direct }); assert.equal(response.status, 403); privateResponse(response);
  }
  assert.equal(observe(), 0); assert.equal(f.reads, 0); assert.equal(f.storage.map.size, 0);
});
for (const [name, value] of [["DUMMY_DOCUMENT_ID", undefined], ["DUMMY_DOCUMENT_ID", "invalid"],
  ["DUMMY_RECORD_SHA256", undefined], ["DUMMY_RECORD_SHA256", "A".repeat(64)], ["DUMMY_RECORD_SHA256", "b".repeat(64)]]) {
  test(`password routes retain mandatory document/ciphertext pin admission (${name}, ${String(value)})`, async () => {
    const f = await fixture(); f.env[name] = value;
    const wrap = f.env.VAULT_WRAP_KEY; let wraps = 0;
    Object.defineProperty(f.env, 'VAULT_WRAP_KEY', { get() { wraps++; return wrap; }, configurable: true });
    const response = await f.request(); assert.equal(response.status, value === "b".repeat(64) ? 403 : 503); privateResponse(response);
    assert.equal(wraps, 0); assert.equal(f.storage.map.has('encrypted-journal'), false);
    if (value !== 'b'.repeat(64)) assert.equal(f.storage.map.size, 0);
  });
}
for (const [label, options, status] of [
  ["cross-origin POST", { headers: { origin: "https://evil.example.test" } }, 403],
  ["missing origin", { headers: { origin: "" } }, 403],
  ["query string", { query: "?password=synthetic" }, 403],
  ["non-JSON request", { headers: { "content-type": "text/plain" } }, 403],
  ["malformed JSON", { body: "{" }, 400],
  ["unknown JSON fields", { body: JSON.stringify({ password: PASSWORD, extra: true }) }, 400],
  ["non-object JSON", { body: JSON.stringify(PASSWORD) }, 400],
  ["array JSON", { body: "[]" }, 400],
  ["oversized password body", { body: JSON.stringify({ password: "a".repeat(10000) }) }, 400],
]) test(`password session rejects ${label}`, async () => {
  const f = await fixture(), response = await f.request("session", options); assert.equal(response.status, status); privateResponse(response);
  assert.equal(response.headers.get("set-cookie"), null);
});
test("reader endpoints reject GET/HEAD/Range content bypasses and unsupported methods", async () => {
  const f = await fixture(), { cookie } = await f.login();
  for (const [action, methods] of [["open", ["GET", "HEAD", "PUT", "DELETE", "OPTIONS"]], ["session", ["GET", "HEAD", "PUT", "OPTIONS"]], ["status", ["HEAD", "POST", "OPTIONS"]]]) {
    for (const method of methods) {
      const response = await f.request(action, { method, cookie }); assert.equal(response.status, 405, `${method} ${action}`); privateResponse(response);
    }
  }
  for (const headers of [{ range: "bytes=0-4" }, { "if-range": '"synthetic-etag"' }]) {
    for (const direct of [false, true]) {
      const ranged = await f.request("open", { cookie, headers, direct });
      assert.equal(ranged.status, 400); privateResponse(ranged); assert.doesNotMatch(await ranged.text(), /%PDF/);
      assert.equal((await f.request("open", { headers, direct })).status, 401);
    }
  }
  assert.equal((await f.state()).events.length, 0);
});
test("open and logout require same-origin strict JSON", async () => {
  const f = await fixture(), { cookie } = await f.login();
  for (const [action, method] of [["open", "POST"], ["session", "DELETE"]]) {
    for (const headers of [{ origin: "https://evil.example.test" }, { origin: "" }, { "content-type": "text/plain" }]) {
      const response = await f.request(action, { method, cookie, headers }); assert.equal(response.status, 403); privateResponse(response);
    }
  }
  assert.equal((await f.request("open", { cookie, query: "?download=1" })).status, 403);
  assert.equal((await f.request("status", { cookie, query: "?token=synthetic" })).status, 403);
  assert.equal((await f.request("session", { method: "DELETE", cookie, body: '{"all":true}' })).status, 400);
});
test("password open validates request IDs and prevents concurrent and restarted replay", async () => {
  const f = await fixture(), { cookie } = await f.login();
  for (const body of ["{}", "{", '{"requestId":"not-a-uuid"}', JSON.stringify({ requestId: crypto.randomUUID(), extra: true })]) {
    assert.equal((await f.request("open", { cookie, body })).status, 400);
  }
  const requestId = crypto.randomUUID(), results = await Promise.all([f.request("open", { cookie, requestId }), f.request("open", { cookie, requestId })]);
  assert.deepEqual(results.map(r => r.status).sort(), [200, 409]);
  f.restart(); assert.equal((await f.request("open", { cookie, requestId })).status, 409); assert.equal((await f.state()).events.length, 1);
});
test("password sessions expire at five minutes and never outlive the document", async () => {
  const f = await fixture(), { cookie, body } = await f.login();
  await withClock(body.sessionExpiresAt, async () => {
    assert.ok([401, 403].includes((await f.request("status", { cookie })).status));
    assert.ok([401, 403].includes((await f.request("open", { cookie })).status));
  });
  const short = await fixture({ expiresAt: Date.now() + 60000 }), session = await short.login();
  assert.ok(session.body.sessionExpiresAt <= short.expiresAt);
  await withClock(short.expiresAt, async () => {
    for (const action of ["status", "open", "session"]) assert.ok([401, 403].includes((await short.request(action, { cookie: session.cookie })).status));
  });
});
for (const boundary of ["document", "session"]) test(`expiry crossing an asynchronous final audit commit denies the PDF (${boundary})`, async () => {
  const f = await fixture({ expiresAt: Date.now() + (boundary === "document" ? 60000 : 600000) });
  const { cookie, body } = await f.login(), originalNow = Date.now, initialWrites = f.storage.writes;
  let crossed = false;
  f.storage.afterCommit = async () => {
    if (f.storage.writes >= initialWrites + 3) {
      await Promise.resolve(); crossed = true; Date.now = () => boundary === "document" ? f.expiresAt : body.sessionExpiresAt;
    }
  };
  let response;
  try { response = await f.request("open", { cookie }); } finally { Date.now = originalNow; f.storage.afterCommit = null; }
  assert.ok(crossed, "the simulated expiry occurred after the final audit transaction");
  assert.equal(response.status, boundary === "session" ? 401 : 403); assert.doesNotMatch(await response.text(), /SYNTHETIC_PASSWORD_BODY/);
});
test("password authentication admits only ten attempts per source/five-minute window, including successes", async () => {
  const f = await fixture(), start = Date.now();
  await withClock(start, async () => {
    for (let i = 0; i < 10; i++) {
      const response = await f.request("session", { body: JSON.stringify({ password: i === 4 ? PASSWORD : "synthetic wrong password" }) });
      assert.equal(response.status, i === 4 ? 200 : 401);
    }
    assert.equal((await f.request()).status, 429);
    f.restart(); assert.equal((await f.request()).status, 429);
  });
  await withClock(start + 299999, async () => { assert.equal((await f.request()).status, 429); });
  await withClock(start + 300001, async () => { assert.equal((await f.request()).status, 200); });
});
test("concurrent wrong-password attempts cannot bypass the durable per-source budget", async () => {
  const f = await fixture();
  const responses = await Promise.all(Array.from({ length: 15 }, () => f.request("session", { body: JSON.stringify({ password: "synthetic wrong password" }) })));
  assert.equal(responses.filter(r => r.status === 401).length, 10); assert.equal(responses.filter(r => r.status === 429).length, 5);
  f.restart(); assert.equal((await f.request()).status, 429);
  assert.equal(f.storage.map.has('encrypted-journal'), false); assert.equal(f.calls.length, 0);
});
test("concurrent correct passwords keep the budget and parse each request once", async () => {
  const f = await fixture(), instance = f.env.VAULT.get(f.id), originalInput = instance.input.bind(instance), inputCalls = [];
  instance.input = async (request, max) => { inputCalls.push({ action: new URL(request.url).pathname.split('/').at(-1), max }); return originalInput(request, max); };
  const responses = await Promise.all(Array.from({ length: 12 }, () => f.request()));
  const details = await Promise.all(responses.map(async response => ({ status: response.status,
    error: await response.clone().json().then(body => body.error ?? null, () => "non_json_response") })));
  assert.equal(responses.filter(r => r.status === 200).length, 10, JSON.stringify(details));
  assert.equal(responses.filter(r => r.status === 429).length, 2, JSON.stringify(details));
  assert.deepEqual(inputCalls, Array.from({ length: 12 }, () => ({ action: "session", max: 2048 })));
  assert.equal((await f.admission()).rates[0].count, 10); assert.equal((await f.state()).sessions.length, 10);
  const cookie = responses.find(r => r.status === 200).headers.get('set-cookie').split(';')[0];
  const opened = await f.request('open', { cookie }); assert.equal(opened.status, 200);
  assert.deepEqual(new Uint8Array(await opened.arrayBuffer()), f.pdf);
  assert.deepEqual(inputCalls.at(-1), { action: "open", max: 128 }); assert.equal(inputCalls.length, 13);
});
test("failure to persist the authentication attempt cannot issue a cookie or session", async () => {
  const f = await fixture(); f.storage.failAt = 1;
  const response = await f.request(); assert.equal(response.status, 503); assert.equal(response.headers.get("set-cookie"), null);
  assert.equal(f.storage.map.size, 0); privateResponse(response);
});
for (const stage of [2, 3]) test(`password open with failing audit commit ${stage - 1} never releases plaintext`, async () => {
  const f = await fixture(), { cookie } = await f.login(); f.storage.failAt = f.storage.writes + stage;
  const response = await f.request("open", { cookie }); assert.equal(response.status, 503); privateResponse(response);
  assert.doesNotMatch(await response.text(), /SYNTHETIC_PASSWORD_BODY/);
});
test("outbound notification waiting cannot block owner status or revocation", async () => {
  const f = await fixture(), { cookie } = await f.login(); assert.equal((await f.request("open", { cookie })).status, 200);
  const entered = deferred(), release = deferred();
  f.providerHandler = async () => { entered.resolve(); await release.promise; return new Response("synthetic accepted", { status: 202 }); };
  const nextAt = Math.max(...(await f.state()).jobs.map(job => job.nextAt)) + 1;
  await withClock(nextAt, async () => {
    const alarm = f.alarm(); let status, revoke;
    try {
      assert.ok(await within(entered.promise.then(() => true)), "notification dispatch started");
      status = await within(f.request("status", { access: true, subject: f.env.VAULT_OWNER_SUB }));
      revoke = await within(f.request("revoke", { access: true, subject: f.env.VAULT_OWNER_SUB }));
    } finally { release.resolve(); await alarm; }
    assert.ok(status, "status completed before the provider responded"); assert.equal(status.status, 200);
    assert.ok(revoke, "revocation completed before the provider responded"); assert.equal(revoke.status, 200);
  });
  assert.equal((await f.request("open", { cookie })).status, 403);
  assert.equal((await f.state()).revoked, true); assert.equal(f.calls.length, 1);
  for (const secret of [f.id, PASSWORD, cookie, "SYNTHETIC_PASSWORD_BODY"]) assert.ok(!JSON.stringify(f.calls[0].payload).includes(secret));
});

for (const [label, change] of [
  ["unknown mode", policy => { policy.authMode = "unrecognized"; }],
  ["null mode", policy => { policy.authMode = null; }],
  ["password grant with Access subjects", policy => { policy.subjects = ["synthetic-access-reader"]; }],
  ["missing verifier", policy => { delete policy.passwordVerifier; }],
  ["unknown verifier version", policy => { policy.passwordVerifier.version = 2; }],
  ["unknown KDF", policy => { policy.passwordVerifier.kdf = "scrypt-2-1-1"; }],
  ["short salt", policy => { policy.passwordVerifier.salt = "ab".repeat(31); }],
  ["malformed salt", policy => { policy.passwordVerifier.salt = "G".repeat(64); }],
  ["short hash", policy => { policy.passwordVerifier.hash = "ab".repeat(31); }],
  ["malformed hash", policy => { policy.passwordVerifier.hash = "G".repeat(64); }],
  ["downgraded mode with password verifier", policy => { policy.authMode = "access"; policy.subjects = ["synthetic-access-reader"]; }],
  ["omitted mode with password verifier", policy => { delete policy.authMode; policy.subjects = ["synthetic-access-reader"]; }],
]) test(`malformed encrypted policy fails closed: ${label}`, async () => {
  const f = await fixture(); await f.replacePolicy(change);
  await assert.rejects(() => readPolicy(f.record, f.id, f.wrappingKey));
  const response = await f.request(); assert.ok([403, 503].includes(response.status)); assert.equal(response.headers.get("set-cookie"), null);
  assert.doesNotMatch(await response.text(), /SYNTHETIC_PASSWORD_BODY/); privateResponse(response);
});
test("legacy Access encrypted policy without authMode remains readable", async () => {
  const f = await fixture({ authMode: "access" }); await f.replacePolicy(policy => { delete policy.authMode; });
  const policy = await readPolicy(f.record, f.id, f.wrappingKey); assert.equal(policy.authMode ?? "access", "access");
  assert.equal((await f.request("open", { access: true, subject: f.subject })).status, 200);
  assert.equal((await f.request()).status, 403);
});
test("session journal stores only hashed tokens bound to the pinned record digest", async () => {
  const f = await fixture(), { cookie, body } = await f.login(), token = cookie.slice(cookie.indexOf("=") + 1), state = await f.state();
  assert.equal(state.sessions.length, 1);
  assert.match(state.sessions[0].hash, /^[a-f0-9]{64}$/); assert.notEqual(state.sessions[0].hash, token);
  assert.equal(state.sessions[0].expiresAt, body.sessionExpiresAt); assert.equal(state.sessions[0].recordDigest, f.env.DUMMY_RECORD_SHA256);
  const rate = (await f.admission()).rates[0]; assert.equal(rate.count, 1); assert.ok(Number.isSafeInteger(rate.start));
});
test("password-session allocation never persists more than 32 active sessions", async () => {
  const f = await fixture(), { cookie } = await f.login(), state = await f.state(), actual = state.sessions[0];
  state.sessions = [actual, ...Array.from({ length: 31 }, (_, i) => ({ ...actual, hash: createHash("sha256").update(`synthetic-${i}`).digest("hex") }))];
  await f.writeState(state); f.restart();
  const response = await f.request(); assert.ok([200, 429, 503].includes(response.status));
  assert.ok((await f.state()).sessions.length <= 32);
  if (response.status !== 200) assert.equal(response.headers.get("set-cookie"), null);
  assert.equal((await f.request("status", { cookie })).status, 200);
});
test("the password rate budget is durable before authentication succeeds or fails", async () => {
  const f = await fixture(), observedCounts = [];
  f.storage.afterCommit = async () => { observedCounts.push((await f.admission()).rates[0].count); };
  assert.equal((await f.request("session", { body: JSON.stringify({ password: "synthetic wrong password" }) })).status, 401);
  assert.equal(observedCounts[0], 1); assert.equal(f.storage.map.has('encrypted-journal'), false);
  f.storage.afterCommit = null; f.restart();
  assert.equal((await f.request()).status, 200); assert.equal((await f.admission()).rates[0].count, 2);
});

async function observeScrypt(callback, operation) {
  // Built-in ESM bindings let this instrument the actual native KDF without a
  // production injection hook or substituting weaker cryptographic parameters.
  const native = cryptoNode.scryptSync;
  cryptoNode.scryptSync = (...args) => { callback(); return native(...args); }; syncBuiltinESMExports();
  try { return await operation(); }
  finally { cryptoNode.scryptSync = native; syncBuiltinESMExports(); }
}
test("every password KDF follows a durable budget commit and over-budget attempts never run it", async () => {
  const f = await fixture(), committedCounts = [], kdfObservations = []; let durableCount = 0, kdfs = 0;
  f.storage.afterCommit = async () => { durableCount = (await f.admission()).rates[0].count; committedCounts.push(durableCount); };
  await observeScrypt(() => {
    kdfs++; kdfObservations.push({ durableCount, kdfs });
    assert.ok(durableCount >= kdfs, `the attempt must be durable before native scrypt starts: ${JSON.stringify(kdfObservations)}`);
  }, async () => {
    const responses = await Promise.all(Array.from({ length: 12 }, () => f.request("session", { body: JSON.stringify({ password: "synthetic wrong password" }) })));
    const responseDetails = await Promise.all(responses.map(async response => ({ status: response.status,
      error: await response.clone().json().then(body => body.error ?? null, () => "non_json_response") })));
    const statusCounts = responseDetails.reduce((counts, response) => { counts[response.status] = (counts[response.status] ?? 0) + 1; return counts; }, {});
    const diagnostic = JSON.stringify({ statusCounts, responses: responseDetails, kdfs, durableCount, committedCounts, kdfObservations });
    assert.equal(responses.filter(response => response.status === 401).length, 10, diagnostic);
    assert.equal(responses.filter(response => response.status === 429).length, 2, diagnostic);
    assert.equal(kdfs, 10, diagnostic); assert.equal(durableCount, 10, diagnostic);
  });
});
test("unknown IDs, bad pins, disabled reader, and failed attempt persistence do not run password KDF", async () => {
  const f = await fixture(); let kdfs = 0;
  await observeScrypt(() => { kdfs++; }, async () => {
    assert.equal((await f.request("session", { id: crypto.randomUUID() })).status, 403);
    const pin = f.env.DUMMY_RECORD_SHA256; f.env.DUMMY_RECORD_SHA256 = "b".repeat(64);
    assert.equal((await f.request()).status, 403); f.env.DUMMY_RECORD_SHA256 = pin;
    f.env.PASSWORD_READER_ENABLED = "0"; assert.equal((await f.request()).status, 403); f.env.PASSWORD_READER_ENABLED = "1";
    f.storage.failAt = f.storage.writes + 1; assert.equal((await f.request()).status, 503);
  });
  assert.equal(kdfs, 0);
});
test("password content and status recheck the exact ciphertext pin before document key access", async () => {
  const f = await fixture(), { cookie } = await f.login();
  f.record.document.ciphertext = "!!!!" + f.record.document.ciphertext.slice(4);
  const wrap = f.env.VAULT_WRAP_KEY; let wraps = 0;
  Object.defineProperty(f.env, 'VAULT_WRAP_KEY', { get() { wraps++; return wrap; } });
  const journal = structuredClone(f.storage.map.get('encrypted-journal'));
  for (const action of ["open", "status", "session"]) {
    const response = await f.request(action, { cookie }); assert.equal(response.status, 403); privateResponse(response);
  }
  assert.equal(wraps, 0); assert.deepEqual(f.storage.map.get('encrypted-journal'), journal);
});
test("password cookies with duplicate names are rejected instead of choosing an attacker-controlled value", async () => {
  const f = await fixture(), { cookie } = await f.login();
  for (const duplicate of [`${cookie}; ${cookie}`, `${cookie}; __Secure-vault-${f.id}=bad`, `__Secure-vault-${f.id}=bad; ${cookie}`]) {
    assert.equal((await f.request("open", { cookie: duplicate })).status, 401);
    assert.equal((await f.request("status", { cookie: duplicate })).status, 401);
  }
  assert.equal((await f.state()).events.length, 0);
});
test("password feature does not bypass mandatory owner and Access configuration", async () => {
  const f = await fixture();
  for (const name of ["ACCESS_ISSUER", "ACCESS_AUDIENCE", "VAULT_OWNER_SUB"]) {
    const value = f.env[name]; delete f.env[name];
    const response = await f.request(); assert.equal(response.status, 503, name); assert.equal(response.headers.get("set-cookie"), null);
    f.env[name] = value;
  }
  assert.equal(f.storage.map.size, 0);
});
test("password document release retains mandatory notification configuration", async () => {
  const f = await fixture(), { cookie } = await f.login(); delete f.env.WEBHOOK_URL;
  const response = await f.request("open", { cookie }); assert.equal(response.status, 503); privateResponse(response);
  assert.doesNotMatch(await response.text(), /SYNTHETIC_PASSWORD_BODY/); assert.equal((await f.state()).events.length, 0);
});

test("one source exhausting password attempts cannot lock out a different source", async () => {
  const f = await fixture();
  for (let i = 0; i < 10; i++) assert.equal((await f.request('session', { body: JSON.stringify({ password: 'synthetic wrong password' }) })).status, 401);
  const reads = f.reads, writes = f.storage.writes, wrap = f.env.VAULT_WRAP_KEY; let wraps = 0, kdfs = 0;
  Object.defineProperty(f.env, 'VAULT_WRAP_KEY', { get() { wraps++; return wrap; } });
  await observeScrypt(() => { kdfs++; }, async () => {
    for (const headers of [{ 'user-agent': 'changed' }, { 'x-forwarded-for': '198.51.100.2' }, { 'x-real-ip': '198.51.100.2' }]) {
      assert.equal((await f.request('session', { headers })).status, 429);
    }
  });
  assert.equal(f.reads, reads); assert.equal(f.storage.writes, writes); assert.equal(wraps, 0); assert.equal(kdfs, 0);
  f.restart(); assert.equal((await f.request()).status, 429);
  const other = await f.login({ headers: { 'cf-connecting-ip': '198.51.100.2' } });
  assert.equal((await f.request('open', { cookie: other.cookie, headers: { 'cf-connecting-ip': '198.51.100.2' } })).status, 200);
  const serialized = JSON.stringify([...f.storage.map]);
  for (const value of ['192.0.2.1', '198.51.100.2', PASSWORD]) assert.ok(!serialized.includes(value));
});
test("equivalent IPv6 forms share an admission budget; missing or invalid edge source fails closed", async () => {
  const f = await fixture();
  for (const source of ['', 'not-an-ip']) assert.equal((await f.request('session', { headers: { 'cf-connecting-ip': source } })).status, 503);
  assert.equal(f.reads, 0); assert.equal(f.storage.map.size, 0);
  for (let i = 0; i < 10; i++) assert.equal((await f.request('session', { headers: { 'cf-connecting-ip': '2001:0db8:0:0:0:0:0:1' }, body: JSON.stringify({ password: 'synthetic wrong password' }) })).status, 401);
  assert.equal((await f.request('session', { headers: { 'cf-connecting-ip': '2001:db8::1' } })).status, 429);
});
test("cookie-less logout is storage-free and keeps route, origin, and strict input checks", async () => {
  const f = await fixture(); let keyAccess = 0;
  for (const name of ['VAULT_AUDIT_KEY', 'VAULT_WRAP_KEY']) Object.defineProperty(f.env, name, { get() { keyAccess++; throw new Error('must_not_access_key'); } });
  for (let i = 0; i < 20; i++) {
    const response = await f.request('session', { method: 'DELETE' }); assert.equal(response.status, 200);
    assert.match(response.headers.get('set-cookie'), /Max-Age=0/);
  }
  assert.equal((await f.request('session', { method: 'DELETE', headers: { origin: 'https://other.example.test' } })).status, 403);
  assert.equal((await f.request('session', { method: 'DELETE', body: '{"extra":true}' })).status, 400);
  assert.equal((await f.request('session', { method: 'DELETE', id: crypto.randomUUID() })).status, 403);
  assert.equal(keyAccess, 0); assert.equal(f.reads, 0); assert.equal(f.storage.map.size, 0);
});
test("forged syntactically valid cookies never read R2 and bounded retries stop further storage writes", async () => {
  const f = await fixture(), { cookie } = await f.login(), journal = structuredClone(f.storage.map.get('encrypted-journal')), reads = f.reads;
  const forged = `__Secure-vault-${f.id}=${'b'.repeat(64)}`;
  for (let i = 0; i < 30; i++) assert.equal((await f.request('open', { cookie: forged })).status, 401);
  const writes = f.storage.writes;
  assert.equal((await f.request('status', { cookie: forged })).status, 429);
  assert.equal(f.reads, reads); assert.equal(f.storage.writes, writes); assert.deepEqual(f.storage.map.get('encrypted-journal'), journal);
  f.restart(); assert.equal((await f.request('open', { cookie: forged })).status, 429);
  assert.equal((await f.request('open', { cookie, headers: { 'cf-connecting-ip': '198.51.100.3' } })).status, 200);
});
test("slow password R2 reads do not hold owner controls and late results respect revocation", async () => {
  const f = await fixture(), { cookie } = await f.login(), entered = deferred(), release = deferred();
  f.recordHandler = async () => { entered.resolve(); await release.promise; };
  const open = f.request('open', { cookie }); let status, revoke;
  try {
    assert.ok(await within(entered.promise.then(() => true)));
    status = await within(f.request('status', { access: true, subject: f.env.VAULT_OWNER_SUB }));
    revoke = await within(f.request('revoke', { access: true, subject: f.env.VAULT_OWNER_SUB }));
  } finally { release.resolve(); }
  assert.equal(status?.status, 200); assert.equal(revoke?.status, 200);
  const denied = await open; assert.equal(denied.status, 403); assert.doesNotMatch(await denied.text(), /SYNTHETIC_PASSWORD_BODY/);
});
test("password reader job quotas count every notification target and do not reset with a new session", async () => {
  const f = await fixture();
  f.env.SLACK_WEBHOOK_URL = 'https://slack.example.test/synthetic';
  f.env.DISCORD_WEBHOOK_URL = 'https://discord.example.test/synthetic';
  const first = await f.login();
  for (let i = 0; i < 3; i++) {
    const response = await f.request('open', { cookie: first.cookie });
    assert.equal(response.status, 200, response.status === 200 ? '' : await response.text());
  }
  assert.equal((await f.state()).jobs.length, 9);
  const rotated = await f.login();
  assert.equal((await f.request('open', { cookie: rotated.cookie })).status, 429);
  assert.equal((await f.state()).jobs.length, 9);
  const other = await f.request('open', { cookie: rotated.cookie, headers: { 'cf-connecting-ip': '198.51.100.4' } });
  assert.equal(other.status, 200); assert.deepEqual(new Uint8Array(await other.arrayBuffer()), f.pdf);
  assert.equal((await f.state()).jobs.length, 12); assert.equal(f.calls.length, 0);
});
