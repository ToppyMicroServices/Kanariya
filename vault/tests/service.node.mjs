import test, { after } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { generateKeyPair, exportJWK, SignJWT } from "jose";
import worker, { VaultDocument } from "../src/worker.js";
import { pdfjsAssetMetadata } from "../src/pdfjs-assets.generated.js";
import { newKey, importKey, sealDocument, readPolicy, decryptDocument, openJSON, utf8 } from "../src/crypto.js";

function list(map, options) {
  return new Map([...map].filter(([key]) => key.startsWith(options.prefix) && (!options.end || key < options.end))
    .sort(([a], [b]) => a.localeCompare(b)).slice(0, options.limit));
}

const originalFetch = globalThis.fetch;
after(() => { globalThis.fetch = originalFetch; });
const pair = await generateKeyPair("RS256", { extractable: true });
const jwk = { ...await exportJWK(pair.publicKey), kid: "fixture", use: "sig", alg: "RS256" };
let fixtureNumber = 0;
class Storage {
  constructor() { this.map = new Map(); this.alarmAt = null; this.writes = 0; this.failAt = Infinity; this.failAlarm = false; }
  async get(key) { return structuredClone(this.map.get(key)); }
  async setAlarm(at) { if (this.failAlarm) throw new Error("synthetic_failure"); this.alarmAt = at; }
  async transaction(fn) {
    const draft = new Map(structuredClone([...this.map])); let alarm = this.alarmAt;
    const result = await fn({ get: async k => structuredClone(draft.get(k)),
      list: async options => list(draft, options), delete: async key => draft.delete(key),
      put: async (k, v) => { if (++this.writes === this.failAt) throw new Error("synthetic_failure"); draft.set(k, structuredClone(v)); },
      setAlarm: async at => { if (this.failAlarm) throw new Error("synthetic_alarm_failure"); alarm = at; },
      deleteAlarm: async () => { alarm = null; } });
    this.map = draft; this.alarmAt = alarm; return result;
  }
}
async function fixture(options = {}) {
  const id = crypto.randomUUID(), subject = "fixture-subject-private", pdf = utf8("%PDF-1.4\nSYNTHETIC_PRIVATE_BODY\n");
  const env = { PUBLIC_ORIGIN: "https://vault.example.test", ACCESS_ISSUER: `https://fixture-${++fixtureNumber}.cloudflareaccess.com`,
    ACCESS_AUDIENCE: "fixture-audience", VAULT_WRAP_KEY: newKey(), VAULT_AUDIT_KEY: newKey(), VAULT_OWNER_SUB: "fixture-owner-private",
    WEBHOOK_URL: "https://notify.example.test/secret-path" };
  const wrappingKey = await importKey(env.VAULT_WRAP_KEY);
  let record = await sealDocument({ id, bytes: pdf, subjects: [subject], expiresAt: Date.now() + 600000, ...options }, wrappingKey);
  const pinRecord = () => { env.DUMMY_DOCUMENT_ID = id; env.DUMMY_RECORD_SHA256 = createHash("sha256").update(JSON.stringify(record)).digest("hex"); };
  pinRecord();
  const calls = []; let reads = 0, providerStatus = 202;
  env.VAULT_DOCUMENTS = { async get(name) { reads++; assert.equal(name, `${id}.sealed.json`);
    if (!record) return null; const bytes = utf8(JSON.stringify(record)); return { size: bytes.length, body: new Response(bytes).body }; } };
  const storage = new Storage(), ctx = { storage, id: { toString: () => `object-${id}` } };
  let instance = new VaultDocument(ctx, env);
  env.VAULT = { idFromName: value => { assert.equal(value, id); return value; }, get: () => instance };
  globalThis.fetch = async (url, options) => {
    if (String(url) === `${env.ACCESS_ISSUER}/cdn-cgi/access/certs`) return Response.json({ keys: [jwk] });
    assert.equal(String(url), env.WEBHOOK_URL); calls.push({ url, options, payload: JSON.parse(options.body) });
    return new Response("synthetic provider body must not be logged", { status: providerStatus });
  };
  async function token(overrides = {}) {
    return new SignJWT({ sub: subject, iss: env.ACCESS_ISSUER, aud: env.ACCESS_AUDIENCE,
      iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + 600, ...overrides })
      .setProtectedHeader({ alg: "RS256", kid: "fixture" }).sign(pair.privateKey);
  }
  async function request(action = "open", options = {}) {
    const headers = { origin: env.PUBLIC_ORIGIN, "content-type": "application/json", "cf-access-jwt-assertion": await token(options.claims), ...options.headers };
    const method = options.method || (action === "status" ? "GET" : "POST");
    const request = new Request(`${env.PUBLIC_ORIGIN}/v1/documents/${options.id || id}/${action}${options.query || ""}`, {
      method, headers, ...(method === "GET" ? {} : { body: options.body ?? JSON.stringify(action === "open" ? { requestId: options.requestId || crypto.randomUUID() } : {}) }),
    });
    return options.direct ? instance.fetch(request) : worker.fetch(request, env);
  }
  async function state() { return openJSON(await storage.get("encrypted-journal"), await importKey(env.VAULT_AUDIT_KEY), `journal:v1:object-${id}`); }
  async function alarm() {
    const before = Date.now, next = Math.max(...(await state()).jobs.map(j => j.nextAt)) + 1;
    Date.now = () => next;
    try { await instance.alarm(); } finally { Date.now = before; }
  }
  return { env, id, subject, pdf, request, token, storage, state, alarm, calls, pinRecord, get reads() { return reads; },
    get record() { return record; }, set record(value) { record = value; },
    set providerStatus(value) { providerStatus = value; },
    restart() { instance = new VaultDocument(ctx, env); }, wrappingKey };
}

test("approved pinned dummy returns exact bytes after encrypted journal commits, never a key", async () => {
  const f = await fixture(), response = await f.request();
  assert.equal(response.status, 200); assert.deepEqual(new Uint8Array(await response.arrayBuffer()), f.pdf);
  assert.match(response.headers.get("cache-control"), /no-store/);
  assert.equal(response.headers.get("content-disposition"), 'inline; filename="protected-document.pdf"');
  assert.equal(response.headers.get("x-vault-download-filename"), null);
  const persisted = JSON.stringify([...f.storage.map]);
  for (const secret of [f.subject, f.env.VAULT_WRAP_KEY, f.env.VAULT_AUDIT_KEY, "SYNTHETIC_PRIVATE_BODY", "application/pdf"]) assert.ok(!persisted.includes(secret));
  const state = await f.state(); assert.equal(state.events[0].outcome, "decrypted"); assert.equal(state.jobs[0].outcome, "decrypted");
  assert.ok(f.storage.alarmAt); assert.equal(f.calls.length, 0);
});
test("Access PDF responses expose only the encrypted owner-selected recipient filename after authorization", async () => {
  const recipientName = "株式会社テスト 採用担当", f = await fixture({ recipientName });
  const denied = await f.request("open", { claims: { sub: "other-private-subject" } });
  assert.equal(denied.status, 403); assert.equal(denied.headers.get("x-vault-download-filename"), null);
  const response = await f.request(), filename = `CV_${recipientName}.pdf`;
  assert.equal(response.status, 200); assert.deepEqual(new Uint8Array(await response.arrayBuffer()), f.pdf);
  assert.equal(decodeURIComponent(response.headers.get("x-vault-download-filename")), filename);
  assert.equal(decodeURIComponent(response.headers.get("content-disposition").split("filename*=UTF-8''")[1]), filename);
  assert.ok(!JSON.stringify(f.record).includes(recipientName));
  assert.ok(!JSON.stringify(await f.state()).includes(recipientName));
  await f.alarm(); assert.ok(!JSON.stringify(f.calls).includes(recipientName));
  const forged = await f.request("open", { body: JSON.stringify({ requestId: crypto.randomUUID(), recipientName: "Other recipient" }) });
  assert.equal(forged.status, 400);
});
function observeKeyReads(env) {
  let reads = 0;
  for (const name of ["VAULT_WRAP_KEY", "VAULT_AUDIT_KEY"]) {
    const value = env[name];
    Object.defineProperty(env, name, { get() { reads++; return value; } });
  }
  return () => reads;
}
for (const direct of [false, true]) test(`unapproved document ID is rejected before storage or keys (${direct ? "object" : "worker"})`, async () => {
  const f = await fixture(), keyReads = observeKeyReads(f.env);
  assert.equal((await f.request("open", { id: crypto.randomUUID(), direct })).status, 403);
  assert.equal(keyReads(), 0); assert.equal(f.reads, 0); assert.equal(f.storage.map.size, 0); assert.equal(f.calls.length, 0);
});
for (const [name, value] of [
  ["DUMMY_DOCUMENT_ID", undefined], ["DUMMY_DOCUMENT_ID", "unconfigured"], ["DUMMY_DOCUMENT_ID", 123],
  ["DUMMY_RECORD_SHA256", undefined], ["DUMMY_RECORD_SHA256", "unconfigured"], ["DUMMY_RECORD_SHA256", "A".repeat(64)],
]) test(`missing or malformed dummy pin fails closed (${name}: ${value === undefined ? "missing" : typeof value === "number" ? "type" : value === "unconfigured" ? "placeholder" : "uppercase"})`, async () => {
  const f = await fixture(), keyReads = observeKeyReads(f.env); f.env[name] = value;
  assert.equal((await f.request()).status, 503);
  assert.equal(keyReads(), 0); assert.equal(f.reads, 0); assert.equal(f.storage.map.size, 0); assert.equal(f.calls.length, 0);
});
test("same-ID replacement is rejected before any key use, journal write or notification", async () => {
  const f = await fixture();
  f.record = await sealDocument({ id: f.id, bytes: utf8("%PDF-1.4\nUNAPPROVED-SYNTHETIC-DOCUMENT\n"), subjects: [f.subject], expiresAt: Date.now() + 600000 }, f.wrappingKey);
  const keyReads = observeKeyReads(f.env);
  assert.equal((await f.request()).status, 403);
  assert.equal(keyReads(), 0); assert.equal(f.reads, 1); assert.equal(f.storage.map.size, 0); assert.equal(f.calls.length, 0);
});
test("pin is checked again after a previous approved open", async () => {
  const f = await fixture(); assert.equal((await f.request()).status, 200);
  const writes = f.storage.writes;
  f.record = await sealDocument({ id: f.id, bytes: f.pdf, subjects: [f.subject], expiresAt: Date.now() + 600000 }, f.wrappingKey);
  const keyReads = observeKeyReads(f.env);
  assert.equal((await f.request()).status, 403);
  assert.equal(keyReads(), 0); assert.equal(f.storage.writes, writes); assert.equal(f.calls.length, 0);
});
for (const [label, claims] of [
  ["wrong audience", { aud: "elsewhere" }], ["wrong issuer", { iss: "https://evil.example.test" }],
  ["expired", { exp: 1 }], ["future issued-at", { iat: Math.floor(Date.now() / 1000) + 1000, exp: Math.floor(Date.now() / 1000) + 2000 }],
  ["missing subject", { sub: undefined }], ["missing expiry", { exp: undefined }],
]) test(`rejects ${label} before reading any document`, async () => {
  const f = await fixture(); assert.equal((await f.request("open", { claims })).status, 401); assert.equal(f.reads, 0);
});
test("unsigned identity header does not authenticate", async () => {
  const f = await fixture(); assert.equal((await f.request("open", { headers: { "cf-access-jwt-assertion": "", "cf-access-authenticated-user-email": "synthetic@example.test" } })).status, 401);
  assert.equal(f.reads, 0);
});
test("modified JWT signature fails", async () => {
  const f = await fixture(), parts = (await f.token()).split("."); parts[2] = (parts[2][0] === "A" ? "B" : "A") + parts[2].slice(1);
  assert.equal((await f.request("open", { headers: { "cf-access-jwt-assertion": parts.join(".") } })).status, 401);
});
test("valid identity without document grant receives no PDF", async () => {
  const f = await fixture(); const response = await f.request("open", { claims: { sub: "other-private-subject" } });
  assert.equal(response.status, 403); assert.ok(!(await response.text()).includes("PRIVATE")); assert.equal(f.storage.map.size, 0);
});
test("expired document policy denies access", async () => {
  const f = await fixture(); f.record = await sealDocument({ id: f.id, bytes: f.pdf, subjects: [f.subject], expiresAt: Date.now() - 1 }, f.wrappingKey);
  f.pinRecord();
  assert.equal((await f.request()).status, 403);
});
for (const [label, options, expected] of [
  ["cross origin", { headers: { origin: "https://evil.example.test" } }, 403],
  ["GET/prefetch", { method: "GET" }, 405], ["query parameters", { query: "?token=fixture" }, 403],
  ["non JSON", { headers: { "content-type": "text/plain" } }, 403],
  ["oversized body", { body: "x".repeat(200) }, 400], ["invalid request ID", { body: '{"requestId":"private-data"}' }, 400],
]) test(`rejects ${label}`, async () => { const f = await fixture(); assert.equal((await f.request("open", options)).status, expected); });
test("missing notification configuration prevents content release", async () => {
  const f = await fixture(); delete f.env.WEBHOOK_URL; assert.equal((await f.request()).status, 503); assert.equal(f.storage.map.size, 0);
});
test("malformed notification configuration prevents content release", async () => {
  const f = await fixture(); f.env.WEBHOOK_URL = "http://unsafe.example.test"; assert.equal((await f.request()).status, 503);
});
test("incomplete email configuration prevents content release", async () => {
  const f = await fixture(); f.env.MAIL_TO = "synthetic@example.test"; assert.equal((await f.request()).status, 503);
});
for (const [name, value] of [
  ["MAIL_FROM", "not-an-address"], ["MAIL_FROM", "synthetic@@example.test"],
  ["MAIL_TO", "synthetic@example.test,not-an-address"], ["MAIL_TO", "synthetic@example.test\n"],
]) test(`malformed ${name} prevents document reads, key access and journal writes (${JSON.stringify(value)})`, async () => {
  const f = await fixture();
  // Even a valid second notification channel must not hide the invalid email target.
  Object.assign(f.env, { MAIL_FROM: "sender@example.test", MAIL_TO: "reader@example.test", MAILCHANNELS_API_KEY: "synthetic-provider-key", [name]: value });
  const keyReads = observeKeyReads(f.env), response = await f.request();
  assert.equal(response.status, 503); assert.doesNotMatch(await response.text(), /SYNTHETIC_PRIVATE_BODY/);
  assert.equal(keyReads(), 0); assert.equal(f.reads, 0); assert.equal(f.storage.map.size, 0); assert.equal(f.calls.length, 0);
});
test("audit key must be separate from wrapping key", async () => {
  const f = await fixture(); f.env.VAULT_AUDIT_KEY = f.env.VAULT_WRAP_KEY; assert.equal((await f.request()).status, 503);
});
test("modified document records cannot be decrypted or transplanted", async () => {
  const f = await fixture(); f.record.id = crypto.randomUUID(); f.pinRecord(); assert.equal((await f.request()).status, 503);
});
test("ciphertext corruption records a failed attempt without returning plaintext", async () => {
  const f = await fixture(); f.record.document.ciphertext = "A" + f.record.document.ciphertext.slice(1);
  // Ensure a change even when the first base64 character was already A.
  f.record.document.ciphertext = f.record.document.ciphertext.slice(0, 5) + "!!!!" + f.record.document.ciphertext.slice(9);
  f.pinRecord(); // Exercise decryption failure after the independent admission gate.
  assert.equal((await f.request()).status, 503); assert.equal((await f.state()).events[0].outcome, "failed");
});
for (const stage of [1, 2]) test(`journal write failure at commit ${stage} prevents content release`, async () => {
  const f = await fixture(); f.storage.failAt = stage; const r = await f.request();
  assert.equal(r.status, 503); assert.ok(!(await r.text()).includes("SYNTHETIC_PRIVATE_BODY"));
  if (stage === 2) { assert.equal((await f.state()).events[0].outcome, "requested"); f.restart(); await f.alarm(); assert.equal(f.calls[0].payload.event.outcome, "unknown"); }
});
test("alarm scheduling failure rolls back reservation and prevents release", async () => {
  const f = await fixture(); f.storage.failAlarm = true; assert.equal((await f.request()).status, 503); assert.equal(f.storage.map.size, 0);
});
test("concurrent replay only releases once; guard survives restart", async () => {
  const f = await fixture(), requestId = crypto.randomUUID();
  const responses = await Promise.all([f.request("open", { requestId }), f.request("open", { requestId })]);
  assert.deepEqual(responses.map(r => r.status).sort(), [200, 409]);
  f.restart(); assert.equal((await f.request("open", { requestId })).status, 409); assert.equal((await f.state()).events.length, 1);
});
test("separate opens each produce a distinct event, without canary deduplication", async () => {
  const f = await fixture(); await f.request(); await f.request(); assert.equal((await f.state()).jobs.length, 2);
  await f.alarm(); assert.equal(f.calls.length, 2); assert.notEqual(f.calls[0].payload.event.id, f.calls[1].payload.event.id);
});
test("notification sends only an opaque event ID and a fixed outcome", async () => {
  const f = await fixture(); await f.request(); await f.alarm();
  const sent = JSON.stringify(f.calls[0].payload);
  for (const secret of [f.id, f.subject, "SYNTHETIC_PRIVATE_BODY", f.env.VAULT_WRAP_KEY, f.env.VAULT_AUDIT_KEY]) assert.ok(!sent.includes(secret));
  assert.equal(f.calls[0].payload.kind, "vault.decryption"); assert.equal(f.calls[0].options.redirect, "manual");
  assert.equal((await f.state()).jobs[0].state, "accepted");
});
test("transient provider failure retries from encrypted durable state", async () => {
  const f = await fixture(); f.providerStatus = 503; await f.request(); await f.alarm();
  assert.equal((await f.state()).jobs[0].state, "pending"); f.providerStatus = 202; f.restart(); await f.alarm();
  assert.equal((await f.state()).jobs[0].state, "accepted"); assert.equal(f.calls.length, 2);
});
test("permanent provider failure blocks further opens until owner retries", async () => {
  const f = await fixture(); f.providerStatus = 401; await f.request(); await f.alarm();
  assert.equal((await f.state()).jobs[0].state, "failed"); assert.equal((await f.request()).status, 503);
  assert.equal((await f.request("retry-notifications")).status, 403);
  assert.equal((await f.request("retry-notifications", { claims: { sub: f.env.VAULT_OWNER_SUB } })).status, 200);
  f.providerStatus = 202; await f.alarm(); assert.equal((await f.request()).status, 200);
});
test("a changed destination never receives already queued notifications automatically", async () => {
  const f = await fixture(); await f.request(); f.env.WEBHOOK_URL = "https://notify.example.test/other-path"; await f.alarm();
  assert.equal(f.calls.length, 0); assert.equal((await f.state()).jobs[0].state, "failed");
});
test("owner revocation survives restart; readers cannot revoke or inspect status", async () => {
  const f = await fixture(); assert.equal((await f.request("status")).status, 403); assert.equal((await f.request("revoke")).status, 403);
  assert.equal((await f.request("revoke", { claims: { sub: f.env.VAULT_OWNER_SUB } })).status, 200);
  f.restart(); assert.equal((await f.request()).status, 403);
  assert.equal((await (await f.request("status", { claims: { sub: f.env.VAULT_OWNER_SUB } })).json()).revoked, true);
});
test("envelope wrapping keeps document key out of the stored record", async () => {
  const f = await fixture(); const policy = await readPolicy(f.record, f.id, f.wrappingKey);
  assert.deepEqual(await decryptDocument(f.record, f.wrappingKey, policy), f.pdf);
  assert.ok(!JSON.stringify(f.record).includes(f.subject));
  const wrongKey = await importKey(newKey());
  await assert.rejects(() => readPolicy(f.record, f.id, wrongKey));
});
test("viewer contains no identity or document bytes and uses no persistent browser storage", async () => {
  const f = await fixture();
  const r = await worker.fetch(new Request(f.env.PUBLIC_ORIGIN + "/", { headers: { "cf-access-jwt-assertion": await f.token() } }), f.env);
  assert.equal(r.status, 200); const text = await r.text(); assert.ok(!text.includes(f.subject)); assert.ok(!text.includes("PRIVATE_BODY"));
  const js = await worker.fetch(new Request(f.env.PUBLIC_ORIGIN + "/viewer.js", { headers: { "cf-access-jwt-assertion": await f.token() } }), f.env);
  assert.doesNotMatch(await js.text(), /localStorage|sessionStorage|indexedDB|console\./);
});

async function assertBrandResponse(response) {
  assert.equal(response.status, 200);
  assert.equal(response.headers.get("content-type"), "image/png");
  assert.equal(response.headers.get("cache-control"), "private, no-store, max-age=0");
  assert.equal(response.headers.get("referrer-policy"), "no-referrer");
  assert.equal(response.headers.get("cross-origin-resource-policy"), "same-origin");
  const csp = response.headers.get("content-security-policy");
  assert.match(csp, /(?:^|; )img-src 'self';/);
  assert.doesNotMatch(csp, /unsafe-inline|unsafe-eval|https:|data:|blob:/);
  const bytes = new Uint8Array(await response.arrayBuffer());
  assert.deepEqual([...bytes.slice(0, 8)], [137, 80, 78, 71, 13, 10, 26, 10]);
  assert.equal(createHash("sha256").update(bytes).digest("hex"), "00d83bad154078750b5c2b3efa0ce2586905dfab3142a93cda9e7164e68ed7c5");
}

test("official brand image requires verified Access identity outside the password reader", async () => {
  const f = await fixture(), keyReads = observeKeyReads(f.env);
  for (const headers of [{}, { "cf-access-jwt-assertion": "invalid" }, { "cf-access-authenticated-user-email": "synthetic@example.test" }]) {
    assert.equal((await worker.fetch(new Request(f.env.PUBLIC_ORIGIN + "/brand.png", { headers }), f.env)).status, 401);
  }
  await assertBrandResponse(await worker.fetch(new Request(f.env.PUBLIC_ORIGIN + "/brand.png", {
    headers: { "cf-access-jwt-assertion": await f.token() },
  }), f.env));
  assert.equal(keyReads(), 0); assert.equal(f.reads, 0); assert.equal(f.storage.map.size, 0); assert.equal(f.calls.length, 0);
});

test("password reader serves only the exact local brand asset without accessing document data", async () => {
  const f = await fixture(), keyReads = observeKeyReads(f.env);
  f.env.PASSWORD_READER_ENABLED = "1";
  await assertBrandResponse(await worker.fetch(new Request(f.env.PUBLIC_ORIGIN + "/p/assets/brand.png"), f.env));
  for (const path of ["/p/brand.png", `/p/${f.id}/brand.png`, `/p/${crypto.randomUUID()}/brand.png`, "/p/assets/brand.svg", "/p/assets/brand.png/private"]) {
    assert.equal((await worker.fetch(new Request(f.env.PUBLIC_ORIGIN + path), f.env)).status, 403);
  }
  assert.equal(keyReads(), 0); assert.equal(f.reads, 0); assert.equal(f.storage.map.size, 0); assert.equal(f.calls.length, 0);
});

test("brand asset retains origin, query, method, password flag and configuration gates", async () => {
  const f = await fixture(), keyReads = observeKeyReads(f.env), path = "/p/assets/brand.png";
  assert.equal((await worker.fetch(new Request(f.env.PUBLIC_ORIGIN + path), f.env)).status, 403);
  f.env.PASSWORD_READER_ENABLED = "0";
  assert.equal((await worker.fetch(new Request(f.env.PUBLIC_ORIGIN + path), f.env)).status, 403);
  f.env.PASSWORD_READER_ENABLED = "1";
  assert.equal((await worker.fetch(new Request("https://elsewhere.example.test" + path), f.env)).status, 403);
  assert.equal((await worker.fetch(new Request(f.env.PUBLIC_ORIGIN + path + "?external=1"), f.env)).status, 403);
  assert.equal((await worker.fetch(new Request(f.env.PUBLIC_ORIGIN + path, { method: "POST" }), f.env)).status, 405);
  const issuer = f.env.ACCESS_ISSUER;
  delete f.env.ACCESS_ISSUER;
  assert.equal((await worker.fetch(new Request(f.env.PUBLIC_ORIGIN + path), f.env)).status, 503);
  f.env.ACCESS_ISSUER = issuer;
  delete f.env.DUMMY_RECORD_SHA256;
  assert.equal((await worker.fetch(new Request(f.env.PUBLIC_ORIGIN + path), f.env)).status, 503);
  assert.equal(keyReads(), 0); assert.equal(f.reads, 0); assert.equal(f.storage.map.size, 0); assert.equal(f.calls.length, 0);
});

const rendererPaths = [
  ["/pdfjs/pdf.min.mjs", "text/javascript; charset=utf-8"],
  ["/pdfjs/pdf.worker.min.mjs", "text/javascript; charset=utf-8"],
  ["/pdfjs/standard_fonts/LiberationSans-Regular.ttf", "font/ttf"],
  ["/pdfjs/standard_fonts/LiberationSans-Bold.ttf", "font/ttf"],
  ["/pdfjs/LICENSE", "text/plain; charset=utf-8"],
  ["/pdfjs/standard_fonts/LICENSE_LIBERATION", "text/plain; charset=utf-8"],
];
for (const [path, mime] of rendererPaths) {
  test(`renderer asset ${path} requires verified Access identity and preserves privacy headers`, async () => {
    const f = await fixture(), keyReads = observeKeyReads(f.env);
    for (const headers of [{}, { "cf-access-jwt-assertion": "invalid" }, { "cf-access-authenticated-user-email": "synthetic@example.test" }]) {
      const denied = await worker.fetch(new Request(f.env.PUBLIC_ORIGIN + path, { headers }), f.env);
      assert.equal(denied.status, 401);
    }
    const response = await worker.fetch(new Request(f.env.PUBLIC_ORIGIN + path, { headers: { "cf-access-jwt-assertion": await f.token() } }), f.env);
    assert.equal(response.status, 200); assert.equal(response.headers.get("content-type"), mime);
    assert.equal(response.headers.get("cache-control"), "private, no-store, max-age=0");
    assert.equal(response.headers.get("cdn-cache-control"), "no-store");
    assert.equal(response.headers.get("referrer-policy"), "no-referrer");
    assert.equal(response.headers.get("x-content-type-options"), "nosniff");
    const csp = response.headers.get("content-security-policy");
    assert.match(csp, /worker-src 'self'/); assert.doesNotMatch(csp, /unsafe-inline|unsafe-eval|https:|blob:/);
    const bytes = new Uint8Array(await response.arrayBuffer());
    const metadata = pdfjsAssetMetadata.assets.find(asset => asset.path === path);
    assert.equal(pdfjsAssetMetadata.version, "6.4.299"); assert.equal(bytes.length, metadata.bytes);
    assert.equal(createHash("sha256").update(bytes).digest("hex"), metadata.sha256);
    assert.equal(keyReads(), 0); assert.equal(f.reads, 0); assert.equal(f.storage.map.size, 0); assert.equal(f.calls.length, 0);
  });
}
test("renderer assets keep the origin, query, method and mandatory dummy-pin gates", async () => {
  const f = await fixture(), keyReads = observeKeyReads(f.env), path = "/pdfjs/pdf.min.mjs";
  const headers = { "cf-access-jwt-assertion": await f.token() };
  assert.equal((await worker.fetch(new Request("https://elsewhere.example.test" + path, { headers }), f.env)).status, 403);
  assert.equal((await worker.fetch(new Request(f.env.PUBLIC_ORIGIN + path + "?external=1", { headers }), f.env)).status, 403);
  assert.equal((await worker.fetch(new Request(f.env.PUBLIC_ORIGIN + path, { method: "POST", headers }), f.env)).status, 404);
  delete f.env.DUMMY_RECORD_SHA256;
  assert.equal((await worker.fetch(new Request(f.env.PUBLIC_ORIGIN + path, { headers }), f.env)).status, 503);
  assert.equal(keyReads(), 0); assert.equal(f.reads, 0); assert.equal(f.storage.map.size, 0); assert.equal(f.calls.length, 0);
});
test("renderer asset serving rejects unknown paths rather than exposing package directories", async () => {
  const f = await fixture(), headers = { "cf-access-jwt-assertion": await f.token() };
  assert.equal(pdfjsAssetMetadata.assets.length, rendererPaths.length);
  assert.deepEqual(pdfjsAssetMetadata.assets.map(asset => asset.path), rendererPaths.map(([path]) => path));
  for (const path of ["/pdfjs/", "/pdfjs/package.json", "/pdfjs/pdf.min.mjs.map", "/pdfjs/pdf.sandbox.mjs", "/pdfjs/standard_fonts/unknown.ttf", "/pdfjs/__proto__", "/pdfjs/pdf%2emin.mjs"]) {
    assert.equal((await worker.fetch(new Request(f.env.PUBLIC_ORIGIN + path, { headers }), f.env)).status, 404);
  }
  assert.equal(f.reads, 0); assert.equal(f.storage.map.size, 0); assert.equal(f.calls.length, 0);
});
