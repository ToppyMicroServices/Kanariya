import test, { after } from "node:test";
import assert from "node:assert/strict";
import cryptoNode, { createHash } from "node:crypto";
import { syncBuiltinESMExports } from "node:module";
import { generateKeyPair, exportJWK, SignJWT } from "jose";
import worker, { VaultDocument } from "../src/worker.js";
import { newKey, importKey, sealDocument, openJSON, utf8 } from "../src/crypto.js";
import { requestBody, failure } from "../src/http.js";

// Local synthetic request streams only. All possible outbound calls are mocked.
const originalFetch = globalThis.fetch;
after(() => { globalThis.fetch = originalFetch; });
const pair = await generateKeyPair("RS256", { extractable: true });
const jwk = { ...await exportJWK(pair.publicKey), kid: "stream-fixture", use: "sig", alg: "RS256" };
let fixtureNumber = 0;
function deferred() { let resolve; const promise = new Promise(done => { resolve = done; }); return { promise, resolve }; }
async function within(promise, ms = 1000) {
  let timer;
  try { return await Promise.race([promise, new Promise(resolve => { timer = setTimeout(() => resolve(null), ms); })]); }
  finally { clearTimeout(timer); }
}
class Storage {
  constructor() { this.map = new Map(); this.writes = 0; this.alarmAt = null; }
  async get(key) { return structuredClone(this.map.get(key)); }
  async transaction(change) {
    const next = new Map(structuredClone([...this.map])); let alarm = this.alarmAt;
    const result = await change({
      get: async key => structuredClone(next.get(key)),
      list: async options => new Map([...next].filter(([key]) => key.startsWith(options.prefix) && (!options.end || key < options.end))
        .sort(([a], [b]) => a.localeCompare(b)).slice(0, options.limit)),
      delete: async key => next.delete(key),
      put: async (key, value) => { this.writes++; next.set(key, structuredClone(value)); },
      setAlarm: async at => { alarm = at; }, deleteAlarm: async () => { alarm = null; },
    });
    this.map = next; this.alarmAt = alarm; return result;
  }
}
async function fixture() {
  const id = crypto.randomUUID(), password = "synthetic-stream-password";
  const env = { PUBLIC_ORIGIN: "https://vault.example.test", PASSWORD_READER_ENABLED: "1",
    ACCESS_ISSUER: `https://stream-fixture-${++fixtureNumber}.cloudflareaccess.com`, ACCESS_AUDIENCE: "synthetic-stream",
    VAULT_OWNER_SUB: "synthetic-stream-owner", VAULT_WRAP_KEY: newKey(), VAULT_AUDIT_KEY: newKey() };
  const record = JSON.stringify(await sealDocument({ id, bytes: utf8("%PDF-1.4\nSYNTHETIC_STREAM_BODY\n"),
    subjects: [], authMode: "password", password, expiresAt: Date.now() + 600000 }, await importKey(env.VAULT_WRAP_KEY)));
  env.DUMMY_DOCUMENT_ID = id; env.DUMMY_RECORD_SHA256 = createHash("sha256").update(record).digest("hex");
  let reads = 0;
  env.VAULT_DOCUMENTS = { async get(name) { reads++; assert.equal(name, `${id}.sealed.json`);
    const bytes = utf8(record); return { size: bytes.length, body: new Response(bytes).body }; } };
  const storage = new Storage(), instance = new VaultDocument({ storage, id: { toString: () => id } }, env);
  env.VAULT = { idFromName: value => { assert.equal(value, id); return value; }, get: () => instance };
  globalThis.fetch = async url => {
    assert.equal(String(url), `${env.ACCESS_ISSUER}/cdn-cgi/access/certs`, "no external calls are permitted");
    return Response.json({ keys: [jwk] });
  };
  const ownerToken = await new SignJWT({ sub: env.VAULT_OWNER_SUB }).setProtectedHeader({ alg: "RS256", kid: jwk.kid })
    .setIssuer(env.ACCESS_ISSUER).setAudience(env.ACCESS_AUDIENCE).setIssuedAt().setExpirationTime("10m").sign(pair.privateKey);
  const owner = action => worker.fetch(new Request(`${env.PUBLIC_ORIGIN}/v1/documents/${id}/${action}`, {
    method: action === "status" ? "GET" : "POST",
    headers: { origin: env.PUBLIC_ORIGIN, "content-type": "application/json", "cf-access-jwt-assertion": ownerToken },
    ...(action === "status" ? {} : { body: "{}" }),
  }), env);
  return { id, password, env, instance, storage, owner, get reads() { return reads; },
    async state() { return openJSON(await storage.get("encrypted-journal"), await importKey(env.VAULT_AUDIT_KEY), `journal:v1:${id}`); } };
}
function privateResponse(response) {
  assert.match(response.headers.get("cache-control"), /no-store/);
  assert.equal(response.headers.get("cdn-cache-control"), "no-store");
  assert.equal(response.headers.get("cloudflare-cdn-cache-control"), "no-store");
}
function streamingRequest(url, stream, method = "POST", headers = {}) {
  return new Request(url, { method, headers: { origin: new URL(url).origin, "content-type": "application/json", "cf-connecting-ip": "192.0.2.1", ...headers }, body: stream, duplex: "half" });
}

for (const [action, method, expected] of [["session", "POST", 403], ["open", "POST", 401], ["session", "DELETE", 200]]) {
  test(`incomplete ${method} ${action} leaves owner status and revoke available without starting reader work`, async () => {
    const f = await fixture(), started = deferred(); let controller, kdfs = 0;
    const body = JSON.stringify(action === "session" && method === "POST" ? { password: f.password }
      : action === "open" ? { requestId: crypto.randomUUID() } : {});
    const stream = new ReadableStream({
      start(value) { controller = value; value.enqueue(utf8(body.slice(0, 1))); },
      pull() { started.resolve(); },
    });
    const native = cryptoNode.scryptSync;
    cryptoNode.scryptSync = (...args) => { kdfs++; return native(...args); }; syncBuiltinESMExports();
    let response, status, revoked, snapshot;
    const reading = worker.fetch(streamingRequest(`${f.env.PUBLIC_ORIGIN}/p/${f.id}/${action}`, stream, method), f.env);
    try {
      await started.promise;
      status = await within(f.owner("status"));
      snapshot = { writes: f.storage.writes, reads: f.reads, kdfs };
      if (status) revoked = await within(f.owner("revoke"));
    } finally {
      try { controller.enqueue(utf8(body.slice(1))); controller.close(); } catch {}
      response = await reading;
      cryptoNode.scryptSync = native; syncBuiltinESMExports();
    }
    assert.ok(status, "owner status must complete while the reader stream is still incomplete");
    assert.equal(status.status, 200);
    assert.deepEqual(snapshot, { writes: 0, reads: 0, kdfs: 0 }, "incomplete reader input must not access the record, write a journal, or run a KDF");
    assert.ok(revoked, "owner revocation must complete while the reader stream is still incomplete");
    assert.equal(revoked.status, 200); assert.equal((await f.state()).revoked, true);
    assert.equal(response.status, expected, "completed input must follow normal authorization, including the newly committed revocation");
    assert.equal(kdfs, 0); privateResponse(response);
  });
}

test("requestBody preserves a complete request at the exact 2048-byte limit", async () => {
  const bytes = utf8("x".repeat(2048)), input = new Request("https://vault.example.test/synthetic", {
    method: "POST", headers: { "content-type": "application/json", "content-length": "2048", "x-synthetic": "retained" }, body: bytes,
  });
  const ready = await requestBody(input, 100);
  assert.equal(ready.method, "POST"); assert.equal(ready.url, input.url); assert.equal(ready.headers.get("x-synthetic"), "retained");
  assert.deepEqual(new Uint8Array(await ready.arrayBuffer()), bytes);
});

test("requestBody rejects oversized streamed bytes and does not wait for cancellation", async () => {
  let cancelled = false;
  const stream = new ReadableStream({ start(controller) { controller.enqueue(utf8("x".repeat(2049))); },
    cancel() { cancelled = true; return new Promise(() => {}); } });
  const result = await within(requestBody(streamingRequest("https://vault.example.test/synthetic", stream), 100)
    .then(() => null, error => error));
  assert.ok(result); assert.equal(result.status, 400); assert.equal(result.code, "invalid_request"); assert.equal(cancelled, true);
  const response = failure(result); privateResponse(response); assert.equal(response.status, 400);
});

for (const length of ["2049", "-1", "1.5", "invalid"]) {
  test(`requestBody rejects invalid declared Content-Length ${length}`, async () => {
    const input = new Request("https://vault.example.test/synthetic", { method: "POST", headers: { "content-length": length }, body: "{}" });
    await assert.rejects(() => requestBody(input, 100), error => error.status === 400 && error.code === "invalid_request");
  });
}

test("requestBody enforces a short absolute deadline and cancels an incomplete stream without waiting", async () => {
  let cancelled = false;
  const stream = new ReadableStream({ start(controller) { controller.enqueue(utf8("{")); },
    cancel() { cancelled = true; return new Promise(() => {}); } });
  const result = await within(requestBody(streamingRequest("https://vault.example.test/synthetic", stream), 25)
    .then(() => null, error => error));
  assert.ok(result); assert.equal(result.status, 408); assert.equal(result.code, "request_timeout"); assert.equal(cancelled, true);
  const response = failure(result); privateResponse(response); assert.deepEqual(await response.json(), { error: "request_timeout" });
});

test("document fetch converts pre-queue body failures to private no-store responses without touching durable state", async () => {
  let storageTouched = false;
  const doc = new VaultDocument({ id: { toString: () => "synthetic" }, storage: new Proxy({}, { get() { storageTouched = true; throw new Error("unexpected storage"); } }) }, {});
  const response = await doc.fetch(new Request("https://vault.example.test/synthetic", { method: "POST", body: "x".repeat(2049) }));
  assert.equal(response.status, 400); privateResponse(response); assert.deepEqual(await response.json(), { error: "invalid_request" });
  assert.equal(storageTouched, false);
});
