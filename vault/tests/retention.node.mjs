import test, { after } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { generateKeyPair, exportJWK, SignJWT } from "jose";
import { VaultDocument } from "../src/document.js";
import { newKey, importKey, sealDocument, sealJSON, openJSON, utf8 } from "../src/crypto.js";

const DAY = 86400000;
const originalFetch = globalThis.fetch;
after(() => { globalThis.fetch = originalFetch; });
const pair = await generateKeyPair("RS256", { extractable: true });
const jwk = { ...await exportJWK(pair.publicKey), kid: "retention-fixture", use: "sig", alg: "RS256" };
let fixtureNumber = 0;

class Storage {
  constructor() { this.map = new Map(); this.alarmAt = null; this.failPut = () => false; }
  async get(key) { return structuredClone(this.map.get(key)); }
  async setAlarm(at) { this.alarmAt = at; }
  async transaction(operation) {
    const draft = new Map(structuredClone([...this.map]));
    let alarm = this.alarmAt;
    const result = await operation({
      get: async key => structuredClone(draft.get(key)),
      put: async (key, value) => {
        if (this.failPut(key)) throw new Error("synthetic_archive_commit_failure");
        draft.set(key, structuredClone(value));
      },
      delete: async key => draft.delete(key),
      list: async ({ prefix, end, limit }) => new Map([...draft]
        .filter(([key]) => key.startsWith(prefix) && (!end || key < end))
        .sort(([a], [b]) => a.localeCompare(b)).slice(0, limit)),
      setAlarm: async at => { alarm = at; },
      deleteAlarm: async () => { alarm = null; },
    });
    this.map = draft; this.alarmAt = alarm;
    return result;
  }
}

async function fixture() {
  const id = crypto.randomUUID(), subject = "retention-reader-one-private", other = "retention-reader-two-private";
  const pdf = utf8("%PDF-1.4\nSYNTHETIC_RETENTION_PRIVATE_BODY\n");
  const env = {
    PUBLIC_ORIGIN: "https://vault.example.test", ACCESS_ISSUER: `https://retention-${++fixtureNumber}.cloudflareaccess.com`,
    ACCESS_AUDIENCE: "retention-fixture", VAULT_OWNER_SUB: "retention-owner-private",
    VAULT_WRAP_KEY: newKey(), VAULT_AUDIT_KEY: newKey(), WEBHOOK_URL: "https://notify.example.test/private-retention-path",
  };
  const record = await sealDocument({ id, bytes: pdf, subjects: [subject, other], expiresAt: Date.now() + 45 * DAY }, await importKey(env.VAULT_WRAP_KEY));
  env.DUMMY_DOCUMENT_ID = id;
  env.DUMMY_RECORD_SHA256 = createHash("sha256").update(JSON.stringify(record)).digest("hex");
  env.VAULT_DOCUMENTS = { async get(name) {
    assert.equal(name, `${id}.sealed.json`);
    const bytes = utf8(JSON.stringify(record));
    return { size: bytes.length, body: new Response(bytes).body };
  } };
  const storage = new Storage(), ctx = { storage, id: { toString: () => `retention-${id}` } };
  const context = `journal:v1:retention-${id}`, auditKey = await importKey(env.VAULT_AUDIT_KEY);
  let instance = new VaultDocument(ctx, env);
  const calls = [];
  globalThis.fetch = async (url, options) => {
    if (String(url) === `${env.ACCESS_ISSUER}/cdn-cgi/access/certs`) return Response.json({ keys: [jwk] });
    assert.equal(String(url), env.WEBHOOK_URL);
    calls.push(JSON.parse(options.body));
    return new Response(null, { status: 202 });
  };
  async function request({ as = subject, requestId = crypto.randomUUID(), action = "open" } = {}) {
    const jwt = await new SignJWT({ sub: as, iss: env.ACCESS_ISSUER, aud: env.ACCESS_AUDIENCE,
      iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + 600 })
      .setProtectedHeader({ alg: "RS256", kid: "retention-fixture" }).sign(pair.privateKey);
    return instance.fetch(new Request(`${env.PUBLIC_ORIGIN}/v1/documents/${id}/${action}`, {
      method: action === "status" ? "GET" : "POST",
      headers: { origin: env.PUBLIC_ORIGIN, "content-type": "application/json", "cf-access-jwt-assertion": jwt },
      ...(action === "status" ? {} : { body: JSON.stringify({ requestId }) }),
    }));
  }
  return {
    id, env, subject, other, pdf, storage, context, auditKey, request, calls,
    state: () => openJSON(storage.map.get("encrypted-journal"), auditKey, context),
    writeState: async state => storage.map.set("encrypted-journal", await sealJSON(state, auditKey, context)),
    archive: name => openJSON(storage.map.get(name), auditKey, `${context}:${name}`),
    status: async () => (await request({ action: "status", as: env.VAULT_OWNER_SUB })).json(),
    alarm: () => instance.alarm(), restart: () => { instance = new VaultDocument(ctx, env); },
  };
}

function legacyState(f, count = 501, at = Date.now() - 120000) {
  const events = Array.from({ length: count }, () => ({ id: crypto.randomUUID(), documentId: f.id, subject: f.subject, at, outcome: "decrypted" }));
  const requests = Array.from({ length: 500 }, () => ({ requestId: crypto.randomUUID(), subject: f.subject, at }));
  // An orphan reservation and an accepted unknown outcome must remain evidence.
  events[0].outcome = "requested";
  events[1].outcome = "requested";
  const jobs = events.flatMap((event, index) => index === 0 ? [] : ["webhook", "slack"].map(type => ({
    eventId: event.id, target: { type, fingerprint: "ab".repeat(32) }, at, state: "accepted",
    attempts: 1, outcome: index === 1 ? "unknown" : "decrypted", nextAt: at + 1000, httpStatus: 202,
  })));
  // These fields match a legacy v1 journal, before the new optional quota fields.
  return { version: 1, documentId: f.id, revoked: false, requests, events, jobs };
}

async function exactPDF(f, response) {
  assert.equal(response.status, 200);
  assert.equal(response.headers.get("content-type"), "application/pdf");
  assert.deepEqual(new Uint8Array(await response.arrayBuffer()), f.pdf);
}

test("saturated v1 history migrates without blocking a different legitimate reader or losing evidence", async () => {
  const f = await fixture(), old = legacyState(f);
  await f.writeState(old);
  await exactPDF(f, await f.request({ as: f.other }));
  const state = await f.state(), archivedEvents = [], archivedJobs = [], archivedRequests = [];
  for (const name of f.storage.map.keys()) {
    if (name.startsWith("audit:")) {
      const saved = await f.archive(name);
      assert.equal(saved.expiresAt, saved.event.at + 30 * DAY);
      archivedEvents.push(saved.event); archivedJobs.push(...saved.jobs);
      await assert.rejects(() => openJSON(f.storage.map.get(name), f.auditKey, `${f.context}:audit:${crypto.randomUUID()}`));
    } else if (name.startsWith("replay:")) {
      const saved = await f.archive(name);
      assert.equal(saved.expiresAt, saved.request.at + 30 * DAY);
      archivedRequests.push(saved.request);
    }
  }
  const sort = (values, key) => values.toSorted((a, b) => a[key].localeCompare(b[key]));
  assert.deepEqual(sort([...archivedEvents, ...state.events.filter(event => event.subject === f.subject)], "id"), sort(old.events, "id"));
  assert.deepEqual(sort([...archivedJobs, ...state.jobs.filter(job => old.events.some(event => event.id === job.eventId))], "eventId"), sort(old.jobs, "eventId"));
  assert.deepEqual(sort([...archivedRequests, ...state.requests.filter(request => request.subject === f.subject)], "requestId"), sort(old.requests, "requestId"));
  assert.ok(archivedEvents.some(event => event.id === old.events[0].id && event.outcome === "requested"));
  assert.deepEqual((await f.archive(`audit:${old.events[0].id}`)).jobs, []);
  assert.ok((await f.archive(`audit:${old.events[1].id}`)).jobs.every(job => job.state === "accepted" && job.outcome === "unknown"));
  assert.ok(state.events.length < 200); assert.ok(state.requests.length < 200); assert.ok(state.jobs.length < 400);
  assert.equal((await f.status()).providerAccepted, old.jobs.length);
  const stored = JSON.stringify([...f.storage.map]);
  for (const secret of [f.subject, f.other, f.env.WEBHOOK_URL, f.env.VAULT_WRAP_KEY, f.env.VAULT_AUDIT_KEY, "SYNTHETIC_RETENTION_PRIVATE_BODY"]) assert.ok(!stored.includes(secret));
  assert.equal(f.calls.length, 0);
});

test("archived replay guards reject reuse after restart across both allowed subjects", async () => {
  const f = await fixture(), old = legacyState(f), requestId = old.requests[0].requestId;
  await f.writeState(old);
  await exactPDF(f, await f.request({ as: f.other }));
  assert.ok(f.storage.map.has(`replay:${requestId}`));
  const before = structuredClone([...f.storage.map]);
  f.restart();
  for (const as of [f.subject, f.other]) {
    const response = await f.request({ as, requestId });
    assert.equal(response.status, 409);
    assert.deepEqual(await response.json(), { error: "request_already_used" });
    assert.deepEqual([...f.storage.map], before);
  }
});

test("expiry cleanup removes old encrypted records and keeps providerAccepted within retained history", async () => {
  const f = await fixture(), now = Date.now(), state = { version: 1, documentId: f.id, revoked: false,
    events: [], jobs: [], requests: [], archivedAccepted: 212 };
  const expired = [], future = [];
  for (let index = 0; index < 106; index++) {
    const at = index === 105 ? now - DAY : now - 30 * DAY - 1, expiresAt = at + 30 * DAY;
    const event = { id: crypto.randomUUID(), documentId: f.id, subject: f.subject, at, outcome: "decrypted" };
    const jobs = ["webhook", "slack"].map(type => ({ eventId: event.id, state: "accepted", target: { type, fingerprint: "ab".repeat(32) }, at, outcome: "decrypted" }));
    const request = { requestId: crypto.randomUUID(), subject: f.subject, at };
    for (const [name, value] of [[`audit:${event.id}`, { event, jobs }], [`replay:${request.requestId}`, { request }]]) {
      f.storage.map.set(name, await sealJSON({ ...value, expiresAt }, f.auditKey, `${f.context}:${name}`));
      f.storage.map.set(`expiry:${String(expiresAt).padStart(13, "0")}:${name}`, name);
      (index === 105 ? future : expired).push(name);
    }
  }
  await f.writeState(state); f.restart();
  for (let pass = 0; pass < 5 && expired.some(name => f.storage.map.has(name)); pass++) {
    await f.alarm();
    const retainedAccepted = 2 * [...f.storage.map.keys()].filter(name => name.startsWith("audit:")).length;
    assert.equal((await f.status()).providerAccepted, retainedAccepted);
    assert.equal((await f.state()).archivedAccepted, retainedAccepted);
  }
  for (const name of expired) assert.ok(!f.storage.map.has(name));
  for (const name of future) assert.ok(f.storage.map.has(name));
  assert.equal((await f.status()).providerAccepted, 2);
  assert.equal(f.storage.alarmAt, now + 29 * DAY);
  assert.equal(f.calls.length, 0);
});

for (const failingKey of ["audit:", "replay:", "encrypted-journal"]) {
  test(`archive transaction failure at ${failingKey} rolls back all evidence and releases no plaintext`, async () => {
    const f = await fixture(), old = legacyState(f), requestId = crypto.randomUUID();
    await f.writeState(old);
    const before = structuredClone([...f.storage.map]);
    f.storage.failPut = key => key.startsWith(failingKey);
    const response = await f.request({ as: f.other, requestId });
    assert.equal(response.status, 503);
    assert.equal(response.headers.get("content-type"), "application/json");
    assert.equal(response.headers.get("x-vault-event"), null);
    assert.doesNotMatch(await response.text(), /SYNTHETIC_RETENTION_PRIVATE_BODY|%PDF-/);
    assert.deepEqual([...f.storage.map], before); assert.equal(f.storage.alarmAt, null);
    assert.equal(f.calls.length, 0);
    f.storage.failPut = () => false; f.restart();
    await exactPDF(f, await f.request({ as: f.other, requestId }));
  });
}

for (const budget of ["pending", "recent", "daily"]) {
  test(`an Access subject's ${budget} quota does not consume another allowed subject's budget`, async () => {
    const f = await fixture();
    await exactPDF(f, await f.request());
    const state = await f.state(), actor = `access:${f.subject}`, now = Date.now();
    const count = budget === "daily" ? 100 : 10, at = budget === "recent" ? now : now - 120000;
    const event = state.events[0], job = state.jobs[0];
    state.events = Array.from({ length: count }, () => ({ ...event, id: crypto.randomUUID(), at }));
    state.jobs = state.events.map(event => ({ ...job, eventId: event.id, actor, at,
      state: budget === "pending" ? "pending" : "accepted", nextAt: at + 10000 }));
    state.requests = Array.from({ length: count }, () => ({ requestId: crypto.randomUUID(), subject: f.subject, actor, at }));
    state.readerUsage = [{ actor, day: Math.floor(now / DAY), count }];
    await f.writeState(state); f.restart();
    const before = structuredClone([...f.storage.map]);
    const denied = await f.request();
    assert.equal(denied.status, 429); assert.deepEqual(await denied.json(), { error: "rate_limited" });
    assert.deepEqual([...f.storage.map], before);
    await exactPDF(f, await f.request({ as: f.other }));
    const latest = await f.state();
    assert.equal(latest.readerUsage.find(usage => usage.actor === `access:${f.other}`).count, 1);
    assert.equal(f.calls.length, 0);
  });
}

test("a previous day's Access subject budget does not block the next day's legitimate open", async () => {
  const f = await fixture();
  await f.writeState({ version: 1, documentId: f.id, revoked: false, events: [], requests: [], jobs: [],
    readerUsage: [{ actor: `access:${f.subject}`, day: Math.floor(Date.now() / DAY) - 1, count: 100 }] });
  f.restart();
  await exactPDF(f, await f.request());
  assert.deepEqual((await f.state()).readerUsage, [{ actor: `access:${f.subject}`, day: Math.floor(Date.now() / DAY), count: 1 }]);
});
