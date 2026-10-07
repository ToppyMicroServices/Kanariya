#!/usr/bin/env node
// Local integration check: no credentials, deployment, or real notification calls.
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { promisify } from "node:util";

const exec = promisify(execFile);
const root = fileURLToPath(new URL("../", import.meta.url));
const startedAt = Date.now();
const deadline = startedAt + 25_000;
const checks = [];
const providerCalls = [];
const blockedOutbound = [];
const versions = { node: process.version };
let temporary;
let mf;
let failure;
let reportPath;

function remaining() {
  const ms = deadline - Date.now();
  if (ms <= 0) throw new Error("Runtime check exceeded its 25-second deadline");
  return ms;
}

async function bounded(promise, milliseconds, label) {
  let timer;
  try {
    return await Promise.race([
      promise,
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error(`${label} timed out`)), milliseconds);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

const pause = milliseconds => new Promise(resolvePause => setTimeout(resolvePause, milliseconds));

async function checkRuntime() {
  const args = process.argv.slice(2);
  if (args.length && (args.length !== 2 || args[0] !== "--report" || !args[1])) {
    throw new Error("Usage: node scripts/check_runtime.mjs [--report PATH]");
  }
  if (args.length) reportPath = resolve(args[1]);

  let wranglerRoot;
  let wranglerPackage;
  let runtime;
  try {
    const { stdout } = await exec(process.platform === "win32" ? "npm.cmd" : "npm", ["root", "-g"], {
      cwd: root, timeout: Math.min(5000, remaining()),
    });
    wranglerRoot = join(stdout.trim(), "wrangler");
    wranglerPackage = JSON.parse(await readFile(join(wranglerRoot, "package.json"), "utf8"));
    assert.match(wranglerPackage.version, /^4\./, "Wrangler 4 is required");
    const miniflareRoot = join(wranglerRoot, "node_modules", "miniflare");
    runtime = await import(pathToFileURL(join(miniflareRoot, "dist", "src", "index.js")).href);
    versions.wrangler = wranglerPackage.version;
    versions.miniflare = JSON.parse(await readFile(join(miniflareRoot, "package.json"), "utf8")).version;
  } catch (error) {
    throw new Error("This check requires globally installed Wrangler 4 and its bundled Miniflare. Install Wrangler 4 before running it.", { cause: error });
  }

  temporary = await mkdtemp(join(tmpdir(), "kanariya-runtime-"));
  const build = join(temporary, "build");
  const wranglerBin = typeof wranglerPackage.bin === "string" ? wranglerPackage.bin : wranglerPackage.bin.wrangler;
  // Capture build output so stdout remains one machine-readable JSON summary.
  await exec(process.execPath, [join(wranglerRoot, wranglerBin), "deploy", "--dry-run", "--outdir", build], {
    cwd: root,
    env: { ...process.env, WRANGLER_SEND_METRICS: "false", WRANGLER_LOG_PATH: join(temporary, "wrangler.log") },
    timeout: Math.min(15_000, remaining()), maxBuffer: 1024 * 1024,
  });
  checks.push("Wrangler dry-run bundles the current Worker");

  const { Miniflare, Response: RuntimeResponse, Log, LogLevel } = runtime;
  let firstWebhook = true;
  mf = new Miniflare({
    modules: true,
    modulesRoot: build,
    scriptPath: join(build, "worker.js"),
    compatibilityDate: "2026-01-12",
    host: "127.0.0.1", port: 0, cf: false,
    log: new Log(LogLevel.ERROR),
    durableObjects: { KANARI_STORE: { className: "KanariyaStore", useSQLite: true } },
    durableObjectsPersist: join(temporary, "durable-objects"),
    kvNamespaces: ["KANARI_KV"],
    kvPersist: join(temporary, "kv"),
    bindings: {
      ADMIN_KEY: "synthetic-runtime-admin",
      IP_HMAC_KEY: "synthetic-runtime-ip-key",
      MASTER_SECRET: "synthetic-runtime-master-secret",
      REQUIRE_SIGNATURE: "1",
      ALLOW_PUBLIC_EXPORT: "1",
      ALLOW_PUBLIC_SIGN: "1",
      WEBHOOK_URL: "https://fixture.test/generic",
      SLACK_WEBHOOK_URL: "https://fixture.test/slack",
      NOTIFY_RETRY_BASE_SECONDS: "1",
      RATE_LIMIT_WINDOW_SECONDS: "86400",
      RATE_LIMIT_MAX: "3",
    },
    outboundService: async request => {
      const url = new URL(request.url);
      if (url.origin !== "https://fixture.test" || !["/generic", "/slack"].includes(url.pathname)) {
        blockedOutbound.push("unexpected outbound request blocked");
        throw new Error("Unexpected outbound request blocked");
      }
      assert.equal(request.method, "POST");
      const body = await request.json();
      const status = url.pathname === "/generic" && firstWebhook ? 503 : 200;
      if (url.pathname === "/generic") firstWebhook = false;
      providerCalls.push({
        channel: url.pathname.slice(1), status,
        test: body.event?.test === true || body.text?.startsWith("Kanariya TEST notification") === true,
      });
      // workerd's service bridge requires Miniflare's Response implementation.
      return new RuntimeResponse(null, { status });
    },
  });
  const origin = (await mf.ready).origin;
  const request = (path, init = {}) => mf.dispatchFetch(new URL(path, origin), {
    ...init, signal: AbortSignal.timeout(Math.min(3000, remaining())),
  });
  const admin = (path, data) => request(path, {
    method: data === undefined ? "GET" : "POST",
    headers: { authorization: "Bearer synthetic-runtime-admin", "content-type": "application/json" },
    body: data === undefined ? undefined : JSON.stringify(data),
  });
  async function adminJson(path, data, expectedStatus = 200) {
    const response = await admin(path, data);
    assert.equal(response.status, expectedStatus, `${path} status`);
    return await response.json();
  }
  const inventory = async token => (await adminJson("/admin/tokens")).tokens.find(row => row.token === token);
  const eventsFor = token => adminJson(`/admin/export?token=${encodeURIComponent(token)}`);
  const hit = (url, ip = "198.51.100.7", ua = "kanariya-runtime-fixture") => request(url, {
    headers: { "cf-connecting-ip": ip, "user-agent": ua },
  });
  async function waitFor(check, label) {
    const stop = Math.min(deadline, Date.now() + 7000);
    while (Date.now() < stop) {
      const result = await check();
      if (result) return result;
      await pause(100);
    }
    throw new Error(`Timed out waiting for ${label}`);
  }

  const secureOrigin = "https://kanariya-runtime.test";
  for (const [method, path] of [["POST", "/admin/tokens"], ["GET", "/admin/sign?token=transport-fixture"], ["GET", "/canary/transport-fixture"], ["OPTIONS", "/admin/tokens"]]) {
    const response = await request(`http://kanariya-runtime.test${path}`, {
      method,
      headers: {
        authorization: "Bearer synthetic-runtime-admin", "content-type": "application/json",
        "x-forwarded-proto": "https", "cf-visitor": '{"scheme":"https"}',
      },
      body: method === "POST" ? JSON.stringify({ name: "Must not be created" }) : undefined,
    });
    assert.equal(response.status, 400);
    assert.equal(await response.text(), "HTTPS required");
    assert.equal(response.headers.get("location"), null);
  }
  assert.equal((await adminJson("/admin/tokens")).tokens.length, 0);
  assert.equal((await eventsFor("transport-fixture")).length, 0);
  assert.equal(providerCalls.length, 0);
  checks.push("Public plaintext requests fail before token creation, evidence or notification, even with forged HTTPS headers");
  const secureToken = await adminJson(`${secureOrigin}/admin/tokens`, { name: "HTTPS transport fixture" }, 201);
  assert.equal(secureToken.url, `${secureOrigin}/canary/${secureToken.token}`);
  const secureSigned = await adminJson(`${secureOrigin}/admin/sign?token=transport-fixture`);
  assert(secureSigned.url.startsWith(`${secureOrigin}/canary/transport-fixture?`));
  checks.push("HTTPS requests issue HTTPS managed and legacy URLs while loopback HTTP administration remains usable");

  const kv = await mf.getKVNamespace("KANARI_KV");
  const legacyToken = "legacy-fixture";
  const oldEvents = Array.from({ length: 103 }, (_, index) => ({
    id: `old-${index}`, token: legacyToken, ts: new Date(startedAt - 60_000 + index).toISOString(), test: false,
  }));
  await Promise.all(oldEvents.map(event => kv.put(`event:${legacyToken}:${event.id}`, JSON.stringify(event))));
  await kv.put(`event:${legacyToken}:sibling:old`, JSON.stringify({ token: `${legacyToken}:sibling`, id: "wrong-token" }));
  for (const path of ["/admin/tokens", `/admin/export?token=${legacyToken}`, `/admin/sign?token=${legacyToken}`]) {
    assert.equal((await request(path)).status, 403);
    assert.equal((await request(path, { headers: { authorization: "Bearer wrong-synthetic-key" } })).status, 403);
  }
  checks.push("Admin inventory, KV history export and legacy signing stay private with old public flags enabled");
  const oldExport = await adminJson(`/admin/export?token=${legacyToken}`);
  assert.equal(oldExport.length, 103);
  assert(oldExport.every(event => event.token === legacyToken));
  assert.deepEqual(new Set(oldExport.map(event => event.id)), new Set(oldEvents.map(event => event.id)));
  checks.push("Legacy KV export reads multiple bulk batches and excludes overlapping token prefixes");

  const managed = await adminJson("/admin/tokens", {
    name: "Runtime concurrency", location: "Local fixture", src: "runtime",
    expiresAt: new Date(Date.now() + 300_000).toISOString(),
  }, 201);
  assert.match(managed.token, /^kr_[a-f0-9]{64}$/);
  assert.equal(managed.state, "active");
  const hits = await Promise.all(Array.from({ length: 12 }, () => hit(managed.url)));
  assert(hits.every(response => response.status === 204));
  const beforeTest = await inventory(managed.token);
  assert.equal(beforeTest.hitCount, 3);
  let events = await eventsFor(managed.token);
  assert.equal(events.length, 3);
  assert(events.every(event => event.test === false && /^[a-f0-9]{64}$/.test(event.ipHash)));
  assert.equal(events.filter(event => event.deliveries.length > 0).length, 1);
  checks.push("Twelve concurrent hits record exactly three detections and one deduplicated notification set");

  events = await waitFor(async () => {
    const rows = await eventsFor(managed.token);
    return rows.some(event => event.deliveries.some(delivery =>
      delivery.type === "webhook" && delivery.state === "accepted" && delivery.attempts === 2)) && rows;
  }, "actual Durable Object alarm retry");
  const detection = events.find(event => event.deliveries.length);
  assert.deepEqual(detection.deliveries.map(delivery => [delivery.type, delivery.state, delivery.attempts, delivery.httpStatus]), [
    ["slack", "accepted", 1, 200], ["webhook", "accepted", 2, 200],
  ]);
  assert.deepEqual(providerCalls.filter(call => call.channel === "generic").map(call => call.status), [503, 200]);
  checks.push("Real Durable Object alarms retry fixture HTTP 503 after a one-second backoff and persist HTTP 200 acceptance");

  const test = await adminJson(`/admin/tokens/${managed.token}/test`, {});
  assert.equal(test.test, true);
  const afterTest = await inventory(managed.token);
  for (const field of ["hitCount", "lastSeenAt", "expiresAt"]) assert.equal(afterTest[field], beforeTest[field], field);
  assert(afterTest.lastTestAt);
  events = await waitFor(async () => {
    const rows = await eventsFor(managed.token);
    return rows.find(event => event.id === test.eventId)?.deliveries.every(delivery => delivery.state === "accepted") && rows;
  }, "separate TEST notification");
  assert.equal(events.length, 4);
  assert.equal(events.filter(event => event.test === true).length, 1);
  assert(providerCalls.some(call => call.channel === "generic" && call.test));
  checks.push("TEST is separately recorded and delivered without changing hit count, last seen or expiry");

  const revoked = await adminJson(`/admin/tokens/${managed.token}/revoke`, {});
  assert.equal(revoked.state, "revoked");
  assert.equal((await hit(managed.url, "198.51.100.8", "after-revoke")).status, 204);
  assert.equal((await inventory(managed.token)).hitCount, 3);
  assert.equal((await eventsFor(managed.token)).length, 4);
  checks.push("Revocation prevents new detection even from a fresh visitor");

  const expiring = await adminJson("/admin/tokens", {
    name: "Brief expiry fixture", expiresAt: new Date(Date.now() + 1200).toISOString(),
  }, 201);
  assert.equal((await hit(expiring.url)).status, 204);
  assert.equal((await inventory(expiring.token)).hitCount, 1);
  await pause(Math.max(0, Date.parse(expiring.expiresAt) - Date.now() + 80));
  assert.equal((await hit(expiring.url, "198.51.100.9", "after-expiry")).status, 204);
  const expired = await inventory(expiring.token);
  assert.equal(expired.state, "expired");
  assert.equal(expired.hitCount, 1);
  assert.equal((await eventsFor(expiring.token)).length, 1);
  checks.push("Managed token expiry prevents new detection after a real short expiry");

  const signed = await adminJson(`/admin/sign?token=${legacyToken}&src=fixture&nonce=runtime-nonce`);
  assert.equal((await hit(signed.url)).status, 204);
  assert.equal((await eventsFor(legacyToken)).length, 104);
  await hit(signed.url);
  await hit(`/canary/${legacyToken}`);
  assert.equal((await eventsFor(legacyToken)).length, 104);
  await kv.put(`nonce:${legacyToken}:pre-migration`, "1");
  const replay = await adminJson(`/admin/sign?token=${legacyToken}&nonce=pre-migration`);
  await hit(replay.url);
  assert.equal((await eventsFor(legacyToken)).length, 104);
  checks.push("Signed legacy URLs append to exported history; unsigned hits and current or migrated nonce replays do not");
  assert.equal(blockedOutbound.length, 0);
}

try {
  await bounded(checkRuntime(), remaining(), "Runtime check");
} catch (error) {
  failure = error.message;
} finally {
  if (mf) {
    try { await bounded(mf.dispose(), 2500, "Miniflare cleanup"); }
    catch (error) { failure ||= error.message; }
  }
  if (temporary) {
    try { await rm(temporary, { recursive: true, force: true }); }
    catch (error) { failure ||= `Temporary directory cleanup failed: ${error.message}`; }
  }
}

const summary = {
  status: failure ? "failed" : "passed", runtime: "workerd through Wrangler-bundled Miniflare",
  versions, durationMs: Date.now() - startedAt, checks, providerCalls,
  productionRequests: 0, blockedOutboundRequests: blockedOutbound.length,
  ...(failure ? { error: failure } : {}),
};
if (reportPath) {
  try {
    await mkdir(dirname(reportPath), { recursive: true });
    await writeFile(reportPath, `${JSON.stringify(summary, null, 2)}\n`);
  } catch (error) {
    summary.status = "failed";
    summary.error = `Could not write report: ${error.message}`;
  }
}
console.log(JSON.stringify(summary, null, 2));
process.exitCode = summary.status === "passed" ? 0 : 1;
