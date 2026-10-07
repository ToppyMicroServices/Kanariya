// All identities, document bytes, keys and notification destinations are synthetic.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { mkdtemp, mkdir, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { generateKeyPair, exportJWK, SignJWT } from "jose";
import { newKey, importKey, sealDocument, utf8 } from "../src/crypto.js";

const exec = promisify(execFile), root = fileURLToPath(new URL("../", import.meta.url));
const report = { status: "running_not_verified", checks: [], realDataUsed: false, liveNotificationsSent: false };
const reportPath = process.argv[2] ? resolve(process.argv[2]) : null;
let temporary, mf;
async function recordReport() { if (reportPath) await writeFile(reportPath, JSON.stringify(report, null, 2)); }
const pause = ms => new Promise(r => setTimeout(r, ms));
async function files(path) {
  const found = [];
  for (const entry of await readdir(path, { withFileTypes: true })) {
    const p = join(path, entry.name);
    if (entry.isDirectory()) found.push(...await files(p)); else found.push(p);
  }
  return found;
}
try {
  await recordReport();
  const npmRoot = (await exec("npm", ["root", "-g"], { timeout: 5000 })).stdout.trim();
  const wrangler = join(npmRoot, "wrangler"), pkg = JSON.parse(await readFile(join(wrangler, "package.json"), "utf8"));
  const runtime = await import(pathToFileURL(join(wrangler, "node_modules/miniflare/dist/src/index.js")));
  temporary = await mkdtemp(join(tmpdir(), "kanariya-vault-runtime-"));
  const build = join(temporary, "build"), persist = join(temporary, "durable-objects");
  await mkdir(build);
  await exec(process.execPath, [join(wrangler, typeof pkg.bin === "string" ? pkg.bin : pkg.bin.wrangler),
    "deploy", "--dry-run", "--outdir", build], { cwd: root, timeout: 25000,
    env: { ...process.env, WRANGLER_SEND_METRICS: "false", WRANGLER_LOG_PATH: join(temporary, "wrangler.log") } });
  report.checks.push("dry_run_bundle");
  const env = { PUBLIC_ORIGIN: "https://vault.example.test", ACCESS_ISSUER: "https://fixture-runtime.cloudflareaccess.com", ACCESS_AUDIENCE: "fixture-runtime",
    VAULT_OWNER_SUB: "synthetic-owner", VAULT_WRAP_KEY: newKey(), VAULT_AUDIT_KEY: newKey(), WEBHOOK_URL: "https://notify.example.test/fixture" };
  const id = crypto.randomUUID(), subject = "synthetic-private-runtime-subject";
  let pdf = utf8("%PDF-1.4\nSYNTHETIC-RUNTIME-PRIVATE-BODY\n");
  if (process.argv[3]) {
    const fixture = await readFile(resolve(process.argv[3]));
    // Only this reviewed synthetic PDF is allowed through the optional fixture
    // input. A real CV or any other file must never reach the runtime service.
    assert.equal(createHash("sha256").update(fixture).digest("hex"), "abe2ac634b12a6d7558ffe419f7cc311a262afc4fe8ef47b1b747faf7de05429");
    pdf = new Uint8Array(fixture);
  }
  report.fixture = { kind: process.argv[3] ? "approved_dummy_pdf" : "generated_synthetic_bytes", sha256: createHash("sha256").update(pdf).digest("hex") };
  const encrypted = await sealDocument({ id, bytes: pdf, subjects: [subject], expiresAt: Date.now() + 300000 }, await importKey(env.VAULT_WRAP_KEY));
  const recordBytes = JSON.stringify(encrypted);
  env.DUMMY_DOCUMENT_ID = id;
  env.DUMMY_RECORD_SHA256 = createHash("sha256").update(recordBytes).digest("hex");
  const pair = await generateKeyPair("RS256", { extractable: true }), jwk = { ...await exportJWK(pair.publicKey), kid: "runtime", use: "sig", alg: "RS256" };
  const token = actor => new SignJWT({ sub: actor }).setProtectedHeader({ alg: "RS256", kid: "runtime" })
    .setIssuer(env.ACCESS_ISSUER).setAudience(env.ACCESS_AUDIENCE).setIssuedAt().setExpirationTime("10m").sign(pair.privateKey);
  const notifications = [], forbidden = [];
  mf = new runtime.Miniflare({ modules: true, modulesRoot: build, scriptPath: join(build, "worker.js"),
    compatibilityDate: "2026-01-12", host: "127.0.0.1", port: 0, cf: false,
    log: new runtime.Log(runtime.LogLevel.ERROR), bindings: env,
    durableObjects: { VAULT: { className: "VaultDocument", useSQLite: true } }, durableObjectsPersist: persist,
    r2Buckets: ["VAULT_DOCUMENTS"],
    outboundService: async request => {
      if (request.url === env.ACCESS_ISSUER + "/cdn-cgi/access/certs") return new runtime.Response(JSON.stringify({ keys: [jwk] }), { headers: { "content-type": "application/json" } });
      if (request.url !== env.WEBHOOK_URL) { forbidden.push("blocked"); throw new Error("unexpected_network"); }
      const body = await request.text();
      for (const secret of [subject, "SYNTHETIC-RUNTIME-PRIVATE-BODY", id, env.VAULT_WRAP_KEY, env.VAULT_AUDIT_KEY]) assert.ok(!body.includes(secret));
      for (const encodedPDF of [Buffer.from(pdf).toString("base64"), JSON.stringify(Buffer.from(pdf).toString("utf8")).slice(1, -1)]) assert.ok(!body.includes(encodedPDF));
      notifications.push(JSON.parse(body));
      return new runtime.Response(null, { status: notifications.length === 1 ? 503 : 202 });
    } });
  await mf.ready;
  const bucket = await mf.getR2Bucket("VAULT_DOCUMENTS");
  await bucket.put(`${id}.sealed.json`, recordBytes);
  async function request(action, actor = subject, requestId = crypto.randomUUID(), documentId = id) {
    return mf.dispatchFetch(`${env.PUBLIC_ORIGIN}/v1/documents/${documentId}/${action}`, {
      method: action === "status" ? "GET" : "POST",
      headers: { origin: env.PUBLIC_ORIGIN, "content-type": "application/json", "cf-access-jwt-assertion": actor ? await token(actor) : "" },
      ...(action === "status" ? {} : { body: JSON.stringify(action === "open" ? { requestId } : {}) }), signal: AbortSignal.timeout(5000) });
  }
  assert.equal((await request("open", "")).status, 401);
  assert.equal((await request("open", "unauthorized-subject")).status, 403);
  report.checks.push("signature_and_document_grant");
  assert.equal((await request("open", subject, crypto.randomUUID(), crypto.randomUUID())).status, 403);
  report.checks.push("unapproved_document_id_denied");
  await bucket.put(`${id}.sealed.json`, recordBytes + "\n");
  assert.equal((await request("open")).status, 403);
  assert.deepEqual(await (await request("status", env.VAULT_OWNER_SUB)).json(), { revoked: false, pending: 0, failed: 0, providerAccepted: 0 });
  assert.equal(notifications.length, 0);
  await bucket.put(`${id}.sealed.json`, recordBytes);
  report.checks.push("changed_record_bytes_denied_without_audit_or_notification");
  const requestId = crypto.randomUUID(), response = await request("open", subject, requestId);
  assert.equal(response.status, 200); assert.deepEqual(new Uint8Array(await response.arrayBuffer()), pdf);
  assert.match(response.headers.get("cache-control"), /no-store/);
  report.checks.push("real_runtime_decrypt_exact_bytes");
  assert.equal((await request("open", subject, requestId)).status, 409);
  report.checks.push("durable_replay_guard");
  const deadline = Date.now() + 12000;
  while (Date.now() < deadline) {
    const state = await (await request("status", env.VAULT_OWNER_SUB)).json();
    if (state.providerAccepted === 1) break;
    await pause(100);
  }
  const status = await (await request("status", env.VAULT_OWNER_SUB)).json();
  assert.equal(status.providerAccepted, 1); assert.ok(notifications.length >= 2);
  assert.equal(notifications.at(-1).event.outcome, "decrypted");
  report.checks.push("alarm_retry_and_provider_acceptance");
  for (const path of await files(persist)) {
    const bytes = await readFile(path);
    assert.ok(!bytes.includes(Buffer.from(pdf)));
    assert.ok(!bytes.includes(Buffer.from(pdf).toString("base64")));
    for (const secret of [subject, "SYNTHETIC-RUNTIME-PRIVATE-BODY", env.VAULT_WRAP_KEY, env.VAULT_AUDIT_KEY]) assert.ok(!bytes.includes(Buffer.from(secret)));
  }
  report.checks.push("durable_storage_contains_no_fixture_plaintext_or_keys");
  assert.equal((await request("revoke", env.VAULT_OWNER_SUB)).status, 200);
  assert.equal((await request("open")).status, 403);
  report.checks.push("owner_revocation");
  assert.deepEqual(forbidden, []); report.checks.push("no_unexpected_outbound");
  report.status = "passed"; report.runtime = { node: process.version, wrangler: pkg.version };
} catch {
  report.status = "failed"; process.exitCode = 1;
} finally {
  try { if (mf) await mf.dispose(); if (temporary) await rm(temporary, { recursive: true, force: true }); }
  catch { report.status = "cleanup_failed"; process.exitCode = 1; }
  await recordReport(); console.log(JSON.stringify(report));
}
