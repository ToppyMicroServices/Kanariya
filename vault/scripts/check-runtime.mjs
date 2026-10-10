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
import { newKey, importKey, sealDocument, sealJSON, utf8 } from "../src/crypto.js";

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
  // This local-only wrapper seeds historical encrypted state to exercise storage
  // migration in workerd. It is never included in the deployment bundle.
  const testWorker = join(build, 'fixture-worker.js');
  await writeFile(testWorker, `import worker, { VaultDocument } from './worker.js';
export default worker;
export class RuntimeDocument extends VaultDocument {
  async fetch(request) {
    if (new URL(request.url).pathname === '/__synthetic_seed') {
      await this.ctx.storage.put('encrypted-journal', await request.json());
      return new Response(null, { status: 204 });
    }
    return super.fetch(request);
  }
}`);
  const env = { PUBLIC_ORIGIN: "https://vault.example.test", ACCESS_ISSUER: "https://fixture-runtime.cloudflareaccess.com", ACCESS_AUDIENCE: "fixture-runtime",
    VAULT_OWNER_SUB: "synthetic-owner", VAULT_WRAP_KEY: newKey(), VAULT_AUDIT_KEY: newKey(), WEBHOOK_URL: "https://notify.example.test/fixture" };
  const id = crypto.randomUUID(), subject = "synthetic-private-runtime-subject", otherSubject = 'synthetic-other-runtime-subject';
  let pdf = utf8("%PDF-1.4\nSYNTHETIC-RUNTIME-PRIVATE-BODY\n");
  if (process.argv[3]) {
    const fixture = await readFile(resolve(process.argv[3]));
    // Only this reviewed synthetic PDF is allowed through the optional fixture
    // input. A real CV or any other file must never reach the runtime service.
    assert.equal(createHash("sha256").update(fixture).digest("hex"), "abe2ac634b12a6d7558ffe419f7cc311a262afc4fe8ef47b1b747faf7de05429");
    pdf = new Uint8Array(fixture);
  }
  report.fixture = { kind: process.argv[3] ? "approved_dummy_pdf" : "generated_synthetic_bytes", sha256: createHash("sha256").update(pdf).digest("hex") };
  const encrypted = await sealDocument({ id, bytes: pdf, subjects: [subject, otherSubject], expiresAt: Date.now() + 300000 }, await importKey(env.VAULT_WRAP_KEY));
  const recordBytes = JSON.stringify(encrypted);
  env.DUMMY_DOCUMENT_ID = id;
  env.DUMMY_RECORD_SHA256 = createHash("sha256").update(recordBytes).digest("hex");
  const pair = await generateKeyPair("RS256", { extractable: true }), jwk = { ...await exportJWK(pair.publicKey), kid: "runtime", use: "sig", alg: "RS256" };
  const token = actor => new SignJWT({ sub: actor }).setProtectedHeader({ alg: "RS256", kid: "runtime" })
    .setIssuer(env.ACCESS_ISSUER).setAudience(env.ACCESS_AUDIENCE).setIssuedAt().setExpirationTime("10m").sign(pair.privateKey);
  const notifications = [], forbidden = [];
  mf = new runtime.Miniflare({ modules: true, modulesRules: [{ type: 'ESModule', include: ['**/*.js'] }], modulesRoot: build, scriptPath: testWorker,
    compatibilityDate: "2026-01-12", compatibilityFlags: ["nodejs_compat"], host: "127.0.0.1", port: 0, cf: false,
    log: new runtime.Log(runtime.LogLevel.ERROR), bindings: env,
    durableObjects: { VAULT: { className: "RuntimeDocument", useSQLite: true } }, durableObjectsPersist: persist,
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
  const namespace = await mf.getDurableObjectNamespace('VAULT'), objectId = namespace.idFromName(id), at = Date.now() - 120000;
  const oldEvents = Array.from({ length: 500 }, () => ({ id: crypto.randomUUID(), documentId: id, subject, at, outcome: 'decrypted' }));
  const oldRequests = oldEvents.map(() => ({ requestId: crypto.randomUUID(), subject, at }));
  const oldJobs = oldEvents.flatMap(event => ['webhook', 'slack'].map(type => ({ eventId: event.id, at, state: 'accepted',
    target: { type, fingerprint: 'ab'.repeat(32) }, attempts: 1, outcome: 'decrypted', nextAt: at, httpStatus: 202 })));
  const oldJournal = await sealJSON({ version: 1, documentId: id, revoked: false, events: oldEvents, requests: oldRequests, jobs: oldJobs },
    await importKey(env.VAULT_AUDIT_KEY), `journal:v1:${objectId.toString()}`);
  assert.equal((await namespace.get(objectId).fetch('https://vault.example.test/__synthetic_seed', { method: 'POST', body: JSON.stringify(oldJournal) })).status, 204);
  const migrated = await request('open', otherSubject);
  assert.equal(migrated.status, 200); assert.deepEqual(new Uint8Array(await migrated.arrayBuffer()), pdf);
  assert.equal((await request('open', subject, oldRequests[0].requestId)).status, 409);
  assert.ok((await (await request('status', env.VAULT_OWNER_SUB)).json()).providerAccepted >= 1000);
  report.checks.push('saturated_legacy_journal_archive_and_replay_in_workerd');
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
  // A separate fresh dummy document exercises shared-password mode without
  // weakening the Access document or reusing its irreversible revocation state.
  await mf.dispose(); mf = null;
  const passwordId = crypto.randomUUID(), password = "synthetic-shared-password-only";
  const passwordRecord = JSON.stringify(await sealDocument({ id: passwordId, bytes: pdf, subjects: [],
    expiresAt: Date.now() + 300000, authMode: "password", password }, await importKey(env.VAULT_WRAP_KEY)));
  const passwordEnv = { ...env, PASSWORD_READER_ENABLED: "1", DUMMY_DOCUMENT_ID: passwordId,
    DUMMY_RECORD_SHA256: createHash("sha256").update(passwordRecord).digest("hex") };
  const passwordPersist = join(temporary, "password-durable-objects");
  mf = new runtime.Miniflare({ modules: true, modulesRoot: build, scriptPath: join(build, "worker.js"),
    compatibilityDate: "2026-01-12", compatibilityFlags: ["nodejs_compat"], host: "127.0.0.1", port: 0, cf: false,
    log: new runtime.Log(runtime.LogLevel.ERROR), bindings: passwordEnv,
    durableObjects: { VAULT: { className: "VaultDocument", useSQLite: true } }, durableObjectsPersist: passwordPersist,
    r2Buckets: ["VAULT_DOCUMENTS"], outboundService: async request => {
      if (request.url === env.ACCESS_ISSUER + "/cdn-cgi/access/certs") return new runtime.Response(JSON.stringify({ keys: [jwk] }), { headers: { "content-type": "application/json" } });
      if (request.url !== env.WEBHOOK_URL) { forbidden.push("blocked"); throw new Error("unexpected_network"); }
      const body = await request.text();
      for (const secret of [password, passwordId, subject, env.VAULT_WRAP_KEY, env.VAULT_AUDIT_KEY]) assert.ok(!body.includes(secret));
      return new runtime.Response(null, { status: 202 });
    } });
  await mf.ready;
  await (await mf.getR2Bucket("VAULT_DOCUMENTS")).put(`${passwordId}.sealed.json`, passwordRecord);
  async function shared(action, { method = action === "status" ? "GET" : "POST", cookie = "", body, headers = {} } = {}) {
    return mf.dispatchFetch(`${env.PUBLIC_ORIGIN}/p/${passwordId}/${action}`, { method,
      headers: { origin: env.PUBLIC_ORIGIN, "content-type": "application/json", "cf-connecting-ip": "192.0.2.1", cookie, ...headers },
      ...(method === "GET" || method === "HEAD" ? {} : { body: JSON.stringify(body ?? (action === "open" ? { requestId: crypto.randomUUID() } : {})) }),
      signal: AbortSignal.timeout(10000) });
  }
  assert.equal((await shared("open")).status, 401);
  assert.equal((await shared("session", { body: { password: "wrong-synthetic-password" } })).status, 401);
  const unlocked = await shared("session", { body: { password } });
  assert.equal(unlocked.status, 200);
  const setCookie = unlocked.headers.get("set-cookie");
  assert.match(setCookie, /Secure/); assert.match(setCookie, /HttpOnly/); assert.match(setCookie, /SameSite=Strict/);
  const cookie = setCookie.split(";")[0];
  assert.equal((await shared("status", { cookie })).status, 200);
  const opened = await shared("open", { cookie });
  assert.equal(opened.status, 200); assert.deepEqual(new Uint8Array(await opened.arrayBuffer()), pdf);
  assert.match(opened.headers.get("cache-control"), /no-store/);
  assert.ok(Number(opened.headers.get("x-vault-expires-at")) > Date.now());
  assert.ok(Number(opened.headers.get("x-vault-session-expires-at")) > Date.now());
  report.checks.push("native_scrypt_password_unlock_cookie_and_exact_pdf");
  assert.equal((await request("status", "", crypto.randomUUID(), passwordId)).status, 401);
  assert.equal((await request("open", subject, crypto.randomUUID(), passwordId)).status, 403);
  assert.equal((await shared("open", { method: "HEAD", cookie, headers: { range: "bytes=0-9" } })).status, 405);
  assert.equal((await shared("session", { body: { password }, headers: { origin: "https://elsewhere.example.test" } })).status, 403);
  report.checks.push("password_cannot_authorize_owner_or_access_routes_or_head_range");
  const guesses = await Promise.all(Array.from({ length: 12 }, () => shared("session", { body: { password: "wrong-synthetic-password" } })));
  assert.equal(guesses.filter(r => r.status === 401).length, 8);
  assert.equal(guesses.filter(r => r.status === 429).length, 4);
  report.checks.push("concurrent_password_attempt_limit_persists");
  const otherUnlock = await shared('session', { body: { password }, headers: { 'cf-connecting-ip': '198.51.100.2' } });
  assert.equal(otherUnlock.status, 200);
  assert.equal((await shared('open', { cookie: otherUnlock.headers.get('set-cookie').split(';')[0], headers: { 'cf-connecting-ip': '198.51.100.2' } })).status, 200);
  assert.equal((await shared('session', { method: 'DELETE' })).status, 200);
  report.checks.push('password_budget_isolates_sources_and_cookie_less_logout');
  assert.equal((await request("revoke", env.VAULT_OWNER_SUB, crypto.randomUUID(), passwordId)).status, 200);
  assert.equal((await shared("status", { cookie })).status, 403);
  assert.equal((await shared("open", { cookie })).status, 403);
  assert.equal((await shared("session", { method: "DELETE", cookie })).status, 200);
  report.checks.push("owner_revocation_invalidates_existing_password_session");
  for (const path of await files(passwordPersist)) {
    const bytes = await readFile(path);
    for (const secret of [password, cookie.split("=")[1], env.VAULT_WRAP_KEY, env.VAULT_AUDIT_KEY]) assert.ok(!bytes.includes(Buffer.from(secret)));
    assert.ok(!bytes.includes(Buffer.from(pdf)));
  }
  report.checks.push("password_session_and_document_secrets_not_persisted_in_plaintext");
  assert.deepEqual(forbidden, []); report.checks.push("no_unexpected_outbound");
  report.status = "passed"; report.runtime = { node: process.version, wrangler: pkg.version };
} catch (error) {
  report.error = typeof error?.code === 'string' ? error.code : 'runtime_validation_failed';
  report.status = "failed"; process.exitCode = 1;
} finally {
  // A runtime disposal error must not skip removal of the synthetic fixture.
  try { if (mf) await mf.dispose(); }
  catch { report.status = "cleanup_failed"; process.exitCode = 1; }
  try { if (temporary) await rm(temporary, { recursive: true, force: true }); }
  catch { report.status = "cleanup_failed"; process.exitCode = 1; }
  await recordReport(); console.log(JSON.stringify(report));
}
