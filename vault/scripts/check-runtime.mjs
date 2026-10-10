// All identities, document bytes, keys and notification destinations are synthetic.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { execFile } from "node:child_process";
import { parseArgs, promisify } from "node:util";
import { mkdtemp, mkdir, readFile, readdir, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { generateKeyPair, exportJWK, SignJWT } from "jose";
import { newKey, importKey, sealDocument, sealJSON, utf8 } from "../src/crypto.js";

const exec = promisify(execFile), root = fileURLToPath(new URL("../", import.meta.url));
const args = parseArgs({ options: { bundle: { type: "string" }, "expected-sha": { type: "string" }, report: { type: "string" } }, allowPositionals: true });
const candidatePath = args.values.bundle ? resolve(args.values.bundle) : null;
const expectedSha256 = args.values["expected-sha"];
const fixturePath = args.positionals[1] ? resolve(args.positionals[1]) : null;
const report = { status: "running_not_verified", pass: false, checks: [], realDataUsed: false, liveNotificationsSent: false,
  compatibilityDate: "2026-01-12", compatibilityFlags: ["nodejs_compat"] };
const reportPath = args.values.report ? resolve(args.values.report) : args.positionals[0] ? resolve(args.positionals[0]) : null;
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
  assert.ok(args.positionals.length <= 2);
  assert.ok(!candidatePath || args.positionals.length === 0, "frozen_bundle_accepts_no_external_fixture");
  assert.ok(candidatePath ? /^[0-9a-f]{64}$/.test(expectedSha256 ?? "") : !expectedSha256, "bundle_and_expected_sha_required_together");
  const npmRoot = (await exec("npm", ["root", "-g"], { timeout: 5000 })).stdout.trim();
  const wrangler = join(npmRoot, "wrangler"), pkg = JSON.parse(await readFile(join(wrangler, "package.json"), "utf8"));
  const miniflarePkg = JSON.parse(await readFile(join(wrangler, "node_modules/miniflare/package.json"), "utf8"));
  report.runtime = { node: process.version, wrangler: pkg.version, miniflare: miniflarePkg.version };
  const runtime = await import(pathToFileURL(join(wrangler, "node_modules/miniflare/dist/src/index.js")));
  temporary = await mkdtemp(join(tmpdir(), "kanariya-vault-runtime-"));
  const build = candidatePath ? dirname(candidatePath) : join(temporary, "build"), persist = join(temporary, "durable-objects");
  const candidate = candidatePath ?? join(build, "worker.js");
  if (candidatePath) {
    report.candidateSha256 = createHash("sha256").update(await readFile(candidate)).digest("hex");
    assert.equal(report.candidateSha256, expectedSha256);
    report.checks.push("frozen_candidate_hash_before_runtime");
  } else {
    await mkdir(build);
    await exec(process.execPath, [join(wrangler, typeof pkg.bin === "string" ? pkg.bin : pkg.bin.wrangler),
      "deploy", "--dry-run", "--outdir", build], { cwd: root, timeout: 25000,
      env: { ...process.env, WRANGLER_SEND_METRICS: "false", WRANGLER_LOG_PATH: join(temporary, "wrangler.log") } });
    report.checks.push("dry_run_bundle");
  }
  // This local-only wrapper seeds historical encrypted state to exercise storage
  // migration in workerd. It is never included in the deployment bundle.
  const fixtureModules = join(temporary, "fixture-modules");
  await mkdir(fixtureModules);
  await symlink(candidate, join(fixtureModules, "worker.js"));
  const testWorker = join(fixtureModules, 'fixture-worker.js');
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
  if (fixturePath) {
    const fixture = await readFile(fixturePath);
    // Only this reviewed synthetic PDF is allowed through the optional fixture
    // input. A real CV or any other file must never reach the runtime service.
    assert.equal(createHash("sha256").update(fixture).digest("hex"), "abe2ac634b12a6d7558ffe419f7cc311a262afc4fe8ef47b1b747faf7de05429");
    pdf = new Uint8Array(fixture);
  }
  report.fixture = { kind: fixturePath ? "approved_dummy_pdf" : "generated_synthetic_bytes", sha256: createHash("sha256").update(pdf).digest("hex") };
  const sealedExpiresAt = Date.now() + 300000;
  const encrypted = await sealDocument({ id, bytes: pdf, subjects: [subject, otherSubject], expiresAt: sealedExpiresAt }, await importKey(env.VAULT_WRAP_KEY));
  const recordBytes = JSON.stringify(encrypted);
  env.DUMMY_DOCUMENT_ID = id;
  env.DUMMY_RECORD_SHA256 = createHash("sha256").update(recordBytes).digest("hex");
  const pair = await generateKeyPair("RS256", { extractable: true }), jwk = { ...await exportJWK(pair.publicKey), kid: "runtime", use: "sig", alg: "RS256" };
  const token = actor => new SignJWT({ sub: actor }).setProtectedHeader({ alg: "RS256", kid: "runtime" })
    .setIssuer(env.ACCESS_ISSUER).setAudience(env.ACCESS_AUDIENCE).setIssuedAt().setExpirationTime("10m").sign(pair.privateKey);
  const notifications = [], forbidden = [];
  mf = new runtime.Miniflare({ modules: true, modulesRules: [{ type: 'ESModule', include: ['**/*.js'] }], modulesRoot: fixtureModules, scriptPath: testWorker,
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
  async function signed(path, { actor = env.VAULT_OWNER_SUB, method = "GET", body, headers = {} } = {}) {
    return mf.dispatchFetch(`${env.PUBLIC_ORIGIN}${path}`, { method,
      headers: { origin: env.PUBLIC_ORIGIN, "content-type": "application/json", "cf-access-jwt-assertion": actor ? await token(actor) : "", ...headers },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }), signal: AbortSignal.timeout(5000) });
  }
  async function request(action, actor = subject, requestId = crypto.randomUUID(), documentId = id, input) {
    const method = ["status", "metadata"].includes(action) ? "GET" : "POST";
    return signed(`/v1/documents/${documentId}/${action}`, { actor, method,
      ...(method === "GET" ? {} : { body: input ?? (action === "open" ? { requestId } : {}) }) });
  }
  function privateManagementHeaders(response) {
    assert.equal(response.headers.get("cache-control"), "private, no-store, max-age=0");
    assert.equal(response.headers.get("referrer-policy"), "no-referrer");
    assert.equal(response.headers.get("x-content-type-options"), "nosniff");
    assert.equal(response.headers.get("content-security-policy"), "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; worker-src 'self'; frame-ancestors 'self'; base-uri 'none'; form-action 'none'");
  }
  const metadataKeys = ["id", "mime", "size", "authMode", "recipientName", "expiresAt", "sealedExpiresAt", "revoked", "pending", "failed", "providerAccepted"].sort();
  function metadataShape(value, documentId, authMode, maximum, recipientName = null) {
    assert.deepEqual(Object.keys(value).sort(), metadataKeys);
    assert.equal(value.id, documentId); assert.equal(value.mime, "application/pdf"); assert.equal(value.size, pdf.length);
    assert.equal(value.authMode, authMode); assert.equal(value.recipientName, recipientName);
    assert.equal(value.sealedExpiresAt, maximum);
    for (const name of ["pending", "failed", "providerAccepted"]) assert.ok(Number.isSafeInteger(value[name]) && value[name] >= 0);
  }
  for (const [path, mime] of [["/v1/admin", "text/html; charset=utf-8"], ["/v1/admin/assets/admin.js", "text/javascript; charset=utf-8"],
    ["/v1/admin/assets/admin.css", "text/css; charset=utf-8"]]) {
    assert.equal((await signed(path, { actor: "" })).status, 401);
    assert.equal((await signed(path, { actor: subject })).status, 403);
    const page = await signed(path);
    assert.equal(page.status, 200); assert.equal(page.headers.get("content-type"), mime); privateManagementHeaders(page);
    const text = await page.text(); assert.ok(text.length > 100);
    if (path === "/v1/admin") {
      assert.match(text, /src="\/v1\/admin\/assets\/admin\.js"/);
      assert.doesNotMatch(text, /<script\s*>|\son[a-z]+\s*=/i);
    }
  }
  report.checks.push("management_html_and_assets_require_owner_with_strict_csp");
  assert.equal((await signed("/v1/management", { actor: "" })).status, 401);
  assert.equal((await signed("/v1/management", { actor: subject })).status, 403);
  assert.deepEqual(await (await signed("/v1/management")).json(), { documentId: id });
  assert.equal((await request("metadata", "")).status, 401);
  assert.equal((await request("metadata", subject)).status, 403);
  const initialMetadataResponse = await request("metadata", env.VAULT_OWNER_SUB);
  privateManagementHeaders(initialMetadataResponse);
  const initialMetadata = await initialMetadataResponse.json();
  metadataShape(initialMetadata, id, "access", sealedExpiresAt);
  assert.equal(initialMetadata.expiresAt, sealedExpiresAt); assert.equal(initialMetadata.revoked, false);
  assert.deepEqual([initialMetadata.pending, initialMetadata.failed, initialMetadata.providerAccepted], [0, 0, 0]);
  assert.equal(notifications.length, 0);
  report.checks.push("owner_only_bootstrap_and_minimal_document_metadata");
  const expiryPath = `/v1/documents/${id}/expiry`, expiryBody = { expiresAt: sealedExpiresAt - 1000, expectedExpiresAt: sealedExpiresAt };
  assert.equal((await signed(expiryPath, { actor: "", method: "POST", body: expiryBody })).status, 401);
  assert.equal((await signed(expiryPath, { actor: subject, method: "POST", body: expiryBody })).status, 403);
  assert.equal((await signed(expiryPath, { method: "POST", body: expiryBody, headers: { origin: "https://elsewhere.example.test" } })).status, 403);
  for (const input of [{ expiresAt: sealedExpiresAt + 1, expectedExpiresAt: sealedExpiresAt },
    { expiresAt: Date.now() - 1, expectedExpiresAt: sealedExpiresAt }, { ...expiryBody, unexpected: true }]) {
    assert.equal((await signed(expiryPath, { method: "POST", body: input })).status, 400);
  }
  assert.equal((await request("metadata", env.VAULT_OWNER_SUB)).status, 200);
  assert.equal(notifications.length, 0);
  report.checks.push("expiry_authentication_origin_and_sealed_maximum_enforced");
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
  const shortenedAccess = Date.now() + 2000;
  const accessUpdate = await signed(expiryPath, { method: "POST", body: { expiresAt: shortenedAccess, expectedExpiresAt: sealedExpiresAt } });
  assert.equal(accessUpdate.status, 200);
  const updatedAccessMetadata = await accessUpdate.json();
  metadataShape(updatedAccessMetadata, id, "access", sealedExpiresAt); assert.equal(updatedAccessMetadata.expiresAt, shortenedAccess);
  assert.equal((await signed(expiryPath, { method: "POST", body: expiryBody })).status, 409);
  const shortenedOpen = await request("open");
  assert.equal(shortenedOpen.status, 200); assert.deepEqual(new Uint8Array(await shortenedOpen.arrayBuffer()), pdf);
  assert.equal(Number(shortenedOpen.headers.get("x-vault-expires-at")), shortenedAccess);
  await pause(Math.max(0, shortenedAccess - Date.now() + 100));
  assert.equal((await request("open")).status, 403);
  const restoredAccess = await signed(expiryPath, { method: "POST", body: { expiresAt: sealedExpiresAt, expectedExpiresAt: shortenedAccess } });
  assert.equal(restoredAccess.status, 200); assert.equal((await restoredAccess.json()).expiresAt, sealedExpiresAt);
  const restoredOpen = await request("open");
  assert.equal(restoredOpen.status, 200); assert.deepEqual(new Uint8Array(await restoredOpen.arrayBuffer()), pdf);
  assert.equal(Number(restoredOpen.headers.get("x-vault-expires-at")), sealedExpiresAt);
  assert.equal(await (await bucket.get(`${id}.sealed.json`)).text(), recordBytes);
  report.checks.push("access_expiry_cas_shortening_expiration_and_restore_without_r2_write");
  for (const path of await files(persist)) {
    const bytes = await readFile(path);
    assert.ok(!bytes.includes(Buffer.from(pdf)));
    assert.ok(!bytes.includes(Buffer.from(pdf).toString("base64")));
    for (const secret of [subject, "SYNTHETIC-RUNTIME-PRIVATE-BODY", env.VAULT_WRAP_KEY, env.VAULT_AUDIT_KEY]) assert.ok(!bytes.includes(Buffer.from(secret)));
  }
  report.checks.push("durable_storage_contains_no_fixture_plaintext_or_keys");
  assert.equal((await request("revoke", env.VAULT_OWNER_SUB)).status, 200);
  assert.equal((await request("open")).status, 403);
  assert.equal((await signed(expiryPath, { method: "POST", body: expiryBody })).status, 403);
  report.checks.push("owner_revocation");
  // A separate fresh dummy document exercises shared-password mode without
  // weakening the Access document or reusing its irreversible revocation state.
  await mf.dispose(); mf = null;
  const passwordId = crypto.randomUUID(), password = "synthetic-shared-password-only";
  const passwordSealedExpiresAt = Date.now() + 300000, recipientName = "Synthetic Runtime Recipient";
  const passwordRecord = JSON.stringify(await sealDocument({ id: passwordId, bytes: pdf, subjects: [],
    expiresAt: passwordSealedExpiresAt, authMode: "password", password, recipientName }, await importKey(env.VAULT_WRAP_KEY)));
  const passwordEnv = { ...env, PASSWORD_READER_ENABLED: "1", DUMMY_DOCUMENT_ID: passwordId,
    DUMMY_RECORD_SHA256: createHash("sha256").update(passwordRecord).digest("hex") };
  const passwordPersist = join(temporary, "password-durable-objects");
  mf = new runtime.Miniflare({ modules: true, modulesRoot: build, scriptPath: candidate,
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
  assert.deepEqual(await (await signed("/v1/management")).json(), { documentId: passwordId });
  const passwordMetadata = await (await request("metadata", env.VAULT_OWNER_SUB, crypto.randomUUID(), passwordId)).json();
  metadataShape(passwordMetadata, passwordId, "password", passwordSealedExpiresAt, recipientName);
  const passwordExpiryPath = `/v1/documents/${passwordId}/expiry`, shortenedPassword = Date.now() + 2000;
  const shortenPasswordResponse = await signed(passwordExpiryPath, { method: "POST", body: { expiresAt: shortenedPassword, expectedExpiresAt: passwordSealedExpiresAt } });
  assert.equal(shortenPasswordResponse.status, 200); assert.equal((await shortenPasswordResponse.json()).expiresAt, shortenedPassword);
  const shortenedSession = await (await shared("status", { cookie })).json();
  assert.deepEqual(shortenedSession, { expiresAt: shortenedPassword, sessionExpiresAt: shortenedPassword });
  const shortPasswordOpen = await shared("open", { cookie });
  assert.equal(shortPasswordOpen.status, 200); assert.deepEqual(new Uint8Array(await shortPasswordOpen.arrayBuffer()), pdf);
  assert.equal(Number(shortPasswordOpen.headers.get("x-vault-expires-at")), shortenedPassword);
  assert.equal(Number(shortPasswordOpen.headers.get("x-vault-session-expires-at")), shortenedPassword);
  report.checks.push("owner_expiry_shortens_existing_password_cookie_and_pdf_deadlines");
  const restorePasswordResponse = await signed(passwordExpiryPath, { method: "POST", body: { expiresAt: passwordSealedExpiresAt, expectedExpiresAt: shortenedPassword } });
  assert.equal(restorePasswordResponse.status, 200); assert.equal((await restorePasswordResponse.json()).expiresAt, passwordSealedExpiresAt);
  assert.deepEqual(await (await shared("status", { cookie })).json(), { expiresAt: passwordSealedExpiresAt, sessionExpiresAt: shortenedPassword });
  const freshSource = { "cf-connecting-ip": "203.0.113.3" };
  const freshUnlock = await shared("session", { body: { password }, headers: freshSource });
  assert.equal(freshUnlock.status, 200);
  const freshCookie = freshUnlock.headers.get("set-cookie").split(";")[0], freshSession = await freshUnlock.json();
  assert.equal(freshSession.expiresAt, passwordSealedExpiresAt); assert.ok(freshSession.sessionExpiresAt > shortenedPassword);
  await pause(Math.max(0, shortenedPassword - Date.now() + 100));
  assert.equal((await shared("status", { cookie })).status, 401);
  assert.equal((await shared("open", { cookie })).status, 401);
  assert.equal((await shared("status", { cookie: freshCookie, headers: freshSource })).status, 200);
  assert.equal(await (await (await mf.getR2Bucket("VAULT_DOCUMENTS")).get(`${passwordId}.sealed.json`)).text(), passwordRecord);
  report.checks.push("restored_document_deadline_does_not_extend_old_password_session");
  assert.equal((await request("revoke", env.VAULT_OWNER_SUB, crypto.randomUUID(), passwordId)).status, 200);
  assert.equal((await shared("status", { cookie })).status, 403);
  assert.equal((await shared("open", { cookie })).status, 403);
  assert.equal((await shared("session", { method: "DELETE", cookie })).status, 200);
  report.checks.push("owner_revocation_invalidates_existing_password_session");
  for (const path of await files(passwordPersist)) {
    const bytes = await readFile(path);
    for (const secret of [password, cookie.split("=")[1], freshCookie.split("=")[1], recipientName, env.VAULT_WRAP_KEY, env.VAULT_AUDIT_KEY]) assert.ok(!bytes.includes(Buffer.from(secret)));
    assert.ok(!bytes.includes(Buffer.from(pdf)));
  }
  report.checks.push("password_session_and_document_secrets_not_persisted_in_plaintext");
  assert.deepEqual(forbidden, []); report.checks.push("no_unexpected_outbound");
  if (candidatePath) {
    report.candidateSha256After = createHash("sha256").update(await readFile(candidate)).digest("hex");
    assert.equal(report.candidateSha256After, expectedSha256);
    report.checks.push("frozen_candidate_hash_unchanged_after_runtime");
  }
  report.status = "passed";
} catch (error) {
  report.error = typeof error?.code === 'string' ? error.code : 'runtime_validation_failed';
  report.status = "failed"; process.exitCode = 1;
} finally {
  // A runtime disposal error must not skip removal of the synthetic fixture.
  try { if (mf) await mf.dispose(); }
  catch { report.status = "cleanup_failed"; process.exitCode = 1; }
  try { if (temporary) await rm(temporary, { recursive: true, force: true }); }
  catch { report.status = "cleanup_failed"; process.exitCode = 1; }
  report.pass = report.status === "passed";
  report.testCounts = { runtimeChecksExpected: 22, runtimeChecksPassed: report.checks.filter(check => check !== "dry_run_bundle" && !check.startsWith("frozen_")).length,
    bundleChecksPassed: report.checks.filter(check => check === "dry_run_bundle" || check.startsWith("frozen_")).length, totalChecksPassed: report.checks.length };
  await recordReport(); console.log(JSON.stringify(report));
}
