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
import { newKey, importKey, sealDocument, sealJSON, openJSON, utf8 } from "../src/crypto.js";

const exec = promisify(execFile), root = fileURLToPath(new URL("../", import.meta.url));
const args = parseArgs({ options: { bundle: { type: "string" }, "expected-sha": { type: "string" }, report: { type: "string" } }, allowPositionals: true });
const candidatePath = args.values.bundle ? resolve(args.values.bundle) : null;
const expectedSha256 = args.values["expected-sha"];
const fixturePath = args.positionals[1] ? resolve(args.positionals[1]) : null;
const report = { status: "running_not_verified", pass: false, checks: [], realDataUsed: false, liveNotificationsSent: false,
  compatibilityDate: "2026-01-12", compatibilityFlags: ["nodejs_compat"] };
const reportPath = args.values.report ? resolve(args.values.report) : args.positionals[0] ? resolve(args.positionals[0]) : null;
let temporary, mf;
const validationErrors = [];
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
  constructor(ctx, env) {
    const metrics = { r2Gets: 0, r2Puts: 0 }, keyMetrics = { reads: 0 };
    const wrappedEnv = { ...env, VAULT_DOCUMENTS: {
      get(...args) { metrics.r2Gets++; return env.VAULT_DOCUMENTS.get(...args); },
      put(...args) { metrics.r2Puts++; return env.VAULT_DOCUMENTS.put(...args); }
    } };
    for (const name of ['VAULT_WRAP_KEY', 'VAULT_AUDIT_KEY']) Object.defineProperty(wrappedEnv, name,
      { enumerable: true, get() { keyMetrics.reads++; return env[name]; } });
    super(ctx, wrappedEnv);
    this.runtimeMetrics = metrics; this.runtimeKeyMetrics = keyMetrics;
  }
  async fetch(request) {
    const path = new URL(request.url).pathname;
    if (path === '/__synthetic_seed') {
      await this.ctx.storage.put('encrypted-journal', await request.json());
      return new Response(null, { status: 204 });
    }
    if (path === '/__synthetic_archive_seed') {
      for (const entry of await request.json()) {
        await this.ctx.storage.put(entry.name, entry.box);
        await this.ctx.storage.put(entry.index, entry.name);
      }
      return new Response(null, { status: 204 });
    }
    if (path === '/__synthetic_state') return Response.json({ metrics: this.runtimeMetrics, keyReads: this.runtimeKeyMetrics.reads,
      journal: await this.ctx.storage.get('encrypted-journal'), registration: await this.ctx.storage.get('encrypted-registration') });
    return super.fetch(request);
  }
}`);
  const env = { PUBLIC_ORIGIN: "https://vault.example.test", ACCESS_ISSUER: "https://fixture-runtime.cloudflareaccess.com", ACCESS_AUDIENCE: "fixture-runtime",
    VAULT_OWNER_SUB: "synthetic-owner", VAULT_WRAP_KEY: newKey(), VAULT_AUDIT_KEY: newKey(), WEBHOOK_URL: "https://notify.example.test/fixture", PASSWORD_READER_ENABLED: '1' };
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
  let notificationAttempts = 0;
  mf = new runtime.Miniflare({ modules: true, modulesRules: [{ type: 'ESModule', include: ['**/*.js'] }], modulesRoot: fixtureModules, scriptPath: testWorker,
    compatibilityDate: "2026-01-12", compatibilityFlags: ["nodejs_compat"], host: "127.0.0.1", port: 0, cf: false,
    log: new runtime.Log(runtime.LogLevel.ERROR), bindings: env,
    durableObjects: { VAULT: { className: "RuntimeDocument", useSQLite: true } }, durableObjectsPersist: persist,
    r2Buckets: ["VAULT_DOCUMENTS"],
    outboundService: async request => {
      if (request.url === env.ACCESS_ISSUER + "/cdn-cgi/access/certs") return new runtime.Response(JSON.stringify({ keys: [jwk] }), { headers: { "content-type": "application/json" } });
      notificationAttempts++;
      if (request.url !== env.WEBHOOK_URL) { forbidden.push("blocked"); throw new Error("unexpected_network"); }
      try {
        const body = await request.text();
        for (const secret of [subject, "SYNTHETIC-RUNTIME-PRIVATE-BODY", id, env.VAULT_WRAP_KEY, env.VAULT_AUDIT_KEY]) assert.ok(!body.includes(secret));
        for (const encodedPDF of [Buffer.from(pdf).toString("base64"), JSON.stringify(Buffer.from(pdf).toString("utf8")).slice(1, -1)]) assert.ok(!body.includes(encodedPDF));
        notifications.push(JSON.parse(body));
      } catch { validationErrors.push('fixture_outbound_validation_failed'); throw new Error('fixture_outbound_validation_failed'); }
      return new runtime.Response(null, { status: notifications.length === 1 ? 503 : 202 });
    } });
  await mf.ready;
  const bucket = await mf.getR2Bucket("VAULT_DOCUMENTS");
  await bucket.put(`${id}.sealed.json`, recordBytes);
  const namespace = await mf.getDurableObjectNamespace('VAULT'), objectId = namespace.idFromName(id);
  const documentStub = namespace.get(objectId), registryStub = namespace.get(namespace.idFromName('owner-registration:v1'));
  const runtimeState = stub => stub.fetch('https://vault.example.test/__synthetic_state').then(response => response.json());
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
  const managementScript = await signed('/v1/admin/assets/management.js');
  assert.equal((await signed('/v1/admin/assets/management.js', { actor: '' })).status, 401);
  assert.equal((await signed('/v1/admin/assets/management.js', { actor: subject })).status, 403);
  assert.equal(managementScript.status, 200); privateManagementHeaders(managementScript); assert.ok((await managementScript.text()).length > 100);
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
  assert.equal(notificationAttempts, 0);
  report.checks.push("owner_only_bootstrap_and_minimal_document_metadata");
  const managementMetrics = (await runtimeState(documentStub)).metrics, logsPath = `/v1/documents/${id}/logs`;
  assert.equal((await signed(logsPath, { actor: '' })).status, 401);
  assert.equal((await signed(logsPath, { actor: subject })).status, 403);
  const emptyLogsResponse = await signed(logsPath); privateManagementHeaders(emptyLogsResponse);
  assert.deepEqual(await emptyLogsResponse.json(), { events: [], nextCursor: null, retentionDays: 30 });
  assert.equal((await signed(logsPath, { method: 'POST', body: { cursor: 'synthetic-invalid-cursor' } })).status, 400);
  assert.equal((await signed(logsPath, { method: 'POST', body: { cursor: 'synthetic-invalid-cursor' }, headers: { origin: 'https://elsewhere.example.test' } })).status, 403);
  assert.deepEqual((await runtimeState(documentStub)).metrics, managementMetrics); assert.equal(notificationAttempts, 0);
  report.checks.push('owner_logs_authentication_cursor_and_no_r2_or_notification_effects');
  const contactsPath = `/v1/documents/${id}/recipients`, contactEmail = 'SyntheticRecipient@example.test';
  assert.equal((await signed(contactsPath, { actor: '' })).status, 401);
  assert.equal((await signed(contactsPath, { actor: subject })).status, 403);
  const emptyContacts = await signed(contactsPath); privateManagementHeaders(emptyContacts);
  assert.deepEqual(await emptyContacts.json(), { revision: 0, emails: [] });
  const contactInput = { expectedRevision: 0, emails: ['SyntheticRecipient@EXAMPLE.test'] };
  assert.equal((await signed(contactsPath, { method: 'POST', actor: '', body: contactInput })).status, 401);
  assert.equal((await signed(contactsPath, { method: 'POST', actor: subject, body: contactInput })).status, 403);
  assert.equal((await signed(contactsPath, { method: 'POST', body: contactInput, headers: { origin: 'https://elsewhere.example.test' } })).status, 403);
  const savedContacts = await signed(contactsPath, { method: 'POST', body: contactInput }); assert.equal(savedContacts.status, 200);
  assert.deepEqual(await savedContacts.json(), { revision: 1, emails: [contactEmail] });
  assert.equal((await signed(contactsPath, { method: 'POST', body: contactInput })).status, 409);
  assert.deepEqual(await (await signed(contactsPath)).json(), { revision: 1, emails: [contactEmail] });
  const contactState = await runtimeState(documentStub);
  assert.deepEqual(contactState.metrics, managementMetrics);
  assert.ok(!JSON.stringify(contactState.journal).includes(contactEmail));
  assert.deepEqual((await openJSON(contactState.journal, await importKey(env.VAULT_AUDIT_KEY), `journal:v1:${objectId.toString()}`)).recipientContacts,
    { recordDigest: env.DUMMY_RECORD_SHA256, revision: 1, emails: [contactEmail] });
  assert.equal(notificationAttempts, 0);
  assert.equal((await signed(`/v1/documents/${id}/open`, { actor: contactEmail, method: 'POST', body: { requestId: crypto.randomUUID() } })).status, 403);
  report.checks.push('owner_contact_metadata_encrypted_cas_and_no_read_permission_granted');
  const registryPath = '/v1/registrations';
  assert.equal((await signed(registryPath, { actor: '' })).status, 401);
  assert.equal((await signed(registryPath, { actor: subject })).status, 403);
  const emptyRegistry = await signed(registryPath); privateManagementHeaders(emptyRegistry);
  assert.deepEqual(await emptyRegistry.json(), { revision: 0, documents: [], pending: 0 });
  const candidateId = crypto.randomUUID(), candidateName = 'Synthetic Runtime Registration.pdf';
  const candidatePDF = new Uint8Array(4096); candidatePDF.fill(32); candidatePDF.set(utf8('%PDF-1.4\nSYNTHETIC-REGISTRATION-PRIVATE-BODY\n'));
  const registrationInput = { id: candidateId, pdfBase64: Buffer.from(candidatePDF).toString('base64'), fileName: candidateName,
    expiresAt: Date.now() + 300000, replaceOf: null, expectedRevision: 0 };
  const registryBefore = await runtimeState(registryStub);
  for (const actor of ['', subject]) assert.equal((await signed(registryPath, { actor, method: 'POST', body: registrationInput })).status, actor ? 403 : 401);
  assert.equal((await signed(registryPath, { method: 'POST', body: registrationInput, headers: { origin: 'https://elsewhere.example.test' } })).status, 403);
  assert.deepEqual(await runtimeState(registryStub), registryBefore); assert.equal(await bucket.head(`staging/${candidateId}.sealed.json`), null);
  report.checks.push('registration_unauthenticated_requests_do_not_read_keys_or_store_documents');
  const registeredResponse = await signed(registryPath, { method: 'POST', body: registrationInput }); assert.equal(registeredResponse.status, 201);
  const registered = await registeredResponse.json(); assert.ok(registered.revision > 0); assert.equal(registered.pending, 0); assert.equal(registered.documents.length, 1);
  assert.deepEqual(Object.keys(registered.documents[0]).sort(), ['id', 'createdAt', 'expiresAt', 'size', 'replaceOf', 'status', 'fileName'].sort());
  assert.equal(registered.documents[0].id, candidateId); assert.equal(registered.documents[0].fileName, candidateName);
  assert.equal(registered.documents[0].size, candidatePDF.length); assert.equal(registered.documents[0].status, 'private');
  assert.equal(registered.documents[0].replaceOf, null); assert.equal(registered.documents[0].expiresAt, registrationInput.expiresAt);
  const storedCandidate = await (await bucket.get(`staging/${candidateId}.sealed.json`)).text();
  for (const value of [Buffer.from(candidatePDF).toString('base64'), 'SYNTHETIC-REGISTRATION-PRIVATE-BODY', candidateName, env.VAULT_WRAP_KEY]) assert.ok(!storedCandidate.includes(value));
  const registrationState = await runtimeState(registryStub);
  assert.ok(registrationState.metrics.r2Gets > 0 && registrationState.metrics.r2Puts > 0);
  assert.ok(!JSON.stringify(registrationState.registration).includes(candidateName));
  assert.deepEqual(await (await signed(registryPath)).json(), registered);
  assert.equal((await signed(registryPath, { method: 'POST', body: { ...registrationInput, id: crypto.randomUUID() } })).status, 409);
  assert.equal((await signed(`/v1/documents/${candidateId}/open`, { actor: subject, method: 'POST', body: { requestId: crypto.randomUUID() } })).status, 403);
  assert.equal((await mf.dispatchFetch(`${env.PUBLIC_ORIGIN}/p/${candidateId}`)).status, 403);
  assert.deepEqual(await (await signed('/v1/management')).json(), { documentId: id });
  assert.equal(await (await bucket.get(`${id}.sealed.json`)).text(), recordBytes); assert.equal(notificationAttempts, 0);
  report.checks.push('owner_pdf_registration_is_encrypted_private_and_does_not_change_active_pin');
  const replacementId = crypto.randomUUID();
  const replacementResponse = await signed(registryPath, { method: 'POST', body: { ...registrationInput, id: replacementId,
    fileName: 'Synthetic Replacement Candidate.pdf', replaceOf: id, expectedRevision: registered.revision } });
  assert.equal(replacementResponse.status, 201);
  const replacement = await replacementResponse.json(); assert.equal(replacement.documents.length, 2); assert.equal(replacement.pending, 0);
  assert.equal(replacement.documents.find(document => document.id === replacementId).replaceOf, id);
  assert.equal((await signed(`/v1/documents/${replacementId}/open`, { actor: subject, method: 'POST', body: { requestId: crypto.randomUUID() } })).status, 403);
  assert.deepEqual(await (await signed('/v1/management')).json(), { documentId: id });
  assert.equal(await (await bucket.get(`${id}.sealed.json`)).text(), recordBytes); assert.equal(notificationAttempts, 0);
  report.checks.push('replacement_candidate_remains_private_until_separate_activation');
  const expiryPath = `/v1/documents/${id}/expiry`, expiryBody = { expiresAt: sealedExpiresAt - 1000, expectedExpiresAt: sealedExpiresAt };
  assert.equal((await signed(expiryPath, { actor: "", method: "POST", body: expiryBody })).status, 401);
  assert.equal((await signed(expiryPath, { actor: subject, method: "POST", body: expiryBody })).status, 403);
  assert.equal((await signed(expiryPath, { method: "POST", body: expiryBody, headers: { origin: "https://elsewhere.example.test" } })).status, 403);
  for (const input of [{ expiresAt: sealedExpiresAt + 1, expectedExpiresAt: sealedExpiresAt },
    { expiresAt: Date.now() - 1, expectedExpiresAt: sealedExpiresAt }, { ...expiryBody, unexpected: true }]) {
    assert.equal((await signed(expiryPath, { method: "POST", body: input })).status, 400);
  }
  assert.equal((await request("metadata", env.VAULT_OWNER_SUB)).status, 200);
  assert.equal(notificationAttempts, 0);
  report.checks.push("expiry_authentication_origin_and_sealed_maximum_enforced");
  assert.equal((await request("open", "")).status, 401);
  assert.equal((await request("open", "unauthorized-subject")).status, 403);
  report.checks.push("signature_and_document_grant");
  assert.equal((await request("open", subject, crypto.randomUUID(), crypto.randomUUID())).status, 403);
  report.checks.push("unapproved_document_id_denied");
  await bucket.put(`${id}.sealed.json`, recordBytes + "\n");
  assert.equal((await request("open")).status, 403);
  assert.deepEqual(await (await request("status", env.VAULT_OWNER_SUB)).json(), { revoked: false, pending: 0, failed: 0, providerAccepted: 0 });
  assert.equal(notificationAttempts, 0);
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
  const at = Date.now() - 120000;
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
  const archiveDeliveryDeadline = Date.now() + 4000;
  while (Date.now() < archiveDeliveryDeadline && (await (await request('status', env.VAULT_OWNER_SUB)).json()).pending) await pause(20);
  assert.equal((await (await request('status', env.VAULT_OWNER_SUB)).json()).pending, 0);
  const archiveNow = Date.now(), expiredEvent = { id: crypto.randomUUID(), documentId: id, subject, at: archiveNow - 31 * 86400000, outcome: 'decrypted' };
  const expiredName = `audit:${expiredEvent.id}`, expiredAt = expiredEvent.at + 30 * 86400000;
  const expiredBox = await sealJSON({ event: expiredEvent, jobs: [], expiresAt: expiredAt }, await importKey(env.VAULT_AUDIT_KEY), `journal:v1:${objectId.toString()}:${expiredName}`);
  assert.equal((await documentStub.fetch('https://vault.example.test/__synthetic_archive_seed', { method: 'POST', body: JSON.stringify([
    { name: expiredName, box: expiredBox, index: `expiry:${String(expiredAt).padStart(13, '0')}:${expiredName}` }
  ]) })).status, 204);
  const metricsBeforeLogs = (await runtimeState(documentStub)).metrics, notificationsBeforeLogs = notificationAttempts;
  const logged = [], logIds = new Set(); let logCursor = null, logPages = 0;
  do {
    const logResponse = await signed(logsPath, logCursor ? { method: 'POST', body: { cursor: logCursor } } : {});
    assert.equal(logResponse.status, 200); privateManagementHeaders(logResponse);
    const logPage = await logResponse.json(); assert.equal(logPage.retentionDays, 30); assert.ok(logPage.events.length <= 50);
    for (const event of logPage.events) {
      assert.deepEqual(Object.keys(event).sort(), ['id', 'at', 'subject', 'outcome', 'notifications'].sort());
      assert.ok(event.at > Date.now() - 30 * 86400000); assert.notEqual(event.id, expiredEvent.id); assert.ok(!logIds.has(event.id)); logIds.add(event.id);
      for (const target of event.notifications) assert.deepEqual(Object.keys(target).sort(), ['type', 'state', 'attempts', 'error', 'httpStatus'].sort());
      logged.push(event);
    }
    logCursor = logPage.nextCursor; assert.ok(++logPages < 30);
  } while (logCursor);
  for (const event of oldEvents) assert.ok(logIds.has(event.id));
  assert.ok(logged.length >= 501); assert.ok(!logIds.has(expiredEvent.id));
  for (let index = 1; index < logged.length; index++) assert.ok(logged[index - 1].at > logged[index].at ||
    (logged[index - 1].at === logged[index].at && logged[index - 1].id > logged[index].id));
  assert.deepEqual((await runtimeState(documentStub)).metrics, metricsBeforeLogs); assert.equal(notificationAttempts, notificationsBeforeLogs);
  report.checks.push('owner_logs_page_encrypted_archive_in_workerd_with_thirty_day_retention');
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
    for (const secret of [subject, contactEmail, candidateName, 'Synthetic Replacement Candidate.pdf', 'SYNTHETIC-REGISTRATION-PRIVATE-BODY',
      Buffer.from(candidatePDF).toString('base64'), "SYNTHETIC-RUNTIME-PRIVATE-BODY", env.VAULT_WRAP_KEY, env.VAULT_AUDIT_KEY]) assert.ok(!bytes.includes(Buffer.from(secret)));
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
      notificationAttempts++;
      if (request.url !== env.WEBHOOK_URL) { forbidden.push("blocked"); throw new Error("unexpected_network"); }
      try {
        const body = await request.text();
        for (const secret of [password, passwordId, subject, env.VAULT_WRAP_KEY, env.VAULT_AUDIT_KEY]) assert.ok(!body.includes(secret));
      } catch { validationErrors.push('fixture_outbound_validation_failed'); throw new Error('fixture_outbound_validation_failed'); }
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
  assert.deepEqual(forbidden, []); assert.deepEqual(validationErrors, []); report.checks.push("no_unexpected_outbound");
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
  if (validationErrors.length) {
    if (report.status === 'passed') report.status = 'failed';
    report.error ??= 'fixture_outbound_validation_failed'; process.exitCode = 1;
  }
  report.pass = report.status === "passed";
  report.testCounts = { runtimeChecksExpected: 28, runtimeChecksPassed: report.checks.filter(check => check !== "dry_run_bundle" && !check.startsWith("frozen_")).length,
    bundleChecksPassed: report.checks.filter(check => check === "dry_run_bundle" || check.startsWith("frozen_")).length, totalChecksPassed: report.checks.length };
  await recordReport(); console.log(JSON.stringify(report));
}
