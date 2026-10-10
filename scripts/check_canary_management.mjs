#!/usr/bin/env node
// Synthetic local workerd check. No live configuration, documents, or mail.
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { mkdtemp, mkdir, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { promisify } from 'node:util';

const exec = promisify(execFile), root = fileURLToPath(new URL('../', import.meta.url));
const startedAt = Date.now(), deadline = startedAt + 40000, checks = [], versions = { node: process.version };
let temporary, mf, reportPath, failure, bundleSha256, outboundRequests = 0;
function remaining() { const value = deadline - Date.now(); if (value <= 0) throw new Error('Canary integration exceeded its 40-second deadline'); return value; }
async function bounded(value, label) {
  let timer;
  try { return await Promise.race([value, new Promise((_, reject) => { timer = setTimeout(() => reject(new Error(label + ' timed out')), remaining()); })]); }
  finally { clearTimeout(timer); }
}
async function check() {
  const args = process.argv.slice(2);
  if (args.length && (args.length !== 2 || args[0] !== '--report' || !args[1])) throw new Error('Usage: node scripts/check_canary_management.mjs [--report PATH]');
  if (args.length) reportPath = resolve(args[1]);
  const { stdout } = await exec(process.platform === 'win32' ? 'npm.cmd' : 'npm', ['root', '-g'], { cwd: root, timeout: Math.min(5000, remaining()) });
  const wranglerRoot = join(stdout.trim(), 'wrangler'), pkg = JSON.parse(await readFile(join(wranglerRoot, 'package.json'), 'utf8'));
  assert.match(pkg.version, /^4\./, 'Globally installed Wrangler 4 is required'); versions.wrangler = pkg.version;
  const runtimeRoot = join(wranglerRoot, 'node_modules', 'miniflare');
  versions.miniflare = JSON.parse(await readFile(join(runtimeRoot, 'package.json'), 'utf8')).version;
  const { Miniflare, Log, LogLevel } = await import(pathToFileURL(join(runtimeRoot, 'dist', 'src', 'index.js')).href);
  temporary = await mkdtemp(join(tmpdir(), 'kanariya-canary-rpc-'));
  const build = join(temporary, 'build'), bin = typeof pkg.bin === 'string' ? pkg.bin : pkg.bin.wrangler;
  await exec(process.execPath, [join(wranglerRoot, bin), 'deploy', '--dry-run', '--outdir', build], {
    cwd: root, env: { ...process.env, WRANGLER_SEND_METRICS: 'false', WRANGLER_LOG_PATH: join(temporary, 'wrangler.log') },
    timeout: Math.min(15000, remaining()), maxBuffer: 1024 * 1024,
  });
  bundleSha256 = createHash('sha256').update(await readFile(join(build, 'worker.js'))).digest('hex');
  checks.push('Wrangler bundles the named WorkerEntrypoint with the current public Worker');
  mf = new Miniflare({ host: '127.0.0.1', port: 0, cf: false, log: new Log(LogLevel.ERROR),
    durableObjectsPersist: join(temporary, 'storage'),
    workers: [{ name: 'canary-fixture', modules: true, modulesRoot: build, scriptPath: join(build, 'worker.js'),
      compatibilityDate: '2026-01-12', durableObjects: { KANARI_STORE: { className: 'KanariyaStore', useSQLite: true } },
      bindings: { ADMIN_KEY: 'synthetic-admin', IP_HMAC_KEY: 'synthetic-ip-key', RATE_LIMIT_MAX: '0', CANARY_SOURCE_KEY: Buffer.alloc(32, 115).toString('base64') },
      outboundService: async () => { outboundRequests++; throw new Error('All external requests are blocked in this check'); },
    }, { name: 'trusted-caller-fixture', modules: true, compatibilityDate: '2026-01-12',
      script: `export default { async fetch(request, env) {
        const input = await request.json(); let result;
        switch(input.action) {
          case 'status': result = await env.CANARY_ADMIN.status(input.id); break;
          case 'create': result = await env.CANARY_ADMIN.create(input.id, input.expiresAt); break;
          case 'revoke': result = await env.CANARY_ADMIN.revoke(input.id); break;
          case 'events': result = await env.CANARY_ADMIN.events(input.id); break;
          case 'test': try { await env.CANARY_ADMIN.test(input.id); return Response.json({ exposed: true }); }
            catch { return Response.json({ exposed: false }); }
          default: return new Response(null, { status: 400 });
        }
        return Response.json(result);
      } };`,
      serviceBindings: { CANARY_ADMIN: { name: 'canary-fixture', entrypoint: 'CanaryManagement' } },
      outboundService: async () => { outboundRequests++; throw new Error('All external requests are blocked in this check'); },
    }],
  });
  await mf.ready;
  const main = await mf.getWorker('canary-fixture'), caller = await mf.getWorker('trusted-caller-fixture');
  const id = randomUUID(), other = randomUUID(), expiresAt = Date.now() + 60000;
  async function rpc(action, doc = id, expiry) {
    const response = await caller.fetch('https://fixture.test/rpc', { method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ action, id: doc, ...(expiry === undefined ? {} : { expiresAt: expiry }) }),
      signal: AbortSignal.timeout(Math.min(5000, remaining())) });
    assert.equal(response.status, 200); return response.json();
  }
  const initial = await rpc('status'); assert.deepEqual(initial, { status: 200, value: { documentId: id, canary: null } });
  checks.push('Native Service Binding reaches only the named management RPC entrypoint');
  for (const action of ['status', 'create', 'revoke', 'events']) {
    const response = await main.fetch('https://fixture.test/internal/vault-canary/' + action, { method: 'POST',
      headers: { authorization: 'Bearer synthetic-admin', 'content-type': 'application/json' }, body: JSON.stringify({ documentId: id, expiresAt }) });
    assert.equal(response.status, 404);
  }
  assert.equal((await main.fetch('https://fixture.test/admin/tokens')).status, 403);
  assert.equal((await main.fetch('https://fixture.test/admin/tokens', { headers: { authorization: 'Bearer wrong' } })).status, 403);
  assert.equal((await main.fetch('https://fixture.test/admin/tokens', { headers: { authorization: 'Bearer synthetic-admin' } })).status, 200);
  assert.deepEqual(await rpc('test'), { exposed: false });
  checks.push('Public internal paths remain 404, existing Bearer checks remain active, and no notification-test RPC is exposed');
  const results = await Promise.all(Array.from({ length: 8 }, () => rpc('create', id, expiresAt)));
  assert.equal(results.filter(result => result.status === 201).length, 1); assert.equal(results.filter(result => result.status === 409).length, 7);
  const canary = (await rpc('status')).value.canary;
  assert.equal(canary.expiresAt, expiresAt); assert.equal(canary.state, 'active'); assert.match(canary.token, /^kr_[a-f0-9]{64}$/);
  assert.equal((await rpc('events')).value.events.length, 0); assert.equal((await rpc('status', other)).value.canary, null);
  checks.push('Native SQLite transactions admit one token per document, enforce exact expiry and keep document scopes separate');
  const hit = await main.fetch('https://fixture.test/canary/' + canary.token + '?src=PRIVATE_SYNTHETIC_EMAIL@example.test', {
    headers: { 'cf-connecting-ip': '198.51.100.17', 'user-agent': 'PRIVATE_SYNTHETIC_UA', referer: 'https://private.example.test/PRIVATE_SYNTHETIC_CV' } });
  assert.equal(hit.status, 204);
  const events = (await rpc('events')).value.events; assert.equal(events.length, 1);
  assert.equal(events[0].outcome, 'url_requested'); assert.deepEqual(events[0].notifications, []);
  assert.equal(events[0].source.ip, '198.51.100.17'); assert.equal(events[0].source.refererHost, 'private.example.test');
  assert.deepEqual((await rpc('events', other)).value.events, []);
  const exportResponse = await main.fetch('https://fixture.test/admin/export?token=' + canary.token, { headers: { authorization: 'Bearer synthetic-admin' } });
  const stored = await exportResponse.json(); assert.equal(stored.length, 1);
  assert.deepEqual(Object.keys(stored[0]).sort(), ['deliveries', 'documentId', 'id', 'kind', 'ts']);
  assert.equal(stored[0].kind, 'vault.canary'); assert.equal(stored[0].documentId, id);
  assert.doesNotMatch(JSON.stringify(stored), /PRIVATE_SYNTHETIC_|198\.51\.100\.17|ipHash|referer|user-agent/);
  const storageRoot = join(temporary, 'storage');
  let storageFilesChecked = 0;
  for (const name of await readdir(storageRoot, { recursive: true })) {
    if (!/\.sqlite(?:-wal|-shm)?$/.test(name)) continue;
    const storedBytes = await readFile(join(storageRoot, name));
    storageFilesChecked++;
    for (const marker of ['198.51.100.17', 'private.example.test', 'PRIVATE_SYNTHETIC_', Buffer.alloc(32, 115).toString('base64')]) {
      assert.equal(storedBytes.includes(Buffer.from(marker)), false, 'Private source or key must never appear in persisted SQLite bytes');
    }
  }
  assert.ok(storageFilesChecked > 0, 'Persisted SQLite files must actually be inspected');
  checks.push('Native owner RPC decrypts source evidence; SQLite bytes and public export omit plaintext source and keys');
  const revoked = await rpc('revoke'); assert.equal(revoked.value.canary.state, 'revoked');
  await main.fetch('https://fixture.test/canary/' + canary.token);
  assert.equal((await rpc('events')).value.events.length, 1);
  const replacement = await rpc('create', id, expiresAt); assert.equal(replacement.status, 201);
  assert.notEqual(replacement.value.canary.token, canary.token); assert.equal((await rpc('status')).value.canary.token, replacement.value.canary.token);
  checks.push('Revocation stops new recording; a replacement remains the current token without erasing earlier evidence');
  const shortExpiry = Date.now() + 1000, short = await rpc('create', other, shortExpiry); assert.equal(short.status, 201);
  await new Promise(resolvePause => setTimeout(resolvePause, Math.max(0, shortExpiry - Date.now() + 80)));
  assert.equal((await rpc('status', other)).value.canary.state, 'expired');
  await main.fetch('https://fixture.test/canary/' + short.value.canary.token);
  assert.equal((await rpc('events', other)).value.events.length, 0);
  assert.equal((await rpc('create', randomUUID(), Date.now() - 1)).status, 400);
  assert.equal((await rpc('status', '../admin')).status, 400);
  checks.push('Real local time expiry and invalid document/deadline inputs fail closed in native workerd');
  assert.equal(outboundRequests, 0);
  checks.push('Status/create/revoke/history and synthetic hits sent zero external requests or real notifications');
}
try { await bounded(check(), 'Canary native integration'); }
catch (error) { failure = error.message; }
finally {
  if (mf) try { await mf.dispose(); } catch (error) { failure ||= error.message; }
  if (temporary) try { await rm(temporary, { recursive: true, force: true }); } catch (error) { failure ||= error.message; }
}
const report = { status: failure ? 'failed' : 'passed', runtime: 'workerd through Wrangler-bundled Miniflare', versions,
  durationMs: Date.now() - startedAt, checks, bundleSha256, localBindingOnly: true, realDocumentsUsed: false,
  productionRequests: 0, realNotificationsSent: 0, outboundRequests, ...(failure ? { error: failure } : {}) };
if (reportPath) try { await mkdir(dirname(reportPath), { recursive: true }); await writeFile(reportPath, JSON.stringify(report, null, 2) + '\n'); }
catch (error) { report.status = 'failed'; report.error = 'Could not save report: ' + error.message; }
console.log(JSON.stringify(report, null, 2)); process.exitCode = report.status === 'passed' ? 0 : 1;
