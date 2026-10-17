import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, mkdir, readFile, readdir, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { newKey, importKey, sealDocument, readPolicy, decryptDocument, normalizeAllowedEmails, validatePolicy, utf8 } from '../src/crypto.js';

const pdf = utf8('%PDF-1.4\nSYNTHETIC-EMAIL-READER-DOCUMENT\n');
function options(changes = {}) {
  return { id: crypto.randomUUID(), bytes: pdf, authMode: 'email', subjects: [],
    allowedEmails: ['Recipient@EXAMPLE.TEST'], expiresAt: Date.now() + 60000, ...changes };
}

test('email grants and document bytes are encrypted and retain exact local-part spelling', async () => {
  const key = await importKey(newKey()), input = options({ allowedEmails: [' Recipient@EXAMPLE.TEST ', 'recipient@example.test'] });
  const record = await sealDocument(input, key), policy = await readPolicy(record, input.id, key);
  assert.equal(policy.authMode, 'email'); assert.deepEqual(policy.subjects, []);
  assert.deepEqual(policy.allowedEmails, ['Recipient@example.test', 'recipient@example.test']);
  assert.deepEqual(await decryptDocument(record, key, policy), pdf);
  for (const plaintext of ['Recipient', 'recipient@example.test', 'allowedEmails', 'SYNTHETIC-EMAIL']) assert.ok(!JSON.stringify(record).includes(plaintext));
  assert.deepEqual(input.allowedEmails, [' Recipient@EXAMPLE.TEST ', 'recipient@example.test']);
});

test('email allowlist supports exactly fifty explicit addresses', async () => {
  const emails = Array.from({ length: 50 }, (_, i) => `reader-${i}@example.test`);
  assert.deepEqual(normalizeAllowedEmails(emails), emails);
  const key = await importKey(newKey()), input = options({ allowedEmails: emails });
  assert.deepEqual((await readPolicy(await sealDocument(input, key), input.id, key)).allowedEmails, emails);
});

for (const [label, allowedEmails] of [
  ['missing', undefined], ['null', null], ['empty', []], ['string', 'reader@example.test'],
  ['invalid email', ['bad-email']], ['non-string email', [123]], ['duplicates', ['reader@example.test', 'reader@example.test']],
  ['normalized duplicates', ['reader@EXAMPLE.TEST', 'reader@example.test']], ['sparse array', Array(1)],
  ['too many', Array.from({ length: 51 }, (_, i) => `reader-${i}@example.test`)],
]) test(`email policy rejects ${label} allowlist`, async () => {
  const key = await importKey(newKey());
  await assert.rejects(sealDocument(options({ allowedEmails }), key), /invalid_policy/);
});

for (const [label, changes] of [
  ['subject grant', { subjects: ['legacy-reader'] }], ['password', { password: 'synthetic-password' }],
  ['verifier', { passwordVerifier: {} }],
]) test(`email policy rejects mixed ${label}`, async () => {
  await assert.rejects(sealDocument(options(changes), await importKey(newKey())), /invalid_policy/);
});

for (const mode of ['access', 'password', 'link']) test(`${mode} policy cannot acquire email grants implicitly`, async () => {
  const input = options({ authMode: mode, subjects: mode === 'access' ? ['subject'] : [],
    ...(mode === 'password' ? { password: 'synthetic-password' } : {}) });
  await assert.rejects(sealDocument(input, await importKey(newKey())), /invalid_policy/);
  assert.throws(() => validatePolicy({ mime: 'application/pdf', size: 5, subjects: input.subjects,
    expiresAt: input.expiresAt, revoked: false, authMode: mode, allowedEmails: [] }), /invalid_policy/);
});

test('stored policy requires canonical email grants and rejects client password material', () => {
  const policy = { mime: 'application/pdf', size: 5, subjects: [], expiresAt: Date.now() + 60000,
    revoked: false, authMode: 'email', allowedEmails: ['recipient@example.test'] };
  assert.equal(validatePolicy(policy), policy);
  for (const changes of [{ allowedEmails: ['recipient@EXAMPLE.TEST'] }, { allowedEmails: [' recipient@example.test '] },
    { password: '' }, { passwordVerifier: null }, { subjects: ['subject'] }]) {
    assert.throws(() => validatePolicy({ ...policy, ...changes }), /invalid_policy/);
  }
});

function run(input) {
  const script = fileURLToPath(new URL('../scripts/seal-document.mjs', import.meta.url));
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [script], { stdio: ['pipe', 'pipe', 'pipe'] });
    let stdout = '', stderr = '';
    child.stdout.on('data', value => { stdout += value; }); child.stderr.on('data', value => { stderr += value; });
    child.on('error', reject); child.on('close', code => resolve({ code, stdout, stderr }));
    child.stdin.end(JSON.stringify(input));
  });
}

test('provisioning receives email grants on stdin and writes only ciphertext with redacted results', async () => {
  const root = await mkdtemp(join(tmpdir(), 'vault-synthetic-email-provision-'));
  try {
    const outputDirectory = join(root, 'sealed'), sourcePath = join(root, 'synthetic.pdf');
    await mkdir(outputDirectory); await writeFile(sourcePath, pdf);
    const request = { outputDirectory, sourcePath, authMode: 'email', subjects: [],
      allowedEmails: ['PrivateRecipient@EXAMPLE.TEST'], expiresAt: Date.now() + 60000, wrappingKey: newKey() };
    const result = await run(request); assert.equal(result.code, 0); assert.equal(result.stderr, '');
    const output = JSON.parse(result.stdout);
    assert.deepEqual(Object.keys(output).sort(), ['ciphertextSha256', 'id', 'status']);
    const path = join(outputDirectory, `${output.id}.sealed.json`), stored = await readFile(path, 'utf8');
    assert.equal((await stat(path)).mode & 0o777, 0o600);
    for (const value of [request.allowedEmails[0], 'PrivateRecipient@example.test', request.wrappingKey, sourcePath, 'SYNTHETIC-EMAIL']) {
      assert.ok(!stored.includes(value)); assert.ok(!result.stdout.includes(value));
    }
    const key = await importKey(request.wrappingKey), record = JSON.parse(stored), policy = await readPolicy(record, output.id, key);
    assert.deepEqual(policy.allowedEmails, ['PrivateRecipient@example.test']);
    assert.deepEqual(await decryptDocument(record, key, policy), pdf);
    for (const allowedEmails of [[], ['PrivateRecipient@example.test', 'PrivateRecipient@EXAMPLE.TEST'], ['private-invalid-email']]) {
      const failed = await run({ ...request, allowedEmails });
      assert.equal(failed.code, 1); assert.equal(failed.stdout, '');
      assert.equal(failed.stderr.trim(), '{"status":"failed","code":"provisioning_failed"}');
      assert.equal((await readdir(outputDirectory)).length, 1);
    }
  } finally { await rm(root, { recursive: true, force: true }); }
});
