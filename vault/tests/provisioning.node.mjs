import test from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtemp, mkdir, readFile, readdir, rm, stat, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { MAX_PDF_BYTES, newKey, importKey, readPolicy, decryptDocument, utf8 } from "../src/crypto.js";
import { verifyPassword } from "../src/password.js";
const script = fileURLToPath(new URL("../scripts/seal-document.mjs", import.meta.url));
function run(input) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [script], { stdio: ["pipe", "pipe", "pipe"] });
    let stdout = "", stderr = "";
    child.stdout.on("data", x => { stdout += x; }); child.stderr.on("data", x => { stderr += x; });
    child.on("error", reject); child.on("close", code => resolve({ code, stdout, stderr }));
    child.stdin.end(JSON.stringify(input));
  });
}
test("provisioning writes only authenticated ciphertext and redacts errors", async () => {
  const root = await mkdtemp(join(tmpdir(), "vault-synthetic-provision-"));
  try {
    const outputDirectory = join(root, "sealed"); await mkdir(outputDirectory);
    const sourcePath = join(root, "synthetic-private-name.pdf"), source = utf8("%PDF-1.4\nSYNTHETIC-PRIVATE-CONTENT\n");
    await writeFile(sourcePath, source);
    const request = { outputDirectory, sourcePath, subjects: ["synthetic-private-subject"], expiresAt: Date.now() + 60000, wrappingKey: newKey() };
    const result = await run(request); assert.equal(result.code, 0); assert.equal(result.stderr, "");
    assert.deepEqual(Object.keys(JSON.parse(result.stdout)).sort(), ["ciphertextSha256", "id", "status"]);
    assert.ok(!result.stdout.includes("synthetic-private")); assert.ok(!result.stdout.includes(request.wrappingKey));
    const id = JSON.parse(result.stdout).id, path = join(outputDirectory, `${id}.sealed.json`);
    assert.equal((await stat(path)).mode & 0o777, 0o600);
    const stored = await readFile(path, "utf8"); assert.ok(!stored.includes("SYNTHETIC-PRIVATE")); assert.ok(!stored.includes("synthetic-private"));
    const record = JSON.parse(stored), key = await importKey(request.wrappingKey), policy = await readPolicy(record, id, key);
    assert.equal(policy.authMode, "access"); assert.equal(Object.hasOwn(policy, "passwordVerifier"), false);
    assert.equal(JSON.parse(result.stdout).ciphertextSha256, createHash("sha256").update(stored).digest("hex"));
    assert.deepEqual(await decryptDocument(record, key, policy), source);
    await symlink(sourcePath, join(root, "symlink.pdf"));
    const denied = await run({ ...request, sourcePath: join(root, "symlink.pdf") });
    assert.equal(denied.code, 1); assert.equal(denied.stdout, ""); assert.deepEqual(JSON.parse(denied.stderr), { status: "failed", code: "provisioning_failed" });
    assert.equal((await readdir(outputDirectory)).length, 1);
  } finally { await rm(root, { recursive: true, force: true }); }
});

test("password provisioning persists only encrypted verifier and document, with redacted output", async () => {
  const root = await mkdtemp(join(tmpdir(), "vault-synthetic-password-provision-"));
  try {
    const outputDirectory = join(root, "sealed"); await mkdir(outputDirectory);
    const sourcePath = join(root, "synthetic-sensitive-file-name.pdf"), source = utf8("%PDF-1.4\nSYNTHETIC-PASSWORD-MODE-BODY\n");
    await writeFile(sourcePath, source);
    const wrappingKey = newKey(), key = await importKey(wrappingKey);
    // Both limits, including multibyte UTF-8 at the maximum, are supported.
    for (const password of ["a".repeat(12), "a".repeat(256), "é".repeat(128)]) {
      const result = await run({ outputDirectory, sourcePath, authMode: "password", subjects: [], password,
        expiresAt: Date.now() + 60000, wrappingKey });
      assert.equal(result.code, 0); assert.equal(result.stderr, "");
      const output = JSON.parse(result.stdout);
      assert.deepEqual(Object.keys(output).sort(), ["ciphertextSha256", "id", "status"]);
      assert.equal(output.status, "sealed");
      const path = join(outputDirectory, `${output.id}.sealed.json`), stored = await readFile(path, "utf8");
      assert.equal((await stat(path)).mode & 0o777, 0o600);
      assert.equal(output.ciphertextSha256, createHash("sha256").update(stored).digest("hex"));
      const record = JSON.parse(stored), policy = await readPolicy(record, output.id, key);
      assert.equal(record.version, 2); assert.equal(policy.authMode, "password"); assert.deepEqual(policy.subjects, []);
      assert.equal(verifyPassword(password, policy.passwordVerifier), true);
      assert.equal(Object.hasOwn(policy, "password"), false);
      assert.deepEqual(await decryptDocument(record, key, policy), source);
      for (const secret of [password, wrappingKey, sourcePath, "SYNTHETIC-PASSWORD-MODE-BODY", policy.passwordVerifier.salt, policy.passwordVerifier.hash]) {
        assert.ok(!stored.includes(secret)); assert.ok(!result.stdout.includes(secret));
      }
    }
    assert.equal((await readdir(outputDirectory)).length, 3);
    assert.deepEqual((await readdir(root)).sort(), ["sealed", "synthetic-sensitive-file-name.pdf"]);
  } finally { await rm(root, { recursive: true, force: true }); }
});

test("invalid modes, mixed credentials and byte bounds produce only redacted provisioning failures", async () => {
  const root = await mkdtemp(join(tmpdir(), "vault-synthetic-invalid-provision-"));
  try {
    const outputDirectory = join(root, "sealed"); await mkdir(outputDirectory);
    const sourcePath = join(root, "synthetic-private-source.pdf"); await writeFile(sourcePath, "%PDF-synthetic");
    const request = { outputDirectory, sourcePath, subjects: ["synthetic-private-subject"], expiresAt: Date.now() + 60000, wrappingKey: newKey() };
    const password = "synthetic-private-password", verifier = { version: 1, kdf: "scrypt-16384-8-5", salt: "01".repeat(32), hash: "02".repeat(32) };
    for (const change of [
      { subjects: [] }, { password }, { authMode: "access", password }, { passwordVerifier: verifier },
      { authMode: "unknown" }, { authMode: null }, { authMode: "password", password },
      { authMode: "password", subjects: [] }, { authMode: "password", subjects: [], password: "a".repeat(11) },
      { authMode: "password", subjects: [], password: "a".repeat(257) },
      { authMode: "password", subjects: [], password: "é".repeat(129) },
      { authMode: "password", subjects: [], password, passwordVerifier: verifier },
      { authMode: "password", subjects: [], password: "x".repeat(32769) },
    ]) {
      const result = await run({ ...request, ...change });
      assert.equal(result.code, 1); assert.equal(result.stdout, "");
      assert.deepEqual(JSON.parse(result.stderr), { status: "failed", code: "provisioning_failed" });
      assert.deepEqual(await readdir(outputDirectory), []);
    }
    await writeFile(sourcePath, new Uint8Array(MAX_PDF_BYTES + 1));
    const oversized = await run({ ...request, authMode: "password", subjects: [], password });
    assert.equal(oversized.code, 1); assert.equal(oversized.stdout, "");
    assert.deepEqual(JSON.parse(oversized.stderr), { status: "failed", code: "provisioning_failed" });
    assert.deepEqual(await readdir(outputDirectory), []);
  } finally { await rm(root, { recursive: true, force: true }); }
});
