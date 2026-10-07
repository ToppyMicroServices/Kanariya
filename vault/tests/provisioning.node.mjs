import test from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtemp, mkdir, readFile, readdir, rm, stat, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { newKey, importKey, readPolicy, decryptDocument, utf8 } from "../src/crypto.js";
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
    assert.ok(!result.stdout.includes("synthetic-private")); assert.ok(!result.stdout.includes(request.wrappingKey));
    const id = JSON.parse(result.stdout).id, path = join(outputDirectory, `${id}.sealed.json`);
    assert.equal((await stat(path)).mode & 0o777, 0o600);
    const stored = await readFile(path, "utf8"); assert.ok(!stored.includes("SYNTHETIC-PRIVATE")); assert.ok(!stored.includes("synthetic-private"));
    const record = JSON.parse(stored), key = await importKey(request.wrappingKey), policy = await readPolicy(record, id, key);
    assert.deepEqual(await decryptDocument(record, key, policy), source);
    await symlink(sourcePath, join(root, "symlink.pdf"));
    const denied = await run({ ...request, sourcePath: join(root, "symlink.pdf") });
    assert.equal(denied.code, 1); assert.equal(denied.stdout, ""); assert.deepEqual(JSON.parse(denied.stderr), { status: "failed", code: "provisioning_failed" });
    assert.equal((await readdir(outputDirectory)).length, 1);
  } finally { await rm(root, { recursive: true, force: true }); }
});
