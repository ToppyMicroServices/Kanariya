// Trusted owner-side provisioning only. Read paths, grants and the wrapping key
// from stdin; write an encrypted record, never a plaintext copy or key file.
import { open } from "node:fs/promises";
import { createHash } from "node:crypto";
import { join } from "node:path";
import { constants } from "node:fs";
import { MAX_PDF_BYTES, importKey, sealDocument } from "../src/crypto.js";
process.umask(0o077);
let fd;
try {
  let input = "";
  for await (const chunk of process.stdin) {
    input += chunk.toString(); if (input.length > 32768) throw new Error();
  }
  const request = JSON.parse(input);
  if (typeof request.outputDirectory !== "string" || typeof request.sourcePath !== "string" ||
      !Number.isSafeInteger(request.expiresAt) || request.expiresAt <= Date.now()) throw new Error();
  fd = await open(request.sourcePath, constants.O_RDONLY | constants.O_NOFOLLOW);
  const info = await fd.stat();
  if (!info.isFile() || info.size < 5 || info.size > MAX_PDF_BYTES) throw new Error();
  const bytes = new Uint8Array(await fd.readFile());
  const id = crypto.randomUUID();
  const record = await sealDocument({ id, bytes, subjects: request.subjects, expiresAt: request.expiresAt }, await importKey(request.wrappingKey));
  bytes.fill(0); request.wrappingKey = ""; input = "";
  const serialized = JSON.stringify(record);
  const output = await open(join(request.outputDirectory, `${id}.sealed.json`), constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  try { await output.writeFile(serialized); await output.sync(); } finally { await output.close(); }
  console.log(JSON.stringify({ status: "sealed", id, ciphertextSha256: createHash("sha256").update(serialized).digest("hex") }));
} catch {
  console.error('{"status":"failed","code":"provisioning_failed"}'); process.exitCode = 1;
} finally { await fd?.close(); }
