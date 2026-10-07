// Trusted owner-side provisioning only. Read paths, grants and the wrapping key
// and any document password from stdin; write only an encrypted record.
import { open } from "node:fs/promises";
import { createHash } from "node:crypto";
import { join } from "node:path";
import { constants } from "node:fs";
import { MAX_PDF_BYTES, importKey, sealDocument } from "../src/crypto.js";
process.umask(0o077);
let fd, request, bytes, input = "";
try {
  process.stdin.setEncoding("utf8");
  for await (const chunk of process.stdin) {
    input += chunk; if (Buffer.byteLength(input, "utf8") > 32768) throw new Error();
  }
  request = JSON.parse(input);
  if (typeof request.outputDirectory !== "string" || typeof request.sourcePath !== "string" ||
      !Number.isSafeInteger(request.expiresAt) || request.expiresAt <= Date.now()) throw new Error();
  fd = await open(request.sourcePath, constants.O_RDONLY | constants.O_NOFOLLOW);
  const info = await fd.stat();
  if (!info.isFile() || info.size < 5 || info.size > MAX_PDF_BYTES) throw new Error();
  bytes = new Uint8Array(await fd.readFile());
  const id = crypto.randomUUID();
  const options = { id, bytes, subjects: request.subjects, expiresAt: request.expiresAt };
  for (const name of ["authMode", "password", "passwordVerifier"]) if (Object.hasOwn(request, name)) options[name] = request[name];
  let record;
  try { record = await sealDocument(options, await importKey(request.wrappingKey)); }
  finally { options.password = ""; }
  bytes.fill(0); request.wrappingKey = ""; request.password = ""; input = "";
  const serialized = JSON.stringify(record);
  const output = await open(join(request.outputDirectory, `${id}.sealed.json`), constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  try { await output.writeFile(serialized); await output.sync(); } finally { await output.close(); }
  console.log(JSON.stringify({ status: "sealed", id, ciphertextSha256: createHash("sha256").update(serialized).digest("hex") }));
} catch {
  console.error('{"status":"failed","code":"provisioning_failed"}'); process.exitCode = 1;
} finally {
  // JS strings are immutable, so clearing references is best effort only.
  bytes?.fill(0); input = "";
  if (request && typeof request === "object") { request.wrappingKey = ""; request.password = ""; }
  await fd?.close();
}
