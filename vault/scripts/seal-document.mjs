// Trusted owner-side provisioning only. Read paths, grants and the wrapping key
// and any document password from stdin; write only an encrypted record.
import { open } from "node:fs/promises";
import { createHash } from "node:crypto";
import { join } from "node:path";
import { constants } from "node:fs";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { MAX_PDF_BYTES, importKey, sealDocument } from "../src/crypto.js";
import { normalizeRecipientName } from "../src/recipient.js";
process.umask(0o077);
async function watermark(bytes, recipientName, fontPath) {
  const python = process.env.KANARIYA_WATERMARK_PYTHON || "python3";
  const script = fileURLToPath(new URL("./watermark-pdf.py", import.meta.url));
  if (fontPath !== undefined && (typeof fontPath !== "string" || !fontPath || fontPath.length > 4096 || fontPath.includes("\0"))) throw new Error();
  const input = JSON.stringify({ pdfBase64: Buffer.from(bytes).toString("base64"), recipientName, ...(fontPath === undefined ? {} : { fontPath }) });
  return new Promise((resolve, reject) => {
    // No document credentials or arbitrary inherited environment reach Python.
    const env = { PATH: process.env.PATH || "/usr/bin:/bin", LANG: process.env.LANG || "en_US.UTF-8", PYTHONDONTWRITEBYTECODE: "1", PYTHONNOUSERSITE: "1" };
    const child = spawn(python, [script], { stdio: ["pipe", "pipe", "ignore"], env });
    const chunks = []; let length = 0, settled = false;
    const fail = () => {
      if (settled) return; settled = true; clearTimeout(timer); child.kill("SIGKILL");
      for (const chunk of chunks) chunk.fill(0);
      reject(new Error("watermark_failed"));
    };
    const timer = setTimeout(fail, 30000);
    child.on("error", fail); child.stdin.on("error", fail);
    child.stdout.on("data", chunk => {
      if (settled) { chunk.fill(0); return; }
      length += chunk.length;
      if (length > MAX_PDF_BYTES) { chunk.fill(0); fail(); return; }
      chunks.push(chunk);
    });
    child.on("close", code => {
      if (settled) return;
      if (code !== 0 || length < 5) { fail(); return; }
      const output = Buffer.concat(chunks, length);
      for (const chunk of chunks) chunk.fill(0);
      if (output.subarray(0, 5).toString("ascii") !== "%PDF-") { output.fill(0); fail(); return; }
      settled = true; clearTimeout(timer); resolve(new Uint8Array(output)); output.fill(0);
    });
    child.stdin.end(input);
  });
}
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
  if (Object.hasOwn(request, "watermarkFontPath") && !Object.hasOwn(request, "recipientName")) throw new Error();
  if (Object.hasOwn(request, "recipientName")) {
    request.recipientName = normalizeRecipientName(request.recipientName);
    const stamped = await watermark(bytes, request.recipientName, request.watermarkFontPath);
    bytes.fill(0); bytes = stamped;
  }
  const id = crypto.randomUUID();
  const options = { id, bytes, subjects: request.subjects, expiresAt: request.expiresAt };
  for (const name of ["authMode", "password", "passwordVerifier", "recipientName"]) if (Object.hasOwn(request, name)) options[name] = request[name];
  let record;
  try { record = await sealDocument(options, await importKey(request.wrappingKey)); }
  finally { options.password = ""; options.recipientName = ""; }
  bytes.fill(0); request.wrappingKey = ""; request.password = ""; request.recipientName = ""; input = "";
  const serialized = JSON.stringify(record);
  const output = await open(join(request.outputDirectory, `${id}.sealed.json`), constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  try { await output.writeFile(serialized); await output.sync(); } finally { await output.close(); }
  console.log(JSON.stringify({ status: "sealed", id, ciphertextSha256: createHash("sha256").update(serialized).digest("hex") }));
} catch {
  console.error('{"status":"failed","code":"provisioning_failed"}'); process.exitCode = 1;
} finally {
  // JS strings are immutable, so clearing references is best effort only.
  bytes?.fill(0); input = "";
  if (request && typeof request === "object") { request.wrappingKey = ""; request.password = ""; request.recipientName = ""; }
  await fd?.close();
}
