import { readFile, mkdir, writeFile, rename, rm } from "node:fs/promises";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";

const version = "6.4.299";
const packageRoot = new URL("../node_modules/pdfjs-dist/", import.meta.url);
const output = new URL("../src/pdfjs-assets.generated.js", import.meta.url);
// These hashes pin the exact upstream package assets, including license bytes.
const files = [
  ["/pdfjs/pdf.min.mjs", "legacy/build/pdf.min.mjs", "text/javascript; charset=utf-8", "utf8", "bccc24ea711db8e44503629519904a5292d73b9daaa214bbe7cdcc282b0f4259"],
  ["/pdfjs/pdf.worker.min.mjs", "legacy/build/pdf.worker.min.mjs", "text/javascript; charset=utf-8", "utf8", "145d2dd3ab0c86151011dba95acfa2d5336e2accd59388ea43dbee0efddaaec6"],
  ["/pdfjs/standard_fonts/LiberationSans-Regular.ttf", "standard_fonts/LiberationSans-Regular.ttf", "font/ttf", "base64", "f8ace1f892b2bd9dc1792ba7f097fa7588f84fed48321480e04de5390828221f"],
  ["/pdfjs/standard_fonts/LiberationSans-Bold.ttf", "standard_fonts/LiberationSans-Bold.ttf", "font/ttf", "base64", "361c61b82d575c5c35fd9157fda8b0194bcfcd0d88ea8521a4fb5dd53d33dddc"],
  ["/pdfjs/LICENSE", "LICENSE", "text/plain; charset=utf-8", "utf8", "0d542e0c8804e39aa7f37eb00da5a762149dc682d7829451287e11b938e94594"],
  ["/pdfjs/standard_fonts/LICENSE_LIBERATION", "standard_fonts/LICENSE_LIBERATION", "text/plain; charset=utf-8", "utf8", "d2c4d5b3e115a519cb58eb691aa64538397e2611f9ebe801392cf9667997e7dc"],
];
let temporary;
try {
  const metadata = JSON.parse(await readFile(new URL("package.json", packageRoot), "utf8"));
  if (metadata.name !== "pdfjs-dist" || metadata.version !== version) throw new Error("asset_version_mismatch");
  const assets = {}, manifest = [];
  for (const [path, source, mime, encoding, expectedHash] of files) {
    const bytes = await readFile(new URL(source, packageRoot));
    const sha256 = createHash("sha256").update(bytes).digest("hex");
    if (sha256 !== expectedHash) throw new Error("asset_hash_mismatch");
    const data = encoding === "base64" ? bytes.toString("base64") : new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    const decoded = Buffer.from(data, encoding);
    if (!decoded.equals(bytes)) throw new Error("asset_encoding_mismatch");
    assets[path] = { mime, encoding, data };
    manifest.push({ path, bytes: bytes.length, sha256 });
  }
  if (Object.keys(assets).length !== 6 || manifest.length !== 6) throw new Error("asset_count_mismatch");
  const content = "// Prepared from pinned pdfjs-dist; upstream license files are served unchanged.\n" +
    "export const pdfjsAssets = Object.freeze(" + JSON.stringify(assets) + ");\n" +
    "export const pdfjsAssetMetadata = Object.freeze(" + JSON.stringify({ version, build: "legacy", assets: manifest }) + ");\n";
  await mkdir(new URL("../src/", import.meta.url), { recursive: true });
  temporary = fileURLToPath(output) + "." + process.pid + ".tmp";
  await writeFile(temporary, content, { flag: "wx", mode: 0o644 });
  await rename(temporary, output);
  temporary = null;
  console.log(JSON.stringify({ version, assets: manifest.length, bytes: manifest.reduce((total, asset) => total + asset.bytes, 0), generatedSha256: createHash("sha256").update(content).digest("hex") }));
} catch (error) {
  if (temporary) await rm(temporary, { force: true });
  console.error(["asset_version_mismatch", "asset_hash_mismatch", "asset_encoding_mismatch", "asset_count_mismatch"].includes(error.message) ? error.message : "viewer_asset_preparation_failed");
  process.exitCode = 1;
}
