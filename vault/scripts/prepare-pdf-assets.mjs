import { readFile, writeFile, rename, rm } from "node:fs/promises";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";

const version = "1.17.1";
const packageRoot = new URL("../node_modules/pdf-lib/", import.meta.url);
const output = new URL("../src/pdf-preparation-assets.generated.js", import.meta.url);
const pinned = [
  ["/v1/admin/assets/pdf-lib.mjs", "dist/pdf-lib.esm.min.js", "text/javascript; charset=utf-8", "72c052d97b4d5d9fa6cdbdcb7ad709f03d4ddb1122390cb3afeba4d88651d969"],
  ["/v1/admin/assets/pdf-lib-LICENSE.md", "LICENSE.md", "text/plain; charset=utf-8", "f2c9fc00fdb66eb99ac156ba52d734af66d8d309f65753ae809ad34ee2883bcb"],
];
let temporary;
try {
  const metadata = JSON.parse(await readFile(new URL("package.json", packageRoot), "utf8"));
  if (metadata.name !== "pdf-lib" || metadata.version !== version) throw new Error("asset_version_mismatch");
  const assets = {}, manifest = [];
  function add(path, mime, bytes) {
    const data = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    if (!Buffer.from(data).equals(bytes)) throw new Error("asset_encoding_mismatch");
    assets[path] = { mime, encoding: "utf8", data };
    manifest.push({ path, bytes: bytes.length, sha256: createHash("sha256").update(bytes).digest("hex") });
  }
  for (const [path, source, mime, expectedHash] of pinned) {
    const bytes = await readFile(new URL(source, packageRoot));
    if (createHash("sha256").update(bytes).digest("hex") !== expectedHash) throw new Error("asset_hash_mismatch");
    add(path, mime, bytes);
  }
  const preparation = await readFile(new URL("../src/pdf-preparation.js", import.meta.url), "utf8");
  const needle = 'from "pdf-lib";';
  if (preparation.split(needle).length !== 2 || !preparation.includes('from "./recipient.js";')) throw new Error("asset_import_mismatch");
  const browserPreparation = preparation.replace(needle, 'from "./pdf-lib.mjs";');
  add("/v1/admin/assets/pdf-preparation.mjs", "text/javascript; charset=utf-8", Buffer.from(browserPreparation));
  add("/v1/admin/assets/recipient.js", "text/javascript; charset=utf-8", await readFile(new URL("../src/recipient.js", import.meta.url)));
  const content = "// Owner-only PDF preparation assets; upstream MIT license is served unchanged.\n" +
    "export const pdfPreparationAssets = Object.freeze(" + JSON.stringify(assets) + ");\n" +
    "export const pdfPreparationAssetMetadata = Object.freeze(" + JSON.stringify({ version, assets: manifest }) + ");\n";
  temporary = fileURLToPath(output) + "." + process.pid + ".tmp";
  await writeFile(temporary, content, { flag: "wx", mode: 0o644 });
  await rename(temporary, output);
  temporary = null;
  console.log(JSON.stringify({ version, assets: manifest.length, bytes: manifest.reduce((total, asset) => total + asset.bytes, 0), generatedSha256: createHash("sha256").update(content).digest("hex") }));
} catch (error) {
  if (temporary) await rm(temporary, { force: true });
  const allowed = ["asset_version_mismatch", "asset_hash_mismatch", "asset_encoding_mismatch", "asset_import_mismatch"];
  console.error(allowed.includes(error.message) ? error.message : "pdf_asset_preparation_failed");
  process.exitCode = 1;
}
