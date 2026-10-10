import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { deflateSync } from "node:zlib";
import { readFile } from "node:fs/promises";
import {
  PDFDocument, PDFArray, PDFDict, PDFName, PDFNumber, PDFString, PDFHexString,
  PDFRawStream, decodePDFRawStream, degrees,
} from "pdf-lib";
import { preparePdf, PDF_PREPARATION_LIMITS } from "../src/pdf-preparation.js";

const hash = bytes => createHash("sha256").update(bytes).digest("hex");
const utf8 = bytes => new TextDecoder().decode(bytes);
const name = "株式会社試験 採用担当";

function crc32(bytes) {
  let crc = 0xffffffff;
  for (const byte of bytes) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit++) crc = (crc >>> 1) ^ (0xedb88320 & -(crc & 1));
  }
  return (crc ^ 0xffffffff) >>> 0;
}
function chunk(type, data) {
  const typeBytes = Buffer.from(type), size = Buffer.alloc(4), checksum = Buffer.alloc(4);
  size.writeUInt32BE(data.length); checksum.writeUInt32BE(crc32(Buffer.concat([typeBytes, data])));
  return Buffer.concat([size, typeBytes, data, checksum]);
}
// Synthetic mark geometry, not a fixture containing private names or a real CV.
function watermark(width = 2048, height = 256) {
  const header = Buffer.alloc(13); header.writeUInt32BE(width); header.writeUInt32BE(height, 4);
  header[8] = 8; header[9] = 6;
  const pixels = Buffer.alloc(height * (1 + width * 4));
  for (let y = Math.floor(height / 3); y < Math.floor(height * 2 / 3); y++) {
    for (let x = Math.floor(width / 8); x < Math.floor(width * 7 / 8); x++) {
      const offset = y * (1 + width * 4) + 1 + x * 4;
      pixels.set([115, 115, 115, 255], offset);
    }
  }
  return new Uint8Array(Buffer.concat([Buffer.from([137,80,78,71,13,10,26,10]), chunk("IHDR", header), chunk("IDAT", deflateSync(pixels)), chunk("IEND", Buffer.alloc(0))]));
}
async function fixture(mutator, pageCount = 2) {
  const document = await PDFDocument.create();
  for (let index = 0; index < pageCount; index++) document.addPage([595, 842]).drawText(`SYNTHETIC TEST PAGE ${index + 1}`, { x: 50, y: 780, size: 16 });
  if (mutator) await mutator(document);
  return document.save({ useObjectStreams: false, addDefaultPage: false });
}
const prepare = (bytes, extra = {}) => preparePdf({ bytes, recipientName: name, watermarkEnabled: true, watermarkPng: watermark(), ...extra });
async function rejected(bytes, code = "unsafe_pdf", extra = {}) { await assert.rejects(prepare(bytes, extra), { message: code }); }
function streams(document, page) {
  const contents = page.node.get(PDFName.of("Contents")), resolved = document.context.lookup(contents);
  const items = resolved instanceof PDFArray ? Array.from({length: resolved.size()}, (_, index) => document.context.lookup(resolved.get(index))) : [resolved];
  return items.filter(value => value instanceof PDFRawStream).map(value => utf8(decodePDFRawStream(value).decode()));
}

test("input and required watermark fields reject before PDF parsing", async () => {
  for (const bytes of [undefined, null, "base64", {}, new Uint8Array()]) {
    await assert.rejects(preparePdf({ bytes, watermarkEnabled: false }), { message: "invalid_pdf_input" });
  }
  await assert.rejects(preparePdf({ bytes: new Uint8Array(PDF_PREPARATION_LIMITS.bytes + 1), watermarkEnabled: false }), { message: "pdf_too_large" });
  const bytes = await fixture();
  for (const watermarkEnabled of [undefined, null, 0, "true"]) await rejected(bytes, "invalid_watermark", { watermarkEnabled });
  for (const recipientName of [undefined, "", "\ud800", "../name", "a".repeat(181)]) await rejected(bytes, "invalid_recipient", { recipientName });
  for (const watermarkPng of [undefined, null, "png", new Uint8Array(30), new Uint8Array(512 * 1024 + 1)]) await rejected(bytes, "invalid_watermark", { watermarkPng });
});

test("validation-only mode returns an independent exact source and hashes", async () => {
  const bytes = await fixture();
  const result = await preparePdf({ bytes: bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength), watermarkEnabled: false });
  assert.deepEqual(Object.keys(result).sort(), ["bytes", "sourceSha256", "finalSha256", "pages"].sort());
  assert.deepEqual(result.bytes, bytes); assert.notEqual(result.bytes, bytes);
  assert.equal(result.sourceSha256, hash(bytes)); assert.equal(result.finalSha256, hash(bytes)); assert.equal(result.pages, 2);
});

test("the final size limit is enforced independently of the bounded input", async () => {
  let padding = PDF_PREPARATION_LIMITS.bytes - 4000, bytes;
  for (let attempt = 0; attempt < 3; attempt++) {
    bytes = await fixture(document => document.context.register(document.context.stream(new Uint8Array(padding))));
    padding += PDF_PREPARATION_LIMITS.bytes - 16 - bytes.length;
  }
  assert.ok(bytes.length <= PDF_PREPARATION_LIMITS.bytes && bytes.length > PDF_PREPARATION_LIMITS.bytes - 32);
  assert.equal((await preparePdf({ bytes, watermarkEnabled: false })).bytes.length, bytes.length);
  await rejected(bytes, "pdf_too_large");
});

test("one embedded image appears as persistent page content on every page, with original text preserved", async () => {
  const bytes = await fixture(undefined, 3), before = await PDFDocument.load(bytes);
  const originals = before.getPages().map(page => streams(before, page));
  const result = await prepare(bytes), after = await PDFDocument.load(result.bytes), images = [];
  assert.equal(result.pages, 3); assert.equal(result.sourceSha256, hash(bytes)); assert.equal(result.finalSha256, hash(result.bytes));
  assert.notEqual(result.sourceSha256, result.finalSha256);
  for (let index = 0; index < after.getPages().length; index++) {
    const page = after.getPages()[index], content = streams(after, page);
    for (const original of originals[index]) assert.ok(content.includes(original), "original text content is retained");
    const resources = page.node.Resources(), xObjects = resources.lookup(PDFName.of("XObject"), PDFDict);
    assert.equal(xObjects.entries().length, 1); images.push(xObjects.entries()[0][1].toString());
    assert.equal(content.join("\n").match(/\/Image-[^\s]+ Do/gu)?.length, 1);
    assert.equal(page.node.Annots()?.size() ?? 0, 0, "mark is page content, not a printable-optional annotation");
    const gs = resources.lookup(PDFName.of("ExtGState"), PDFDict).entries().map(([, value]) => after.context.lookup(value));
    assert.ok(gs.some(value => value.lookup(PDFName.of("ca"), PDFNumber).asNumber() === 0.2));
  }
  assert.equal(new Set(images).size, 1, "same image ref reused across all pages");
});

test("crop offsets and all quarter-turn rotations retain visible fitted stamp geometry", async () => {
  const bytes = await fixture(document => {
    for (const [index, rotation] of [0, 90, 180, 270].entries()) {
      const page = document.getPages()[index]; page.setMediaBox(-100, -100, 900, 1100);
      page.setCropBox(-50, -25, 650, 850); page.setRotation(degrees(rotation));
    }
  }, 4);
  const result = await prepare(bytes), document = await PDFDocument.load(result.bytes);
  for (const page of document.getPages()) {
    assert.deepEqual(page.getCropBox(), { x:-50, y:-25, width:650, height:850 });
    const stamp = streams(document, page).find(stream => /\/Image-[^\s]+ Do/u.test(stream));
    const transforms = Array.from(stamp.matchAll(/(-?[\d.]+) (-?[\d.]+) (-?[\d.]+) (-?[\d.]+) (-?[\d.]+) (-?[\d.]+) cm/gu), match => match.slice(1).map(Number));
    assert.ok(transforms.length >= 3);
    const [, , , , x, y] = transforms[0], [cosine, sine] = transforms[1], [width, , , height] = transforms[2];
    const corners = [[0,0],[width,0],[0,height],[width,height]].map(([a,b]) => [x + cosine * a - sine * b, y + sine * a + cosine * b]);
    for (const [px, py] of corners) assert.ok(px > -50 && px < 600 && py > -25 && py < 825, "all watermark corners fit CropBox");
    assert.ok(height >= 24);
  }
});

test("unsafe features are rejected even outside the reachable page tree or watermark-disabled mode", async t => {
  const keys = ["AcroForm","OpenAction","AA","JS","JavaScript","EmbeddedFiles","EF","AF","XFA","RichMedia","Launch","SubmitForm","ImportData","ByteRange","Perms"];
  for (const key of keys) await t.test(key, async () => {
    const bytes = await fixture(document => document.context.register(document.context.obj({ [key]: "synthetic" })));
    await rejected(bytes); await rejected(bytes, "unsafe_pdf", { watermarkEnabled: false });
  });
  const actions = ["JavaScript","Launch","GoToR","GoToE","SubmitForm","ImportData","Rendition","Sound","Movie","URL","Hide","SetOCGState","Trans","GoTo3DView","Named","Thread","ResetForm"];
  for (const action of actions) await t.test(action, async () => {
    await rejected(await fixture(document => document.context.register(document.context.obj({ S: action }))));
  });
  for (const type of ["Sig", "Filespec", "EmbeddedFile"]) await rejected(await fixture(document => document.context.register(document.context.obj({ Type: type }))));
  await rejected(await fixture(document => document.context.register(document.context.obj({ FT: "Sig" }))));
  for (const subtype of ["Widget","RichMedia","Screen","Movie","Sound","3D"]) await rejected(await fixture(document => document.context.register(document.context.obj({ Subtype: subtype }))));
  await rejected(await fixture(document => { document.context.trailerInfo.Encrypt = document.context.register(document.context.obj({ Filter: "Standard" })); }), "unsupported_pdf");
});

function addLink(document, uri, extra = {}) {
  const action = document.context.obj({ S: "URI", URI: PDFString.of(uri), ...extra });
  const annot = document.context.register(document.context.obj({ Type: "Annot", Subtype: "Link", Rect: [0,0,10,10], A: action }));
  document.getPages()[0].node.addAnnot(annot);
}
test("static HTTPS, mailto and internal links survive; unsafe or chained actions are rejected", async () => {
  for (const uri of ["https://example.com/cv", "mailto:synthetic@example.com"]) {
    await prepare(await fixture(document => addLink(document, uri)));
  }
  for (const uri of ["http://example.com", "javascript:alert(1)", "file:///tmp/cv", "https://example.com/\n", "mailto:", "mailto:x@example.com?body=%0d%0aInjected", "https://", "https://example.com/ space"]) {
    await rejected(await fixture(document => addLink(document, uri)));
  }
  await rejected(await fixture(document => addLink(document, "https://example.com", { Next: document.context.obj({ S: "URI", URI: PDFString.of("https://example.com") }) })));
  await rejected(await fixture(document => document.context.register(document.context.obj({ Type: "Action", S: "FutureUnsafeAction" }))));
  await rejected(await fixture(document => document.catalog.set(PDFName.of("A"), document.context.obj({ S: "FutureUnsafeAction" }))));
  await prepare(await fixture(document => {
    const page = document.getPages()[0];
    page.node.addAnnot(document.context.register(document.context.obj({ Subtype: "Link", Dest: document.context.obj([page.ref, "Fit"]) })));
  }));
});

test("page graph, page count, object count and malformed geometry fail closed", async () => {
  await rejected(await fixture(undefined, 21), "pdf_complexity_limit");
  await rejected(await fixture(document => document.catalog.Pages().set(PDFName.of("Count"), PDFNumber.of(99))), "pdf_complexity_limit");
  await rejected(await fixture(document => document.catalog.Pages().Kids().push(document.catalog.get(PDFName.of("Pages")))), "unsupported_pdf");
  await rejected(await fixture(document => document.getPages()[0].node.set(PDFName.of("Parent"), document.getPages()[0].ref)), "unsupported_pdf");
  await rejected(await fixture(document => {
    for (let index = 0; index < PDF_PREPARATION_LIMITS.objects; index++) document.context.register(PDFString.of(`test ${index}`));
  }), "pdf_complexity_limit");
  await rejected(await fixture(document => document.getPages()[0].node.set(PDFName.of("Rotate"), PDFNumber.of(45))), "invalid_page_geometry");
  await rejected(await fixture(document => document.getPages()[0].node.set(PDFName.of("UserUnit"), PDFNumber.of(2))), "invalid_page_geometry");
  await rejected(await fixture(document => document.getPages()[0].setCropBox(-1, 0, 595, 842)), "invalid_page_geometry");
  await rejected(await fixture(document => document.getPages()[0].setMediaBox(0, 0, 0, 842)), "invalid_page_geometry");
  await rejected(await fixture(document => document.getPages()[0].setMediaBox(0, 0, 20001, 842)), "invalid_page_geometry");
  await rejected(await fixture(document => document.getPages()[0].setMediaBox(0, 0, 36, 36)), "watermark_does_not_fit");
});

test("PNG dimensions, checksums and duplicated, animated or incomplete PNGs are rejected", async () => {
  const bytes = await fixture();
  const valid = watermark(), badCrc = valid.slice(); badCrc[29] ^= 1;
  const excessiveDimensions = valid.slice(); new DataView(excessiveDimensions.buffer).setUint32(16, 0xffffffff);
  const insert = (type, data) => new Uint8Array(Buffer.concat([Buffer.from(valid.subarray(0, 33)), chunk(type, data), Buffer.from(valid.subarray(33))]));
  await prepare(bytes, { watermarkPng: insert("sBIT", Buffer.from([8,8,8,8])) });
  for (const png of [badCrc, excessiveDimensions, valid.subarray(0, valid.length - 12),
    insert("IHDR", Buffer.from(valid.subarray(16,29))), insert("acTL", Buffer.alloc(8)),
    insert("sBIT", Buffer.from([9,8,8,8])),
    new Uint8Array(Buffer.concat([Buffer.from(valid), Buffer.from("tail")])), watermark(256,256)]) {
    await rejected(bytes, "invalid_watermark", { watermarkPng: png });
  }
});

test("malformed envelopes are rejected without exposing PDF text in errors", async () => {
  const bytes = await fixture(), text = utf8(bytes);
  const altered = text.replace(/startxref\s+\d+/u, "startxref\n0");
  await rejected(new TextEncoder().encode(altered), "unsupported_pdf");
  await rejected(new Uint8Array(Buffer.concat([Buffer.from(bytes), Buffer.from("secret trailing data")])), "unsupported_pdf");
  await rejected(new TextEncoder().encode("%PDF-1.7\nprivate parser text\nstartxref\n9\n%%EOF"), "unsupported_pdf");
});

function rawNamedFixture(entry) {
  let text = "%PDF-1.7\n", offsets = [0];
  const objects = [
    `<< /Type /Catalog /Pages 2 0 R ${entry} >>`,
    "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
    "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << >> /Contents 4 0 R >>",
    "<< /Length 0 >>\nstream\n\nendstream",
  ];
  for (const [index, object] of objects.entries()) {
    offsets.push(text.length); text += `${index + 1} 0 obj\n${object}\nendobj\n`;
  }
  const startxref = text.length;
  text += "xref\n0 5\n0000000000 65535 f \n";
  for (const offset of offsets.slice(1)) text += `${String(offset).padStart(10,"0")} 00000 n \n`;
  text += `trailer\n<< /Size 5 /Root 1 0 R >>\nstartxref\n${startxref}\n%%EOF\n`;
  return new TextEncoder().encode(text);
}
test("ambiguous lowercase PDF name escapes cannot bypass checks when preserving the source", async () => {
  for (const entry of ["/#4aS (synthetic)", "/#4fpenAction << /S /#4aavaScript /JS (synthetic) >>", "/A << /S /#4aavaScript /#4aS (synthetic) >>"]) {
    const bytes = rawNamedFixture(entry);
    await rejected(bytes, "unsupported_pdf");
    await rejected(bytes, "unsupported_pdf", { watermarkEnabled:false });
  }
  await rejected(rawNamedFixture("/#4AS (synthetic)"), "unsafe_pdf", { watermarkEnabled:false });
});

test("asset preparation includes the pinned exact library and unchanged MIT license", async () => {
  const { pdfPreparationAssets: assets, pdfPreparationAssetMetadata: metadata } = await import("../src/pdf-preparation-assets.generated.js");
  assert.equal(metadata.version, "1.17.1"); assert.equal(Object.keys(assets).length, 4);
  const library = await readFile(new URL("../node_modules/pdf-lib/dist/pdf-lib.esm.min.js", import.meta.url));
  const license = await readFile(new URL("../node_modules/pdf-lib/LICENSE.md", import.meta.url));
  assert.equal(assets["/v1/admin/assets/pdf-lib.mjs"].data, library.toString());
  assert.equal(assets["/v1/admin/assets/pdf-lib-LICENSE.md"].data, license.toString());
  const helper = assets["/v1/admin/assets/pdf-preparation.mjs"].data;
  assert.match(helper, /from "\.\/pdf-lib\.mjs"/u); assert.doesNotMatch(helper, /from "pdf-lib"/u);
  for (const item of metadata.assets) assert.equal(item.sha256, hash(Buffer.from(assets[item.path].data)));
});
