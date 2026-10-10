import {
  PDFDocument, PDFArray, PDFDict, PDFHexString, PDFInvalidObject, PDFName,
  PDFNumber, PDFRef, PDFStream, PDFString, degrees,
} from "pdf-lib";
import { normalizeRecipientName } from "./recipient.js";

export const PDF_PREPARATION_LIMITS = Object.freeze({
  bytes: 1024 * 1024, pages: 20, objects: 2000, nodes: 20000, depth: 64,
  pngBytes: 512 * 1024, pngPixels: 2 * 1024 * 1024,
});
const forbiddenKeys = new Set([
  "AcroForm", "OpenAction", "AA", "JS", "JavaScript", "EmbeddedFiles", "EF", "AF",
  "XFA", "RichMedia", "Launch", "SubmitForm", "ImportData", "ByteRange", "Perms",
]);
const forbiddenActions = new Set([
  "JavaScript", "Launch", "GoToR", "GoToE", "SubmitForm", "ImportData", "Rendition",
  "Sound", "Movie", "URL", "Hide", "SetOCGState", "Trans", "GoTo3DView", "Named", "Thread", "ResetForm",
]);
const forbiddenTypes = new Set(["Sig", "Filespec", "EmbeddedFile"]);
const forbiddenSubtypes = new Set(["Widget", "RichMedia", "Screen", "Movie", "Sound", "3D"]);
const errorCodes = new Set([
  "invalid_pdf_input", "pdf_too_large", "invalid_watermark", "invalid_recipient", "unsupported_pdf",
  "unsafe_pdf", "pdf_complexity_limit", "invalid_page_geometry", "watermark_does_not_fit",
]);
const fail = code => { throw new Error(code); };
function nameOf(value) {
  if (!(value instanceof PDFName)) return undefined;
  const name = value.decodeText();
  // pdf-lib 1.17.1 does not normalize lowercase hex name escapes consistently.
  // Do not pass an ambiguous name through unchanged in validation-only mode.
  if (/#[0-9a-f]{2}/iu.test(name)) fail("unsupported_pdf");
  return name;
}

function inputBytes(value, code) {
  if (value instanceof Uint8Array) return value;
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  fail(code);
}

function checkEnvelope(bytes) {
  if (!bytes.length) fail("invalid_pdf_input");
  if (bytes.length > PDF_PREPARATION_LIMITS.bytes) fail("pdf_too_large");
  const header = new TextDecoder("ascii").decode(bytes.subarray(0, 9));
  if (!/^%PDF-(?:1\.[0-7]|2\.0)[\r\n]/u.test(header)) fail("unsupported_pdf");
  const tail = new TextDecoder("ascii").decode(bytes.subarray(Math.max(0, bytes.length - 1024)));
  const trailer = /startxref\s+(\d+)\s+%%EOF[\x00\x09\x0a\x0c\x0d\x20]*$/u.exec(tail);
  if (!trailer) fail("unsupported_pdf");
  const offset = Number(trailer[1]);
  if (!Number.isSafeInteger(offset) || offset < 9 || offset >= bytes.length) fail("unsupported_pdf");
  const target = new TextDecoder("ascii").decode(bytes.subarray(offset, offset + 40));
  if (!/^xref\b/u.test(target) && !/^\d+\s+\d+\s+obj\b/u.test(target)) fail("unsupported_pdf");
}

function resolve(context, value) {
  const resolved = value instanceof PDFRef ? context.lookup(value) : value;
  if (value instanceof PDFRef && resolved === undefined) fail("unsupported_pdf");
  return resolved;
}

function get(context, dict, key) { return resolve(context, dict.get(PDFName.of(key))); }

function checkUri(value) {
  if (!(value instanceof PDFString || value instanceof PDFHexString)) fail("unsafe_pdf");
  const uri = value.decodeText();
  if (uri.length > 2048 || /[\s\u0000-\u001f\u007f-\u009f]/u.test(uri) || /%(?:0[0-9a-f]|1[0-9a-f]|7f)/iu.test(uri)) fail("unsafe_pdf");
  let url;
  try { url = new URL(uri); } catch { fail("unsafe_pdf"); }
  if (!(url.protocol === "https:" && url.hostname) && !(url.protocol === "mailto:" && url.pathname)) fail("unsafe_pdf");
}

function checkAction(context, value) {
  const action = resolve(context, value);
  if (!(action instanceof PDFDict) || action.has(PDFName.of("Next"))) fail("unsafe_pdf");
  const kind = nameOf(get(context, action, "S"));
  if (kind === "URI") checkUri(get(context, action, "URI"));
  else if (kind !== "GoTo" || get(context, action, "D") === undefined) fail("unsafe_pdf");
}

function checkObjects(document) {
  const context = document.context;
  const objects = context.enumerateIndirectObjects();
  if (objects.length > PDF_PREPARATION_LIMITS.objects) fail("pdf_complexity_limit");
  if (document.isEncrypted || context.trailerInfo.Encrypt) fail("unsafe_pdf");
  const seen = new Set();
  let nodes = 0;
  function walk(raw, depth) {
    if (++nodes > PDF_PREPARATION_LIMITS.nodes || depth > PDF_PREPARATION_LIMITS.depth) fail("pdf_complexity_limit");
    const value = resolve(context, raw);
    if (!value || seen.has(value)) return;
    seen.add(value);
    if (value instanceof PDFInvalidObject) fail("unsupported_pdf");
    if (value instanceof PDFName) { nameOf(value); return; }
    if (value instanceof PDFStream) { walk(value.dict, depth + 1); return; }
    if (value instanceof PDFArray) {
      for (let index = 0; index < value.size(); index++) walk(value.get(index), depth + 1);
      return;
    }
    if (!(value instanceof PDFDict)) return;
    const type = nameOf(get(context, value, "Type"));
    const subtype = nameOf(get(context, value, "Subtype"));
    const action = nameOf(get(context, value, "S"));
    if (forbiddenTypes.has(type) || forbiddenSubtypes.has(subtype) || forbiddenActions.has(action) || nameOf(get(context, value, "FT")) === "Sig") fail("unsafe_pdf");
    if (type === "Action" || action === "URI" || action === "GoTo") checkAction(context, value);
    const linkedAction = get(context, value, "A");
    if (linkedAction instanceof PDFDict && linkedAction.has(PDFName.of("S"))) checkAction(context, linkedAction);
    if (type === "Annot" || subtype === "Link") {
      if (subtype !== "Link") fail("unsafe_pdf");
      if (value.has(PDFName.of("A"))) checkAction(context, value.get(PDFName.of("A")));
      else if (!value.has(PDFName.of("Dest"))) fail("unsafe_pdf");
    }
    if (value.has(PDFName.of("UserUnit"))) {
      const unit = get(context, value, "UserUnit");
      if (!(unit instanceof PDFNumber) || unit.asNumber() !== 1) fail("invalid_page_geometry");
    }
    for (const [key, item] of value.entries()) {
      if (forbiddenKeys.has(nameOf(key))) fail("unsafe_pdf");
      walk(item, depth + 1);
    }
  }
  for (const [, value] of objects) walk(value, 0);
}

// Check the page/parent graph before calling pdf-lib's recursive page helpers.
function checkPageTree(document) {
  const context = document.context;
  const root = get(context, document.catalog, "Pages");
  const seen = new Set();
  let pages = 0;
  function visit(node, parent, depth) {
    if (!(node instanceof PDFDict) || seen.has(node) || depth > 20) fail("unsupported_pdf");
    seen.add(node);
    if (get(context, node, "Parent") !== parent) fail("unsupported_pdf");
    const type = nameOf(get(context, node, "Type"));
    if (type === "Page") {
      if (node.has(PDFName.of("Kids")) || ++pages > PDF_PREPARATION_LIMITS.pages) fail("pdf_complexity_limit");
      const annots = get(context, node, "Annots");
      if (annots !== undefined) {
        if (!(annots instanceof PDFArray)) fail("unsafe_pdf");
        for (let index = 0; index < annots.size(); index++) {
          const annotation = resolve(context, annots.get(index));
          if (!(annotation instanceof PDFDict) || nameOf(get(context, annotation, "Subtype")) !== "Link") fail("unsafe_pdf");
          if (annotation.has(PDFName.of("A"))) checkAction(context, annotation.get(PDFName.of("A")));
          else if (!annotation.has(PDFName.of("Dest"))) fail("unsafe_pdf");
        }
      }
      return 1;
    }
    if (type !== "Pages") fail("unsupported_pdf");
    const kids = get(context, node, "Kids"), count = get(context, node, "Count");
    if (!(kids instanceof PDFArray) || !(count instanceof PDFNumber)) fail("unsupported_pdf");
    if (kids.size() > PDF_PREPARATION_LIMITS.pages) fail("pdf_complexity_limit");
    const expected = count.asNumber();
    if (!Number.isInteger(expected) || expected < 1 || expected > PDF_PREPARATION_LIMITS.pages) fail("pdf_complexity_limit");
    let actual = 0;
    for (let index = 0; index < kids.size(); index++) actual += visit(resolve(context, kids.get(index)), node, depth + 1);
    if (actual !== expected) fail("unsupported_pdf");
    return actual;
  }
  visit(root, undefined, 0);
  if (!pages) fail("unsupported_pdf");
  return pages;
}

function pageGeometry(page) {
  const media = page.getMediaBox(), crop = page.getCropBox(), rotation = page.getRotation().angle;
  function valid(box) {
    return [box.x, box.y, box.width, box.height].every(Number.isFinite) &&
      box.width >= 36 && box.height >= 36 && box.width <= 20000 && box.height <= 20000 &&
      Math.abs(box.x) <= 20000 && Math.abs(box.y) <= 20000 &&
      Math.abs(box.x + box.width) <= 20000 && Math.abs(box.y + box.height) <= 20000;
  }
  if (!valid(media) || !valid(crop) || !Number.isInteger(rotation) || rotation % 90 !== 0 ||
      crop.x < media.x || crop.y < media.y || crop.x + crop.width > media.x + media.width || crop.y + crop.height > media.y + media.height) fail("invalid_page_geometry");
  return { crop, rotation: ((rotation % 360) + 360) % 360 };
}

function checkPng(bytes) {
  if (!bytes.length || bytes.length > PDF_PREPARATION_LIMITS.pngBytes) fail("invalid_watermark");
  const signature = [137, 80, 78, 71, 13, 10, 26, 10];
  if (bytes.length < 33 || signature.some((value, index) => bytes[index] !== value)) fail("invalid_watermark");
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  if (view.getUint32(8) !== 13 || new TextDecoder().decode(bytes.subarray(12, 16)) !== "IHDR") fail("invalid_watermark");
  const width = view.getUint32(16), height = view.getUint32(20);
  if (width < 256 || height < 32 || width > 4096 || height > 512 || width * height > PDF_PREPARATION_LIMITS.pngPixels ||
      width / height < 2 || width / height > 20 || bytes[24] !== 8 || bytes[25] !== 6 || bytes[26] !== 0 || bytes[27] !== 0 || bytes[28] !== 0) fail("invalid_watermark");
  // Canvas PNGs are static RGBA. Reject APNG/trailing data and malformed chunks.
  let offset = 8, idat = false, ended = false, chunks = 0;
  const allowedChunks = new Set(["IHDR", "IDAT", "IEND", "sRGB", "sBIT", "pHYs", "gAMA", "cHRM"]);
  while (offset + 12 <= bytes.length) {
    if (++chunks > 256) fail("invalid_watermark");
    const length = view.getUint32(offset), end = offset + length + 12;
    if (end > bytes.length) fail("invalid_watermark");
    const type = new TextDecoder().decode(bytes.subarray(offset + 4, offset + 8));
    if (!allowedChunks.has(type) || (type === "IHDR" && offset !== 8)) fail("invalid_watermark");
    const ancillaryLengths = { sRGB: 1, sBIT: 4, pHYs: 9, gAMA: 4, cHRM: 32 };
    if (Object.hasOwn(ancillaryLengths, type) && length !== ancillaryLengths[type]) fail("invalid_watermark");
    if (type === "sBIT" && Array.from(bytes.subarray(offset + 8, end - 4)).some(bit => bit < 1 || bit > 8)) fail("invalid_watermark");
    let crc = 0xffffffff;
    for (let index = offset + 4; index < end - 4; index++) {
      crc ^= bytes[index];
      for (let bit = 0; bit < 8; bit++) crc = (crc >>> 1) ^ (0xedb88320 & -(crc & 1));
    }
    if (((crc ^ 0xffffffff) >>> 0) !== view.getUint32(end - 4)) fail("invalid_watermark");
    if (type === "IDAT") idat = true;
    if (type === "IEND") {
      if (length !== 0 || end !== bytes.length) fail("invalid_watermark");
      ended = true; break;
    }
    offset = end;
  }
  if (!idat || !ended) fail("invalid_watermark");
  return { width, height };
}

async function sha256(bytes) {
  return Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)), value => value.toString(16).padStart(2, "0")).join("");
}

/**
 * Prepare a bounded static PDF in an owner browser worker or offline tooling.
 * The caller supplies a transparent PNG of the confirmed recipient name in
 * opaque 45% gray. PDF opacity is fixed at 20%; the image is page content, so it
 * remains when printed. This preserves existing text instead of rasterizing it.
 * It does not verify that the PNG spells the supplied name, or replace qpdf /
 * Ghostscript structural checks. Terminate the caller's worker on its timeout:
 * pdf-lib may decompress object streams before these post-parse limits apply.
 */
export async function preparePdf({ bytes, recipientName, watermarkEnabled, watermarkPng }) {
  try {
    const original = inputBytes(bytes, "invalid_pdf_input");
    checkEnvelope(original);
    const input = original.slice();
    if (typeof watermarkEnabled !== "boolean") fail("invalid_watermark");
    let png, pngSize;
    if (watermarkEnabled) {
      normalizeRecipientName(recipientName);
      const sourcePng = inputBytes(watermarkPng, "invalid_watermark");
      pngSize = checkPng(sourcePng);
      png = sourcePng.slice();
    }
    const document = await PDFDocument.load(input, { ignoreEncryption: false, throwOnInvalidObject: true, updateMetadata: false, parseSpeed: 50 });
    checkObjects(document);
    const count = checkPageTree(document), pages = document.getPages();
    if (pages.length !== count) fail("unsupported_pdf");
    const geometry = pages.map(pageGeometry);
    const sourceSha256 = await sha256(input);
    // Validation-only mode retains the exact source, including its hash.
    if (!watermarkEnabled) return { bytes: input.slice(), sourceSha256, finalSha256: sourceSha256, pages: count };
    const image = await document.embedPng(png);
    if (image.width !== pngSize.width || image.height !== pngSize.height) fail("invalid_watermark");
    for (let index = 0; index < pages.length; index++) {
      const { crop, rotation } = geometry[index];
      const angle = 35 + rotation, radians = angle * Math.PI / 180, cosine = Math.cos(radians), sine = Math.sin(radians);
      const spanWidth = Math.abs(cosine) * image.width + Math.abs(sine) * image.height;
      const spanHeight = Math.abs(sine) * image.width + Math.abs(cosine) * image.height;
      const scale = Math.min(crop.width * 0.8 / spanWidth, crop.height * 0.8 / spanHeight);
      const width = image.width * scale, height = image.height * scale;
      if (!Number.isFinite(scale) || height < 24) fail("watermark_does_not_fit");
      const centerX = crop.x + crop.width / 2, centerY = crop.y + crop.height / 2;
      pages[index].drawImage(image, {
        x: centerX - cosine * width / 2 + sine * height / 2,
        y: centerY - sine * width / 2 - cosine * height / 2,
        width, height, rotate: degrees(angle), opacity: 0.2,
      });
    }
    const output = await document.save({ useObjectStreams: false, addDefaultPage: false, updateFieldAppearances: false, objectsPerTick: 50 });
    if (output.length > PDF_PREPARATION_LIMITS.bytes) fail("pdf_too_large");
    checkEnvelope(output);
    return { bytes: output, sourceSha256, finalSha256: await sha256(output), pages: count };
  } catch (error) {
    // Do not surface parser diagnostics containing source-document data.
    throw new Error(errorCodes.has(error?.message) ? error.message : "unsupported_pdf");
  }
}
