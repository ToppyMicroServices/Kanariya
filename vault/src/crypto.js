import { createPasswordVerifier, passwordVerifierValid } from "./password.js";
import { normalizeRecipientName } from "./recipient.js";

export const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
export const MAX_PDF_BYTES = 1024 * 1024;
export const MAX_RECORD_BYTES = 2 * MAX_PDF_BYTES;
const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });
export const utf8 = value => encoder.encode(value);

export function b64(bytes) {
  let value = "";
  for (let i = 0; i < bytes.length; i += 8192) value += String.fromCharCode(...bytes.subarray(i, i + 8192));
  return btoa(value);
}
export function unb64(value, max = MAX_RECORD_BYTES) {
  if (typeof value !== "string" || value.length > Math.ceil(max / 3) * 4 || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) throw new Error("invalid_encoding");
  const out = Uint8Array.from(atob(value), c => c.charCodeAt(0));
  if (out.length > max) throw new Error("oversized");
  return out;
}
export function newKey() { return b64(crypto.getRandomValues(new Uint8Array(32))); }
export async function importKey(value) {
  const raw = unb64(value, 32);
  if (raw.length !== 32) throw new Error("invalid_key");
  return crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]);
}
export async function seal(bytes, key, context) {
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  return { nonce: b64(nonce), ciphertext: b64(new Uint8Array(await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: nonce, additionalData: utf8(context), tagLength: 128 }, key, bytes))) };
}
export async function open(box, key, context) {
  if (!box || typeof box !== "object") throw new Error("invalid_box");
  const nonce = unb64(box.nonce, 12);
  if (nonce.length !== 12) throw new Error("invalid_nonce");
  return new Uint8Array(await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: nonce, additionalData: utf8(context), tagLength: 128 }, key, unb64(box.ciphertext)));
}
export const sealJSON = (value, key, context) => seal(utf8(JSON.stringify(value)), key, context);
export async function openJSON(box, key, context) { return JSON.parse(decoder.decode(await open(box, key, context))); }

export function validatePolicy(policy) {
  if (!policy || typeof policy !== "object" || Array.isArray(policy) || policy.mime !== "application/pdf" ||
      !Number.isSafeInteger(policy.size) || policy.size < 5 || policy.size > MAX_PDF_BYTES ||
      !Number.isSafeInteger(policy.expiresAt) || !Array.isArray(policy.subjects) || policy.subjects.length > 50 ||
      policy.subjects.some(s => typeof s !== "string" || s.length < 1 || s.length > 256) ||
      typeof policy.revoked !== "boolean" || Object.hasOwn(policy, "password")) throw new Error("invalid_policy");
  if (Object.hasOwn(policy, "recipientName")) {
    try { if (normalizeRecipientName(policy.recipientName) !== policy.recipientName) throw new Error(); }
    catch { throw new Error("invalid_policy"); }
  }
  const mode = Object.hasOwn(policy, "authMode") ? policy.authMode : "access";
  if (mode === "access") {
    if (!policy.subjects.length || Object.hasOwn(policy, "passwordVerifier")) throw new Error("invalid_policy");
  } else if (mode === "password") {
    if (policy.subjects.length || !passwordVerifierValid(policy.passwordVerifier)) throw new Error("invalid_policy");
  } else throw new Error("invalid_policy");
  return policy;
}
// Provisioning is an offline operation. This function is never a public upload API.
// Trusted callers supplying recipientName must provide the final watermarked PDF
// and complete their PDF checks. The seal-document CLI stamps before encryption.
export async function sealDocument(options, wrappingKey) {
  const { id, bytes, subjects, expiresAt } = options;
  if (!UUID.test(id) || !(bytes instanceof Uint8Array) || decoder.decode(bytes.subarray(0, 5)) !== "%PDF-") throw new Error("invalid_document");
  const authMode = Object.hasOwn(options, "authMode") ? options.authMode : "access";
  if (Object.hasOwn(options, "passwordVerifier") || (authMode !== "password" && Object.hasOwn(options, "password"))) throw new Error("invalid_policy");
  const policy = { mime: "application/pdf", size: bytes.length, subjects, expiresAt, revoked: false, authMode };
  if (Object.hasOwn(options, "recipientName")) policy.recipientName = normalizeRecipientName(options.recipientName);
  if (authMode === "password") {
    if (!Array.isArray(subjects) || subjects.length) throw new Error("invalid_policy");
    policy.passwordVerifier = createPasswordVerifier(options.password);
  }
  validatePolicy(policy);
  const raw = crypto.getRandomValues(new Uint8Array(32));
  try {
    const dek = await importKey(b64(raw));
    return { version: 2, id,
      policy: await sealJSON(policy, wrappingKey, `policy:v2:${id}`),
      wrappedKey: await seal(raw, wrappingKey, `key:v2:${id}`),
      document: await seal(bytes, dek, `document:v2:${id}`) };
  } finally { raw.fill(0); }
}
export async function readPolicy(record, id, wrappingKey) {
  if (record?.version !== 2 || record.id !== id) throw new Error("invalid_record");
  return validatePolicy(await openJSON(record.policy, wrappingKey, `policy:v2:${id}`));
}
export async function decryptDocument(record, wrappingKey, policy) {
  const raw = await open(record.wrappedKey, wrappingKey, `key:v2:${record.id}`);
  if (raw.length !== 32) throw new Error("invalid_key");
  const key = await importKey(b64(raw)); raw.fill(0);
  const bytes = await open(record.document, key, `document:v2:${record.id}`);
  if (bytes.length !== policy.size || decoder.decode(bytes.subarray(0, 5)) !== "%PDF-") throw new Error("invalid_pdf");
  return bytes;
}
export async function boundedBody(response, max) {
  if (Number(response.headers.get("content-length")) > max) throw new Error("oversized");
  if (!response.body) return new Uint8Array();
  const reader = response.body.getReader(); const chunks = []; let length = 0;
  try {
    while (true) {
      const { value, done } = await reader.read(); if (done) break;
      length += value.length;
      if (length > max) { await reader.cancel(); throw new Error("oversized"); }
      chunks.push(value);
    }
  } finally { reader.releaseLock(); }
  const bytes = new Uint8Array(length); let offset = 0;
  for (const c of chunks) { bytes.set(c, offset); offset += c.length; }
  return bytes;
}
export function parseJSON(bytes) { return JSON.parse(decoder.decode(bytes)); }
