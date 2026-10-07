import { randomBytes, scryptSync, timingSafeEqual } from "node:crypto";
import { Buffer } from "node:buffer";

export const SESSION_MS = 300000;
export const ATTEMPT_WINDOW_MS = 300000;
export const MAX_ATTEMPTS = 10;
export const MAX_SESSIONS = 32;
const HEX_32 = /^[0-9a-f]{64}$/;
const DOCUMENT_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SCRYPT = { N: 16384, r: 8, p: 5, maxmem: 32 * 1024 * 1024 };
const KDF = "scrypt-16384-8-5";

export function passwordValid(password) {
  if (typeof password !== "string" || password.length > 256) return false;
  const length = Buffer.byteLength(password, "utf8");
  return length >= 12 && length <= 256;
}
export function passwordVerifierValid(verifier) {
  return !!verifier && typeof verifier === "object" && !Array.isArray(verifier) &&
    Object.keys(verifier).length === 4 && ["version", "kdf", "salt", "hash"].every(name => Object.hasOwn(verifier, name)) &&
    verifier.version === 1 && verifier.kdf === KDF &&
    typeof verifier.salt === "string" && HEX_32.test(verifier.salt) &&
    typeof verifier.hash === "string" && HEX_32.test(verifier.hash);
}
function derive(password, salt) {
  const bytes = Buffer.from(password, "utf8");
  try { return scryptSync(bytes, Buffer.from(salt, "hex"), 32, SCRYPT); }
  finally { bytes.fill(0); }
}
export function createPasswordVerifier(password) {
  if (!passwordValid(password)) throw new Error("invalid_password");
  const salt = randomBytes(32).toString("hex"), hash = derive(password, salt);
  try { return { version: 1, kdf: KDF, salt, hash: hash.toString("hex") }; }
  finally { hash.fill(0); }
}
export function verifyPassword(password, verifier) {
  if (!passwordValid(password) || !passwordVerifierValid(verifier)) return false;
  const actual = derive(password, verifier.salt), expected = Buffer.from(verifier.hash, "hex");
  try { return timingSafeEqual(actual, expected); }
  finally { actual.fill(0); expected.fill(0); }
}
export function randomToken() { return randomBytes(32).toString("hex"); }
export async function hashToken(token) {
  if (typeof token !== "string" || !HEX_32.test(token)) throw new Error("invalid_session");
  return Buffer.from(await crypto.subtle.digest("SHA-256", Buffer.from(token, "utf8"))).toString("hex");
}
export function readSession(request, id) {
  if (typeof id !== "string" || !DOCUMENT_ID.test(id)) return null;
  const name = `__Secure-vault-${id}`, cookies = request.headers.get("cookie");
  if (!cookies || cookies.length > 16384) return null;
  let token = null, count = 0;
  for (const entry of cookies.split(";")) {
    const part = entry.trim(), separator = part.indexOf("=");
    const key = separator < 0 ? part : part.slice(0, separator).trim();
    if (key !== name) continue;
    count++;
    token = separator < 0 ? "" : part.slice(separator + 1);
  }
  // Refuse cookie tossing/ambiguity rather than selecting a first/last value.
  return count === 1 && HEX_32.test(token) ? token : null;
}
export function sessionCookie(id, token, maxAge) {
  if (typeof id !== "string" || !DOCUMENT_ID.test(id) || typeof token !== "string" ||
      !(HEX_32.test(token) || (token === "" && maxAge === 0)) || !Number.isSafeInteger(maxAge) ||
      maxAge < 0 || maxAge > SESSION_MS / 1000) throw new Error("invalid_session");
  return `__Secure-vault-${id}=${token}; Path=/p/${id}/; Secure; HttpOnly; SameSite=Strict; Max-Age=${maxAge}`;
}
