import test from "node:test";
import assert from "node:assert/strict";
import { createHash, scryptSync } from "node:crypto";
import { passwordValid, passwordVerifierValid, createPasswordVerifier, verifyPassword, randomToken, hashToken,
  readSession, sessionCookie, SESSION_MS, ATTEMPT_WINDOW_MS, MAX_ATTEMPTS, MAX_SESSIONS } from "../src/password.js";
import { MAX_PDF_BYTES, newKey, importKey, sealDocument, readPolicy, decryptDocument, validatePolicy, sealJSON, utf8 } from "../src/crypto.js";

const password = "synthetic-password-only";
const verifier = { version: 1, kdf: "scrypt-16384-8-5", salt: "12".repeat(32),
  hash: scryptSync(password, Buffer.from("12".repeat(32), "hex"), 32, { N: 16384, r: 8, p: 5, maxmem: 32 * 1024 * 1024 }).toString("hex") };
const basePolicy = { mime: "application/pdf", size: 16, expiresAt: Date.now() + 60000, subjects: ["synthetic-subject"], revoked: false };

test("password bounds count UTF-8 bytes, including both exact limits", () => {
  for (const value of ["a".repeat(12), "a".repeat(256), "界".repeat(4), "é".repeat(128), "😀".repeat(64)]) assert.equal(passwordValid(value), true);
  for (const value of [undefined, null, 123, [], {}, "", "a".repeat(11), "a".repeat(257), "界".repeat(3), "é".repeat(129), "😀".repeat(65)]) {
    assert.equal(passwordValid(value), false);
    assert.throws(() => createPasswordVerifier(value), /invalid_password/);
    assert.equal(verifyPassword(value, verifier), false);
  }
});
test("password verifiers use fresh salts and fixed native scrypt parameters", () => {
  const first = createPasswordVerifier(password), second = createPasswordVerifier(password);
  assert.equal(passwordVerifierValid(first), true); assert.equal(passwordVerifierValid(second), true);
  assert.notEqual(first.salt, second.salt); assert.notEqual(first.hash, second.hash);
  assert.deepEqual(Object.keys(first).sort(), ["hash", "kdf", "salt", "version"]);
  assert.ok(!JSON.stringify(first).includes(password));
  assert.equal(first.hash, scryptSync(password, Buffer.from(first.salt, "hex"), 32,
    { N: 16384, r: 8, p: 5, maxmem: 32 * 1024 * 1024 }).toString("hex"));
  assert.equal(verifyPassword(password, first), true);
  assert.equal(verifyPassword(password, verifier), true);
  assert.equal(verifyPassword("synthetic-password-wrong", verifier), false);
  assert.equal(verifyPassword(`${password} `, verifier), false);
});
test("malformed and unsupported verifiers fail closed", () => {
  const invalid = [null, [], {}, { ...verifier, version: 2 }, { ...verifier, kdf: "scrypt-2-1-1" },
    { ...verifier, salt: "A".repeat(64) }, { ...verifier, salt: "1".repeat(63) }, { ...verifier, salt: 123 },
    { ...verifier, hash: "x".repeat(64) }, { ...verifier, hash: "1".repeat(66) }, { ...verifier, hash: null },
    { ...verifier, password }, { version: 1, kdf: verifier.kdf, salt: verifier.salt },
    Object.assign(Object.create(verifier), { one: 1, two: 2, three: 3, four: 4 })];
  for (const value of invalid) {
    assert.equal(passwordVerifierValid(value), false); assert.equal(verifyPassword(password, value), false);
  }
});
test("session tokens are random and only their SHA-256 hashes need persistence", async () => {
  const tokens = Array.from({ length: 100 }, randomToken);
  assert.equal(new Set(tokens).size, 100);
  for (const token of tokens) assert.match(token, /^[0-9a-f]{64}$/);
  const hash = await hashToken(tokens[0]);
  assert.equal(hash, createHash("sha256").update(tokens[0], "utf8").digest("hex"));
  assert.notEqual(hash, tokens[0]); assert.equal(await hashToken(tokens[0]), hash);
  for (const value of [undefined, null, 123, "", "a".repeat(63), "A".repeat(64), `${tokens[0]};`]) await assert.rejects(() => hashToken(value), /invalid_session/);
});
test("document session cookies have bounded lifetime and document-only secure scope", () => {
  const id = crypto.randomUUID(), token = randomToken();
  assert.equal(SESSION_MS, 300000); assert.equal(ATTEMPT_WINDOW_MS, 300000);
  assert.equal(MAX_ATTEMPTS, 10); assert.equal(MAX_SESSIONS, 32);
  assert.equal(sessionCookie(id, token, 300), `__Secure-vault-${id}=${token}; Path=/p/${id}/; Secure; HttpOnly; SameSite=Strict; Max-Age=300`);
  assert.equal(sessionCookie(id, "", 0), `__Secure-vault-${id}=; Path=/p/${id}/; Secure; HttpOnly; SameSite=Strict; Max-Age=0`);
  for (const age of [-1, 301, 0.5, NaN, Infinity, "300"]) assert.throws(() => sessionCookie(id, token, age), /invalid_session/);
  for (const value of [undefined, "", `${id}/../`, `${id}; injected=true`]) assert.throws(() => sessionCookie(value, token, 300), /invalid_session/);
  for (const value of [undefined, "", "A".repeat(64), `${token}; injected=true`]) assert.throws(() => sessionCookie(id, value, 300), /invalid_session/);
});
test("session parsing rejects duplicate, malformed and oversized cookies without decoding", () => {
  const id = crypto.randomUUID(), otherId = crypto.randomUUID(), token = "ab".repeat(32), name = `__Secure-vault-${id}`;
  const read = cookie => readSession(new Request("https://vault.example.test/", { headers: cookie === null ? {} : { cookie } }), id);
  assert.equal(read(`${name}=${token}`), token);
  assert.equal(read(`unrelated=x; ${name}=${token}; another=y`), token);
  for (const cookie of [null, "", `${name}=`, name, `${name}=${token}; ${name}=${token}`,
    `${name}=${token}; ${name}=bad`, `${name}=bad; ${name}=${token}`, `${name}=${token}; ${name}`,
    `${name}=${token}; ${name} =${token}`, `${name}="${token}"`, `${name}=${token.toUpperCase()}`,
    `${name}=%${token}`, `${name}=${token}extra`, `${name}=${token}, ${name}=${token}`,
    `__Secure-vault-${otherId}=${token}`, `padding=${"x".repeat(16384)}; ${name}=${token}`]) assert.equal(read(cookie), null);
  const suffix = `; ${name}=${token}`, padding = "x".repeat(16384 - suffix.length - "padding=".length);
  assert.equal(read(`padding=${padding}${suffix}`), token); assert.equal(read(`padding=${padding}x${suffix}`), null);
  assert.equal(readSession(new Request("https://vault.example.test/"), "invalid"), null);
});
test("policy validation preserves old Access mode and rejects mixed or unsupported modes", () => {
  assert.equal(validatePolicy(basePolicy), basePolicy);
  assert.equal(Object.hasOwn(validatePolicy(basePolicy), "authMode"), false);
  assert.equal(validatePolicy({ ...basePolicy, authMode: "access" }).authMode, "access");
  assert.equal(validatePolicy({ ...basePolicy, authMode: "password", subjects: [], passwordVerifier: verifier }).authMode, "password");
  for (const change of [{ authMode: null }, { authMode: undefined }, { authMode: "unknown" }, { authMode: "Access" },
    { subjects: [] }, { password }, { password: undefined }, { passwordVerifier: verifier }, { passwordVerifier: undefined },
    { authMode: "access", passwordVerifier: verifier }, { authMode: "password" },
    { authMode: "password", passwordVerifier: verifier }, { authMode: "password", subjects: [] },
    { authMode: "password", subjects: [], passwordVerifier: verifier, password },
    { authMode: "password", subjects: [], passwordVerifier: { ...verifier, version: 2 } },
    { size: MAX_PDF_BYTES + 1 }, { size: 4 }, { expiresAt: 1.5 }, { revoked: 0 },
    { subjects: Array(51).fill("s") }, { subjects: [""] }, { subjects: ["a".repeat(257)] }]) {
    assert.throws(() => validatePolicy({ ...basePolicy, ...change }), /invalid_policy/);
  }
  for (const value of [null, [], "access"]) assert.throws(() => validatePolicy(value), /invalid_policy/);
});
test("version-2 encryption supports both modes and never persists the raw password", async () => {
  const id = crypto.randomUUID(), key = await importKey(newKey()), bytes = utf8("%PDF-1.4\nSYNTHETIC-SECRET-BODY\n");
  const options = { id, bytes, subjects: ["synthetic-subject"], expiresAt: Date.now() + 60000 };
  const accessRecord = await sealDocument(options, key), accessPolicy = await readPolicy(accessRecord, id, key);
  assert.equal(accessRecord.version, 2); assert.equal(accessPolicy.authMode, "access");
  assert.equal(Object.hasOwn(accessPolicy, "passwordVerifier"), false);
  assert.deepEqual(await decryptDocument(accessRecord, key, accessPolicy), bytes);
  // A real historical v2 record had no authMode member in its sealed policy.
  delete accessPolicy.authMode;
  accessRecord.policy = await sealJSON(accessPolicy, key, `policy:v2:${id}`);
  const historical = await readPolicy(accessRecord, id, key);
  assert.equal(Object.hasOwn(historical, "authMode"), false);
  assert.deepEqual(await decryptDocument(accessRecord, key, historical), bytes);
  const record = await sealDocument({ ...options, authMode: "password", subjects: [], password }, key);
  const policy = await readPolicy(record, id, key), stored = JSON.stringify(record);
  assert.equal(record.version, 2); assert.equal(policy.authMode, "password"); assert.deepEqual(policy.subjects, []);
  assert.equal(verifyPassword(password, policy.passwordVerifier), true);
  assert.equal(Object.hasOwn(policy, "password"), false);
  for (const value of [password, policy.passwordVerifier.hash, policy.passwordVerifier.salt, "scrypt", "SYNTHETIC-SECRET-BODY"]) assert.ok(!stored.includes(value));
  assert.deepEqual(await decryptDocument(record, key, policy), bytes);
});
test("sealing rejects missing grants, externally supplied verifiers, mixed inputs and bad passwords", async () => {
  const options = { id: crypto.randomUUID(), bytes: utf8("%PDF-test"), subjects: ["synthetic-subject"], expiresAt: Date.now() + 60000 };
  const key = await importKey(newKey());
  for (const change of [{ subjects: [] }, { password }, { password: undefined }, { passwordVerifier: verifier },
    { authMode: "access", password }, { authMode: "unknown" }, { authMode: null }, { authMode: undefined },
    { authMode: "password", password }, { authMode: "password", subjects: [] },
    { authMode: "password", subjects: [], password: "too-short" },
    { authMode: "password", subjects: [], password: "a".repeat(257) },
    { authMode: "password", subjects: [], password, passwordVerifier: verifier }]) {
    await assert.rejects(() => sealDocument({ ...options, ...change }, key), /invalid_policy|invalid_password/);
  }
});
test("document sealing accepts the exact PDF size cap and rejects larger plaintext", async () => {
  const bytes = new Uint8Array(MAX_PDF_BYTES); bytes.set(utf8("%PDF-"));
  const options = { id: crypto.randomUUID(), bytes, subjects: ["synthetic-subject"], expiresAt: Date.now() + 60000 };
  const key = await importKey(newKey()), record = await sealDocument(options, key), policy = await readPolicy(record, options.id, key);
  assert.equal(policy.size, MAX_PDF_BYTES); assert.deepEqual(await decryptDocument(record, key, policy), bytes);
  const oversized = new Uint8Array(MAX_PDF_BYTES + 1); oversized.set(bytes);
  await assert.rejects(() => sealDocument({ ...options, bytes: oversized }, key), /invalid_policy/);
});
test("recipient metadata is canonical inside encrypted policy and absent in legacy records", async () => {
  const options = { id: crypto.randomUUID(), bytes: utf8("%PDF-already-watermarked-synthetic"), subjects: ["synthetic-subject"], expiresAt: Date.now() + 60000 };
  const key = await importKey(newKey()), recipientName = "株式会社テスト 採用担当";
  const record = await sealDocument({ ...options, recipientName: `  ${recipientName}  ` }, key);
  const policy = await readPolicy(record, options.id, key);
  assert.equal(policy.recipientName, recipientName);
  assert.ok(!JSON.stringify(record).includes(recipientName));
  assert.deepEqual(await decryptDocument(record, key, policy), options.bytes);
  assert.equal(Object.hasOwn(await readPolicy(await sealDocument(options, key), options.id, key), "recipientName"), false);
  for (const name of [null, "", "  ", "bad\r\nheader", "../other", "a".repeat(181), "界".repeat(61), "name\u202e", "\ud800"]) {
    await assert.rejects(() => sealDocument({ ...options, recipientName: name }, key), /invalid_recipient/);
    assert.throws(() => validatePolicy({ ...policy, recipientName: name }), /invalid_policy/);
  }
  for (const name of ["  padded  ", "Cafe\u0301"]) assert.throws(() => validatePolicy({ ...policy, recipientName: name }), /invalid_policy/);
});
