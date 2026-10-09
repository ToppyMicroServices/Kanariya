import test from "node:test";
import assert from "node:assert/strict";
import { normalizeRecipientName, downloadFilename, recipientHeaders } from "../src/recipient.js";

test("recipient names are canonical and bound Japanese filenames within a safe byte limit", () => {
  assert.equal(normalizeRecipientName("  株式会社テスト 採用担当  "), "株式会社テスト 採用担当");
  assert.equal(normalizeRecipientName("Cafe\u0301"), "Café");
  assert.equal(normalizeRecipientName("界".repeat(60)), "界".repeat(60));
  assert.equal(downloadFilename("株式会社テスト 採用担当"), "CV_株式会社テスト 採用担当.pdf");
  for (const name of [undefined, null, 1, [], {}, "", "  ", "a".repeat(181), "界".repeat(61), "\ud800",
    "name\r\nX-Injected: yes", "../name", "name\\child", "name:file", "name*", "name?", 'name"', "<name>", "name|other",
    "name\u0000", "name\u0085", "name\u061c", "name\u200e", "name\u200f", "name\u202e", "name\u2066", "name\u2028", "name\u2029"]) {
    assert.throws(() => normalizeRecipientName(name), /invalid_recipient/);
  }
});

test("response headers encode Japanese and punctuation without raw Unicode or header syntax", () => {
  const recipientName = "日本支社 O'Connor (試験)!", filename = downloadFilename(recipientName);
  const headers = recipientHeaders({ recipientName });
  assert.equal(decodeURIComponent(headers["x-vault-download-filename"]), filename);
  const encoded = headers["content-disposition"].split("filename*=UTF-8''")[1];
  assert.equal(decodeURIComponent(encoded), filename);
  assert.doesNotMatch(encoded, /[^\x20-\x7e]|[!'()*]/);
  assert.doesNotThrow(() => new Response("", { headers }));
  assert.deepEqual(recipientHeaders({}), { "content-disposition": 'inline; filename="protected-document.pdf"' });
});
