const encoder = new TextEncoder();
const unsafe = /[\u0000-\u001f\u007f-\u009f\u061c\u200e\u200f\u2028\u2029\u202a-\u202e\u2066-\u2069\\/:*?"<>|]/u;

// Owner-supplied metadata only. It identifies the intended recipient of a copy,
// not the person using a shared password. Keep it inside the encrypted policy.
export function normalizeRecipientName(value) {
  if (typeof value !== "string" || !value.isWellFormed() || unsafe.test(value)) throw new Error("invalid_recipient");
  const name = value.normalize("NFC").trim();
  if (!name || encoder.encode(name).length > 180) throw new Error("invalid_recipient");
  return name;
}

export function downloadFilename(recipientName) {
  return `CV_${normalizeRecipientName(recipientName)}.pdf`;
}

export function recipientHeaders(policy) {
  if (!Object.hasOwn(policy, "recipientName")) return { "content-disposition": 'inline; filename="protected-document.pdf"' };
  const filename = downloadFilename(policy.recipientName);
  const encoded = encodeURIComponent(filename);
  const extended = encoded.replace(/[!'()*]/g, character => `%${character.charCodeAt(0).toString(16).toUpperCase()}`);
  return { "content-disposition": `inline; filename="protected-document.pdf"; filename*=UTF-8''${extended}`,
    "x-vault-download-filename": encoded };
}
