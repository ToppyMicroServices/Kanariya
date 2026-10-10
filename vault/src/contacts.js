import { Denied } from './http.js';

export const MAX_RECIPIENT_CONTACTS = 50;
export const MAX_RECIPIENT_EMAIL_BYTES = 254;
export const MAX_RECIPIENT_REQUEST_BYTES = 16 * 1024;
const DIGEST = /^[0-9a-f]{64}$/;
const LOCAL = /^[A-Za-z0-9!#$%&'*+\/=?^_`{|}~-]+(?:\.[A-Za-z0-9!#$%&'*+\/=?^_`{|}~-]+)*$/;
const LABEL = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/;

// Contact metadata does not grant access or identify a shared-password reader.
// Keep local-part case intact; only DNS domain names are case-insensitive.
export function normalizeContactEmail(value) {
  if (typeof value !== 'string' || value.length > MAX_RECIPIENT_EMAIL_BYTES + 2 ||
      /[^\x20-\x7e]/.test(value)) throw new Denied(400, 'invalid_recipients');
  const email = value.trim(), separator = email.lastIndexOf('@');
  if (!email || email.length > MAX_RECIPIENT_EMAIL_BYTES || separator < 1 ||
      email.indexOf('@') !== separator) throw new Denied(400, 'invalid_recipients');
  const local = email.slice(0, separator), domain = email.slice(separator + 1);
  if (local.length > 64 || !LOCAL.test(local) || !domain || domain.length > 253 ||
      domain.split('.').some(label => !LABEL.test(label))) throw new Denied(400, 'invalid_recipients');
  return `${local}@${domain.toLowerCase()}`;
}

function contactEmails(value, stored = false) {
  if (!Array.isArray(value) || value.length > MAX_RECIPIENT_CONTACTS) throw new Denied(400, 'invalid_recipients');
  const emails = Array.from(value, normalizeContactEmail);
  if (new Set(emails).size !== emails.length || (stored && emails.some((email, index) => email !== value[index]))) {
    throw new Denied(400, 'invalid_recipients');
  }
  return emails;
}

export function readContacts(state, digest) {
  if (!state || typeof state !== 'object' || Array.isArray(state) || typeof digest !== 'string' || !DIGEST.test(digest)) throw new Error('invalid_journal');
  if (!Object.hasOwn(state, 'recipientContacts')) return { revision: 0, emails: [] };
  const contacts = state.recipientContacts;
  if (!contacts || typeof contacts !== 'object' || Array.isArray(contacts) ||
      Object.keys(contacts).length !== 3 || contacts.recordDigest !== digest ||
      !Number.isSafeInteger(contacts.revision) || contacts.revision < 1 ||
      !Object.hasOwn(contacts, 'recordDigest') || !Object.hasOwn(contacts, 'revision') || !Object.hasOwn(contacts, 'emails')) {
    throw new Error('invalid_journal');
  }
  try { return { revision: contacts.revision, emails: contactEmails(contacts.emails, true) }; }
  catch { throw new Error('invalid_journal'); }
}

export function setContacts(state, digest, input) {
  if (!input || typeof input !== 'object' || Array.isArray(input) || Object.keys(input).length !== 2 ||
      !Object.hasOwn(input, 'expectedRevision') || !Object.hasOwn(input, 'emails') ||
      !Number.isSafeInteger(input.expectedRevision) || input.expectedRevision < 0) throw new Denied(400, 'invalid_recipients');
  const emails = contactEmails(input.emails), current = readContacts(state, digest);
  if (input.expectedRevision !== current.revision) throw new Denied(409, 'recipients_changed');
  if (current.revision === Number.MAX_SAFE_INTEGER) throw new Error('invalid_journal');
  const revision = current.revision + 1;
  state.recipientContacts = { recordDigest: digest, revision, emails };
  return { revision, emails: [...emails] };
}
