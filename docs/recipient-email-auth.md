# Recipient email authentication

Vault can require a recipient to authenticate by email before retrieving a PDF.
This is an opt-in document mode. Existing Access, password and bearer-link
documents retain their behavior; deploying this code does not change their
permissions or undo revocation.

## Authentication and records

The reader opens `/e/<document-id>`. A separate Cloudflare Access application
sends the login code. Vault verifies the signed application token, its issuer,
reader audience, subject, email and expiry, then checks the email against the
document's encrypted `allowedEmails` list on every PDF request. Unsigned email
headers, contact metadata, passwords and bearer links cannot authorize an email
document. Reader credentials cannot authorize owner routes.

The owner log records the verified email, account subject, time, document and
the requested purpose (`view` or `download`) with the existing decryption result.
The email and permission list are encrypted at rest. Only the owner log exposes
the recorded account; notification messages retain the existing event ID and
status without adding recipient addresses. Old events are not relabeled.

These records establish which authenticated email account requested the PDF.
They do not prove a particular person read it, that a download completed, or
that an account or downloaded copy was not shared. The viewer checks its
authorization every 15 seconds and clears its display on a failed check or
expiry. Revocation denies later retrieval, including existing authenticated
sessions; it cannot recall downloaded files.

## Cloudflare configuration before activation

Create a separate reader Access application for the chosen Vault hostname's
`/e/*` path, including `/e/assets/*`. Preserve the existing owner application
and its restrictions on `/v1/*` and the existing Access reader paths.

- Include only the explicitly approved recipient email addresses.
- Require the **One-time PIN** login method. Do not add a Bypass, Service Auth,
  or alternate Allow policy that skips this requirement.
- Set `READER_ACCESS_AUDIENCE` to this application's AUD. It must differ from
  the administrator's `ACCESS_AUDIENCE`. Both use the existing `ACCESS_ISSUER`.
- Enable `EMAIL_READER_ENABLED="1"` only after reviewing the effective policies
  and checking the dummy reader. Missing configuration denies access.
- Check that `/e/*` is not covered by an existing public-path bypass or a more
  specific conflicting Access application. Keep `workers.dev` and preview URLs
  disabled. Do not replace the existing deployment configuration with examples.

The application JWT contains a verified email but does **not** guarantee an
`amr` claim identifying OTP. The code therefore does not invent an `amr` check:
OTP enforcement is the dedicated Access application's responsibility. A valid
Access session can be reused; this does not require a fresh code for every
PDF request. The provider's policy and real OTP delivery must be checked before
calling the deployed service ready.

Official documentation:

- [Application token claims](https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/authorization-cookie/application-token/)
- [One-time PIN](https://developers.cloudflare.com/cloudflare-one/integrations/identity-providers/one-time-pin/)
- [Common Access policies](https://developers.cloudflare.com/cloudflare-one/access-controls/policies/common-policies/)

## Document preparation

The trusted `vault/scripts/seal-document.mjs` command accepts the existing
private stdin request with these document permission fields:

```json
{
  "authMode": "email",
  "subjects": [],
  "allowedEmails": ["reviewer@example.test"]
}
```

These are permission fields, not a complete provisioning request. Supply the
approved source, output path, wrapping key and deadline through the existing
private stdin workflow; do not put them into command arguments, Git or chat.
The command writes an encrypted record and reports only its ID and digest.
It does not upload, admit or publish the record. When stamping a recipient name,
complete the required final-PDF quality checks before admission.

The permission list permits 1–50 distinct addresses. Domain case is normalized;
local-part case is preserved. Wildcards and domain-wide grants are not accepted.
The list is sealed with the document. The owner console shows it read-only;
editing the separate contact list does not change access. The existing browser
registration flow remains owner-private and does not activate this mode.
Preparing a replacement for an email document preserves its exact permission
list and rejects conversion to a bearer link. The owner can review the list on
screen; the downloaded replacement review omits recipient names and emails,
and binds the prepared record through its ciphertext hash.
An owner may prepare a replacement after the original document expires, as
long as it has not been revoked. This leaves the expired document unavailable;
the replacement remains private until its own ID and hash are admitted.
Changing a sealed permission list requires a separately reviewed record and
admission change. Do not reuse the link-only rotation helper for this mode.

Use a new dummy document in an isolated environment for activation checks.
Do not replace the admitted production document, change its deadline or undo
an existing share's stop state while testing this feature.

## Verification

Run `npm test` from `vault/` for synthetic JWT, policy, route, audit and viewer
tests. The runtime verifier `vault/scripts/check-runtime.mjs` additionally checks
the built Worker in local workerd with synthetic R2 and Durable Objects. Its
outbound services are intercepted; these tests do not send real email or
validate Cloudflare's configured OTP policy.

After the specific recipient, reader application and environment are approved,
verify a real dummy flow: code receipt, allowed account retrieval, recorded
email and purpose, rejection of an unapproved account and direct unauthenticated
requests, inability to access owner APIs, expiry, revocation, and mobile display.
Keep local test success, provider configuration, OTP delivery and production
activation as separate results.
