# Kanariya

Kanariya records access to canary URLs placed in your documents, notes, or files and queues notifications to your chosen destinations. An access event shows that a URL was requested; it does not prove a data leak or identify the person responsible.

The current implementation provides registered tokens with expiry and revocation, a token inventory, a separate notification test, and durable delivery through generic webhooks, Slack, Discord, or MailChannels email. This README describes the repository implementation, not the state of a deployed service.

## Registered tokens

Create one token for each placement through Token Studio or `POST /admin/tokens`. Each token has a name, optional location and source label, and a URL containing `kr_` followed by 64 random hexadecimal characters (256 random bits).

- URLs remain reusable until expiry or revocation. The default expiry is 90 days after creation. Set `expiresAt` to a future ISO timestamp or `null` for no scheduled expiry.
- Name, location, and source come from the registry. A visitor cannot change the notification's placement labels by adding query parameters.
- Revocation is permanent and stops future public hits. It does not cancel notifications already queued. There is no restore, metadata-edit, expiry-extension, or delete endpoint; create a replacement token when needed.
- The inventory retains expired and revoked records, including their last-seen time and hit count. These records count toward the default limit of 1,000 tokens.

Registered URLs do not use the legacy timestamp signature or nonce. `REQUIRE_SIGNATURE` applies only to legacy URLs.

Use the separate **Send test notification** action to check a registered token's notification configuration. It records an event marked `test: true` and queues real test notifications, without accessing the planted URL or increasing its hit count. Tests are limited to one per token every ten seconds. An administrator can also test an expired or revoked token; this does not reactivate it.

## Storage and delivery

One SQLite-backed Durable Object holds an installation's registry, events, delivery outbox, and temporary rate-limit, deduplication, and nonce records. The binding is `KANARI_STORE`, the class is `KanariyaStore`, and the object name is `kanariya-v1`.

An accepted hit commits its event, token summary update, outbox entries, and alarm scheduling in a storage transaction. Provider requests run later, outside that transaction. Alarms process due deliveries and schedule recovery after interruptions. Cloudflare documents [at-least-once alarm execution](https://developers.cloudflare.com/durable-objects/api/alarms/); delivery can therefore be duplicated if a provider accepts a message before its result is saved.

```mermaid
flowchart LR
  Placement[Planted URL] --> Worker[Worker validates request]
  Studio[Authenticated Token Studio] --> Worker
  Worker --> Store[(SQLite Durable Object)]
  Store --> Alarm[Delivery and cleanup alarm]
  Alarm --> Provider[Webhook / Slack / Discord / email]
  Store --> Export[Private inventory and event export]
  Legacy[(Existing Workers KV)] --> Export
```

Events and their delivery records expire after 30 days by default. Export excludes expired SQLite events immediately; alarms remove expired events, delivery rows, and temporary guards, with cleanup scheduled at least hourly while records remain. Token summaries and revoked/expired inventory records persist independently of event retention. Hit counts describe accepted non-test requests, including repeats whose notifications were deduplicated; dropped requests do not increase them.

`KANARI_KV` is an optional compatibility binding for historical events and still-live legacy nonce records. New data is written to SQLite. Legacy export reads at most the first `EXPORT_MAX_ITEMS` matching KV keys, in batches of up to 100 values, and merges that subset with current events. The returned subset is sorted newest first and capped at 1,000 by default. If the response header `x-kanariya-legacy-truncated` is `true`, more old KV keys exist; the response does not represent the globally newest legacy history. Historical KV entries retain their existing KV expiration, and are not copied into SQLite.

## Local quick start

Use a current Node.js 22 release or newer with `node:sqlite`, plus Wrangler 4. The store tests use Node's SQLite support. Wrangler follows the supported Node.js release lifecycle; see its [installation requirements](https://developers.cloudflare.com/workers/wrangler/install-and-update/).

Install the repository's existing dependencies and run its tests:

```bash
npm ci
npm test
# With Wrangler 4 installed globally:
npm run test:runtime
```

The runtime check bundles locally with `--dry-run`, starts a temporary workerd instance, and intercepts all notification requests with local fixtures. It checks actual SQLite transactions and alarm retries without contacting providers. CI runs it before deployment; `npm run test:runtime -- --report <path>` also saves its result.

Create `.dev.vars` in the repository root. These values are synthetic and for local use only; there is no checked-in `.dev.vars.example`:

```bash
cat > .dev.vars <<'EOF'
ADMIN_KEY="local-only-admin-key-replace-for-production"
IP_HMAC_KEY="local-only-ip-hmac-key-replace-for-production"
MASTER_SECRET="local-only-legacy-signing-key"
EOF
```

Leave notification destinations unset for an offline local session. Configured destinations receive real requests, including when you use the test action. Webhook destinations must use HTTPS. Plaintext HTTP is allowed for local development only on `localhost`, `127.0.0.1` and `[::1]`.

Start the local Worker with Wrangler 4:

```bash
npx wrangler@4 dev --local
```

In a second terminal, create a registered token:

```bash
curl --fail-with-body http://127.0.0.1:8787/admin/tokens \
  -H 'Authorization: Bearer local-only-admin-key-replace-for-production' \
  -H 'Content-Type: application/json' \
  --data '{"name":"Local note","location":"Local test folder","src":"local-note"}'
```

The `201` response includes `token`, `url`, and `expiresAt`. Use the returned token for the test and export endpoints below. A test response with an empty `deliveries` array means no notification destinations are configured.

## Token Studio

Public API requests require HTTPS. The Worker rejects plaintext requests with `400 HTTPS required` before authentication, storage, signing or notifications, including preflight requests. It does not redirect or trust forwarded-protocol headers. The loopback development hosts above are the only HTTP exception; the signing CLI enforces the same restriction on its base URL. Start with an HTTPS URL: rejecting an HTTP request cannot undo its transmission over plaintext. This policy applies to requests that reach the Worker; deployment and any Cloudflare rules must be verified separately.

The static UI is in `public/index.html` and `docs/index.html`. It connects to a Worker API; it does not contain the Worker or its database. Set the API base URL and enter the Admin key before selecting **Connect and load**. The default base URL is `https://kanariya.toppymicros.com`; change it explicitly to `http://127.0.0.1:8787` for local work or to your own deployed API. The key stays in page memory and is cleared by disconnecting; it is not saved in browser storage.

The UI provides token creation, inventory, expiry and last-seen information, revocation, notification testing, and event/delivery inspection. Copy the registered URL or download the HTML beacon for a chosen placement. Loading remote images may be blocked or prefetched by the application opening the file, so a file open does not always produce a request, and a request need not represent a human open.

For a local UI, serve the static files separately:

```bash
python3 -m http.server 8080 --directory public
```

Open `http://127.0.0.1:8080`, then connect to the local Worker. GitHub Pages can serve the `docs` directory; the API continues to run on Cloudflare Workers. Review `docs/CNAME` before publishing a fork.

## API

After the transport check, all `/admin/*` operations require `Authorization: Bearer <ADMIN_KEY>`. A missing server key or missing/incorrect bearer token returns `403`. The previous `ALLOW_PUBLIC_EXPORT` and `ALLOW_PUBLIC_SIGN` settings are ignored. CORS preflight `OPTIONS` requests expose no administrative data and do not require the key.

| Method and path | Request | Successful response |
| --- | --- | --- |
| `POST /admin/tokens` | JSON: required `name`; optional `location`, `src`, `expiresAt` | `201`, one token record |
| `GET /admin/tokens` | No body | `200`, `{ "tokens": [...], "notifications": [...] }` |
| `POST /admin/tokens/<token>/revoke` | No body | `200`, token record with `state: "revoked"` |
| `POST /admin/tokens/<token>/test` | No body | `200`, `{ "eventId": "...", "test": true, "deliveries": [...] }` |
| `GET /admin/export?token=<token>` | One token ID | `200`, event array; returned subset sorted newest first |
| `GET /admin/sign?token=<legacy-token>&src=<source>` | Legacy token, optional `src` and `nonce` | `200`, signed `url`, `token`, Unix-seconds `ts`, and `nonce` |
| `GET /canary/<token>` | Registered URL, or legacy URL and its query | `204`, no body |

Token creation accepts a nonblank name of at most 120 characters, location up to 240, and source up to 512. Its JSON body is limited to 8 KiB. Omit `expiresAt` for 90 days; use `null` for no scheduled expiry. Invalid creation data returns `400`; a full inventory returns `409`.

Token records contain `token`, `name`, `location`, `src`, `createdAt`, `expiresAt`, `revokedAt`, `lastSeenAt`, `hitCount`, `lastTestAt`, `state`, and `url`. Nullable times are `null`; other times are ISO strings. State is `active`, `expired`, or `revoked`.

Revoke and test return `404` for an unknown registered token. Tests inside the ten-second interval return `429`. Unsupported methods return `405`; storage configuration or access failures on admin operations return `503`. Duplicate query parameters are rejected.

After the transport check, the public canary endpoint deliberately returns `204` for accepted hits as well as invalid, expired, revoked, rate-limited, replayed, or otherwise dropped hits. **A `204` does not confirm storage or notification delivery.** Check the authenticated export. Only `GET` records a hit.

Current events contain `id`, `ts`, `token`, `test`, `src`, `ipHash`, `country`, `asn`, `ua`, and `referer`; registered-token events also contain `name` and `location`. Export adds `deliveries`, with each delivery's `id`, `type`, `state`, `attempts`, `httpStatus`, `error`, `nextAttemptAt`, and `updatedAt`. Historical KV events can lack newer fields.

## Notifications

Configure any combination of these destinations:

| Setting | Delivery format |
| --- | --- |
| `WEBHOOK_URL` | JSON `{ "kind": "kanariya.canary", "event": { ... }, "deliveryId": "..." }` |
| `SLACK_WEBHOOK_URL` | Native Slack incoming webhook with plain-text blocks and a short notification fallback |
| `DISCORD_WEBHOOK_URL` | Native Discord webhook with `wait=true`, content limited to 2,000 characters, and mentions disabled |
| `MAIL_FROM`, `MAIL_TO`, `MAILCHANNELS_API_KEY` | MailChannels text email; `MAIL_TO` is comma-separated |

Slack and Discord use their own payloads; no separate relay adapter is needed. The adapters follow [Slack's text-formatting rules](https://docs.slack.dev/messaging/formatting-message-text/) and [Discord's webhook API](https://discord.com/developers/docs/resources/webhook#execute-webhook). Chat and email text distinguish **TEST** from **DETECTION**; the generic webhook exposes `event.test`. All formats include stable event and delivery IDs. See [the MailChannels guide](howto_MailChannels.md) for email authentication and domain setup.

Public hits notify once per `(token, ipHash, ua)` within the default 30-minute deduplication interval. Repeated accepted hits still create events. Deduplication requires both an IP hash and a User-Agent; admin tests bypass it.

Each configured destination gets its own delivery status:

- `pending`: saved for a first attempt.
- `retrying`: an attempt is in progress or another is scheduled.
- `accepted`: the destination returned an HTTP 2xx response.
- `failed`: a terminal error, exhausted attempts, expired event, or full queue.

The default maximum is six attempts total. Network failures, ten-second timeouts, HTTP `408`, `429`, and `5xx` are retried. The backoff starts at 30 seconds and doubles, capped at one hour; a provider's `Retry-After` can extend it up to 24 hours. Other HTTP errors fail without retry. The queue holds at most 10,000 pending/retrying destination deliveries by default; overflow is recorded as `queue_full` while the event is retained.

Delivery uses at-least-once semantics within these attempt and retention limits. Receivers may use `deliveryId` to recognize duplicates. `accepted` confirms only provider HTTP acceptance, not inbox arrival or that anyone read a message. Inspect the destination when testing.

Only a fingerprint of each destination is stored in the outbox. Removing or changing a destination stops its queued deliveries with `configuration_changed`, preventing old events from being sent to a new recipient. Rotating only the MailChannels API key keeps the same email destination identity. Incomplete email settings produce `configuration_error`. Provider response bodies and raw exception text are not retained. HTTPS is required, URL userinfo is rejected, and redirects are not followed.

## Configuration

Keep production credentials in Cloudflare Worker secrets. `.dev.vars` is ignored by Git and is for local development. Do not put webhook URLs or API keys in `wrangler.toml`.

| Secret | Purpose |
| --- | --- |
| `ADMIN_KEY` | Required for token management, testing, signing, and export |
| `IP_HMAC_KEY` | HMAC key for IP pseudonyms; without it, no raw IP is stored and `ipHash` is empty |
| `WEBHOOK_URL`, `SLACK_WEBHOOK_URL`, `DISCORD_WEBHOOK_URL` | Optional HTTPS notification destinations |
| `MAILCHANNELS_API_KEY` | Required when email is configured; sent as `X-Api-Key` |
| `MASTER_SECRET` | Legacy per-token signing master key; not needed for registered URLs |
| `SIGNING_SECRET` | Legacy signing key and fallback master when `MASTER_SECRET` is absent |

Configure these non-secret values in `[vars]` in `wrangler.toml`, or the matching deployment environment. Numeric store settings are rounded down and clamped to the documented range; invalid nonnumeric values use the fallback.

| Setting | Code default | Range or behavior |
| --- | --- | --- |
| `TOKEN_MAX_ITEMS` | `1000` | `1`–`10000`; includes retained expired/revoked records |
| `EVENT_TTL_SECONDS` | `2592000` | `60`–`31536000`; event and delivery retention |
| `DEDUPE_TTL_SECONDS` | `1800` | `1`–`86400` |
| `EXPORT_MAX_ITEMS` | `1000` | `1`–`1000`; per-token merged export limit |
| `RATE_LIMIT_WINDOW_SECONDS` | `60` | `0`–`86400`; `0` disables rate limiting |
| `RATE_LIMIT_MAX` | `60` | `0`–`100000`; `0` disables rate limiting |
| `NOTIFY_QUEUE_MAX` | `10000` | `1`–`100000`; pending/retrying deliveries |
| `NOTIFY_MAX_ATTEMPTS` | `6` | `1`–`10`; includes first attempt |
| `NOTIFY_RETRY_BASE_SECONDS` | `30` | `1`–`3600` |
| `REQUIRE_SIGNATURE` | Off if unset | Checked-in config sets `1`; applies only to legacy tokens |
| `SIGNATURE_WINDOW_SECONDS` | `300` | Checked-in config also sets `300`; a value `<= 0` disables the legacy timestamp window |
| `MAIL_FROM`, `MAIL_TO` | Unset | Sender and comma-separated recipients |
| `MAIL_FROM_NAME` | `Kanariya` | Email sender display name |
| `MAIL_SUBJECT_PREFIX` | `Kanariya alert` | Email subject prefix |

Rate limiting uses `(token, ipHash)` and a fixed time window. Requests without an IP hash share that token's empty-hash bucket. The ten-second admin-test interval, 90-day creation default, ten-second provider timeout, and 24-hour `Retry-After` ceiling are fixed in code.

## Deployment and migration

This update introduces a new SQLite-backed Durable Object. The checked-in `wrangler.toml` declares:

```toml
[[durable_objects.bindings]]
name = "KANARI_STORE"
class_name = "KanariyaStore"

[[migrations]]
tag = "v1-kanariya-store"
new_sqlite_classes = ["KanariyaStore"]
```

Before deploying, verify that the target Cloudflare account and deployment token can create/use the required Durable Object, and review current [Durable Objects pricing and limits](https://developers.cloudflare.com/durable-objects/platform/pricing/). SQLite Durable Objects are available on Free and Paid plans, with different allowances and failure/billing behavior. The repository's older [Cloudflare permission notes](docs/cloudflare_token_permissions.md) do not by themselves verify this new capability for your account.

The configuration uses Cloudflare's supported `migrations` flow; see [class lifecycle configuration](https://developers.cloudflare.com/durable-objects/reference/durable-objects-migrations/). Deploying this migration provisions the SQLite class namespace. It does not convert existing Workers KV data into SQLite. Keep the existing `KANARI_KV` binding if its historical exports and nonce compatibility are needed. A fresh installation can omit it.

For your own installation, update the Worker name, routes, zone, and any retained KV namespace ID. Configure both `/canary/*` and `/admin/*` routes on your API hostname, then set credentials through Cloudflare or Wrangler:

```bash
npx wrangler@4 secret put ADMIN_KEY
npx wrangler@4 secret put IP_HMAC_KEY
# Configure only the notification services you use:
npx wrangler@4 secret put SLACK_WEBHOOK_URL
npx wrangler@4 secret put DISCORD_WEBHOOK_URL
npx wrangler@4 secret put WEBHOOK_URL
npx wrangler@4 secret put MAILCHANNELS_API_KEY
```

When the target account, routes, configuration, and costs have been reviewed, deploy with `npx wrangler@4 deploy`. Verify the deployed service by creating a registered token, using its test action, inspecting export status, and checking the intended destination. Those are live checks and can send messages.

The GitHub Actions workflow deploys on pushes to `main` and manual dispatch. It uses repository secrets `CF_API_TOKEN` and `CF_ACCOUNT_ID` for deployment and syncs nonempty `ADMIN_KEY`, `IP_HMAC_KEY`, `WEBHOOK_URL`, `SLACK_WEBHOOK_URL`, `DISCORD_WEBHOOK_URL`, and `MAILCHANNELS_API_KEY` into Worker secrets. An unset optional GitHub secret does not delete an existing Worker secret. Configure `MAIL_FROM`, `MAIL_TO`, and other mail variables separately in the deployment configuration. Manage legacy signing secrets directly in Cloudflare; the workflow does not sync them.

### Existing planted URLs

Legacy tokens remain available with their existing signature and timestamp rules. With the checked-in settings, a signed URL has a 300-second timestamp window. A nonce is consumed by an accepted request and retained through the signature validity interval, including allowed future clock skew. When the timestamp window is disabled, nonce retention remains five minutes. The legacy signer and `scripts/gen_signed_url.py` remain for compatibility; they do not create registry records or long-lived registered URLs.

Token IDs must now be 1–512 URL-safe characters from `A–Z`, `a–z`, `0–9`, `_`, and `-`. Only IDs matching `^kr_[a-f0-9]{64}$` are treated as registered tokens. Other URL-safe IDs, including `kr_invoice`, remain legacy tokens. Extra path segments, percent-encoded aliases, and duplicate query parameters are rejected. Legacy URLs using those forms need replacement.

An old signed URL cannot be turned into a registered URL or given a new stored expiry. Create a registered token and replace the URL in each document or file. Keep existing signing secrets and signature settings while still supporting valid legacy placements. The old smoke-test script exercises a public hit, not the separate admin test action; use the new test endpoint for a notification check that must not increase a registered token's hit count.

## Privacy and limits

Kanariya stores an HMAC of the request IP when `IP_HMAC_KEY` is configured, plus country/ASN and bounded User-Agent and Referer strings. It does not store request bodies or the full request query. User-Agent, Referer, and placement labels can still contain sensitive information, and configured notification services receive the event metadata.

Use tokens only in systems and data you own or are authorized to monitor. Link scanners, previews, and email proxies can trigger requests. Files that are never opened, or clients that block remote resources, may produce no event. This is an HTTP access signal, not a high-interaction honeypot or proof of exfiltration.

One Durable Object serves the installation. Inventory and delivery limits bound parts of its workload; they are not a guarantee against all public-endpoint abuse. Rate limits, storage availability, and provider limits can cause dropped events or failed deliveries. Local unit tests do not establish production capacity, migration success, or live provider delivery.

## License

Apache License 2.0 (Apache-2.0). Copyright (c) 2026 ToppyMicroServices OÜ.

See `LICENSE` for the full text.
