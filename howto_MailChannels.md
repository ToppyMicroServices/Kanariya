# MailChannels email notifications

Kanariya sends text email through `https://api.mailchannels.net/tx/v1/send`, with `MAILCHANNELS_API_KEY` in the `X-Api-Key` header. Email uses the same durable outbox and delivery-status handling as webhook notifications. The adapter is implemented; a successful local test does not establish that your account or domain can deliver mail.

## Account and domain setup

The current MailChannels Email API requires an account, an API key with the `api` scope, and Domain Lockdown for the sending domain. Create the key in the MailChannels Console, then follow its account-specific instructions for the `_mailchannels.<sending-domain>` TXT record. That record must authorize your MailChannels account or sender; a bare `v=mc1` value is not a complete configuration. See [Authentication](https://docs.mailchannels.com/email-api/authentication) and [Domain Lockdown](https://docs.mailchannels.com/email-api/domain-lockdown).

Before a payment method is added, recipients are limited to verified Users in the MailChannels account. Check this condition for the intended test recipient; configuring Gmail as `MAIL_TO` does not create a sending credential. See the [current quickstart](https://docs.mailchannels.com/email-api/curl/quickstart).

Review MailChannels' current SPF, DKIM, and DMARC guidance for your sender domain. If updating SPF, merge the required authorization into the existing SPF record instead of creating a second one. Kanariya's current adapter does not provide DKIM signing fields. These DNS settings and the API key solve different parts of email authentication; DNS setup alone does not authenticate an API request.

## Worker configuration

Store the API key as a Worker secret:

```bash
npx wrangler@4 secret put MAILCHANNELS_API_KEY
```

Set the sender and recipients in the `[vars]` section of `wrangler.toml`, or in the matching deployment environment. Replace these example addresses with addresses for the verified sender domain and intended recipients:

```toml
MAIL_FROM = "alerts@example.com"
MAIL_TO = "operator@example.com,backup@example.com"
MAIL_FROM_NAME = "Kanariya"
MAIL_SUBJECT_PREFIX = "Kanariya alert"
```

`MAIL_FROM` and `MAIL_TO` are required for sending; `MAIL_TO` is a comma-separated list. The display name and subject prefix are optional and have the defaults shown above. Treat recipient configuration according to your repository's privacy needs; Cloudflare-managed values may be preferable to committing personal addresses. Keep the deployment configuration consistent with whichever location owns those settings.

The GitHub deployment workflow syncs a nonempty repository secret named `MAILCHANNELS_API_KEY` to Cloudflare. It does not configure `MAIL_FROM`, `MAIL_TO`, `MAIL_FROM_NAME`, or `MAIL_SUBJECT_PREFIX`. Leaving the GitHub secret empty does not remove an existing Worker secret.

For local work, put only synthetic credentials in `.dev.vars` unless you intend to contact the provider. A configured local email target sends real requests when a hit or admin test queues a delivery.

## Test and inspect delivery

After deploying the configured Worker, create a registered token in Token Studio and use **Send test notification**. This action sends real **TEST** messages, records a test event, and leaves the token's detection count unchanged. It can also be called with the authenticated API:

```text
POST /admin/tokens/<registered-token>/test
Authorization: Bearer <ADMIN_KEY>
```

The response contains an `eventId` and the initial delivery records. Inspect the token's event export after the alarm has run:

```text
GET /admin/export?token=<registered-token>
Authorization: Bearer <ADMIN_KEY>
```

For the delivery with `type: "email"`, `accepted` means the API returned HTTP 2xx. Check the recipient's mailbox and the provider's delivery information separately; API acceptance does not confirm inbox arrival. The subject and body distinguish **TEST** from **DETECTION**, and the body includes the stable event and delivery IDs.

## Failure handling

If either sender or recipient configuration is present, Kanariya creates an email delivery record. Missing sender, recipients, or API key causes `configuration_error` without an outbound request. Check the record's fixed error code and HTTP status; provider response bodies and raw exceptions are not saved.

Network errors, ten-second timeouts, HTTP `408`, `429`, and `5xx` are retried, with six total attempts by default. Other HTTP failures are terminal. A provider's `Retry-After` is honored up to 24 hours. See [Notifications in the README](README.md#notifications) for queue limits, backoff, and retention.

Changing `MAIL_FROM` or `MAIL_TO` stops old queued email deliveries with `configuration_changed`. Rotating only `MAILCHANNELS_API_KEY` preserves the destination identity, so pending retries can use the new key. A delivery already marked `failed` is not automatically restarted; fix the settings and create a new test event. Interrupted sends can be duplicated, so use the event and delivery IDs to recognize repeated notifications.
