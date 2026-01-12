# MailChannels DNS setup (Cloudflare + Workers)

This project uses the MailChannels HTTPS send API. To send mail successfully, your sender domain must be verified.

## Where each step happens

- DNS records: Cloudflare Dashboard -> your zone -> DNS
- Worker secrets/vars: Wrangler CLI or Cloudflare Dashboard -> Workers -> your Worker -> Variables
- CI updates (optional): GitHub -> Settings -> Secrets and variables -> Actions

## 1) Decide the sender domain

Choose the domain you will use in `MAIL_FROM`, e.g.

- `alerts@toppymicros.com`

All DNS records below must be set on that domain (or subdomain) in Cloudflare DNS.

## 2) SPF record

Add (or update) an SPF TXT record so it includes MailChannels:

- **Type**: TXT
- **Name**: `@` (root) or the specific subdomain
- **Value** (example):

```
v=spf1 include:spf.mailchannels.net -all
```

If you already have SPF, **merge** the include into your existing record (do not create multiple SPF records).

## 3) MailChannels domain verification (Domain Lockdown)

Add the MailChannels verification TXT record:

- **Type**: TXT
- **Name**: `_mailchannels`
- **Value**:

```
v=mc1
```

This allows MailChannels to send on behalf of your domain.

## 4) Wait for DNS propagation

It can take a few minutes for DNS changes to propagate.

## 5) Configure Worker variables

Set the sender/recipient variables on the Worker:

- `MAIL_FROM` (e.g. `alerts@toppymicros.com`)
- `MAIL_TO` (comma-separated list)
- optional: `MAIL_FROM_NAME`, `MAIL_SUBJECT_PREFIX`

Set them with Wrangler:

```bash
wrangler secret put MAIL_FROM
wrangler secret put MAIL_TO
wrangler secret put MAIL_FROM_NAME       # optional
wrangler secret put MAIL_SUBJECT_PREFIX  # optional
```

## 6) Test

Trigger a canary hit and verify delivery:

```bash
BASE_URL="https://kanariya.toppymicros.com" ./scripts/smoke_test.sh
```

## References

MailChannels documentation may update. If sending fails, verify the latest DNS requirements in their docs.

## Do I need a MailChannels account?

For the Cloudflare Workers send API (`https://api.mailchannels.net/tx/v1/send`),
no separate MailChannels account is required. DNS verification (SPF + `_mailchannels`)
is the key requirement. If you use MailChannels SMTP or marketing features, that
may require a separate account.
