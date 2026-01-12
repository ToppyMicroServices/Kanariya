# Cloudflare API Token Permissions (Kanariya)

This project uses Cloudflare APIs for **DNS**, **Workers**, **KV**, and optional **WAF/Rate limit** rules.

## Recommended minimal permissions

Scope your token to the specific account + zone.

- Zone
  - Zone:Read
  - DNS:Edit
  - Workers Routes:Edit
  - Zone WAF:Edit (optional, for WAF/rate limit rules)
- Account
  - Workers Scripts:Edit
  - Workers KV Storage:Edit

Notes:

- If you only need read-only verification, use:
  - Zone:Read
  - DNS:Read
  - Workers Routes:Read
  - Workers Scripts:Read
  - Workers KV Storage:Read
- In the Cloudflare UI, "Workers Routes" appears under Zone permissions (not Account).
- Some endpoints require `Account:Read` to list accounts. If you already know the account ID, you can avoid it.

## Token strategy (recommended)

Split tokens by purpose and scope them to the target account and zone.

### A) Provision token (bootstrap scripts)

For `scripts/cf_bootstrap.py` and initial setup:

- Zone: Zone:Read, DNS:Edit, Workers Routes:Edit
- Account: Workers Scripts:Edit, Workers KV Storage:Edit, Account Settings:Read
- Optional (if you automate WAF/Rate Limit): Zone WAF:Edit

### B) Deploy token (CI / wrangler deploy)

For CI deploys:

- Account: Workers Scripts:Edit, Workers KV Storage:Edit, Account Settings:Read
- Zone: Workers Routes:Edit
- User scopes may be required in some accounts: User Details:Read, Memberships:Read

### C) Pages token (only if you manage Pages via API/CLI)

- Pages:Read or Pages:Edit (only if you manage Pages via API/CLI)

If you connect Pages to GitHub directly, you can skip a Pages API token.

## Architecture tip (Cloudflare only)

The shortest Cloudflare-only setup is:

- UI on Cloudflare Pages
- API on Cloudflare Workers (`/canary/*`)

This keeps a single domain and splits by path while staying entirely on Cloudflare.
