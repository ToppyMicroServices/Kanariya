#!/usr/bin/env python3
# Copyright 2026 ToppyMicroServices OÜ
# Licensed under the Apache License, Version 2.0. See LICENSE.
import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

API_BASE = "https://api.cloudflare.com/client/v4"


def api_request(method, path, token, params=None):
    url = API_BASE + path
    if params:
        url += "?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(url, method=method)
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            data = resp.read().decode("utf-8")
            return resp.status, json.loads(data)
    except urllib.error.HTTPError as err:
        body = err.read().decode("utf-8")
        try:
            payload = json.loads(body)
        except json.JSONDecodeError:
            payload = {"errors": [{"message": body or "HTTP error"}]}
        return err.code, payload
    except Exception as err:
        return 0, {"errors": [{"message": str(err)}]}


def record_check(checks, name, ok, status, detail, hint=None):
    entry = {"name": name, "ok": ok, "status": status, "detail": detail}
    if hint:
        entry["hint"] = hint
    checks.append(entry)


def main():
    parser = argparse.ArgumentParser(
        description="Check Cloudflare API token access for Kanariya."
    )
    parser.add_argument("--zone", default="toppymicros.com", help="Zone name")
    parser.add_argument("--account-id", default=os.getenv("CF_ACCOUNT_ID", ""))
    args = parser.parse_args()

    token = os.getenv("CF_API_TOKEN")
    if not token:
        print("CF_API_TOKEN is not set.", file=sys.stderr)
        sys.exit(2)

    checks = []

    status, payload = api_request("GET", "/user/tokens/verify", token)
    ok = status == 200 and payload.get("success")
    record_check(
        checks,
        "token_verify",
        ok,
        status,
        payload.get("errors") or payload.get("messages") or "ok",
    )

    zone_id = None
    status, payload = api_request("GET", "/zones", token, params={"name": args.zone})
    if status == 200 and payload.get("success") and payload.get("result"):
        zone_id = payload["result"][0]["id"]
        record_check(checks, "zone_read", True, status, f"zone_id={zone_id}")
    else:
        record_check(
            checks,
            "zone_read",
            False,
            status,
            payload.get("errors") or "zone not found",
            hint="Need Zone:Read",
        )

    account_id = args.account_id
    if not account_id:
        status, payload = api_request("GET", "/accounts", token)
        if status == 200 and payload.get("success") and payload.get("result"):
            account_id = payload["result"][0]["id"]
            record_check(
                checks, "account_read", True, status, f"account_id={account_id}"
            )
        else:
            record_check(
                checks,
                "account_read",
                False,
                status,
                payload.get("errors") or "account list failed",
                hint="Need Account:Read or pass --account-id",
            )

    if zone_id:
        status, payload = api_request(
            "GET", f"/zones/{zone_id}/dns_records", token, params={"per_page": 1}
        )
        record_check(
            checks,
            "dns_read",
            status == 200 and payload.get("success"),
            status,
            payload.get("errors") or "ok",
            hint="Need DNS:Read or DNS:Edit",
        )

        status, payload = api_request(
            "GET", f"/zones/{zone_id}/workers/routes", token, params={"per_page": 1}
        )
        record_check(
            checks,
            "workers_routes_read",
            status == 200 and payload.get("success"),
            status,
            payload.get("errors") or "ok",
            hint="Need Workers Routes:Read or Edit",
        )

        status, payload = api_request(
            "GET", f"/zones/{zone_id}/firewall/rules", token, params={"per_page": 1}
        )
        record_check(
            checks,
            "waf_rules_read",
            status == 200 and payload.get("success"),
            status,
            payload.get("errors") or "ok",
            hint="Need Zone WAF:Read or Edit (optional)",
        )

    if account_id:
        status, payload = api_request(
            "GET",
            f"/accounts/{account_id}/workers/scripts",
            token,
            params={"per_page": 1},
        )
        record_check(
            checks,
            "workers_scripts_read",
            status == 200 and payload.get("success"),
            status,
            payload.get("errors") or "ok",
            hint="Need Workers Scripts:Read or Edit",
        )

        status, payload = api_request(
            "GET",
            f"/accounts/{account_id}/storage/kv/namespaces",
            token,
            params={"per_page": 1},
        )
        record_check(
            checks,
            "kv_namespaces_read",
            status == 200 and payload.get("success"),
            status,
            payload.get("errors") or "ok",
            hint="Need Workers KV Storage:Read or Edit",
        )

    print(json.dumps({"zone": args.zone, "account_id": account_id, "checks": checks}, indent=2))

    if any(not c["ok"] for c in checks):
        sys.exit(1)


if __name__ == "__main__":
    main()
