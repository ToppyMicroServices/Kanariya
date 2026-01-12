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


def api_request(method, path, token, params=None, body=None):
    url = API_BASE + path
    if params:
        url += "?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(url, method=method)
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Content-Type", "application/json")
    if body is not None:
        req.data = json.dumps(body).encode("utf-8")
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


def record(result, key, status, detail):
    result[key] = {"status": status, "detail": detail}


def main():
    parser = argparse.ArgumentParser(description="Bootstrap Cloudflare resources for Kanariya.")
    parser.add_argument("--zone", default="toppymicros.com", help="Zone name")
    parser.add_argument("--hostname", default="kanariya.toppymicros.com", help="DNS hostname")
    parser.add_argument("--dry-run", action="store_true", help="Do not apply changes")
    args = parser.parse_args()

    token = os.getenv("CF_API_TOKEN")
    if not token:
        print("CF_API_TOKEN is not set.", file=sys.stderr)
        sys.exit(2)

    account_id = os.getenv("CF_ACCOUNT_ID", "")
    worker_name = os.getenv("CF_WORKER_NAME", "kanariya")
    kv_title = os.getenv("CF_KV_TITLE", "KANARI_KV")
    dns_type = os.getenv("CF_DNS_TYPE", "A")
    dns_target = os.getenv("CF_DNS_TARGET", "192.0.2.1")
    enable_admin_route = os.getenv("ENABLE_ADMIN_ROUTE", "").lower() in ("1", "true", "yes")

    result = {
        "zone": args.zone,
        "hostname": args.hostname,
        "dry_run": args.dry_run,
        "actions": {},
    }

    status, payload = api_request("GET", "/zones", token, params={"name": args.zone})
    if status != 200 or not payload.get("result"):
        record(result["actions"], "zone", "error", payload.get("errors") or "zone not found")
        print(json.dumps(result, indent=2))
        sys.exit(1)

    zone_id = payload["result"][0]["id"]
    record(result["actions"], "zone", "ok", {"zone_id": zone_id})

    if not account_id:
        status, payload = api_request("GET", "/accounts", token)
        if status == 200 and payload.get("result"):
            account_id = payload["result"][0]["id"]
            record(result["actions"], "account", "ok", {"account_id": account_id})
        else:
            record(
                result["actions"],
                "account",
                "error",
                payload.get("errors") or "account list failed",
            )
            print(json.dumps(result, indent=2))
            sys.exit(1)
    else:
        record(result["actions"], "account", "ok", {"account_id": account_id})

    # DNS record
    status, payload = api_request(
        "GET",
        f"/zones/{zone_id}/dns_records",
        token,
        params={"name": args.hostname, "type": dns_type},
    )
    if status == 200 and payload.get("result"):
        record(
            result["actions"],
            "dns_record",
            "exists",
            {"name": args.hostname, "type": dns_type},
        )
    elif args.dry_run:
        record(
            result["actions"],
            "dns_record",
            "dry_run",
            {"name": args.hostname, "type": dns_type, "content": dns_target},
        )
    else:
        body = {
            "type": dns_type,
            "name": args.hostname,
            "content": dns_target,
            "proxied": True,
        }
        status, payload = api_request(
            "POST", f"/zones/{zone_id}/dns_records", token, body=body
        )
        if status == 200 and payload.get("success"):
            record(result["actions"], "dns_record", "created", body)
        else:
            record(
                result["actions"],
                "dns_record",
                "error",
                payload.get("errors") or "create failed",
            )

    # KV namespace
    status, payload = api_request(
        "GET",
        f"/accounts/{account_id}/storage/kv/namespaces",
        token,
        params={"per_page": 100},
    )
    existing = None
    if status == 200 and payload.get("result"):
        for item in payload["result"]:
            if item.get("title") == kv_title:
                existing = item
                break

    if existing:
        record(result["actions"], "kv_namespace", "exists", existing)
    elif args.dry_run:
        record(result["actions"], "kv_namespace", "dry_run", {"title": kv_title})
    else:
        status, payload = api_request(
            "POST",
            f"/accounts/{account_id}/storage/kv/namespaces",
            token,
            body={"title": kv_title},
        )
        if status == 200 and payload.get("success"):
            record(result["actions"], "kv_namespace", "created", payload.get("result"))
        else:
            record(
                result["actions"],
                "kv_namespace",
                "error",
                payload.get("errors") or "create failed",
            )

    # Worker routes
    status, payload = api_request(
        "GET", f"/zones/{zone_id}/workers/routes", token, params={"per_page": 100}
    )
    routes = payload.get("result") if status == 200 else []
    desired = [f"{args.hostname}/canary/*"]
    if enable_admin_route:
        desired.append(f"{args.hostname}/admin/*")

    created = []
    existing_routes = []
    for pattern in desired:
        if any(r.get("pattern") == pattern for r in routes):
            existing_routes.append(pattern)
            continue
        if args.dry_run:
            created.append({"pattern": pattern, "script": worker_name, "dry_run": True})
            continue
        body = {"pattern": pattern, "script": worker_name}
        status, payload = api_request(
            "POST", f"/zones/{zone_id}/workers/routes", token, body=body
        )
        if status == 200 and payload.get("success"):
            created.append(body)
        else:
            created.append({"pattern": pattern, "error": payload.get("errors")})

    record(
        result["actions"],
        "worker_routes",
        "ok",
        {"existing": existing_routes, "created": created},
    )

    # WAF / rate limit placeholders
    record(
        result["actions"],
        "waf_rate_limit",
        "skipped",
        "Manual review recommended before enabling WAF/Rate Limit rules.",
    )

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
