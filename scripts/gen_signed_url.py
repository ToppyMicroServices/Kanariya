#!/usr/bin/env python3
# Copyright 2026 ToppyMicroServices OÜ
# Licensed under the Apache License, Version 2.0. See LICENSE.
import argparse
import base64
import hashlib
import hmac
import os
import time
import urllib.parse


def to_base64_url(data):
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def generate_token(byte_len):
    return to_base64_url(os.urandom(byte_len))


def canonical_query(params):
    entries = [(k, v) for k, v in params if k != "sig"]
    entries.sort(key=lambda item: (item[0], item[1]))
    return "&".join(
        f"{urllib.parse.quote(k, safe='')}={urllib.parse.quote(v, safe='')}"
        for k, v in entries
    )


def hmac_hex(secret, value):
    return hmac.new(secret.encode("utf-8"), value.encode("utf-8"), hashlib.sha256).hexdigest()


def main():
    parser = argparse.ArgumentParser(description="Generate signed Kanariya URLs.")
    parser.add_argument("--base-url", default="https://kanariya.toppymicros.com/canary")
    parser.add_argument("--token", default="")
    parser.add_argument("--src", default="")
    parser.add_argument("--secret", default=os.getenv("SIGNING_SECRET", ""))
    parser.add_argument("--nonce", default="")
    parser.add_argument("--bytes", type=int, default=16)
    args = parser.parse_args()

    if not args.secret:
        raise SystemExit("SIGNING_SECRET is required (use --secret or env).")

    token = args.token or generate_token(max(8, args.bytes))
    base_url = args.base_url.rstrip("/")
    parsed = urllib.parse.urlparse(base_url)
    path = parsed.path.rstrip("/") + f"/{token}"

    ts = int(time.time())
    nonce = args.nonce or to_base64_url(os.urandom(8))

    params = [("ts", str(ts))]
    if args.src:
        params.append(("src", args.src))
    if nonce:
        params.append(("nonce", nonce))

    query = canonical_query(params)
    string_to_sign = f"{ts}|{path}|{query}"
    sig = hmac_hex(args.secret, string_to_sign)

    signed_query = f"{query}&sig={sig}"
    url = urllib.parse.urlunparse(
        (parsed.scheme, parsed.netloc, path, "", signed_query, "")
    )
    print(url)


if __name__ == "__main__":
    main()
