#!/usr/bin/env python3
# Copyright 2026 ToppyMicroServices OÜ
# Licensed under the Apache License, Version 2.0. See LICENSE.
import argparse
import base64
import hashlib
import hmac
import ipaddress
import os
import re
import sys
import time
import urllib.parse


def to_base64_url(data):
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def generate_token(byte_len):
    return to_base64_url(os.urandom(byte_len))


def canonical_query(params):
    entries = [(k, v) for k, v in params if k != "sig"]
    entries.sort(key=lambda item: (item[0], item[1]))
    # Match encodeURIComponent in the Worker, including its unescaped punctuation.
    safe = "-_.!~*'()"
    return "&".join(
        f"{urllib.parse.quote(k, safe=safe)}={urllib.parse.quote(v, safe=safe)}"
        for k, v in entries
    )


def hmac_hex(secret, value):
    return hmac.new(secret.encode("utf-8"), value.encode("utf-8"), hashlib.sha256).hexdigest()


def derived_signing_key(master_secret, token):
    return hmac_hex(master_secret, f"token:{token}")


def parse_base_url(value):
    try:
        # Reject characters browsers may normalize differently from urlparse.
        if any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in value) or "\\" in value:
            raise ValueError
        parsed = urllib.parse.urlparse(value.rstrip("/"))
        host = parsed.hostname
        if not host or parsed.username is not None or parsed.password is not None:
            raise ValueError
        if parsed.scheme != "https" and not (
            parsed.scheme == "http" and host in {"localhost", "127.0.0.1", "::1"}
        ):
            raise ValueError
        # Accessing port validates both its syntax and its range.
        parsed.port
        authority = r"\[[^\]]+\](?::[0-9]+)?" if ":" in host else r"[^:]+(?::[0-9]+)?"
        if not re.fullmatch(authority, parsed.netloc) or "%" in host:
            raise ValueError
        if ":" in host:
            ipaddress.IPv6Address(host)
        else:
            ascii_host = host.encode("idna").decode("ascii").rstrip(".")
            if len(ascii_host) > 253 or not all(
                re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
                for label in ascii_host.split(".")
            ):
                raise ValueError
        return parsed
    except ValueError:
        raise SystemExit("Invalid base URL: use HTTPS, or HTTP on localhost, without credentials.") from None


def main():
    # Reject old secret options before argparse can include their values in errors.
    secret_options = ("--master-secret", "--secret")
    if any(
        option.startswith(flag.split("=", 1)[0])
        for flag in sys.argv[1:]
        if flag.startswith("--") and len(flag.split("=", 1)[0]) > 2
        for option in secret_options
    ):
        raise SystemExit(
            "Secret command-line arguments are not supported. "
            "Set MASTER_SECRET or SIGNING_SECRET in the environment."
        )

    class SafeArgumentParser(argparse.ArgumentParser):
        def error(self, message):
            # Malformed or unknown arguments can contain a mistakenly supplied secret.
            super().error("Invalid arguments. Use --help for supported options.")

    parser = SafeArgumentParser(
        description="Generate signed Kanariya URLs using MASTER_SECRET or SIGNING_SECRET from the environment.",
        allow_abbrev=False,
    )
    parser.add_argument("--base-url", default="https://kanariya.toppymicros.com/canary")
    parser.add_argument("--token", default="")
    parser.add_argument("--src", default="")
    parser.add_argument("--nonce", default="")
    parser.add_argument("--bytes", type=int, default=16)
    args = parser.parse_args()

    master_secret = os.getenv("MASTER_SECRET", "")
    secret = os.getenv("SIGNING_SECRET", "")
    if not master_secret and not secret:
        raise SystemExit(
            "Set MASTER_SECRET in the environment. "
            "Alternatively set the legacy SIGNING_SECRET."
        )

    parsed = parse_base_url(args.base_url)
    token = args.token or generate_token(max(8, args.bytes))
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
    if master_secret:
        per_token = derived_signing_key(master_secret, token)
        sig = hmac_hex(per_token, string_to_sign)
    else:
        sig = hmac_hex(secret, string_to_sign)

    signed_query = f"{query}&sig={sig}"
    url = urllib.parse.urlunparse(
        (parsed.scheme, parsed.netloc, path, "", signed_query, "")
    )
    print(url)


if __name__ == "__main__":
    main()
