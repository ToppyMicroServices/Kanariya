#!/usr/bin/env python3
# Copyright 2026 ToppyMicroServices OÜ
# Licensed under the Apache License, Version 2.0. See LICENSE.
import argparse
import base64
import os


def generate_token(byte_len):
    raw = os.urandom(byte_len)
    return base64.urlsafe_b64encode(raw).decode("utf-8").rstrip("=")


def main():
    parser = argparse.ArgumentParser(description="Generate URL-safe random tokens.")
    parser.add_argument(
        "--bytes", type=int, default=24, help="Random bytes per token (default: 24)"
    )
    parser.add_argument(
        "--count", type=int, default=1, help="How many tokens to generate"
    )
    args = parser.parse_args()

    for _ in range(max(1, args.count)):
        print(generate_token(max(8, args.bytes)))


if __name__ == "__main__":
    main()
