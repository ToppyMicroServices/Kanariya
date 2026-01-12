#!/usr/bin/env bash
# Copyright 2026 ToppyMicroServices OÜ
# Licensed under the Apache License, Version 2.0. See LICENSE.
set -euo pipefail

BASE_URL="${BASE_URL:-https://kanariya.toppymicros.com}"
TOKEN="${TOKEN:-}"
SRC="${SRC:-smoke}"
ADMIN_KEY="${ADMIN_KEY:-}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ -z "${BASE_URL}" ]]; then
  echo "Usage: BASE_URL=https://kanariya.example.com TOKEN=... [ADMIN_KEY=...] $0"
  exit 1
fi

if [[ -z "${TOKEN}" ]]; then
  if ! TOKEN="$(python3 "${SCRIPT_DIR}/gen_token.py")"; then
    echo "Failed to generate token. Set TOKEN=... explicitly."
    exit 1
  fi
  echo "Generated TOKEN=${TOKEN}"
fi

CANARY_URL="${BASE_URL%/}/canary/${TOKEN}?src=${SRC}"
STATUS=$(curl -s -o /dev/null -w "%{http_code}" "${CANARY_URL}")
echo "GET ${CANARY_URL} -> ${STATUS}"

if [[ -n "${ADMIN_KEY}" ]]; then
  EXPORT_URL="${BASE_URL%/}/admin/export?token=${TOKEN}"
  echo "GET ${EXPORT_URL}"
  curl -s -H "Authorization: Bearer ${ADMIN_KEY}" "${EXPORT_URL}" | head -c 800
  echo ""
fi
