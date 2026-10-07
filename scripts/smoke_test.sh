#!/usr/bin/env bash
# Copyright 2026 ToppyMicroServices OÜ
# Licensed under the Apache License, Version 2.0. See LICENSE.
set -euo pipefail

BASE_URL="${BASE_URL:-https://kanariya.toppymicros.com}"
TOKEN="${TOKEN:-}"
SRC="${SRC:-smoke}"
ADMIN_KEY="${ADMIN_KEY:-}"
SIGNING_SECRET="${SIGNING_SECRET:-}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ -z "${BASE_URL}" ]]; then
  echo "Usage: BASE_URL=https://kanariya.example.com TOKEN=... [ADMIN_KEY=...] $0"
  exit 1
fi

# Validate before sending either a token or an admin credential over the network.
BASE_URL="${BASE_URL}" python3 -B - "${SCRIPT_DIR}" <<'PY'
import os
import sys
sys.path.insert(0, sys.argv[1])
from gen_signed_url import parse_base_url
parse_base_url(os.environ["BASE_URL"])
PY

if [[ -z "${TOKEN}" ]]; then
  if ! TOKEN="$(python3 "${SCRIPT_DIR}/gen_token.py")"; then
    echo "Failed to generate token. Set TOKEN=... explicitly."
    exit 1
  fi
  echo "Generated TOKEN=${TOKEN}"
fi

if [[ -n "${SIGNING_SECRET}" ]]; then
  CANARY_URL="$(python3 "${SCRIPT_DIR}/gen_signed_url.py" \
    --base-url "${BASE_URL%/}/canary" \
    --token "${TOKEN}" \
    --src "${SRC}" \
    --secret "${SIGNING_SECRET}")"
else
  CANARY_URL="${BASE_URL%/}/canary/${TOKEN}?src=${SRC}"
fi
STATUS=$(curl -s -o /dev/null -w "%{http_code}" "${CANARY_URL}")
echo "GET ${CANARY_URL} -> ${STATUS}"

if [[ -n "${ADMIN_KEY}" ]]; then
  EXPORT_URL="${BASE_URL%/}/admin/export?token=${TOKEN}"
  echo "GET ${EXPORT_URL}"
  curl -s -H "Authorization: Bearer ${ADMIN_KEY}" "${EXPORT_URL}" | head -c 800
  echo ""
fi
