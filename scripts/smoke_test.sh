#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-}"
TOKEN="${TOKEN:-}"
SRC="${SRC:-smoke}"
ADMIN_KEY="${ADMIN_KEY:-}"

if [[ -z "${BASE_URL}" || -z "${TOKEN}" ]]; then
  echo "Usage: BASE_URL=https://kanariya.example.com TOKEN=... [ADMIN_KEY=...] $0"
  exit 1
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
