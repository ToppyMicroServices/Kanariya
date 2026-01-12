#!/usr/bin/env bash
set -euo pipefail

WRANGLER_TOML="${WRANGLER_TOML:-wrangler.toml}"
KV_TITLE="${KV_TITLE:-KANARI_KV}"

echo "Deploying worker..."
wrangler deploy

if ! wrangler kv:namespace list --json > /tmp/kv_namespaces.json; then
  echo "Failed to list KV namespaces. Update ${WRANGLER_TOML} manually."
  exit 1
fi

if [[ "${AUTO_UPDATE_TOML:-}" != "1" ]]; then
  echo "KV namespaces (select the ID for ${KV_TITLE} and update ${WRANGLER_TOML}):"
  cat /tmp/kv_namespaces.json
  exit 0
fi

python3 - <<'PY'
import json
import os
import re

toml_path = os.environ.get("WRANGLER_TOML", "wrangler.toml")
kv_title = os.environ.get("KV_TITLE", "KANARI_KV")

with open("/tmp/kv_namespaces.json", "r", encoding="utf-8") as fh:
    data = json.load(fh)

kv_id = None
for item in data:
    if item.get("title") == kv_title:
        kv_id = item.get("id")
        break

if not kv_id:
    raise SystemExit(f"KV namespace {kv_title} not found.")

with open(toml_path, "r", encoding="utf-8") as fh:
    text = fh.read()

pattern = r'(binding\s*=\s*"KANARI_KV"\s*,\s*id\s*=\s*")[^"]*(")'
if not re.search(pattern, text):
    raise SystemExit("KANARI_KV binding not found in wrangler.toml.")

text = re.sub(pattern, rf'\1{kv_id}\2', text)
with open(toml_path, "w", encoding="utf-8") as fh:
    fh.write(text)

print(f"Updated {toml_path} with KV id {kv_id}")
PY
