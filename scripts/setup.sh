#!/usr/bin/env bash
# PromptShield-Lab — post-install setup.
# Creates indices, imports dashboards, sends a smoke-test prompt.
set -euo pipefail

OSE=${OSE:-http://localhost:9200}
OSD=${OSD:-http://localhost:5602}
MON=${MON:-http://localhost:8080}

echo "[+] Waiting for OpenSearch..."
until curl -s "$OSE" >/dev/null; do sleep 2; done

echo "[+] Creating indices..."
for idx in promptshield-2026 zeek-llm-2026 wazuh-alerts-2026; do
  curl -s -X PUT "$OSE/$idx" -H 'content-type: application/json' \
    -d '{"settings":{"number_of_shards":1,"number_of_replicas":0}}' >/dev/null
done

echo "[+] Importing dashboards..."
curl -s -X POST "$OSD/api/saved_objects/_import?overwrite=true" \
  -H 'osd-xsrf: true' \
  --form file=@dashboards/opensearch_dashboard.ndjson >/dev/null || \
  echo "    (dashboard import skipped — run manually if dashboards UI not yet ready)"

echo "[+] Smoke-test prompt..."
curl -s -X POST "$MON/chat" -H 'content-type: application/json' \
  -d '{"prompt":"Hello from setup.sh","user":"setup"}' | head -c 400
echo

echo "[+] Done. Open https://localhost:5601 (Wazuh) and http://localhost:5602 (OpenSearch)."
