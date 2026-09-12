#!/usr/bin/env bash
# PromptShield-Lab post-install setup.
#
# Installs the index template, imports the dashboard bundle and sends a
# smoke-test prompt. It does NOT create indices by hand: the template matches
# `promptshield-*` and the log-shipper service creates the daily index on first
# write. Pre-creating a dated index here would race the shipper and leave a
# stray empty index behind.
#
# Topology this script targets (see docs/architecture.md):
#   standalone OpenSearch   host :9200   <- promptshield-*      <- log-shipper
#   OpenSearch Dashboards   host :5602   reads the above
#   Wazuh indexer           host :9201   <- wazuh-alerts-*      <- wazuh.manager
#   Wazuh Dashboard         host :5601 (TLS) reads the above
set -euo pipefail

OSE=${OSE:-http://localhost:9200}
OSD=${OSD:-http://localhost:5602}
MON=${MON:-http://localhost:8080}
TEMPLATE=${TEMPLATE:-config/opensearch/promptshield-template.json}

echo "[+] Waiting for OpenSearch at ${OSE}..."
for _ in $(seq 1 60); do
  curl -sf "${OSE}/_cluster/health" >/dev/null 2>&1 && break
  sleep 2
done
curl -sf "${OSE}/_cluster/health" >/dev/null || {
  echo "    OpenSearch did not become ready at ${OSE}" >&2
  exit 1
}

echo "[+] Installing the promptshield index template..."
# _meta_name is read by the shipper to name the template; strip it before PUT
# because OpenSearch rejects unknown top-level keys.
python3 - "$TEMPLATE" <<'PY' > /tmp/ps-template.json
import json, pathlib, sys
t = json.loads(pathlib.Path(sys.argv[1]).read_text())
t.pop("_meta_name", None)
print(json.dumps(t))
PY
curl -sf -X PUT "${OSE}/_index_template/promptshield" \
  -H 'content-type: application/json' \
  --data @/tmp/ps-template.json >/dev/null \
  && echo "    ok" || echo "    FAILED to install template" >&2

echo "[+] Importing dashboards into ${OSD}..."
curl -sf -X POST "${OSD}/api/saved_objects/_import?overwrite=true" \
  -H 'osd-xsrf: true' \
  --form file=@dashboards/opensearch_dashboard.ndjson >/dev/null \
  && echo "    ok" \
  || echo "    skipped — Dashboards not ready yet; re-run this script" >&2

echo "[+] Smoke-test prompt through the monitor..."
curl -s -X POST "${MON}/chat" -H 'content-type: application/json' \
  -d '{"prompt":"Hello from setup.sh","user":"setup"}' | head -c 400
echo

echo "[+] Waiting for the shipper to index that event..."
for _ in $(seq 1 30); do
  COUNT=$(curl -sf "${OSE}/promptshield-*/_count" 2>/dev/null \
    | python3 -c 'import json,sys; print(json.load(sys.stdin).get("count",0))' 2>/dev/null || echo 0)
  [ "${COUNT:-0}" -gt 0 ] && break
  sleep 2
done

if [ "${COUNT:-0}" -gt 0 ]; then
  echo "    promptshield-* has ${COUNT} document(s)"
else
  echo "    promptshield-* is still empty." >&2
  echo "    Check the shipper: docker compose logs log-shipper" >&2
fi

cat <<EOF

[+] Done.
    OpenSearch Dashboards  http://localhost:5602   (PromptShield telemetry)
    Wazuh Dashboard        https://localhost:5601  (Wazuh alerts; self-signed)
    Monitor API            ${MON}
EOF
