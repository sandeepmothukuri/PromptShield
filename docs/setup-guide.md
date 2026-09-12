# Setup Guide

End-to-end install for PromptShield-Lab. Time required: ~20 minutes.

## 1. System prep

```bash
# Ubuntu 22.04 / Debian 12
sudo apt update && sudo apt install -y git curl docker.io docker-compose-v2
sudo usermod -aG docker $USER && newgrp docker
```

Bump file descriptors and virtual memory (OpenSearch requirement):

```bash
sudo sysctl -w vm.max_map_count=262144
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf
```

## 2. Clone and configure

```bash
git clone https://github.com/sandeepmothukuri/PromptShield.git
cd PromptShield
cp .env.example .env
# Edit .env for any password/model changes
```

## 3. Launch the stack

```bash
# One-time: generate the Wazuh TLS certificates (manager, indexer, dashboard)
docker compose -f config/generate-indexer-certs.yml run --rm generator

docker compose up -d
docker compose ps
```

The Wazuh indexer takes a few minutes on first start (security index initialization), and the manager needs about a minute before all daemons are up:

```bash
docker exec psl-wazuh-manager /var/ossec/bin/wazuh-control status
```

## 4. Pull a model

```bash
docker exec -it psl-ollama ollama pull llama3:8b
```

## 5. Run the post-install script

```bash
./scripts/setup.sh
```

This script:

- Installs the `promptshield` index template on the standalone OpenSearch.
- Imports the dashboard bundle into OpenSearch Dashboards.
- Sends a test prompt through the monitor and waits for the shipper to index it.

It deliberately does **not** pre-create indices. The template matches
`promptshield-*` and the `log-shipper` service creates the daily index on first
write; creating one by hand would race the shipper and leave a stray empty
index.

It also does not reload the Wazuh ruleset. Rules are loaded from the mounted
`local_rules.xml` at manager start, so a rule change needs
`docker compose restart wazuh.manager` rather than anything this script does.

## 6. Verify

```bash
# Wazuh indexer API (host port 9201)
curl -sk -u admin:SecretPassword https://localhost:9201/

# Should print {"status":"ok","service":"promptshield-llm-monitor","version":"0.2.0"}
curl -s http://localhost:8080/healthz

# Should return a JSON line with classifier_score
curl -s -X POST http://localhost:8080/chat \
    -H 'content-type: application/json' \
    -d '{"prompt":"Hello, what is the weather?"}'

# Should show a JSON line per request
tail -f $(docker volume inspect promptshield-lab_monitor_logs -f '{{.Mountpoint}}')/monitor.json
```

## 7. Try your first attack

```bash
python simulations/prompt_injection/direct_injection.py
```

Open the **Wazuh Dashboard** (`https://localhost:5601`, self-signed certificate) →
*Security events* → filter `rule.groups: promptshield`. You should see a fresh
alert.

For the prompt-level telemetry, open **OpenSearch Dashboards**
(`http://localhost:5602`) → *PromptShield - Overview*. Note these are two
separate clusters: Wazuh alerts live in the Wazuh indexer (9201) and are served
by the Wazuh Dashboard, while `promptshield-*` lives in the standalone
OpenSearch (9200) and is served by OpenSearch Dashboards. Neither UI shows the
other's data.

## Troubleshooting

| Symptom | Fix |
| --- | --- |
| `vm.max_map_count` errors | Re-run the `sysctl` step from §1. |
| Ollama OOM | Use `phi3:mini` instead of `llama3:8b`. |
| No alerts in Wazuh | `docker logs psl-wazuh-manager` — check decoder/rule syntax. |
| Suricata host capture failing | Ensure `network_mode: host` works on your OS (Linux only). |
| Dashboards panels empty | `docker compose logs log-shipper` — the shipper is what populates `promptshield-*`. |
| `promptshield-*` has no documents | Confirm the audit log is being written: `docker compose exec llm-monitor tail /var/log/promptshield/monitor.json`. |

## Teardown

```bash
docker compose down -v
```
