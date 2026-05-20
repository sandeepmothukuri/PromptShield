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
git clone https://github.com/sandeepmothukuri/PromptShield-Lab.git
cd PromptShield-Lab
cp .env.example .env
# Edit .env for any password/model changes
```

## 3. Launch the stack

```bash
docker compose up -d
docker compose ps
```

You should see ten healthy containers.

## 4. Pull a model

```bash
docker exec -it psl-ollama ollama pull llama3:8b
```

## 5. Run the post-install script

```bash
./scripts/setup.sh
```

This script:
- Creates the `promptshield-*` indices in OpenSearch.
- Imports the dashboards bundle.
- Triggers a Wazuh ruleset reload.
- Sends a synthetic test prompt to verify the full pipeline.

## 6. Verify

```bash
# Should print "ok"
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

Open the **Wazuh Dashboard** (`https://localhost:5601`) → *Security events* → filter `rule.groups: promptshield`. You should see a fresh alert.

## Troubleshooting

| Symptom | Fix |
| --- | --- |
| `vm.max_map_count` errors | Re-run the `sysctl` step from §1. |
| Ollama OOM | Use `phi3:mini` instead of `llama3:8b`. |
| No alerts in Wazuh | `docker logs psl-wazuh-manager` — check decoder/rule syntax. |
| Suricata host capture failing | Ensure `network_mode: host` works on your OS (Linux only). |

## Teardown

```bash
docker compose down -v
```
