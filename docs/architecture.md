# Architecture

PromptShield-Lab is split into four planes. Each runs in Docker and exchanges data over a single bridge network (`promptshield`).

## 1. LLM plane
- **Ollama** — local model runtime (Llama 3, Mistral, Phi-3).
- **OpenWebUI** — chat front-end.
- **LLM-Monitor proxy** — a Python FastAPI service that sits *between* OpenWebUI and Ollama. Every prompt and completion is:
  1. Classified by a lightweight transformer-based classifier (`classifier.py`).
  2. Filtered by LangChain guardrails (`langchain_guard.py`) — regex + LLM-based heuristics for jailbreak strings.
  3. Logged as one JSON line to `/var/log/promptshield/monitor.json`.

## 2. Detection plane
- **Suricata** sniffs the host interface and applies signatures in `detections/suricata/promptshield.rules`.
- **Zeek** parses HTTP/JSON traffic and emits a custom `llm.log` from `llm_telemetry.zeek`.
- **Wazuh manager** ingests the JSON audit log via `localfile` and decodes it with `detections/wazuh/decoders.xml`.

## 3. Storage / search plane
- **OpenSearch** stores Wazuh alerts, Suricata `eve.json`, Zeek logs.
- **OpenSearch Dashboards** hosts the PromptShield dashboards.

## 4. Adversary plane
- Python attack scripts under `simulations/`.
- Atomic Red Team tests in `simulations/atomic_red_team/`.

## Data flow

```
Attacker → OpenWebUI → llm-monitor (classify+guard+log) → Ollama
                              │
                              ├─→ /var/log/promptshield/monitor.json ──→ Wazuh
                              └─→ HTTP traffic ──→ Suricata + Zeek ──→ Wazuh
                                                                     │
                                                                     ▼
                                                                OpenSearch ──→ Dashboards
```

## Why a proxy?

Inspecting traffic on the wire alone is brittle — most LLM traffic is TLS-encrypted in production. A reverse proxy gives you the cleartext prompt + completion as a structured event, which is what detection engineering actually needs. This mirrors how mature enterprises front their LLMs (e.g., Lakera Guard, Cloudflare AI Gateway).

## Extensibility

Drop in a new model by editing `ollama` startup. Drop in a new detection by writing a Sigma rule — the CI pipeline converts it to a Wazuh rule on PR merge.
