# Architecture

PromptShield-Lab is an inline inspection lab, not a network-only one. Everything
runs in Docker on a single bridge network (`promptshield`), and the audit log is
the single artefact every downstream control consumes.

![Reference architecture](img/architecture.svg)

Diagram source: [`docs/diagrams/architecture.mmd`](diagrams/architecture.mmd).

## Design decision: inspect at the proxy

Network sensors cannot read LLM traffic in production because it is TLS. A
reverse proxy in front of the model runtime yields the cleartext prompt and
completion as a structured event, which is what detection engineering actually
needs. Wire-level detection is kept in the lab as a defence-in-depth layer for
plaintext deployments and for connection metadata, not as the primary control.

## Planes

### 1. LLM plane

| Component | Role | Port |
| --- | --- | --- |
| OpenWebUI | chat front-end | 3000 |
| **LLM-Monitor proxy** | classification, rate limiting, audit logging | 8080 |
| Ollama | local model runtime | 11434 |

The proxy sits between the front-end and the model runtime. Every request is
classified, optionally blocked, and logged as one JSON line. It is intentionally
stateless apart from the in-memory rate limiter, so it can be scaled
horizontally or removed without leaving the application broken.

Two guards run on the request path, and they are deliberately different
implementations:

- `classifier.py` — a weighted multi-indicator classifier. No ML model; ~200
  regex and string indicators grouped into 10 attack types, each with a weight,
  scored against a threshold. Deterministic, fast, and testable in CI without a
  model download.
- `langchain_guard.py` — a hand-rolled guardrail with the same interface a
  LangChain guard would expose. It is **not** wired into the request path; it
  exists so the same indicators can be applied in a LangChain pipeline.

### 2. Telemetry plane

The audit log is the contract. One JSON object per request, 27 documented
fields, written to `/var/log/promptshield/monitor.json`. The full field list,
semantics and the version history are in
[`docs/telemetry-schema.md`](telemetry-schema.md).

### 3. Detection plane

| Asset | Engine | Status |
| --- | --- | --- |
| `detections/wazuh/` | Wazuh rules 100100-100190 | active in the lab stack |
| `detections/sigma/` | 10 Sigma rules, pySigma-compatible | portable logic; CI-validated, not deployed to a SIEM here |
| `detections/suricata/` | 7 signatures | runs on Linux hosts; see [network-detection.md](network-detection.md) |
| `detections/zeek/` | `llm_telemetry.zeek` | runs on Linux hosts; same caveat |

### 4. Search plane

Wazuh indexer holds `wazuh-alerts-*` (host port 9201) and `promptshield-*`
(host port 9200). OpenSearch Dashboards on host port 5602 serves the imported bundle; the Wazuh Dashboard is separate, on host port 5601 over TLS.

### 5. Analyst plane

`hunting/` holds 11 queries; `playbooks/` holds 5 response playbooks and a
post-incident template.

## Data flow

```
simulations/, scripts/ingest_logs.py, OpenWebUI
                    │
                    ▼
        LLM-Monitor proxy :8080
        classifier.py ── verdict: allow | block
                    │
                    ├──► Ollama :11434 ──► completion
                    │
                    ▼
        monitor.json  (one JSON line per request)
                    │
        ┌───────────┴───────────┐
        ▼                       ▼
   Wazuh manager           promptshield-*
   rules 100100-100190     (LLM telemetry index)
        │                       │
        ▼                       │
   wazuh-alerts-*               │
        └───────────┬───────────┘
                    ▼
        OpenSearch Dashboards :5602
                    │
        ┌───────────┴───────────┐
        ▼                       ▼
   hunting/ queries        incident response
                               │
                               ▼
              new indicators, rules, fixtures
```

The loop at the bottom is the point. A finding that does not become an
indicator, a rule or a regression sample will be re-discovered next quarter.

## Detection pipeline

![Detection pipeline](img/detection-pipeline.svg)

Diagram source: [`docs/diagrams/detection-pipeline.mmd`](diagrams/detection-pipeline.mmd).

Field names are the contract between the proxy and its three consumers. Three
tests keep that contract from drifting:

| Test | Asserts |
| --- | --- |
| `llm-monitor/tests/test_proxy_telemetry.py` | the emitted record matches the documented schema, field for field |
| `tests/test_sigma_rules.py` | every Sigma rule fires on its corpus and on nothing benign |
| `tests/test_dashboards.py` | no dashboard panel references a field the proxy never emits |

## Attack to detection to response

![Attack to detection to response](img/attack-to-detection.svg)

Diagram source: [`docs/diagrams/attack-to-detection.mmd`](diagrams/attack-to-detection.mmd).

## Adding a model

Edit the `ollama` command in `docker-compose.yml` to pull a different model, and
set `OLLAMA_MODEL` in `.env`. The proxy passes `model` through from the client,
so the front-end can select any model the runtime has pulled. The `model` and
`provider` fields in the telemetry exist for exactly this reason.

## Adding a detection

There is **no** automated Sigma-to-Wazuh conversion in this repository. The
earlier revision of this page claimed CI converted Sigma rules to Wazuh rules on
merge; no such pipeline exists, and `sigma convert` cannot target Wazuh in the
first place (its backends are `lucene`, `eql`, `esql`, `elastalert`,
`opensearch_lucene`, `open_search_ppl`).

The supported path is:

1. Write the rule in `detections/sigma/` with full metadata.
2. Add corpus samples to `datasets/` so the rule is exercised.
3. Write the equivalent Wazuh rule in `detections/wazuh/local_rules.xml`.
4. Record the Wazuh rule ID in the Sigma rule's `metadata.wazuh_rule_id`.
5. `tests/test_attack_mappings.py` then asserts both name a common ATT&CK
   technique, so the pair cannot drift apart silently.

## Network detection limits

`detections/suricata/` and `detections/zeek/` run, but under
`network_mode: host` they see only traffic on the host interface. The
proxy-to-model leg stays on the Docker bridge, and on Docker Desktop the sensors
see nothing useful at all. Neither log ships to the index, so there are no
dashboard panels for them. Details and the supported fixes are in
[`docs/network-detection.md`](network-detection.md).
