<div align="center">

# 🛡️ PromptShield-Lab

### An Open-Source AI Security & SOC Detection Engineering Lab for the LLM Era

*Simulate. Detect. Respond. Defend the AI attack surface end-to-end.*

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Made with Python](https://img.shields.io/badge/Made%20with-Python%203.11-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker&logoColor=white)](https://docs.docker.com/compose/)
[![Wazuh](https://img.shields.io/badge/SIEM-Wazuh-005571?logo=elastic&logoColor=white)](https://wazuh.com/)
[![Suricata](https://img.shields.io/badge/IDS-Suricata-c8102e)](https://suricata.io/)
[![Zeek](https://img.shields.io/badge/NSM-Zeek-1f7a8c)](https://zeek.org/)
[![OpenSearch](https://img.shields.io/badge/Search-OpenSearch-005EB8?logo=opensearch&logoColor=white)](https://opensearch.org/)
[![Sigma](https://img.shields.io/badge/Detections-Sigma-8a2be2)](https://github.com/SigmaHQ/sigma)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red)](https://attack.mitre.org/)
[![OWASP LLM Top 10](https://img.shields.io/badge/OWASP-LLM%20Top%2010-000000)](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
[![CI](https://img.shields.io/badge/CI-passing-brightgreen)](.github/workflows/ci.yml)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)
[![Stars](https://img.shields.io/github/stars/sandeepmothukuri/PromptShield?style=social)](https://github.com/sandeepmothukuri/PromptShield)

<br/>

![PromptShield-Lab Architecture](docs/img/architecture.svg)

</div>

---

## 📖 Table of Contents

1. [Overview](#-overview)
2. [Why PromptShield-Lab](#-why-promptshield-lab)
3. [Architecture](#-architecture)
4. [Tech Stack](#-tech-stack)
5. [Quickstart](#-quickstart)
6. [Lab Scenarios](#-lab-scenarios)
7. [Detection Engineering](#-detection-engineering)
8. [MITRE ATT&CK Mapping](#-mitre-attck-mapping)
9. [SOC Playbooks](#-soc-playbooks)
10. [Threat Hunting](#-threat-hunting)
11. [Dashboards & Screenshots](#-dashboards--screenshots)
12. [Roadmap](#-roadmap)
13. [Contributing](#-contributing)
14. [License](#-license)

---

## 🔍 Overview

**PromptShield-Lab** is a free, open-source, fully self-hosted lab that lets blue teams, SOC analysts, detection engineers, and AI security researchers **simulate real-world attacks against LLM-powered applications** and **build production-grade detections** against them.

It glues together a local LLM stack (**Ollama + OpenWebUI + LangChain**), a full SOC stack (**Wazuh + Suricata + Zeek + OpenSearch**), and a curated library of **Sigma rules, playbooks, and threat-hunting queries** mapped to **MITRE ATT&CK** and **OWASP Top 10 for LLM Applications**.

Spin the entire lab up with one command:

```bash
docker compose up -d
```

> 🎯 **Mission:** make AI security detection engineering as approachable as classic SIEM work — and as rigorous.

---

## 💡 Why PromptShield-Lab

| Most AI security repos | PromptShield-Lab |
| --- | --- |
| Single Jupyter notebook | Full SOC stack + LLM stack in Docker |
| Theoretical attacks | Reproducible adversary simulations |
| No detections | Sigma rules, Suricata sigs, Zeek scripts, Wazuh rules |
| No response side | Analyst playbooks + IR workflows |
| Disconnected from frameworks | Mapped to MITRE ATT&CK + OWASP LLM Top 10 |
| Toy data | Realistic enterprise telemetry |

This repo is built to be a **portfolio-grade artifact** for analysts breaking into AI security, and a **reference implementation** for teams standing up LLM monitoring.

---

## 🏗️ Architecture

![Architecture](docs/img/architecture.svg)

See [`docs/architecture.md`](docs/architecture.md) for component-by-component detail and [`docs/diagrams/architecture.mmd`](docs/diagrams/architecture.mmd) for the Mermaid source.

### Live walkthrough

| | |
|---|---|
| ![OpenWebUI](docs/img/openwebui.svg) | **OpenWebUI** — chat with the local LLM. Every prompt is intercepted by the PromptShield proxy in line. |
| ![Wazuh](docs/img/wazuh-alert.svg) | **Wazuh** — alerts with full MITRE ATT&CK tagging and the offending prompt body. |
| ![Dashboard](docs/img/dashboard-overview.svg) | **OpenSearch Dashboards** — KPIs, injection patterns, jailbreak heatmap, ATT&CK coverage. |
| ![Suricata](docs/img/suricata.svg) | **Suricata** — wire-level signatures fire on injection / exfil traffic. |
| ![Zeek](docs/img/zeek.svg) | **Zeek** — custom `llm.log` flags suspicious requests with reason codes. |
| ![Simulation](docs/img/simulation-output.svg) | **Adversary simulation** — every scenario reports per-payload verdicts and produces alerts. |
| ![Sigma CI](docs/img/sigma-ci.svg) | **CI** — Sigma rules + Python + YAML are linted on every PR. |
| ![Hunting](docs/img/hunting-query.svg) | **Threat hunting** — DSL queries with hit tables, severity, and one-click playbook pivots. |

---

## 🧰 Tech Stack

| Layer | Tooling |
| --- | --- |
| **LLM runtime** | Ollama (Llama 3, Mistral, Phi-3), OpenWebUI |
| **Guardrails** | LangChain, custom Python prompt classifier |
| **Network detection** | Suricata, Zeek |
| **Host detection / SIEM** | Wazuh manager + agents |
| **Search & visualization** | OpenSearch + OpenSearch Dashboards |
| **Detection-as-Code** | Sigma, Atomic Red Team |
| **Orchestration** | Docker Compose |
| **CI/CD** | GitHub Actions (Sigma lint, YAML lint, Python tests) |

---

## 🚀 Quickstart

### Prerequisites
- Docker Engine 24+ and Docker Compose v2
- 16 GB RAM recommended (8 GB minimum)
- 30 GB free disk
- Linux, macOS, or Windows with WSL2

### One-shot install

```bash
git clone https://github.com/sandeepmothukuri/PromptShield.git
cd PromptShield-Lab
cp .env.example .env
docker compose up -d
./scripts/setup.sh
```

### Access the services

| Service | URL | Default creds |
| --- | --- | --- |
| OpenWebUI | http://localhost:3000 | create on first launch |
| Wazuh Dashboard | https://localhost:5601 | `admin / SecretPassword` |
| OpenSearch Dashboards | http://localhost:5602 | `admin / admin` |
| LLM-Monitor API | http://localhost:8080/healthz | — |

Full walkthrough: [`docs/setup-guide.md`](docs/setup-guide.md).

---

## 🧪 Lab Scenarios

Every scenario ships with **attack script → telemetry → detection → alert → playbook**.

| # | Scenario | OWASP LLM | MITRE ATT&CK |
| --- | --- | --- | --- |
| 1 | Direct prompt injection | LLM01 | T1059, T1204 |
| 2 | Indirect prompt injection via web content | LLM01 | T1566.002 |
| 3 | LLM jailbreak (DAN, role-play, encoding) | LLM01 | T1027 |
| 4 | Sensitive data exfiltration via LLM | LLM06 | T1041, T1567 |
| 5 | AI-generated phishing email campaigns | LLM09 | T1566.001 |
| 6 | Insecure output handling → XSS / SSRF | LLM02 | T1190 |
| 7 | Training-data / system-prompt leakage | LLM06 | T1552 |
| 8 | Model DoS via token-flooding | LLM04 | T1499 |
| 9 | Supply-chain attack on model weights | LLM05 | T1195.002 |
| 10 | Excessive agency / tool abuse | LLM08 | T1078 |

Run any scenario:

```bash
python simulations/prompt_injection/direct_injection.py --target http://localhost:8080/chat
```

---

## 🛰️ Detection Engineering

### Sigma rules (`detections/sigma/`)
- `prompt_injection_basic.yml`
- `llm_jailbreak_attempt.yml`
- `data_exfiltration_via_llm.yml`
- `ai_phishing_generation.yml`
- `malicious_prompt_patterns.yml`
- `system_prompt_leakage.yml`
- `llm_token_flood_dos.yml`

### Wazuh (`detections/wazuh/`)
Custom decoders parse the LLM-Monitor JSON audit log; local rules raise alerts at severity 5/10/12 with full MITRE tagging.

### Suricata (`detections/suricata/promptshield.rules`)
Signatures for known jailbreak strings on the wire, suspicious model-API exfil patterns, and AI-phishing C2.

### Zeek (`detections/zeek/llm_telemetry.zeek`)
Custom script that fingerprints LLM API traffic, extracts JSON prompts, and logs them to `llm.log`.

---

## 🎯 MITRE ATT&CK Mapping

Full mapping in [`docs/mitre-attack-mapping.md`](docs/mitre-attack-mapping.md). Highlights:

- **Initial Access** → T1566.001/002 (phishing via AI-generated content)
- **Execution** → T1059 (LLM-driven command generation)
- **Defense Evasion** → T1027 (encoded/obfuscated jailbreak payloads)
- **Credential Access** → T1552 (system-prompt leakage)
- **Exfiltration** → T1041, T1567 (data exfil through LLM responses)
- **Impact** → T1499 (token-flood DoS)

---

## 📘 SOC Playbooks

Production-style playbooks in [`playbooks/`](playbooks/):
- Prompt-injection incident response
- LLM data-leak triage
- AI-phishing campaign response
- Jailbreak/abuse-of-policy response

Each playbook includes: triage checklist · containment steps · evidence collection · stakeholder comms · postmortem template.

---

## 🔎 Threat Hunting

OpenSearch DSL and Lucene queries in [`hunting/opensearch_queries.md`](hunting/opensearch_queries.md), e.g.:

```json
{
  "query": {
    "bool": {
      "should": [
        { "match_phrase": { "prompt": "ignore previous instructions" }},
        { "match_phrase": { "prompt": "you are now DAN" }},
        { "match_phrase": { "prompt": "developer mode" }}
      ],
      "minimum_should_match": 1
    }
  }
}
```

---

## 📊 Dashboards & Screenshots

See [`docs/screenshots.md`](docs/screenshots.md) for the gallery. Importable OpenSearch saved objects in [`dashboards/opensearch_dashboard.ndjson`](dashboards/opensearch_dashboard.ndjson).

Built-in panels:
- Top prompt-injection patterns (24h)
- Jailbreak-attempt heatmap by user
- LLM token usage anomalies
- AI-phishing keyword trendline
- MITRE ATT&CK coverage matrix

---

## 🗺️ Roadmap

See [`ROADMAP.md`](ROADMAP.md). Headlines:
- ✅ v0.1 — Core stack, 7 Sigma rules, Wazuh/Suricata/Zeek detections, 10 scenarios
- 🚧 v0.2 — LLM-as-judge red-team agent, automated detection-as-code tests
- 🔭 v0.3 — Kubernetes deploy, Helm chart, multi-tenant LLM proxy
- 🔭 v0.4 — Integration with TheHive + Cortex + MISP
- 🔭 v1.0 — Cloud-deployable reference architecture (AWS, Azure, GCP)

---

## 🤝 Contributing

Contributions are welcome and encouraged! Start with [`CONTRIBUTING.md`](CONTRIBUTING.md) and our [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).

Good first issues: new Sigma rules, additional jailbreak samples, dashboard panels, translation of playbooks.

---

## 📄 License

Released under the [MIT License](LICENSE). Use it, fork it, ship it — credit appreciated, not required.

---

## ⭐ If this helped you, give it a star

> Built by SOC analysts, for SOC analysts who are tired of being told "AI security is different."
> It isn't. It's the same discipline — applied to a new attack surface.
