# LinkedIn — Project Description

Drafts for announcing this repository. Counts and component claims match what is
actually in the tree; if the lab changes, update this file in the same commit.

## Short (for the Projects section)

**PromptShield-Lab — AI Security and SOC Detection Engineering Lab**

An open-source lab that runs a local LLM stack behind an inspecting proxy, so
prompt injection, jailbreak, exfiltration and resource-exhaustion attempts
produce the same structured telemetry a SOC would see from any other host. Ten
Sigma rules, ten Wazuh rules and seven Suricata signatures, all mapped to MITRE
ATT&CK and the OWASP Top 10 for LLM Applications, with a dashboard, eleven
hunting queries and five response playbooks. Docker Compose orchestrated.

github.com/sandeepmothukuri/PromptShield

## Long (for a Featured post)

Sharing **PromptShield-Lab**, an open-source lab I built for AI-security
detection engineering.

**The problem it addresses**

Most AI-security material stops at "here is a prompt injection." That is the
attack, not the defence. A defender needs telemetry with stable field names,
detections that fire on that telemetry, alerts that carry enough context to
triage without re-querying, and a response path. PromptShield-Lab covers that
whole chain in one `docker compose up`.

**The design decision**

Rather than sniffing the network, an inspecting proxy sits between the chat
front-end and the model runtime. LLM traffic is TLS in production, so wire-level
detection cannot read the prompt. The proxy yields the cleartext prompt and
completion as one structured event per request, which is what detection
engineering actually consumes. Suricata and Zeek are included as a
defence-in-depth layer, with their limitations documented rather than hidden.

**What is in it**

- Local LLM stack: Ollama, OpenWebUI, and an inspecting proxy in Python/FastAPI
- A weighted multi-indicator classifier covering ten attack types, with
  de-obfuscation for base64, ROT13 and hex payloads
- SOC stack: Wazuh, OpenSearch, OpenSearch Dashboards, Suricata, Zeek
- Ten Sigma rules, validated in CI with pySigma, plus equivalent Wazuh rules
- Mappings to MITRE ATT&CK v19 and MITRE ATLAS, checked against the live feeds
  by a test rather than by hand
- Ten attack scenarios, including token flooding and unsafe output handling
- A dashboard with thirteen panels, every one of which reads a field the proxy
  actually emits
- Eleven threat-hunting queries and five incident response playbooks

**What it is not**

It is a lab. The Suricata and Zeek logs do not ship to the search index, so
there are no panels for them. There is no automated Sigma-to-Wazuh conversion.
The classifier is a deterministic rule engine, not a model. These limits are
documented in the repository rather than left for someone to discover.

**Who it is for**

SOC analysts moving into AI security, detection engineers, purple-team
practitioners, and anyone who wants a concrete example of how LLM telemetry maps
to ATT&CK.

**Tech**: Python, Docker Compose, FastAPI, Wazuh, OpenSearch, Suricata, Zeek,
Sigma, Ollama, OpenWebUI

github.com/sandeepmothukuri/PromptShield

#AISecurity #SOC #DetectionEngineering #LLMSecurity #PromptInjection
#MITREATTACK #BlueTeam #OpenSource

## Factual claims, for review

Every number above is checked by CI. Keep them in step.

| Claim | Value | Verified by |
| --- | --- | --- |
| Sigma rules | 10 | `tests/test_sigma_rules.py` |
| Wazuh rules | 10 (100100-100190) | `tests/test_attack_mappings.py` |
| Suricata signatures | 7 | `tests/test_attack_mappings.py` |
| Attack types classified | 10 | `llm-monitor/classifier.py::ATTACK_TYPES` |
| Dashboard panels | 13 | `tests/test_dashboards.py` |
| Hunting queries | 11 | `hunting/opensearch_queries.md` |
| Playbooks | 5 plus a post-incident template | `playbooks/` |
| Attack simulations | 10 | `simulations/` |
| Telemetry fields | 27 | `docs/telemetry-schema.md` |
| Corpus size | 72 labelled prompts | `datasets/README.md` |
