# Résumé — Project Description

## One-line (skills section)

**PromptShield-Lab** — Open-source AI-security & SOC detection lab (Wazuh, Suricata, Zeek, OpenSearch, Sigma, Ollama, LangChain, Docker) mapped to MITRE ATT&CK and OWASP LLM Top 10.

## Bulleted (project section)

**PromptShield-Lab — AI Security Detection Engineering Lab** · *Personal Open-Source Project · 2026*
*github.com/sandeepmothukuri/PromptShield*

- Architected and shipped a self-hosted lab that simulates prompt-injection, LLM jailbreak, AI-phishing, and data-exfiltration attacks against a local **Ollama + OpenWebUI + LangChain** stack and monitors them with a **Wazuh + Suricata + Zeek + OpenSearch** SOC pipeline.
- Authored **Sigma, Wazuh, Suricata, and Zeek detections** mapped to **MITRE ATT&CK** and **OWASP LLM Top 10**; built CI-as-code validation in **GitHub Actions** (Sigma lint, YAML lint, `pytest`).
- Engineered a Python FastAPI **LLM-Monitor proxy** with a transformer-based prompt classifier and LangChain guardrails, producing structured JSON audit logs consumed by Wazuh decoders.
- Designed **10 reproducible adversary scenarios** and **4 SOC analyst playbooks** covering triage, containment, evidence collection, and stakeholder communication.
- Delivered importable **OpenSearch dashboards** (injection trends, jailbreak heatmap, MITRE coverage matrix) and a **threat-hunting query library**.
- Tech: Python · Docker Compose · Wazuh · Suricata · Zeek · OpenSearch · Sigma · Atomic Red Team · LangChain · Ollama · GitHub Actions.

## One-paragraph (cover letter)

PromptShield-Lab is an open-source, free, Docker-orchestrated lab I built to bridge classical SOC detection engineering and emerging LLM-application threats. It packages a local LLM stack, a full SOC stack, Sigma/Wazuh/Suricata/Zeek detections, ten reproducible attack scenarios, and SOC analyst playbooks — all mapped to MITRE ATT&CK and OWASP LLM Top 10. It demonstrates that I can not only describe AI-security risks but build the telemetry, detections, and response workflows needed to defend against them.
