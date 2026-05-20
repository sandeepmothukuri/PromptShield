# LinkedIn — Project Description

## Short (for the *Projects* section)

**PromptShield-Lab — AI Security & SOC Detection Lab**
Open-source lab simulating prompt-injection, LLM jailbreaks, AI phishing, and data exfiltration against a local Ollama-based LLM stack, with end-to-end detections in Wazuh, Suricata, Zeek, and OpenSearch. Sigma, Wazuh, Suricata, and Zeek detections mapped to MITRE ATT&CK and OWASP LLM Top 10. Built entirely with free/open tooling and orchestrated by Docker Compose. ➜ github.com/sandeepmothukuri/PromptShield

## Long (for a *Featured* post)

🛡️ Excited to share **PromptShield-Lab** — an open-source, enterprise-grade lab I built to make AI-security detection engineering accessible to every SOC analyst.

**Why I built it**
Most AI-security content stops at "here's a prompt injection." Real defenders need *telemetry, detections, alerts, and response*. PromptShield-Lab gives you the full kill-chain — from attack simulation to dashboard — in one `docker compose up`.

**What's inside**
✅ Local LLM stack — Ollama + OpenWebUI + LangChain
✅ Full SOC stack — Wazuh + Suricata + Zeek + OpenSearch
✅ Sigma, Wazuh, Suricata, and Zeek detections mapped to MITRE ATT&CK + OWASP LLM Top 10
✅ 10 reproducible attack scenarios (prompt injection, jailbreak, exfil, AI phishing, model DoS)
✅ 4 SOC analyst playbooks
✅ Threat-hunting query library
✅ OpenSearch dashboards & CI-validated detection-as-code

**Who it's for**
SOC analysts pivoting into AI security · Detection engineers · Red-team / purple-team practitioners · CTI teams modeling LLM threats · Students building portfolio projects.

**Tech**: Python · Docker · Wazuh · Suricata · Zeek · OpenSearch · Sigma · Atomic Red Team · Ollama · LangChain

⭐ Star it, fork it, break it — PRs welcome.
👉 github.com/sandeepmothukuri/PromptShield

#AISecurity #SOC #DetectionEngineering #LLMSecurity #PromptInjection #MITREATTACK #Cybersecurity #BlueTeam #OpenSource
