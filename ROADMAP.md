# 🗺️ PromptShield-Lab Roadmap

A living document. PRs that move items forward are very welcome.

---

## v0.1 — Foundation (current)

- [x] Docker Compose stack: Ollama, OpenWebUI, Wazuh, Suricata, Zeek, OpenSearch
- [x] LLM-Monitor proxy with prompt classifier + LangChain guardrails
- [x] 7 Sigma rules across prompt injection, jailbreak, exfil, phishing
- [x] Wazuh decoders + local rules with MITRE ATT&CK tagging
- [x] Suricata signatures + Zeek `llm_telemetry.zeek`
- [x] 10 reproducible attack scenarios
- [x] 4 SOC playbooks
- [x] OpenSearch dashboard bundle
- [x] Threat-hunting query library
- [x] GitHub Actions CI (Sigma lint, YAML lint, Python tests)
- [x] OWASP LLM Top 10 + MITRE ATT&CK mapping

---

## v0.2 — Adversary emulation

- [ ] LLM-as-judge red-team agent that iteratively probes the proxy
- [ ] Automated detection-as-code regression tests (`pytest` → Sigma → Wazuh)
- [ ] PurpleSharp-style score card per scenario
- [ ] 20 additional Sigma rules from real-world incidents
- [ ] Atomic Red Team test definitions (T1059, T1041, T1567 variants)

---

## v0.3 — Cloud & scale

- [ ] Kubernetes manifests + Helm chart
- [ ] Multi-tenant LLM proxy with per-tenant policy
- [ ] OpenTelemetry traces for every prompt
- [ ] Terraform module for AWS deployment

---

## v0.4 — Response & enrichment

- [ ] TheHive + Cortex integration
- [ ] MISP threat-intel feed of malicious prompt patterns
- [ ] SOAR-style auto-containment playbooks (n8n + Tines examples)
- [ ] Slack/Teams alerting bot with analyst-in-the-loop

---

## v1.0 — Reference architecture

- [ ] Cloud-deployable reference: AWS, Azure, GCP
- [ ] Hardened production guide
- [ ] Compliance mappings: SOC 2, ISO 27001, NIST AI RMF
- [ ] Published whitepaper

---

## Ideas welcome

Open a Discussion with the **idea** label. Some seeds:

- Federated learning poisoning simulation
- Vector-DB exfiltration scenarios
- MCP-server abuse detections
- Browser-agent prompt-injection lab
- LLM watermark-stripping detection
