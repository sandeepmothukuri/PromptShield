# MITRE ATT&CK + OWASP LLM Top 10 Mapping

Every detection in `detections/sigma/` carries `tags:` referencing this matrix. The table below is the authoritative cross-reference.

## Coverage matrix

| Detection | MITRE ATT&CK | OWASP LLM | Severity |
| --- | --- | --- | --- |
| `prompt_injection_basic` | T1059 — Command and Scripting Interpreter | LLM01 | High |
| `prompt_injection_indirect_url` | T1566.002 — Spearphishing Link | LLM01 | High |
| `llm_jailbreak_attempt` | T1027 — Obfuscated Files or Information | LLM01 | High |
| `llm_jailbreak_encoded` | T1027.013 — Encrypted/Encoded File | LLM01 | High |
| `system_prompt_leakage` | T1552 — Unsecured Credentials | LLM06 / LLM07 | Critical |
| `data_exfiltration_via_llm` | T1041 — Exfiltration Over C2 Channel | LLM06 | Critical |
| `data_exfiltration_dns_via_llm` | T1048.003 — Exfiltration Over Unencrypted Non-C2 | LLM06 | Critical |
| `ai_phishing_generation` | T1566.001 — Spearphishing Attachment | LLM09 | High |
| `malicious_prompt_patterns` | T1204 — User Execution | LLM01 | Medium |
| `llm_token_flood_dos` | T1499.001 — OS Exhaustion Flood | LLM04 | High |
| `excessive_agency_tool_abuse` | T1078 — Valid Accounts | LLM08 | High |
| `model_supply_chain_pull` | T1195.002 — Compromise Software Supply Chain | LLM05 | Critical |
| `insecure_output_xss` | T1190 — Exploit Public-Facing Application | LLM02 | High |

## ATT&CK tactics covered

- **TA0001 — Initial Access**
- **TA0002 — Execution**
- **TA0005 — Defense Evasion**
- **TA0006 — Credential Access**
- **TA0009 — Collection**
- **TA0010 — Exfiltration**
- **TA0040 — Impact**

## OWASP LLM Top 10 covered

| ID | Title | Detections |
| --- | --- | --- |
| LLM01 | Prompt Injection | 5 |
| LLM02 | Insecure Output Handling | 1 |
| LLM04 | Model Denial of Service | 1 |
| LLM05 | Supply Chain Vulnerabilities | 1 |
| LLM06 | Sensitive Information Disclosure | 3 |
| LLM07 | Insecure Plugin Design | 1 |
| LLM08 | Excessive Agency | 1 |
| LLM09 | Overreliance | 1 |

## Visualization

The OpenSearch dashboard ships with a **MITRE ATT&CK Coverage** heatmap that consumes the `rule.mitre.id` field tagged on every Wazuh alert.
