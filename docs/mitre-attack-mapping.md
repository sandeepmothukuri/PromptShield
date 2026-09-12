# Detection Mapping Review — MITRE ATT&CK, MITRE ATLAS and OWASP LLM Top 10

Authoritative cross-reference for every detection in this repository.

Three independent sources are used, and they are deliberately kept separate:

| Framework | What it describes | How it is recorded here |
| --- | --- | --- |
| **MITRE ATT&CK Enterprise** | Adversary behaviour on systems and networks | Sigma `tags: attack.*`, Wazuh `<mitre><id>`, the `technique` telemetry field |
| **MITRE ATLAS** | Adversary behaviour against ML systems | Sigma `metadata.atlas` only — see [Why ATLAS is not an ATT&CK tag](#why-atlas-ids-are-not-att&ck-tags) |
| **OWASP Top 10 for LLM Applications (2025)** | Application-level weakness being exercised | Sigma `metadata.owasp_llm_2025` |

OWASP categories are **not** ATT&CK techniques and are never tagged as such.
`owasp` is not a valid Sigma tag namespace; earlier revisions of these rules used
`tags: owasp.llm01`, which `sigma check` rejects with `InvalidNamespaceTagIssue`.
The mapping now lives in rule metadata.

All ATT&CK IDs are validated against a snapshot of the live MITRE feed by
`tests/test_attack_mappings.py`. Refresh it with
`python tests/data/refresh_attack_snapshot.py`.

---

## Verification baseline

Verified against `enterprise-attack.json` (ATT&CK v19.2) and ATLAS v5.6.0 on
2026-09-12. Two findings changed the content of this repository:

### 1. `T1059.011` is **Lua**, not prompt injection

`T1059.011` exists in ATT&CK Enterprise and its name is **Lua** — a sub-technique
of Command and Scripting Interpreter for the Lua scripting language. It has no
relationship to large language models, and the similarity of the name to "LLM"
makes it an easy mapping to get wrong.

There is currently **no** ATT&CK Enterprise technique or sub-technique for LLM
prompt injection. `tests/test_attack_mappings.py::test_t1059_011_appears_nowhere_in_the_repository`
fails the build if the ID reappears anywhere outside this file.

### 2. ATT&CK v19 renamed and added tactics

| ID | Name in v19.2 | Previously |
| --- | --- | --- |
| TA0005 | **Stealth** | Defense Evasion |
| TA0112 | **Defense Impairment** | *(new tactic)* |

pySigma 3.x validates `attack.*` tags against the v19.2 slugs, which are
**hyphenated** (`attack.initial-access`, `attack.credential-access`,
`attack.stealth`). The underscore forms common in older rule sets
(`attack.initial_access`, `attack.defense_evasion`) now fail validation with
`InvalidATTACKTagIssue`. This repository uses the v19.2 slugs so that
`sigma check` is clean; the tactic a technique belongs to is shown below.

---

## Detection → behaviour → technique mapping

Every row is defensible on its own terms. Where a mapping is conditional or a
closer technique was rejected, the reason is stated.

| Detection | Attack behaviour | MITRE ATT&CK (v19.2) | Justification |
| --- | --- | --- | --- |
| `prompt_injection_direct.yml` | User instructs the model to discard or override its operator instructions | **T1059** Command and Scripting Interpreter · *Execution* | The model is the interpreter that executes the attacker-supplied instruction stream. The rule fires on the override itself, independent of any resulting command. |
| `prompt_injection_indirect_url.yml` | User directs the agent to fetch remote content and obey instructions inside it | **T1566.002** Spearphishing Link · *Initial Access* | The delivery primitive is a link retrieved on the attacker's behalf — the same mechanism as spearphishing link, with an LLM agent as the victim instead of a person. |
| `llm_jailbreak_attempt.yml` | Persona, hypothetical or authority framing used to move the model outside policy | **T1059** Command and Scripting Interpreter · *Execution* | The observable is an attempt to make the interpreter produce output its operator policy forbids. No Enterprise technique describes AI policy circumvention; ATLAS `AML.T0054` is the native mapping. |
| `llm_jailbreak_encoded_payload.yml` | base64 / ROT13 / hex-escaped instruction block | **T1027** Obfuscated Files or Information · *Stealth* | The payload is deliberately obfuscated to defeat keyword filters. The **parent** technique is used, not T1027.013 (Encrypted/Encoded File), because the obfuscation is applied to inline request text rather than to a file on disk. |
| `system_prompt_leakage.yml` | Probing for the hidden system prompt, developer instructions or tool list | **T1552** Unsecured Credentials · *Credential Access* | System prompts are an unsecured store of privileged configuration and routinely embed API keys and internal endpoints. The rule fires on the extraction attempt. ATLAS `AML.T0056` (Extract LLM System Prompt) is the precise mapping. |
| `data_exfiltration_via_llm.yml` | Credential material or regulated PII present in a model completion | **T1552** Unsecured Credentials · *Credential Access* | The detection identifies secret material residing in a channel that is not an approved secret store. **T1041 and T1567 are deliberately not tagged**: they describe transmission out of the environment, which this rule does not observe. They become correct only when the completion is subsequently egressed. |
| `ai_phishing_generation.yml` | Coercing the model to produce delivery-ready phishing or smishing content | **T1566** Phishing · *Initial Access* | The parent technique is used because the rule fires at **generation** time. T1566.001 (Attachment) and T1566.002 (Link) describe the delivery vector, which is not yet chosen and cannot be inferred from the prompt. |
| `malicious_prompt_patterns.yml` | Requesting working malware, reverse shells, credential-dumping or enumeration tooling | **T1588.001** Obtain Capabilities: Malware · *Resource Development*<br>**T1059** Command and Scripting Interpreter · *Execution* | T1588.001 because the requester is acquiring malware capability. T1059 because the requested artefact is command/script content destined for an interpreter. |
| `llm_token_flood_dos.yml` | Oversized prompts and request bursts that exhaust inference capacity | **T1499.004** Application or System Exploitation · *Impact* | Resource exhaustion is achieved with expensive-but-valid application requests. **T1499.001 (OS Exhaustion Flood) is not used** — no network-level flood is generated, so mapping it would misrepresent the telemetry. |
| `llm_insecure_output_handling.yml` | Model completion containing script, event handlers or injection primitives | **T1190** Exploit Public-Facing Application · *Initial Access* | The unsanitised completion is consumed by a public-facing application component; executing it is exploitation of that component's weakness. The rule inspects the completion, so it fires on output that actually reached the rendering layer. |
| Wazuh rule `100190` | Repeated abusive requests from one user inside 5 minutes | **T1078** Valid Accounts · *Stealth / Initial Access* | The requester is an authenticated principal using legitimate credentials to exercise the application beyond its intended use. Correlation rule; no single event is sufficient. |

### Detections that are documented but not implemented

The following appear in earlier revisions of this document. They are **not**
shipped, because the telemetry they would need does not exist yet. They are
tracked in [ROADMAP.md](../ROADMAP.md) rather than mapped here.

| Planned detection | Would map to | Missing prerequisite |
| --- | --- | --- |
| DNS exfiltration via LLM | T1048.003 Exfiltration Over Unencrypted Non-C2 Protocol · *Exfiltration* | Zeek DNS logs are not shipped into the search index; `suricata` SID 9000006 covers the wire but has no indexed field to query |
| Model supply-chain integrity | T1195.002 Compromise Software Supply Chain · *Initial Access* | No model-artifact verification step exists, so there is no telemetry to detect against |
| Tool / agent abuse | T1078 Valid Accounts | The proxy accepts a `tools` field but does not execute tools, so there is no tool-invocation telemetry |

---

## Why ATLAS IDs are not ATT&CK tags

MITRE ATLAS (`AML.Txxxx`) is the correct framework for several behaviours in this
lab, and Enterprise ATT&CK has no equivalent. ATLAS IDs are recorded in
`metadata.atlas` for analyst reference but are **never** written as `attack.*`
tags — pySigma validates that namespace against the Enterprise feed and would
correctly reject them.

| Behaviour | ATLAS (v5.6.0, verified) | Enterprise ATT&CK equivalent |
| --- | --- | --- |
| Direct prompt injection | `AML.T0051.000` LLM Prompt Injection: Direct | none |
| Indirect prompt injection | `AML.T0051.001` LLM Prompt Injection: Indirect | T1566.002 by delivery vector |
| Jailbreak | `AML.T0054` LLM Jailbreak | none — T1059 used as the closest defensible mapping |
| Prompt obfuscation | `AML.T0068` LLM Prompt Obfuscation | T1027 |
| System prompt extraction | `AML.T0056` Extract LLM System Prompt | none — T1552 used for the credential-exposure consequence |
| LLM data leakage | `AML.T0057` LLM Data Leakage | none — T1552 used for the credential-exposure consequence |
| Cost harvesting / token abuse | `AML.T0034` Cost Harvesting | T1499.004 |
| External harms (phishing content) | `AML.T0048` External Harms | T1566 |
| Exploit public-facing application | `AML.T0049` Exploit Public-Facing Application | T1190 |

---

## OWASP Top 10 for LLM Applications mapping

This repository previously used the **2023-24** list. That revision is superseded;
the **2025** list is current, and several IDs changed meaning. Rules carry
`metadata.owasp_llm_2025` as authoritative and `metadata.owasp_llm_2023` for
continuity with older notes.

| 2023-24 ID | 2023-24 title | 2025 ID | 2025 title |
| --- | --- | --- | --- |
| LLM01 | Prompt Injection | **LLM01** | Prompt Injection |
| LLM02 | Insecure Output Handling | **LLM05** | Improper Output Handling |
| LLM04 | Model Denial of Service | **LLM10** | Unbounded Consumption |
| LLM05 | Supply Chain Vulnerabilities | **LLM03** | Supply Chain Vulnerabilities |
| LLM06 | Sensitive Information Disclosure | **LLM02** | Sensitive Information Disclosure |
| LLM07 | Insecure Plugin Design | **LLM08** | Vector and Embedding Weaknesses |
| LLM08 | Excessive Agency | **LLM06** | Excessive Agency |
| LLM09 | Overreliance | **LLM09** | Misinformation |
| — | — | **LLM04** | Data and Model Poisoning |
| — | — | **LLM07** | System Prompt Leakage |

### Per-rule OWASP mapping and audit notes

| Detection | OWASP LLM 2025 | Audit note |
| --- | --- | --- |
| `prompt_injection_direct.yml` | LLM01 Prompt Injection | Correct and unchanged. |
| `prompt_injection_indirect_url.yml` | LLM01 Prompt Injection | Correct — LLM01 covers indirect injection explicitly. |
| `llm_jailbreak_attempt.yml` | LLM01 Prompt Injection | Retained. A jailbreak is a policy-bypass form of injection; it is not a separate Top 10 category. |
| `llm_jailbreak_encoded_payload.yml` | LLM01 Prompt Injection | Retained; the encoding is the evasion mechanism, not a separate risk. |
| `system_prompt_leakage.yml` | **LLM07** System Prompt Leakage | **Corrected.** Previously mapped to LLM06 (Sensitive Information Disclosure). 2025 introduced a dedicated category and it is the precise fit. |
| `data_exfiltration_via_llm.yml` | **LLM02** Sensitive Information Disclosure | **Corrected** from the 2023 numbering (LLM06 → LLM02). |
| `ai_phishing_generation.yml` | LLM09 Misinformation | **Weak mapping, retained with a caveat.** The model is producing content intended to deceive a third party, which is the closest Top 10 entry. This is fundamentally an *abuse* case rather than an application vulnerability; no category covers it cleanly. Where the request only succeeded because a jailbreak defeated the content filter, LLM01 is the contributing control failure. The caveat is recorded in the rule's `metadata.mapping_note`. |
| `malicious_prompt_patterns.yml` | **none-direct** | **Corrected.** Previously mapped to LLM01, which was wrong: an authenticated user asking the model to write malware is not prompt injection. No 2025 category covers it. LLM05 applies only if the generated code is consumed by an automated pipeline without review. Recorded as `none-direct` with the reasoning in `metadata.mapping_note`. |
| `llm_token_flood_dos.yml` | **LLM10** Unbounded Consumption | **Corrected** from LLM04 (2023 Model Denial of Service). |
| `llm_insecure_output_handling.yml` | **LLM05** Improper Output Handling | **Corrected** from LLM02 (2023 numbering). |

### Categories with no detection in this repository

Stated plainly rather than filled with a forced mapping:

| OWASP LLM 2025 | Status |
| --- | --- |
| LLM03 Supply Chain Vulnerabilities | Not covered — no model-artifact verification step exists yet |
| LLM04 Data and Model Poisoning | Not covered — the lab does not train or fine-tune |
| LLM06 Excessive Agency | Partially covered by Wazuh correlation rule `100190`; true coverage requires tool-invocation telemetry |
| LLM08 Vector and Embedding Weaknesses | Not covered — the lab has no RAG index |

---

## ATT&CK tactic coverage

| Tactic (v19.2) | ID | Detections |
| --- | --- | --- |
| Initial Access | TA0001 | `prompt_injection_indirect_url`, `ai_phishing_generation`, `llm_insecure_output_handling` |
| Execution | TA0002 | `prompt_injection_direct`, `llm_jailbreak_attempt`, `malicious_prompt_patterns` |
| Stealth | TA0005 | `llm_jailbreak_encoded_payload` |
| Credential Access | TA0006 | `system_prompt_leakage`, `data_exfiltration_via_llm` |
| Exfiltration | TA0010 | *planned only* — DNS exfiltration rule |
| Impact | TA0040 | `llm_token_flood_dos` |
| Resource Development | TA0042 | `malicious_prompt_patterns` |

---

## Consistency guarantees enforced by tests

| Test | What it proves |
| --- | --- |
| `tests/test_attack_mappings.py::test_every_technique_id_in_the_repository_is_a_real_technique` | No invented or retired ATT&CK ID anywhere in the repo |
| `tests/test_attack_mappings.py::test_t1059_011_appears_nowhere_in_the_repository` | T1059.011 (Lua) is never used for prompt injection |
| `tests/test_attack_mappings.py::test_no_unapproved_technique_is_asserted` | New mappings must be added to `APPROVED_TECHNIQUES` with a written justification |
| `tests/test_attack_mappings.py::test_sigma_and_wazuh_techniques_agree` | A Sigma rule and its Wazuh rule name a common technique |
| `tests/test_attack_mappings.py::test_classifier_technique_matches_the_sigma_rule_for_the_same_attack_type` | The `technique` field in telemetry equals the Sigma tag equals the Wazuh alert |
| `tests/test_attack_mappings.py::test_suricata_metadata_uses_approved_techniques` | Suricata metadata asserts only approved techniques |
| `tests/test_attack_mappings.py::test_owasp_mappings_use_the_2025_list` | Every rule carries a valid 2025 OWASP id or `none-direct` |
