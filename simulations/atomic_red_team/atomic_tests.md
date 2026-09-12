# Atomic Red Team — LLM Extensions

Atomic Red Team ships no LLM-specific tests. The YAML files alongside this
document follow the standard Atomic Red Team schema, so they load directly:

```powershell
Invoke-AtomicTest T1059 -PathToAtomicsFolder ./simulations/atomic_red_team
```

Or run them by hand — every executor command is a plain `curl` against the
monitor on `:8080`, so no Atomic framework is required.

Earlier revisions of this file embedded the YAML in fenced code blocks inside
the markdown, which is not something `Invoke-AtomicRedTeam` can load. The tests
are now real `.yaml` files and this document is an index.

## Tests

| File | Technique | Tests | Expected detection |
| --- | --- | --- | --- |
| `T1059.yaml` | T1059 Command and Scripting Interpreter | 2 | 100110 / 100120 |
| `T1552.yaml` | T1552 Unsecured Credentials | 2 | 100130 / 100150 |
| `T1566.yaml` | T1566 Phishing | 1 | 100140 |
| `T1499.004.yaml` | T1499.004 Application or System Exploitation | 1 | 100160 |
| `T1027.yaml` | T1027 Obfuscated Files or Information | 1 | 100120 |

## Technique choices, and the ones that were rejected

Each of these was considered and deliberately not used. They are recorded here
because each looks plausible at a glance.

| Rejected | Why |
| --- | --- |
| `T1059.011` | This is **Lua** execution. It has nothing to do with prompt injection. An earlier revision used it as a catch-all for LLM execution. Prompt injection maps to the parent `T1059` — the LLM is the interpreter. |
| `T1041` / `T1567` | These describe exfiltration *out of the environment* over a C2 channel or web service. The lab observes secret material landing in a model completion, not leaving the network. They become correct only if the completion is subsequently egressed. `T1552` is what the evidence supports. |
| `T1566.001` | Spearphishing **Attachment** asserts a delivery mechanism. The model generates phishing copy; nothing here attaches or delivers it. The parent `T1566` is accurate. |
| `T1027.013` | Encrypted/Encoded **File**. There is no file — only an encoded string in a request body. The parent `T1027` is accurate. |
| `T1499.001` | OS Exhaustion Flood targets the operating system. The target here is the inference application and its cost budget, which is `.004`. |

## Relationship to the other detection layers

These tests are one of four independent expressions of the same threat model:

| Layer | Location | Purpose |
| --- | --- | --- |
| Atomic Red Team | `simulations/atomic_red_team/*.yaml` | portable, framework-loadable test definitions |
| Simulations | `simulations/*/*.py` | richer scenarios with assertions and multi-stage flows |
| Sigma | `detections/sigma/*.yml` | portable detection logic, CI-validated |
| Wazuh | `detections/wazuh/local_rules.xml` | the detection that actually fires in this lab |

`tests/test_attack_mappings.py` asserts that every technique cited here is a
real ATT&CK Enterprise technique and that the Sigma rules cover it, so the four
layers cannot drift apart silently.

## Adding a test

1. Create `T<id>.yaml` using the schema of an existing file.
2. Generate a fresh `auto_generated_guid` (`uuidgen`).
3. Confirm the technique is a current ATT&CK Enterprise technique — the mapping
   test validates against the committed feed snapshot.
4. State the expected Wazuh rule ID and level in the `description`.
5. If no existing Sigma rule covers the technique, add one; the mapping test
   will fail otherwise.
