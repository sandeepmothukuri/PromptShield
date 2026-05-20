# Playbook — LLM Data Leak

**Trigger:** Wazuh rule `100130` (sensitive data in LLM response) or external report.

## Triage
1. Confirm the leak: pull the `completion` field from `monitor.json`.
2. Classify the data — secret material (keys/tokens), PII, regulated (HIPAA/PCI), internal-only.
3. Identify the **ingestion path** — did the secret arrive via user input, RAG corpus, or system prompt?

## Containment
- Rotate every leaked credential **before** anything else. AWS/GCP/Azure keys: revoke + rotate in IAM; GitHub PATs: revoke; Slack tokens: revoke.
- Block the session at the proxy.
- If the secret was sourced from RAG, remove the document and reindex.

## Eradication
- Patch the upstream source — secret scanners must run on RAG ingestion (`gitleaks`, `trufflehog`).
- Add a Sigma rule covering the new secret format if novel.

## Recovery
- Validate rotation in cloud provider; verify the old credential is rejected.
- Re-enable user / session.

## Comms
- Security leadership, key owner, app owner: immediate.
- If regulated data: privacy/legal within 1 h, regulator within statutory window.

## Evidence
- Audit-log JSON line(s)
- Cloud provider rotation events
- Wazuh alert export
- Diff of the RAG corpus before/after removal
