# Threat-Hunting Guide

A hunt is a hypothesis, evidence, and a verdict. Use this template:

```
HYPOTHESIS:  e.g., "An insider is using the LLM to draft phishing emails for external targets."
DATA SOURCES: monitor.json (OpenSearch), mail gateway, IdP
QUERY:       (link to hunt query)
TRIAGE:      what makes a hit interesting vs. noise
ESCALATE:    when to open an incident
```

## Recommended cadence

| Hunt | Cadence |
| --- | --- |
| Prompt-injection candidates | Daily |
| Jailbreak heatmap | Weekly |
| Secrets in completions | On every push (CI-driven) |
| Token-flood by user | Hourly (alert) |
| First-seen jailbreak by new user | Weekly |
| RAG corpus indirect-injection scan | On every ingestion |

## Notes

- Always pair a positive hunt with a **new detection** (Sigma rule, classifier sample, or playbook update). A hunt that doesn't change the system is a hunt that will repeat itself.
- Save successful hunts as OpenSearch "saved searches" and link them from this doc.
