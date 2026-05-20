# OpenSearch Dashboards

## Import

```bash
curl -X POST 'http://localhost:5602/api/saved_objects/_import?overwrite=true' \
  -H 'osd-xsrf: true' \
  --form file=@opensearch_dashboard.ndjson
```

Or via UI: **Stack Management → Saved Objects → Import**.

## Panels

| Panel | Description | Index |
| --- | --- | --- |
| Prompt volume (24h) | Line chart of `prompts/min` | `promptshield-*` |
| Top injection patterns | Terms agg on `prompt.keyword` for `category:prompt_injection` | `promptshield-*` |
| Jailbreak heatmap | `user` × hour-of-day for `category:jailbreak` | `promptshield-*` |
| Token usage anomaly | Sum of `prompt_tokens` per user, sigma deviation | `promptshield-*` |
| AI-phishing trend | Time-series of `category:ai_phishing` | `promptshield-*` |
| MITRE ATT&CK coverage | Tag-cloud of `rule.mitre.id` | `wazuh-alerts-*` |
| Suricata flows by SID | Bar chart of `alert.signature_id` | `suricata-*` |
| Zeek llm.log suspicious flag | Pie of `suspicious=true/false` | `zeek-llm-*` |

A starter NDJSON is included; flesh out in `opensearch_dashboard.ndjson` as you add panels.
