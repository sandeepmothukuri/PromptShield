# Dashboards

One dashboard, twelve panels, generated from code.

## Files

| File | Purpose |
| --- | --- |
| `generate_dashboard.py` | emits the NDJSON bundle. Edit this, not the JSON. |
| `opensearch_dashboard.ndjson` | generated output: 1 dashboard, 12 visualizations, 1 index pattern |

Regenerate after changing a panel or a field name:

```bash
python dashboards/generate_dashboard.py
```

The generated file is committed so the bundle is reviewable in a diff and
importable without running Python. `tests/test_dashboards.py` fails if the
committed file drifts from what the generator produces.

## Panels

| # | Panel | Type | Index pattern | Fields |
| --- | --- | --- | --- | --- |
| 1 | Total requests | metric | `promptshield-*` | `request_id` |
| 2 | Blocked requests | metric | `promptshield-*` | `blocked` |
| 3 | Obfuscated payloads | metric | `promptshield-*` | `obfuscated` |
| 4 | Secrets disclosed | metric | `promptshield-*` | `secrets_in_completion` |
| 5 | Attack type distribution | histogram | `promptshield-*` | `attack_type.keyword` |
| 6 | Severity distribution | pie | `promptshield-*` | `severity.keyword` |
| 7 | Response status | pie | `promptshield-*` | `response_status` |
| 8 | Detections over time | area | `promptshield-*` | `@timestamp`, `attack_type.keyword` |
| 9 | ATT&CK technique coverage | tag cloud | `promptshield-*` | `technique.keyword` |
| 10 | Top users by blocked requests | data table | `promptshield-*` | `user.keyword`, `blocked` |
| 11 | Top source IPs | data table | `promptshield-*` | `source_ip.keyword` |
| 12 | Prompt tokens by user | data table | `promptshield-*` | `user.keyword`, `prompt_tokens` |

Every field above is emitted by `llm-monitor/proxy.py`. That is enforced by
`tests/test_dashboards.py`, which parses each panel's `visState`, walks the
aggregations, and asserts the field exists in the documented telemetry schema.

## Index patterns

| Pattern | Populated by |
| --- | --- |
| `promptshield-*` | `scripts/setup.sh`, from the audit log |
| `wazuh-alerts-*` | the Wazuh indexer, from rules 100100–100190 |

`zeek-llm-*` and `suricata-*` are **not** included. Nothing in this repository
ships those logs to the indexer, so panels against them would render empty.
An earlier revision of this file documented a "Suricata flows by SID" panel and
a "Zeek suspicious flag" panel against those patterns; both were removed. See
[`../docs/network-detection.md`](../docs/network-detection.md) for what it
would take to add them honestly.

`tests/test_dashboards.py::test_no_panels_reference_data_sources_that_are_not_shipped`
fails if a panel is added against an unshipped index, so this cannot regress
silently.

## Import

```bash
./scripts/setup.sh
```

Or manually:

```bash
curl -X POST "http://localhost:5602/api/saved_objects/_import?overwrite=true" \
  -H "osd-xsrf: true" \
  --form file=@dashboards/opensearch_dashboard.ndjson
```

## Adding a panel

1. Confirm the field is in `docs/telemetry-schema.md`. If it is not, add it to
   the proxy first — a panel cannot precede the data.
2. Add the panel to `generate_dashboard.py`.
3. Add the field name to `TELEMETRY_FIELDS` in `tests/test_dashboards.py` if it
   is new.
4. Run `python dashboards/generate_dashboard.py`.
5. Commit both the script and the regenerated NDJSON.

## What is deliberately not visualised

- **Prompt text.** Storing full prompts in an indexed field is a data-protection
  problem, and a panel on free text is not actionable. `prompt_hash` is indexed
  for correlation; the full prompt stays in the audit log.
- **Classifier score histograms.** Useful while tuning, misleading afterwards,
  because the distribution changes whenever an indicator is added. Hunt 2 covers
  the sub-threshold question properly.
- **Any panel requiring Suricata or Zeek data.** Not shipped.
