# Visuals

This page is explicit about provenance. Nothing here is presented as a live
screenshot unless it was captured from a running system, and nothing is
presented as a diagram unless it was drawn from this repository's own code and
configuration.

## What exists today

### Diagrams (authored, in `docs/img/`)

| File | Shows | Source |
| --- | --- | --- |
| `architecture.svg` | the six planes and what actually runs in each | `docs/diagrams/architecture.mmd` |
| `attack-to-detection.svg` | the nine-stage workflow with the command for each stage | `docs/diagrams/attack-to-detection.mmd` |
| `detection-pipeline.svg` | one record fanning out to Wazuh, Sigma and dashboards | `docs/diagrams/detection-pipeline.mmd` |
| `soc-investigation.svg` | the analyst pivot path and correlation identifiers | `docs/diagrams/soc-investigation.mmd` |
| `incident-response.svg` | NIST SP 800-61 phases and the artefacts each consumes | `docs/diagrams/incident-response.mmd` |

Each `.svg` is hand-authored and each has a `.mmd` source committed alongside it.
The Mermaid sources render natively on GitHub if you paste them into a
```` ```mermaid ```` fenced block, and can be re-rendered with:

```bash
npx @mermaid-js/mermaid-cli -i docs/diagrams/architecture.mmd -o docs/img/architecture.svg
```

### Illustrative mockups (drawn, in `docs/img/`)

These are hand-drawn SVGs showing what a given screen looks like when the stack
is running. **They are not screenshots and contain no measured data.** Every one
carries a visible "Illustrative mockup — not a captured screenshot" badge and a
matching `<desc>` element, so the provenance survives being copied elsewhere.

| File | Depicts |
| --- | --- |
| `dashboard-overview.svg` | the LLM Security Overview layout and panel arrangement |
| `wazuh-alert.svg` | the Wazuh Security Events table with PromptShield rules |
| `hunting-query.svg` | a hunt written against the telemetry schema |
| `openwebui.svg` | the chat front-end with a guardrail in front of the model |
| `suricata.svg` | `eve.json` alert output from the Suricata ruleset |
| `zeek.svg` | the `llm.log` stream produced by the Zeek script |
| `simulation-output.svg` | a simulation run and its block/allow summary |

Values in these images are representative, chosen to look plausible — they are
not measurements from a run. Where an image states a fact that the repository
can check, that fact has been made to agree with the repository: `suricata.svg`
names Suricata 7.0.17 and 7 loaded rules (matching the compose pin and the rule
count), and `wazuh-alert.svg` uses the real rule IDs, levels and ATT&CK
technique IDs from `detections/wazuh/local_rules.xml`.

`sigma-ci.svg` is the exception: it is a diagram rather than a mockup, redrawn
from `.github/workflows/ci.yml`, and shows the four real jobs, their actual
commands and the pinned tool versions.

### Runtime captures (real output, in `docs/captures/`)

These are terminal transcripts from an actual run of this repository's proxy
against a model runtime, not mockups. Reproduce them with the commands printed
in each file.

| File | Contains |
| --- | --- |
| `01-api-smoke.txt` | `/healthz`, an allowed prompt, a blocked prompt with its classifier reason |
| `02-simulations.txt` | all six prompt-level attack simulations and their block rates |
| `03-dos-and-stats.txt` | 413 and 429 handling, `/stats` counters |
| `04-audit-log.txt` | 50 audit records: field dump, histograms, obfuscation flagging |
| `05-validation.txt` | `sigma check`, the test suite, the linter |

The proxy was run locally against a stub model runtime because Ollama is not
available in this environment. Everything in front of the model — classification,
blocking, rate limiting, telemetry, statistics — is the real code path. The
completions are fixtures, and the captures say so.

### Reference material (external, not stored in the repo)

Not fetched or vendored here; linked from the README with attribution:

- OpenWebUI — https://github.com/open-webui/open-webui
- OpenSearch Dashboards — https://opensearch.org/docs/latest/dashboards/index/
- Wazuh — https://documentation.wazuh.com/
- Suricata — https://suricata.io/
- Zeek — https://docs.zeek.org/
- Sigma — https://sigmahq.io/
- MITRE ATT&CK for Enterprise — https://attack.mitre.org/
- MITRE ATLAS — https://atlas.mitre.org/

These are third-party products, shown with their own names and marks, and none
of them endorses this project.

## What is deliberately absent

- **No UI screenshots.** The stack requires Docker, which is not available in
  this environment. The `docs/img/` mockups are drawings, not captures, and are
  labelled as such in the image itself. Real captures replace them one for one —
  see the runbook below.
- **No `suricata-*` or `zeek-*` panels.** Those logs are not shipped to the
  index. See [`network-detection.md`](network-detection.md).
- **No "before/after" charts.** There is no measured baseline, so there is
  nothing honest to plot against.

## Capturing the missing screenshots

Run these on a machine with Docker, then commit the images to
`docs/img/screenshots/` and reference them from the README.

### 1. Bring the stack up

```bash
cp .env.example .env
docker compose up -d
docker compose ps          # wait until every service is healthy
```

### 2. Generate traffic

```bash
python scripts/ingest_logs.py --dataset datasets/ --rate 10
python simulations/llm_dos/token_flood.py --target http://localhost:8080
python simulations/insecure_output/xss_output.py --target http://localhost:8080
```

### 3. Import the dashboards

```bash
./scripts/setup.sh
```

### 4. Capture each screen

| # | Screen | Where | File name |
| --- | --- | --- | --- |
| 1 | LLM Security Overview, 12 panels populated | http://localhost:5602 | `01-overview.png` |
| 2 | Attack type histogram + severity donut | same dashboard | `02-attack-distribution.png` |
| 3 | ATT&CK tag cloud | same dashboard | `03-attck-coverage.png` |
| 4 | Wazuh Security Events, PromptShield rules firing | https://localhost:5601 | `04-wazuh-alerts.png` |
| 5 | A single alert expanded, showing `data.request_id` | same | `05-alert-detail.png` |
| 6 | Threat Hunting view with a hunt query result | http://localhost:5602/app/dev_tools#/console | `06-hunt-result.png` |
| 7 | OpenWebUI with a blocked request | http://localhost:3000 | `07-openwebui-block.png` |
| 8 | `curl` output of a blocked request | terminal | `08-terminal-block.png` |

Capture guidance: use the browser's native screenshot rather than a window
capture, so the images are sharp and free of desktop chrome. Crop to the panel
group being discussed rather than the whole viewport. Do not blur or invent
data; if you must redact a hostname, redact consistently and say so in the
caption.

### 5. Reference them correctly

In the README, put the strongest visual first (the architecture diagram), and
caption every image with what it shows and, for screenshots, the command that
produced the underlying data.

## Image hygiene

- Diagrams live in `docs/img/*.svg`, sources in `docs/diagrams/*.mmd`.
- Screenshots live in `docs/img/screenshots/*.png`.
- Every image referenced from the README must exist at that exact path and
  case. `tests/test_docs_references.py` checks this, so a broken link fails CI
  rather than shipping.
- No stock photography, no "hacker in a hoodie" imagery, no decorative icons
  standing in for functionality.
