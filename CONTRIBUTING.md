# Contributing to PromptShield-Lab

First — thank you. This project exists because defenders share. Whether you're adding a Sigma rule, fixing a typo, or proposing a new attack scenario, you are welcome here.

## Ways to contribute

- **Detections.** Sigma rules, Suricata signatures, Zeek scripts, Wazuh decoders/rules.
- **Simulations.** New prompt-injection, jailbreak, or AI-abuse scenarios.
- **Playbooks.** SOC analyst response workflows.
- **Datasets.** Curated, license-clean prompt corpora (NO real PII).
- **Docs.** Setup guides, screenshots, translations.
- **Dashboards.** OpenSearch panels and visualizations.

## Ground rules

1. **No real secrets, PII, or proprietary data** in samples or commits.
2. **Reproducible.** If you add a simulation, it must run via `python …` with arguments documented in a `README.md`.
3. **Mapped.** New detections must reference at least one MITRE ATT&CK technique and (where applicable) one OWASP LLM Top 10 entry.
4. **Tested.** Sigma rules must pass `sigma check` (CI enforces this). Python code must pass `ruff` + `pytest`.
5. **Documented.** Add or update the relevant doc page.

## Workflow

```bash
git checkout -b feat/<short-description>
# ... make changes ...
ruff check .
sigma check detections/sigma
git commit -m "feat(detections): add rule for X"
git push origin feat/<short-description>
# Open a PR using the template
```

## Commit style

We use [Conventional Commits](https://www.conventionalcommits.org/):

- `feat(detections): add Sigma rule for indirect injection`
- `fix(monitor): handle empty prompt edge case`
- `docs(playbooks): clarify containment step in jailbreak playbook`

## Code of Conduct

By participating you agree to abide by the [Code of Conduct](CODE_OF_CONDUCT.md).

## Questions?

Open a Discussion — chances are someone else is wondering the same thing.
