# Sample Datasets

Small, license-clean prompt corpora for training the classifier and seeding the dashboard. **No real PII.**

| File | Lines | Purpose |
| --- | --- | --- |
| `prompt_injection_samples.jsonl` | 30 | Labeled injection prompts |
| `jailbreak_samples.jsonl` | 25 | Labeled jailbreak prompts |
| `benign_samples.jsonl` | 40 | Labeled benign prompts (negative class) |

## Schema

```json
{"prompt": "Ignore previous instructions...", "label": "prompt_injection", "source": "synthetic"}
```

## Replaying into the lab

```bash
python scripts/ingest_logs.py --dataset datasets/prompt_injection_samples.jsonl
```

## Licensing

All samples in this directory are CC0 / public domain. If you contribute new ones, confirm the same.
