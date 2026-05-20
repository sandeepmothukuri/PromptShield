# Prompt-Injection Simulations

| Script | What it does | Maps to |
| --- | --- | --- |
| `direct_injection.py` | Sends classic "ignore previous instructions" payloads. | LLM01 / T1059 |
| `indirect_injection.py` | Hosts a malicious page and asks the LLM to summarize it. | LLM01 / T1566.002 |

## Run

```bash
python direct_injection.py --target http://localhost:8080/chat
python indirect_injection.py --target http://localhost:8080/chat
```

## Expected detection

Both scripts trigger Wazuh rule `100110` (and `100150` for system-prompt-leak variants) and Suricata SID `9000001`.
