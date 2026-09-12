# Playbook — Prompt Injection Incident Response

**Trigger:** Wazuh rule `100110` / `100120` fires, or analyst-reported user complaint of LLM behaving outside policy.

**Severity:** High (escalate to Critical if downstream tool/system action was taken on the malicious instruction).

---

## 1. Triage (≤ 15 min)

| Step | Action | Owner |
| --- | --- | --- |
| 1.1 | Open the alert in Wazuh; copy `user`, `session_id`, `prompt`. | Tier-1 analyst |
| 1.2 | Pull the full session from `monitor.json` via OpenSearch (`session_id:"<id>"`). | Tier-1 |
| 1.3 | Classify: *opportunistic test*, *targeted insider*, *automated probe*. | Tier-1 |
| 1.4 | Check user's recent activity (auth, downloads, repo activity) — last 24 h. | Tier-1 |
| 1.5 | If LLM is wired to **agentic tools** (email send, code exec, ticket create), assume **breach** and jump to §3. | Tier-2 |

## 2. Containment

The proxy has no session-blocking API. `POST /admin/block_session` appears in
older revisions of this playbook and does not exist; the proxy exposes only
`/healthz`, `/stats`, `/chat` and `/v1/chat/completions`. Adding one without
authentication first would be worse than not having it, since anyone who can
reach `:8080` could then deny service to arbitrary users. Until it exists with
auth, contain at a layer that already has identity:

- **Suspend the account at the IdP.** This is the primary control, because it
  removes the identity rather than one session.
- **Revoke or rotate the API credential** the session used, if the caller
  authenticated with one rather than an interactive login.
- **For automated probes from a single IP, drop at the gateway or WAF.** Note
  that `source_ip` comes from `X-Forwarded-For`; confirm your ingress sets it,
  or you will block the wrong host.
- **Lower `RATE_LIMIT_REQUESTS`** in `.env` and restart `llm-monitor` if the
  abuse is distributed across identities.

## 3. Eradication

- Identify the **injection vector** — direct chat, RAG document, web URL, plugin. Patch at the source.
- For RAG/indirect attacks: requarantine and re-scan the document corpus.
- Rotate any secret that may have appeared in the session.

## 4. Recovery

- Lift session block once root cause is patched and corpus re-scanned.
- Add the offending payload to the test fixtures in `simulations/`.

## 5. Evidence collection

- Wazuh alert JSON (export).
- Full `monitor.json` session lines.
- Suricata `eve.json` flows for the session window.
- Zeek `llm.log` rows tagged `suspicious=T`.

## 6. Communications

| Audience | Channel | Within |
| --- | --- | --- |
| SOC manager | Slack #soc-ops | 30 min |
| App owner | Email | 1 h |
| Legal / Privacy (if PII leaked) | Email | 2 h |
| Affected user | Email | 24 h |

## 7. Postmortem

Use the template in `playbooks/_template_postmortem.md`. Track in the IR ticket. Add a new Sigma rule that would have caught the payload sooner. Update training corpus.
