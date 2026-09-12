# Playbook — LLM Resource Exhaustion / Cost Harvesting

**Trigger:** Wazuh rule `100160` (attack_type `token_flood`), or Sigma rule
`llm_token_flood_dos.yml`, or a cost alert from the inference provider.

**Technique:** T1499.004 Application or System Exploitation
**OWASP LLM (2025):** LLM10 Unbounded Consumption

**Severity guidance**

| Condition | Severity |
| --- | --- |
| Single user tripping the rate limit once | Low — likely a large document or a retry loop |
| Sustained rate limiting from one user or IP | Medium |
| Multiple identities from one source IP | High — suggests automation |
| Inference cost materially above baseline, or user-facing latency degradation | High, escalate to Critical if the service is unavailable |

---

## 1. Triage

Distinguish a workload from an attack. Both produce identical telemetry; the
difference is intent and shape.

| Check | Query | Interpretation |
| --- | --- | --- |
| Rate-limited vs allowed ratio | hunt 7 in `hunting/opensearch_queries.md` | A ratio above 50% is deliberate; a handful of 429s is a user with a big file. |
| Distinct users per source IP | hunt 9 | Many users behind one IP is normal for NAT; many *new* users is not. |
| Prompt diversity | `terms` on `prompt_hash` for the user | Thousands of near-identical prompts indicate scripting. Varied prompts suggest genuine use. |
| Request timing | `date_histogram` on `@timestamp`, 1s interval | Machine-regular spacing is automation. |
| Account history | `min` on `@timestamp` for the user | A new account generating load immediately is higher risk. |

Record whether the traffic is **oversized prompts** (`response_status: 413`),
**request bursts** (`response_status: 429`), or both. They have different causes
and different fixes.

## 2. Evidence collection

- Audit records for the window: `request_id`, `user`, `source_ip`,
  `prompt_tokens`, `response_status`, `detection_reason`.
- `prompt_hash` frequency table — this is what proves repetition without
  exporting prompt content.
- Inference provider usage report for the same window, if the model is hosted.
- Proxy logs for connection-level errors.

## 3. Scope determination

Answer before acting:

1. How many distinct users and source IPs are involved?
2. Is the traffic inside or outside the expected network range?
3. Is inference degraded for other users, or is only the attacker's own traffic affected?
4. Is there a legitimate job (batch summarisation, load test) that explains it?

If inference is degraded for other users, treat it as an availability incident and
contain before completing scope.

## 4. Containment

In rough order of reversibility — prefer the least disruptive control that works.

1. **Lower the per-user limits** on the monitor: `RATE_LIMIT_REQUESTS` and
   `MAX_PROMPT_CHARS`. Apply globally only if the abuse is distributed.
2. **Block the source IP** at the ingress or WAF. Note that `source_ip` comes
   from `X-Forwarded-For`; confirm your ingress sets it, or you will block the
   wrong host.
3. **Suspend the identity** at the IdP if the abuse is tied to one account.
4. **Cap model-level concurrency** at the runtime if the host is saturated.
5. **Deny at the provider** only if cost is the primary impact and the above have
   not contained it.

## 5. Eradication

- Identify how the actor obtained access: stolen credentials, a leaked API key,
  or an over-permissive anonymous endpoint.
- If credentials were used, rotate them and review the authentication path.
- If the endpoint is anonymous by design, that is the root cause — see recovery.

## 6. Recovery

- Verify legitimate users can complete requests at normal latency.
- Restore the original rate limits once the abuse stops, and monitor for a shift
  to a lower rate that stays under the threshold.
- Confirm the inference cost curve returns to baseline.

## 7. Validation

- Re-run the simulation to confirm the limits still fire:
  `python simulations/llm_dos/token_flood.py --target http://localhost:8080 --burst 26`
- Confirm rule `100160` fires and the alert carries `technique: T1499.004`.
- Confirm the dashboard panel "Response status" shows the 413/429 distribution.

## 8. Threat hunting pivots

- Hunt 7 (token abuse by user) over a 7-day window, not just the incident window.
- Hunt 9 (source-IP anomalies) to find other origins with the same shape.
- Hunt 8 (repeat offender) to check whether the same identity also attempted
  injection or extraction — resource abuse is often cover for something else.

## 9. Escalation criteria

Escalate to the SOC manager when:

- Inference is unavailable to legitimate users.
- More than five distinct identities are involved.
- The source is external and the endpoint was intended to be internal.
- Cost impact exceeds the agreed threshold.

## 10. Lessons learned

Complete `playbooks/_template_postmortem.md`. For this scenario, pay particular
attention to:

- Whether the thresholds were set from measurement or guessed. The defaults in
  `.env.example` are starting points; they should be tuned to observed traffic.
- Whether cost monitoring alerted before or after the SOC did.

## 11. Post-incident actions

| Action | Where |
| --- | --- |
| Retune `RATE_LIMIT_REQUESTS` / `MAX_PROMPT_CHARS` from observed traffic | `.env`, documented in `docs/telemetry-schema.md` |
| Add a per-model or per-tenant budget if multi-tenant use is planned | `llm-monitor/proxy.py` |
| Add a saved OpenSearch alert on `response_status: 429` count | Dashboards |
| Record the payload shape in `datasets/` if it was novel | `datasets/` |
