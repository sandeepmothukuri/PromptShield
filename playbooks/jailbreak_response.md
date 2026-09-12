# Playbook — LLM Jailbreak / Policy Bypass

**Trigger:** Wazuh rule `100120`.

## Triage
- Repeat offender? Query `monitor.json` for prior `category:jailbreak` for the same user (30-day window).
- Determine intent — curiosity, research, or coercion toward a malicious output.

## Containment
- 1st offense: warn via inline UX message + log.
- 2nd offense in 30 days: temporary access suspension (15 min cool-down). The
  proxy has no session-blocking API, so apply this at the IdP or the gateway in
  front of it, not at `:8080`.
- 3rd offense: account-level review; pause LLM access pending manager approval.

## Eradication
- Add the new jailbreak string to the classifier corpus.
- Open a PR adding a Sigma rule + simulation script under `simulations/jailbreak/`.

## Recovery
- Reinstate after review.
- Document in monthly metrics review.

## Severity
`high` on a single attempt, `critical` once a jailbreak has produced a policy
violating completion rather than just being attempted.

## Escalation
- A jailbreak that succeeded in producing disallowed output: escalate to the
  detection team the same day; the classifier missed it and needs a corpus entry.
- Encoded or multi-turn payloads: treat as deliberate evasion, not curiosity.
- Repeat offender across accounts from one source IP: escalate to hunt 9
  (source-IP anomalies).

## Evidence
- Audit log lines.
- Prior offense history.
- Communications with user.
