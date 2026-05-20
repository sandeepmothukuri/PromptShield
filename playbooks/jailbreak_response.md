# Playbook — LLM Jailbreak / Policy Bypass

**Trigger:** Wazuh rule `100120`.

## Triage
- Repeat offender? Query `monitor.json` for prior `category:jailbreak` for the same user (30-day window).
- Determine intent — curiosity, research, or coercion toward a malicious output.

## Containment
- 1st offense: warn via inline UX message + log.
- 2nd offense in 30 days: temporary session-level block (15 min cool-down).
- 3rd offense: account-level review; pause LLM access pending manager approval.

## Eradication
- Add the new jailbreak string to the classifier corpus.
- Open a PR adding a Sigma rule + simulation script under `simulations/jailbreak/`.

## Recovery
- Reinstate after review.
- Document in monthly metrics review.

## Evidence
- Audit log lines.
- Prior offense history.
- Communications with user.
