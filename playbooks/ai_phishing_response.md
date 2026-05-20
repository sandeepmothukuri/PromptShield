# Playbook — AI-Phishing Generation Response

**Trigger:** Wazuh rule `100140` — user coerced the LLM into producing phishing content.

## Triage
- Was this an **authorized** awareness/red-team exercise? Confirm with the requesting team's documented engagement. If yes, mark FP and close.
- If unauthorized: capture user, completion text, intended target indicators (brand, domain, persona).

## Containment
- Block session; suspend the account pending HR/insider-risk review.
- Search outbound email/Slack/Teams for any sent variants of the generated content.

## Eradication / Recovery
- Recall sent emails where possible.
- Brief abuse@ teams of impersonated brands.
- Add the persona/template to mail-filter rules and the awareness corpus.

## Evidence
- Audit log lines.
- Mail-gateway logs for outbound matches.
- Insider-risk timeline.
