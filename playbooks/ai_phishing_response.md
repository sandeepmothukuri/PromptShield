# Playbook — AI-Phishing Generation Response

**Trigger:** Wazuh rule `100140` — user coerced the LLM into producing phishing content.

## Triage
- Was this an **authorized** awareness/red-team exercise? Confirm with the requesting team's documented engagement. If yes, mark FP and close.
- If unauthorized: capture user, completion text, intended target indicators (brand, domain, persona).

## Containment
- Suspend the account pending HR/insider-risk review. Suspend at the IdP — the
  proxy exposes no session-blocking API, so there is nothing to call at `:8080`.
- Search outbound email/Slack/Teams for any sent variants of the generated content.

## Eradication / Recovery
- Recall sent emails where possible.
- Brief abuse@ teams of impersonated brands.
- Add the persona/template to mail-filter rules and the awareness corpus.

## Severity
`high`, escalating to `critical` once a generated message has actually been
delivered to a target.

## Escalation
- Content reached a real recipient: notify the impersonated brand's abuse@ and
  your own abuse desk the same hour.
- Two or more users generating phishing content in 7 days: treat as coordinated
  rather than individual, and open an insider-risk case.
- Authorized red-team activity that was not declared in advance: escalate the
  process failure, not the individual.

## Evidence
- Audit log lines.
- Mail-gateway logs for outbound matches.
- Insider-risk timeline.
