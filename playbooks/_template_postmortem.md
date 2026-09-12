# Post-Incident Review Template

Referenced by every playbook in this directory. Copy it into the incident ticket
and complete it within five working days of closure.

An incomplete review is the normal failure mode of incident response: the
containment work gets done, the learning does not. This template exists to make
the learning a checklist item with an owner.

---

## 1. Identification

| Field | Value |
| --- | --- |
| Incident ID | |
| Title | |
| Detected at (UTC) | |
| Closed at (UTC) | |
| Detection source | Wazuh rule `______` / hunt `______` / external report |
| Severity assigned | |
| Incident commander | |
| ATT&CK technique(s) | |
| OWASP LLM category | |
| `attack_type` | |

## 2. Summary

Three to five sentences, written for someone who was not on shift. What happened,
how it was found, what the impact was, what was done.

## 3. Timeline

All times UTC. Include detection latency explicitly — the gap between first
malicious event and first alert is the metric that drives detection work.

| Time | Event | Source |
| --- | --- | --- |
| | First malicious request (`request_id`) | `promptshield-*` |
| | First alert fired | Wazuh |
| | Analyst acknowledged | |
| | Containment applied | |
| | Root cause identified | |
| | Recovery verified | |
| | Closed | |

**Detection latency:** ______ **Response latency:** ______

## 4. What went well

Be specific. "The team communicated well" is not an observation.

## 5. What did not go well

Name the failure and its cause, not the person.

## 6. Root cause

Distinguish the **proximate cause** (the payload, the misconfiguration) from the
**systemic cause** (why the control did not exist or did not fire).

## 7. Action items

Every action item needs an owner and a date. Detection items should be merged
before the ticket closes wherever possible.

| # | Action | Type | Owner | Due | Verification |
| --- | --- | --- | --- | --- | --- |
| 1 | | detection / process / tooling | | | |

Action types, and what "done" means for each:

| Type | Definition of done |
| --- | --- |
| **Detection** | A Sigma rule, Wazuh rule or classifier indicator exists, and a test proves it fires on the incident payload. |
| **Fixture** | The payload is in `datasets/` with the correct label, so the regression suite covers it. |
| **Playbook** | The triage step that was missing is written into the relevant playbook. |
| **Hunt** | The query used to scope the incident is in `hunting/opensearch_queries.md` with objective and pivot. |
| **Process** | The change is documented where the next on-call analyst will find it. |

## 8. Detection gap analysis

Answer all four. If any answer is "no", it becomes an action item.

1. Did an alert fire for the first malicious event? If not, why not?
2. Did the alert contain enough context to triage without re-querying?
3. Was the severity assigned by the rule correct, or did the analyst override it?
4. Could this incident have been detected earlier in the chain?

## 9. Metrics for trend tracking

| Metric | This incident |
| --- | --- |
| Time to detect | |
| Time to contain | |
| Number of affected users | |
| Number of affected requests | |
| Credentials rotated | |
| Alerts generated (signal) | |
| Alerts reviewed and dismissed (noise) | |

## 10. Distribution

| Audience | Within |
| --- | --- |
| SOC team | 24 h |
| Application owner | 24 h |
| Security leadership | 48 h |
| Legal / Privacy (if PII or regulated data) | per statutory clock |
