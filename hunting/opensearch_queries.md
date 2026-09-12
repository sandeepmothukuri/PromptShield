# Threat Hunting — OpenSearch Queries

Every query below runs against fields the LLM-Monitor actually writes. The schema
is documented in [`docs/telemetry-schema.md`](../docs/telemetry-schema.md); the
index is `promptshield-*` with `@timestamp` as the time field.

Run them in **OpenSearch Dashboards → Dev Tools**, or save them as Discover
searches. Each hunt lists the fields it depends on so a schema change breaks the
hunt visibly rather than silently returning nothing.

A hunt is a hypothesis, evidence and a verdict:

```
HYPOTHESIS  what you expect to be true if the adversary is present
DATA SOURCE which index and which fields
QUERY       the search
TRIAGE      what separates a real hit from noise
ESCALATE    the condition that turns a hit into an incident
PIVOT       the next query, keyed on a field from this result
```

---

## 1. Prompt-injection candidates

**Hypothesis** — someone is trying to override the model's operator instructions.

```json
GET promptshield-*/_search
{
  "size": 100,
  "sort": [{ "@timestamp": "desc" }],
  "query": {
    "bool": {
      "filter": [
        { "range": { "@timestamp": { "gte": "now-24h" } } },
        { "terms": { "attack_type": ["prompt_injection", "indirect_prompt_injection"] } }
      ]
    }
  },
  "_source": ["@timestamp","request_id","session_id","user","source_ip","attack_type","technique","classifier_score","verdict","detection_reason","prompt"]
}
```

**Fields** `attack_type`, `classifier_score`, `verdict`, `detection_reason`
**Expect** Blocked attempts from red-team accounts and curiosity-driven users. Volume alone is not an incident.
**Triage** Interesting when `verdict` is `allow` (the payload scored under the threshold), when one `user` appears with many distinct `detection_reason` values, or when `source_ip` is outside the corporate range.
**Escalate** Any `allow` verdict on `indirect_prompt_injection`, or the same `prompt_hash` from multiple users.
**Pivot** → hunt 8 (per-user history) using the `user` value.

---

## 2. Sub-threshold probing

**Hypothesis** — an adversary is testing payloads just under the block threshold to map the filter.

```json
GET promptshield-*/_search
{
  "size": 100,
  "query": {
    "bool": {
      "filter": [
        { "range": { "@timestamp": { "gte": "now-7d" } } },
        { "term": { "attack_type": "benign" } },
        { "range": { "classifier_score": { "gt": 0 } } }
      ]
    }
  },
  "_source": ["@timestamp","user","source_ip","classifier_score","detection_reason","prompt"]
}
```

**Fields** `classifier_score`, `detection_reason` (holds `below_threshold:<type>`)
**Expect** Occasional low scores from benign phrasing.
**Triage** The signal is *clustering*, not any single hit: one user accumulating many `below_threshold:` reasons across different attack types is probing. A single match on a document-summarisation prompt is noise.
**Escalate** Five or more sub-threshold hits from one `user` or `source_ip` in an hour.
**Pivot** → hunt 9 using `source_ip`.

---

## 3. Jailbreak activity by user

**Hypothesis** — a small number of users account for most policy-bypass attempts.

```json
GET promptshield-*/_search
{
  "size": 0,
  "query": {
    "bool": {
      "filter": [
        { "range": { "@timestamp": { "gte": "now-7d" } } },
        { "term": { "attack_type": "jailbreak" } }
      ]
    }
  },
  "aggs": {
    "by_user": {
      "terms": { "field": "user.keyword", "size": 25 },
      "aggs": {
        "obfuscated": { "filter": { "term": { "obfuscated": true } } },
        "allowed": { "filter": { "term": { "verdict": "allow" } } },
        "first_seen": { "min": { "field": "@timestamp" } }
      }
    }
  }
}
```

**Fields** `attack_type`, `user`, `obfuscated`, `verdict`
**Expect** A long tail of one-off attempts.
**Triage** Rank by `obfuscated.doc_count` — encoded payloads indicate deliberate evasion rather than curiosity. A user whose `first_seen` is recent but whose count is already high is more interesting than a long-standing noisy account.
**Escalate** Any user with `allowed.doc_count > 0`, or three or more obfuscated attempts.
**Pivot** → hunt 8 using `user`.

---

## 4. Encoded-payload evasion

**Hypothesis** — someone is encoding payloads specifically to defeat the filter.

```json
GET promptshield-*/_search
{
  "size": 100,
  "query": {
    "bool": {
      "filter": [
        { "range": { "@timestamp": { "gte": "now-7d" } } },
        { "term": { "obfuscated": true } }
      ]
    }
  },
  "_source": ["@timestamp","user","source_ip","attack_type","technique","classifier_score","verdict","prompt"]
}
```

**Fields** `obfuscated`, `technique` (T1027 when the obfuscation is the finding)
**Expect** Rare. Legitimate base64 in a programming question decodes to text that scores benign.
**Triage** The interesting case is `obfuscated: true` **and** a non-benign `attack_type`. Obfuscation plus a decoded malicious instruction is deliberate.
**Escalate** Any `obfuscated: true` with `verdict: allow`.
**Pivot** → hunt 8 using `user`, then check whether the same user has un-encoded attempts (escalating sophistication).

---

## 5. Secrets disclosed in completions

**Hypothesis** — credential material is leaving the model in responses.

```json
GET promptshield-*/_search
{
  "size": 100,
  "query": {
    "bool": {
      "filter": [
        { "range": { "@timestamp": { "gte": "now-24h" } } },
        { "exists": { "field": "secrets_in_completion" } }
      ],
      "must_not": [
        { "term": { "secrets_in_completion": "" } }
      ]
    }
  },
  "_source": ["@timestamp","request_id","user","model","secrets_in_completion","attack_type","verdict"]
}
```

**Fields** `secrets_in_completion` (array of pattern names, never the secret itself)
**Expect** Nothing, or the lab's synthetic `AKIAIOSFODNN7EXAMPLE` during simulation runs.
**Triage** Filter on the *names*: `aws_access_key_id`, `private_key`, `slack_token` are actionable; `payment_card` may be test data. Query this field rather than regexing `completion` — it is precomputed and does not require reading the secret.
**Escalate** Any real credential. Rotate before investigating further; see [`playbooks/llm_data_leak.md`](../playbooks/llm_data_leak.md).
**Pivot** Pull the full record by `request_id` to determine whether the secret arrived in the prompt (user pasted it) or appeared only in the completion (model reproduced it).

---

## 6. System prompt extraction

**Hypothesis** — someone is mapping the application's hidden configuration.

```json
GET promptshield-*/_search
{
  "size": 100,
  "query": {
    "bool": {
      "filter": [
        { "range": { "@timestamp": { "gte": "now-7d" } } },
        { "term": { "attack_type": "system_prompt_leak" } }
      ]
    }
  },
  "_source": ["@timestamp","user","source_ip","verdict","classifier_score","prompt"]
}
```

**Fields** `attack_type`, `verdict`
**Expect** Developers debugging their own application.
**Triage** Extraction is normally a *precursor*. The question is what happened next in the same session — a targeted follow-up after successful extraction is the real signal.
**Escalate** Extraction followed by tool-abuse or injection attempts in the same `session_id`.
**Pivot** `GET promptshield-*/_search { "query": { "term": { "session_id": "<id>" } }, "sort": [{"@timestamp":"asc"}] }`

---

## 7. Token abuse and cost harvesting

**Hypothesis** — a user is exhausting inference capacity or driving up cost.

```json
GET promptshield-*/_search
{
  "size": 0,
  "query": { "range": { "@timestamp": { "gte": "now-1h" } } },
  "aggs": {
    "by_user": {
      "terms": { "field": "user.keyword", "size": 20 },
      "aggs": {
        "total_tokens": { "sum": { "field": "prompt_tokens" } },
        "requests": { "value_count": { "field": "request_id" } },
        "rate_limited": { "filter": { "term": { "response_status": 429 } } },
        "oversized": { "filter": { "term": { "response_status": 413 } } }
      }
    }
  }
}
```

**Fields** `prompt_tokens`, `response_status`, `request_id`
**Expect** Batch jobs and load tests.
**Triage** `rate_limited` and `oversized` counts distinguish deliberate flooding from a user with a large document. A single 413 is a user pasting something big; repeated 429s are a burst.
**Escalate** More than 50 rate-limited requests from one user in an hour, or sustained load from an account with no batch workload.
**Pivot** → hunt 9 using `source_ip` to check for a distributed source.

---

## 8. Repeat offender by user

**Hypothesis** — one identity is responsible for several distinct attack types.

```json
GET promptshield-*/_search
{
  "size": 0,
  "query": {
    "bool": {
      "filter": [
        { "range": { "@timestamp": { "gte": "now-30d" } } },
        { "term": { "verdict": "block" } }
      ]
    }
  },
  "aggs": {
    "by_user": {
      "terms": { "field": "user.keyword", "size": 20 },
      "aggs": {
        "attack_types": { "terms": { "field": "attack_type.keyword", "size": 10 } },
        "techniques": { "terms": { "field": "technique.keyword", "size": 10 } },
        "first_seen": { "min": { "field": "@timestamp" } },
        "last_seen": { "max": { "field": "@timestamp" } }
      }
    }
  }
}
```

**Fields** `verdict`, `user`, `attack_type`, `technique`
**Triage** Breadth beats volume. A user triggering four different `attack_type` values is behaving differently from one who triggers forty injection attempts out of curiosity. Compare `first_seen` against the account's known history.
**Escalate** Three or more distinct attack types, or any single `critical` severity event.
**Pivot** Pull the timeline: `{ "query": { "term": { "user": "<user>" } }, "sort": [{"@timestamp":"asc"}] }`

---

## 9. Source-IP anomalies

**Hypothesis** — abuse is arriving from an unexpected network origin.

```json
GET promptshield-*/_search
{
  "size": 0,
  "query": { "range": { "@timestamp": { "gte": "now-24h" } } },
  "aggs": {
    "by_ip": {
      "terms": { "field": "source_ip.keyword", "size": 50 },
      "aggs": {
        "distinct_users": { "cardinality": { "field": "user.keyword" } },
        "blocked": { "filter": { "term": { "verdict": "block" } } }
      }
    }
  }
}
```

**Fields** `source_ip`, `user`, `verdict`
**Triage** Two patterns matter: one IP presenting many distinct users (shared NAT is normal, credential stuffing is not), and one IP with a high `blocked` ratio. `source_ip` comes from `X-Forwarded-For` when a proxy sets it — confirm your ingress actually sets that header before trusting it.
**Escalate** An IP with more blocked than allowed requests, or an external IP appearing at all if the lab is meant to be internal-only.
**Pivot** → hunt 8 for the users behind that IP.

---

## 10. Unsafe model output

**Hypothesis** — the model is producing content that is dangerous once rendered or executed.

```json
GET promptshield-*/_search
{
  "size": 100,
  "query": {
    "bool": {
      "filter": [
        { "range": { "@timestamp": { "gte": "now-7d" } } },
        { "term": { "attack_type": "insecure_output" } }
      ]
    }
  },
  "_source": ["@timestamp","request_id","user","model","detection_reason","endpoint"]
}
```

**Fields** `attack_type`, `detection_reason`, `endpoint`
**Triage** A front-end development conversation legitimately produces script tags. The question is whether the *consuming application* renders it. Check `endpoint` and the model in use.
**Escalate** Any hit where the completion is rendered as HTML or piped to a shell by the calling application.
**Pivot** Retrieve the full completion by `request_id` and test it against the actual renderer, not in the dashboard.

---

## 11. Request-ID pivot across sources

**Hypothesis** — one request can be traced end to end.

```json
GET promptshield-*/_search
{
  "query": { "term": { "request_id": "corr-1234" } }
}
```

Then in Wazuh (index `wazuh-alerts-*`):

```json
GET wazuh-alerts-*/_search
{
  "query": { "match_phrase": { "data.request_id": "corr-1234" } },
  "_source": ["timestamp","rule.id","rule.description","rule.mitre.id","data.user","data.attack_type"]
}
```

**Why this matters** — `request_id` is the only identifier that survives from the
caller's HTTP header into the audit record and on into the Wazuh alert. It is what
lets an analyst prove that a specific alert corresponds to a specific request
rather than inferring it from timestamps.

---

## Cadence

| Hunt | Cadence | Automation candidate |
| --- | --- | --- |
| 1 Prompt-injection candidates | Daily | Alert on `verdict: allow` only |
| 2 Sub-threshold probing | Daily | Alert on count per user per hour |
| 3 Jailbreak by user | Weekly | — |
| 4 Encoded-payload evasion | Daily | Alert on any hit |
| 5 Secrets in completions | Continuous | Alert on any hit |
| 6 System prompt extraction | Daily | — |
| 7 Token abuse | Hourly | Alert on `response_status: 429` count |
| 8 Repeat offender | Weekly | — |
| 9 Source-IP anomalies | Daily | Alert on blocked ratio |
| 10 Unsafe output | Daily | — |

Pair every confirmed hunt with a detection change — a new Sigma rule, a new
classifier indicator, or a threshold adjustment. A hunt that does not change the
system will be repeated next quarter with the same result.
