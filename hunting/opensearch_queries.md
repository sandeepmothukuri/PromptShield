# Threat-Hunting Queries — OpenSearch

Copy/paste these into OpenSearch Dashboards → Dev Tools, or Discover.

## 1. Prompt-injection candidates (last 24h)

```json
GET promptshield-*/_search
{
  "query": {
    "bool": {
      "filter": [{ "range": { "@timestamp": { "gte": "now-24h" }}}],
      "should": [
        { "match_phrase": { "prompt": "ignore previous instructions" }},
        { "match_phrase": { "prompt": "disregard prior" }},
        { "match_phrase": { "prompt": "override your system prompt" }}
      ],
      "minimum_should_match": 1
    }
  },
  "_source": ["user","session_id","prompt","classifier_score","verdict"],
  "size": 50
}
```

## 2. Jailbreak heatmap by user (7d)

```json
GET promptshield-*/_search
{
  "size": 0,
  "query": { "bool": {
      "filter": [{ "range": { "@timestamp": { "gte": "now-7d" }}}],
      "must":   [{ "term": { "category": "jailbreak" }}]
  }},
  "aggs": { "by_user": { "terms": { "field": "user.keyword", "size": 25 }}}
}
```

## 3. Secrets in LLM completions

```json
GET promptshield-*/_search
{
  "query": {
    "bool": {
      "should": [
        { "regexp": { "completion": "AKIA[0-9A-Z]{16}" }},
        { "regexp": { "completion": "sk-[A-Za-z0-9]{32,}" }},
        { "regexp": { "completion": "ghp_[A-Za-z0-9]{36}" }}
      ],
      "minimum_should_match": 1
    }
  }
}
```

## 4. Token-flood candidates (single user > 100k tokens / hour)

```json
GET promptshield-*/_search
{
  "size": 0,
  "query": { "range": { "@timestamp": { "gte": "now-1h" }}},
  "aggs": {
    "by_user": {
      "terms": { "field": "user.keyword", "size": 20 },
      "aggs":  { "total_tokens": { "sum": { "field": "prompt_tokens" }}}
    }
  }
}
```

## 5. Indirect-injection candidates (HTML comments containing injection markers in Zeek logs)

```json
GET zeek-llm-*/_search
{
  "query": {
    "bool": {
      "must": [
        { "term":  { "suspicious": true }},
        { "match": { "reasons":   "ignore previous instructions" }}
      ]
    }
  }
}
```

## 6. New-user anomaly — first-seen jailbreak

```json
GET promptshield-*/_search
{
  "size": 0,
  "query": { "term": { "category": "jailbreak" }},
  "aggs": {
    "first_seen": {
      "terms": { "field": "user.keyword", "size": 50 },
      "aggs":  { "earliest": { "min": { "field": "@timestamp" }}}
    }
  }
}
```
