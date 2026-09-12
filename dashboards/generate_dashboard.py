#!/usr/bin/env python3
"""Generate dashboards/opensearch_dashboard.ndjson.

The bundle is generated rather than hand-edited so that panel definitions stay
consistent and reviewable in git. Every field referenced here is validated
against the telemetry schema by tests/test_dashboards.py.

    python dashboards/generate_dashboard.py
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path

OUT = Path(__file__).with_name("opensearch_dashboard.ndjson")

PS_INDEX_ID = "index-pattern-promptshield"
# There is deliberately no `wazuh-alerts-*` index pattern here. Wazuh alerts
# live in the Wazuh indexer (host port 9201), a separate cluster from the
# standalone OpenSearch (host port 9200) that this dashboard bundle is
# imported into. A panel on wazuh-alerts-* would therefore always render
# empty; ATT&CK coverage from the proxy side is panel 9 (technique.keyword),
# and alert-side coverage is visible in the Wazuh Dashboard on port 5601.


def _uid(prefix: str) -> str:
    """Stable-ish readable id (dashboards are keyed by id, so keep them fixed)."""
    return f"{prefix}-{uuid.uuid5(uuid.NAMESPACE_DNS, f'promptshield/{prefix}')}"


def _search_source(index_id: str, query: dict | None = None, extra: dict | None = None) -> str:
    src = {
        "index": index_id,
        "query": query or {"query": "", "language": "kuery"},
        "filter": [],
    }
    if extra:
        src.update(extra)
    return json.dumps(src, separators=(",", ":"))


def _vis(
    vid: str,
    title: str,
    index_id: str,
    vis_type: str,
    params: dict,
    agg: list[dict],
    query: dict | None = None,
    description: str = "",
) -> dict:
    vis_state = {"title": title, "type": vis_type, "params": params, "aggs": agg}
    return {
        "type": "visualization",
        "id": vid,
        "attributes": {
            "title": title,
            "visState": json.dumps(vis_state, separators=(",", ":")),
            "uiStateJSON": "{}",
            "description": description,
            "version": 1,
            "kibanaSavedObjectMeta": {"searchSourceJSON": _search_source(index_id, query)},
        },
        "references": [{"name": "indexpattern", "type": "index-pattern", "id": index_id}],
    }


def _count_agg() -> list[dict]:
    return [{"id": "1", "type": "count", "schema": "metric", "params": {}}]


def _terms_agg(field: str, schema: str = "segment", size: int = 10, order_by: str = "1") -> dict:
    return {
        "id": "2",
        "type": "terms",
        "schema": schema,
        "params": {"field": field, "orderBy": order_by, "order": "desc", "size": size},
    }


def _date_agg(interval: str = "auto") -> dict:
    return {
        "id": "2",
        "type": "date_histogram",
        "schema": "segment",
        "params": {"field": "@timestamp", "interval": interval, "timeZone": "UTC"},
    }


def _filter(term: str, value) -> dict:
    return {"query": {"bool": {"filter": [{"term": {term: value}}]}}, "language": "kuery"}


def build() -> list[dict]:
    objects: list[dict] = []

    objects.append(
        {
            "type": "index-pattern",
            "id": PS_INDEX_ID,
            "attributes": {"title": "promptshield-*", "timeFieldName": "@timestamp"},
            "references": [],
        }
    )

    panels = []

    def add(vid: str, obj: dict, grid: dict) -> None:
        objects.append(obj)
        panels.append(
            {
                "id": vid,
                "type": "visualization",
                "gridData": grid,
                "panelIndex": str(len(panels) + 1),
            }
        )

    # --- Row 1: headline metrics -------------------------------------------
    add(
        _uid("vis-total-requests"),
        _vis(
            _uid("vis-total-requests"),
            "Total LLM requests",
            PS_INDEX_ID,
            "metric",
            {"addTooltip": True, "type": "metric"},
            _count_agg(),
            description="Every inference request the monitor saw, benign and malicious.",
        ),
        {"x": 0, "y": 0, "w": 3, "h": 3, "i": "1"},
    )

    add(
        _uid("vis-blocked"),
        _vis(
            _uid("vis-blocked"),
            "Blocked requests",
            PS_INDEX_ID,
            "metric",
            {"addTooltip": True, "type": "metric"},
            _count_agg(),
            query=_filter("verdict", "block"),
            description="Requests the classifier or a rate limit stopped.",
        ),
        {"x": 3, "y": 0, "w": 3, "h": 3, "i": "2"},
    )

    add(
        _uid("vis-obfuscated"),
        _vis(
            _uid("vis-obfuscated"),
            "Obfuscated payloads",
            PS_INDEX_ID,
            "metric",
            {"addTooltip": True, "type": "metric"},
            _count_agg(),
            query=_filter("obfuscated", True),
            description="Requests containing decoded base64 / ROT13 / hex content.",
        ),
        {"x": 6, "y": 0, "w": 3, "h": 3, "i": "3"},
    )

    add(
        _uid("vis-secret-disclosure"),
        _vis(
            _uid("vis-secret-disclosure"),
            "Secret disclosures in completions",
            PS_INDEX_ID,
            "metric",
            {"addTooltip": True, "type": "metric"},
            _count_agg(),
            query={"query": "secrets_in_completion:*", "language": "kuery"},
            description="Completions containing credential or PII patterns. Should be zero outside simulations.",
        ),
        {"x": 9, "y": 0, "w": 3, "h": 3, "i": "4"},
    )

    # --- Row 2: distribution ----------------------------------------------
    add(
        _uid("vis-attack-types"),
        _vis(
            _uid("vis-attack-types"),
            "Attack type distribution",
            PS_INDEX_ID,
            "histogram",
            {
                "type": "histogram",
                "addTooltip": True,
                "addLegend": True,
                "legendPosition": "right",
                "scale": "linear",
                "mode": "stacked",
            },
            [*_count_agg(), _terms_agg("attack_type.keyword", "group", 12)],
        ),
        {"x": 0, "y": 3, "w": 6, "h": 5, "i": "5"},
    )

    add(
        _uid("vis-severity"),
        _vis(
            _uid("vis-severity"),
            "Severity distribution",
            PS_INDEX_ID,
            "pie",
            {
                "type": "pie",
                "addTooltip": True,
                "addLegend": True,
                "legendPosition": "right",
                "isDonut": True,
            },
            [*_count_agg(), _terms_agg("severity.keyword", "segment", 6)],
        ),
        {"x": 6, "y": 3, "w": 3, "h": 5, "i": "6"},
    )

    add(
        _uid("vis-response-status"),
        _vis(
            _uid("vis-response-status"),
            "Response status",
            PS_INDEX_ID,
            "pie",
            {"type": "pie", "addTooltip": True, "addLegend": True, "legendPosition": "right"},
            [*_count_agg(), _terms_agg("response_status", "segment", 8)],
            description="413 = oversized prompt, 429 = rate limited, 200 = served or blocked inline.",
        ),
        {"x": 9, "y": 3, "w": 3, "h": 5, "i": "7"},
    )

    # --- Row 3: trends -----------------------------------------------------
    add(
        _uid("vis-detection-trend"),
        _vis(
            _uid("vis-detection-trend"),
            "Detections over time by attack type",
            PS_INDEX_ID,
            "area",
            {
                "type": "area",
                "grid": {"categoryLines": True},
                "categoryAxes": [
                    {
                        "id": "CategoryAxis-1",
                        "type": "category",
                        "position": "bottom",
                        "show": True,
                        "style": {},
                        "scale": {"type": "linear"},
                        "labels": {"show": True, "filter": True},
                    }
                ],
                "valueAxes": [
                    {
                        "id": "ValueAxis-1",
                        "name": "Count",
                        "type": "value",
                        "position": "left",
                        "show": True,
                        "style": {},
                        "scale": {"type": "linear", "mode": "normal"},
                    }
                ],
                "addTooltip": True,
                "addLegend": True,
                "legendPosition": "right",
                "smoothLines": True,
            },
            [*_count_agg(), _date_agg("auto"), _terms_agg("attack_type.keyword", "group", 10)],
        ),
        {"x": 0, "y": 8, "w": 8, "h": 5, "i": "8"},
    )

    add(
        _uid("vis-attack-coverage"),
        _vis(
            _uid("vis-attack-coverage"),
            "MITRE ATT&CK technique coverage (telemetry)",
            PS_INDEX_ID,
            "tagcloud",
            {
                "scale": "linear",
                "orientation": "single",
                "minFontSize": 12,
                "maxFontSize": 42,
                "showLabel": True,
            },
            [*_count_agg(), _terms_agg("technique.keyword", "segment", 15)],
            description="Techniques written to the `technique` field by the monitor.",
        ),
        {"x": 8, "y": 8, "w": 4, "h": 5, "i": "9"},
    )

    # --- Row 4: identity ---------------------------------------------------
    add(
        _uid("vis-top-users"),
        _vis(
            _uid("vis-top-users"),
            "Top users by blocked requests",
            PS_INDEX_ID,
            "table",
            {
                "perPage": 10,
                "showPartialRows": False,
                "showMetricsAtAllLevels": False,
                "sort": {"columnIndex": None, "direction": None},
                "showTotal": False,
                "totalFunc": "sum",
                "percentageCol": "",
            },
            [
                {"id": "1", "type": "count", "schema": "metric", "params": {}},
                {
                    "id": "2",
                    "type": "terms",
                    "schema": "bucket",
                    "params": {
                        "field": "user.keyword",
                        "orderBy": "1",
                        "order": "desc",
                        "size": 15,
                    },
                },
                {
                    "id": "3",
                    "type": "terms",
                    "schema": "bucket",
                    "params": {
                        "field": "attack_type.keyword",
                        "orderBy": "1",
                        "order": "desc",
                        "size": 5,
                    },
                },
            ],
            query=_filter("verdict", "block"),
        ),
        {"x": 0, "y": 13, "w": 6, "h": 5, "i": "10"},
    )

    add(
        _uid("vis-top-ips"),
        _vis(
            _uid("vis-top-ips"),
            "Top source IPs",
            PS_INDEX_ID,
            "table",
            {
                "perPage": 10,
                "showPartialRows": False,
                "showMetricsAtAllLevels": False,
                "sort": {"columnIndex": None, "direction": None},
                "showTotal": False,
                "totalFunc": "sum",
                "percentageCol": "",
            },
            [
                {"id": "1", "type": "count", "schema": "metric", "params": {}},
                {
                    "id": "2",
                    "type": "unique_count",
                    "schema": "metric",
                    "params": {"field": "user.keyword"},
                },
                {
                    "id": "3",
                    "type": "terms",
                    "schema": "bucket",
                    "params": {
                        "field": "source_ip.keyword",
                        "orderBy": "1",
                        "order": "desc",
                        "size": 15,
                    },
                },
            ],
        ),
        {"x": 6, "y": 13, "w": 6, "h": 5, "i": "11"},
    )

    # --- Row 5: volume -----------------------------------------------------
    add(
        _uid("vis-token-usage"),
        _vis(
            _uid("vis-token-usage"),
            "Prompt tokens by user",
            PS_INDEX_ID,
            "histogram",
            {
                "type": "histogram",
                "addTooltip": True,
                "addLegend": True,
                "legendPosition": "right",
                "scale": "linear",
                "mode": "normal",
            },
            [
                {
                    "id": "1",
                    "type": "sum",
                    "schema": "metric",
                    "params": {"field": "prompt_tokens"},
                },
                {
                    "id": "2",
                    "type": "terms",
                    "schema": "segment",
                    "params": {
                        "field": "user.keyword",
                        "orderBy": "1",
                        "order": "desc",
                        "size": 15,
                    },
                },
            ],
            description="Cost-harvesting indicator. Compare against the per-user rate limit.",
        ),
        {"x": 0, "y": 18, "w": 6, "h": 5, "i": "12"},
    )

    dashboard = {
        "type": "dashboard",
        "id": "dashboard-promptshield-overview",
        "attributes": {
            "title": "PromptShield - Overview",
            "hits": 0,
            "description": (
                "LLM telemetry from the PromptShield monitor. Panels reference only "
                "fields documented in docs/telemetry-schema.md."
            ),
            "panelsJSON": json.dumps(panels, separators=(",", ":")),
            "optionsJSON": json.dumps(
                {
                    "hidePanelTitles": False,
                    "useMargins": True,
                    "darkTheme": False,
                },
                separators=(",", ":"),
            ),
            "version": 1,
            "timeRestore": False,
            "refreshInterval": {"pause": True, "value": 0},
            "timeTo": "now",
            "timeFrom": "now-24h",
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps(
                    {"query": {"query": "", "language": "kuery"}, "filter": []},
                    separators=(",", ":"),
                )
            },
        },
        "references": [
            {"name": f"{p['id']}:panel", "type": "visualization", "id": p["id"]} for p in panels
        ],
    }
    objects.append(dashboard)
    return objects


def main() -> None:
    objects = build()
    with OUT.open("w", encoding="utf-8") as fh:
        for obj in objects:
            fh.write(json.dumps(obj, separators=(",", ":"), ensure_ascii=False) + "\n")
    kinds = {}
    for obj in objects:
        kinds[obj["type"]] = kinds.get(obj["type"], 0) + 1
    print(f"wrote {OUT.name}: {kinds}")


if __name__ == "__main__":
    main()
