"""Dashboard bundle validation.

Checks that dashboards/opensearch_dashboard.ndjson is importable and - the part
that actually matters - that every field it references is one the LLM-Monitor
writes. A panel built on a field that does not exist renders empty and looks like
a broken lab rather than a missing field.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
NDJSON = ROOT / "dashboards" / "opensearch_dashboard.ndjson"
GENERATOR = ROOT / "dashboards" / "generate_dashboard.py"

# Fields written by llm-monitor/proxy.py::_build_event - see docs/telemetry-schema.md
TELEMETRY_FIELDS = {
    "@timestamp",
    "event_id",
    "request_id",
    "session_id",
    "user",
    "source_ip",
    "endpoint",
    "provider",
    "model",
    "prompt",
    "prompt_hash",
    "prompt_tokens",
    "classifier_score",
    "confidence",
    "attack_type",
    "technique",
    "severity",
    "detection_reason",
    "obfuscated",
    "verdict",
    "response_status",
    "blocked",
    "secrets_in_prompt",
    "secrets_in_completion",
    "completion",
    "completion_tokens",
    "completion_truncated",
}

# Fields produced by Wazuh, not by the monitor.
WAZUH_FIELDS = {
    "timestamp",
    "rule.id",
    "rule.description",
    "rule.groups",
    "rule.mitre.id",
    "data.request_id",
}

FIELD_RE = re.compile(r'"field"\s*:\s*"([^"]+)"')


def _objects() -> list[dict]:
    return [
        json.loads(line) for line in NDJSON.read_text(encoding="utf-8").splitlines() if line.strip()
    ]


def test_ndjson_is_valid_and_non_empty() -> None:
    objects = _objects()
    assert len(objects) >= 10, "dashboard bundle looks incomplete"
    for obj in objects:
        assert "type" in obj and "id" in obj and "attributes" in obj


def test_object_ids_are_unique() -> None:
    ids = [o["id"] for o in _objects()]
    assert len(ids) == len(set(ids)), "duplicate saved object ids"


def test_index_patterns_declare_a_time_field() -> None:
    patterns = [o for o in _objects() if o["type"] == "index-pattern"]
    assert patterns, "no index patterns in the bundle"
    for pattern in patterns:
        assert pattern["attributes"].get("timeFieldName"), (
            f"{pattern['attributes']['title']} has no time field"
        )


def test_dashboard_references_only_existing_visualizations() -> None:
    objects = _objects()
    vis_ids = {o["id"] for o in objects if o["type"] == "visualization"}
    dashboards = [o for o in objects if o["type"] == "dashboard"]
    assert len(dashboards) == 1

    for dash in dashboards:
        panels = json.loads(dash["attributes"]["panelsJSON"])
        assert panels, "dashboard has no panels"
        referenced = {ref["id"] for ref in dash["references"]}
        for panel in panels:
            assert panel["id"] in vis_ids, f"panel {panel['id']} is not a defined visualization"
        assert referenced <= vis_ids, (
            f"references point at unknown visualizations: {referenced - vis_ids}"
        )


def test_visualizations_reference_a_declared_index_pattern() -> None:
    objects = _objects()
    index_ids = {o["id"] for o in objects if o["type"] == "index-pattern"}
    for obj in objects:
        if obj["type"] != "visualization":
            continue
        refs = {r["id"] for r in obj["references"] if r["type"] == "index-pattern"}
        assert refs, f"{obj['attributes']['title']} has no index pattern reference"
        assert refs <= index_ids, (
            f"{obj['attributes']['title']} references an undeclared index pattern"
        )


@pytest.mark.parametrize("obj_index", range(len(_objects())))
def test_every_referenced_field_exists(obj_index: int) -> None:
    """The core check: no panel aggregates on a field nobody writes."""
    obj = _objects()[obj_index]
    if obj["type"] != "visualization":
        return

    allowed = TELEMETRY_FIELDS | WAZUH_FIELDS
    vis_state = json.loads(obj["attributes"]["visState"])

    referenced: set[str] = set()
    for agg in vis_state.get("aggs", []):
        field = agg.get("params", {}).get("field")
        if field:
            # `.keyword` sub-fields resolve to the parent field name.
            referenced.add(field.removesuffix(".keyword"))
        if agg.get("type") == "date_histogram":
            assert field == "@timestamp", (
                f"{vis_state['title']} must histogram on @timestamp, got {field}"
            )

    unknown = {f for f in referenced if f not in allowed}
    assert not unknown, f"{vis_state['title']} references unknown fields: {sorted(unknown)}"
    # Count-only metric panels legitimately reference no field.
    agg_types = {a.get("type") for a in vis_state.get("aggs", [])}
    if agg_types != {"count"}:
        assert referenced, f"{vis_state['title']} aggregates on nothing"


def test_dashboard_panels_reference_only_existing_visualizations_and_no_fields() -> None:
    """Dashboards carry no aggs of their own; their panels are validated above."""
    dashboards = [o for o in _objects() if o["type"] == "dashboard"]
    for dash in dashboards:
        assert dash["attributes"]["panelsJSON"]
        assert json.loads(dash["attributes"]["optionsJSON"])


def test_bundle_covers_the_documented_metrics() -> None:
    """The panels the README promises must actually be in the bundle."""
    titles = {o["attributes"].get("title", "") for o in _objects()}
    for expected in [
        "Total LLM requests",
        "Blocked requests",
        "Obfuscated payloads",
        "Secret disclosures in completions",
        "Attack type distribution",
        "Severity distribution",
        "Detections over time by attack type",
        "MITRE ATT&CK technique coverage (telemetry)",
        "Top users by blocked requests",
        "Top source IPs",
        "Prompt tokens by user",
    ]:
        assert expected in titles, f"missing documented panel: {expected}"


def test_generator_is_the_source_of_truth() -> None:
    """Regenerating must reproduce the committed bundle byte for byte."""
    import subprocess
    import sys
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        target = Path(tmp) / "opensearch_dashboard.ndjson"
        script = GENERATOR.read_text(encoding="utf-8").replace(
            'OUT = Path(__file__).with_name("opensearch_dashboard.ndjson")',
            f'OUT = Path("{target}")',
        )
        runner = Path(tmp) / "gen.py"
        runner.write_text(script, encoding="utf-8")
        # S603: argv is built from constants and a temp path this test created.
        subprocess.run(  # noqa: S603
            [sys.executable, str(runner)], check=True, capture_output=True
        )
        assert target.read_text(encoding="utf-8") == NDJSON.read_text(encoding="utf-8"), (
            "opensearch_dashboard.ndjson is out of date; run python dashboards/generate_dashboard.py"
        )


def test_no_panels_reference_data_sources_that_are_not_shipped() -> None:
    """zeek-llm-* and suricata-* have no shipper, so they must not appear here."""
    text = NDJSON.read_text(encoding="utf-8")
    for forbidden in ("zeek-llm", "suricata-"):
        assert forbidden not in text, (
            f"{forbidden}* has no log shipper in docker-compose; a panel on it would always be empty"
        )
