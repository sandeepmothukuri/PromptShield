"""End-to-end tests for the audit-log shipper.

These start a real HTTP server on localhost standing in for OpenSearch, then
drive the actual `Shipper` class against it. Nothing here mocks the shipper's
own logic — the request bodies it produces are inspected on the wire.

The shipper exists because without it `promptshield-*` is created but never
written, and every dashboard panel bound to that pattern renders empty.
"""

from __future__ import annotations

import json
import os
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import ClassVar
from unittest.mock import patch

import pytest

from scripts.ship_logs import Shipper

SCHEMA_FIELDS = {
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
    "completion_truncated",
    "completion_tokens",
}


def make_event(n: int, attack_type: str = "benign") -> dict:
    return {
        "@timestamp": f"2026-09-12T19:{n:02d}:00.000Z",
        "event_id": f"evt-{n:04d}",
        "request_id": f"req-{n:04d}",
        "session_id": "sess-1",
        "user": "tester",
        "source_ip": "127.0.0.1",
        "endpoint": "/chat",
        "provider": "ollama",
        "model": "llama3:8b",
        "prompt": f"prompt number {n}",
        "prompt_hash": f"hash-{n:04d}",
        "prompt_tokens": 10 + n,
        "classifier_score": 0.1,
        "confidence": 0.1,
        "attack_type": attack_type,
        "technique": "none",
        "severity": "informational",
        "detection_reason": "",
        "obfuscated": False,
        "verdict": "allow",
        "response_status": 200,
        "blocked": False,
        "secrets_in_prompt": [],
        "secrets_in_completion": [],
        "completion": "ok",
        "completion_truncated": False,
        "completion_tokens": 2,
    }


class BulkRecorder(BaseHTTPRequestHandler):
    """Captures bulk request bodies so tests can assert on what was sent."""

    # ClassVar: these are shared request-capture buffers, deliberately mutable
    # class state so the fixture can reset them between tests.
    bodies: ClassVar[list[bytes]] = []
    reject_ids: ClassVar[set[str]] = set()

    def log_message(self, *args) -> None:  # silence request logging
        pass

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        type(self).bodies.append(body)

        if self.path.startswith("/_index_template/"):
            self._json(200, {"acknowledged": True})
            return

        # Parse the NDJSON so the test can assert on accepted/rejected docs.
        lines = [ln for ln in body.decode().splitlines() if ln.strip()]
        items = []
        for i in range(0, len(lines), 2):
            action = json.loads(lines[i])
            # lines[i + 1] is the document; the handler only needs the action
            # metadata to decide the response, but the pair must stay aligned.
            json.loads(lines[i + 1])
            doc_id = action["index"].get("_id", "")
            status = 400 if doc_id in type(self).reject_ids else 201
            item = {"index": {"_id": doc_id, "status": status}}
            if status >= 300:
                item["index"]["error"] = {"reason": "mapper_parsing_exception"}
            items.append(item)

        self._json(
            200,
            {"took": 1, "errors": any(i["index"]["status"] >= 300 for i in items), "items": items},
        )

    def _json(self, code: int, payload: dict) -> None:
        raw = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


@pytest.fixture()
def server():
    BulkRecorder.bodies = []
    BulkRecorder.reject_ids = set()
    httpd = HTTPServer(("127.0.0.1", 0), BulkRecorder)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{httpd.server_port}"
    finally:
        httpd.shutdown()
        thread.join(timeout=5)


def write_log(path: Path, events: list[dict]) -> None:
    path.write_text("".join(json.dumps(e) + "\n" for e in events), encoding="utf-8")


def make_shipper(tmp_path: Path, endpoint: str) -> Shipper:
    return Shipper(
        log_path=tmp_path / "monitor.json",
        endpoint=endpoint,
        index="promptshield",
        registry=tmp_path / "monitor.json.offset",
    )


# ---------------------------------------------------------------------------
# Core behaviour
# ---------------------------------------------------------------------------


def test_ships_every_line_as_a_bulk_request(tmp_path: Path, server: str) -> None:
    log = tmp_path / "monitor.json"
    write_log(log, [make_event(i) for i in range(1, 4)])

    shipper = make_shipper(tmp_path, server)
    shipped = shipper.drain_once()

    assert shipped == 3, "all three events should be indexed"
    body = BulkRecorder.bodies[0].decode()
    lines = [ln for ln in body.splitlines() if ln.strip()]
    assert len(lines) == 6, "expected an action line and a document line per event"
    assert body.endswith("\n"), "bulk payload must be newline-terminated"


def test_event_id_is_used_as_the_document_id(tmp_path: Path, server: str) -> None:
    """Re-shipping must update in place rather than duplicate."""
    log = tmp_path / "monitor.json"
    write_log(log, [make_event(1)])

    make_shipper(tmp_path, server).drain_once()

    action = json.loads(BulkRecorder.bodies[0].decode().splitlines()[0])
    assert action["index"]["_id"] == "evt-0001"
    assert action["index"]["_index"] == "promptshield"


def test_registry_prevents_reshipping(tmp_path: Path, server: str) -> None:
    log = tmp_path / "monitor.json"
    write_log(log, [make_event(1), make_event(2)])

    shipper = make_shipper(tmp_path, server)
    assert shipper.drain_once() == 2
    assert shipper.drain_once() == 0, "a second pass over unchanged data ships nothing"
    assert len(BulkRecorder.bodies) == 1


def test_new_lines_after_a_pass_are_shipped(tmp_path: Path, server: str) -> None:
    log = tmp_path / "monitor.json"
    write_log(log, [make_event(1)])

    shipper = make_shipper(tmp_path, server)
    shipper.drain_once()

    with log.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(make_event(2)) + "\n")

    assert shipper.drain_once() == 1


def test_truncated_log_resets_the_offset(tmp_path: Path, server: str) -> None:
    """Rotation must not cause the shipper to skip to the new end."""
    log = tmp_path / "monitor.json"
    write_log(log, [make_event(i) for i in range(1, 4)])

    shipper = make_shipper(tmp_path, server)
    shipper.drain_once()

    write_log(log, [make_event(9)])  # smaller file => rotated
    assert shipper.drain_once() == 1, "rotated log should be re-read from the start"


def test_unparseable_lines_are_skipped_not_fatal(tmp_path: Path, server: str) -> None:
    log = tmp_path / "monitor.json"
    log.write_text(
        json.dumps(make_event(1)) + "\n" + "not json at all\n" + json.dumps(make_event(2)) + "\n",
        encoding="utf-8",
    )

    shipper = make_shipper(tmp_path, server)
    assert shipper.drain_once() == 2
    assert shipper.skipped == 1


def test_partial_trailing_line_is_left_for_the_next_pass(tmp_path: Path, server: str) -> None:
    """The proxy may be mid-write; never index half a JSON object."""
    log = tmp_path / "monitor.json"
    log.write_text(
        json.dumps(make_event(1)) + "\n" + '{"event_id": "evt-0002", "us', encoding="utf-8"
    )

    shipper = make_shipper(tmp_path, server)
    assert shipper.drain_once() == 1

    with log.open("a", encoding="utf-8") as fh:
        fh.write('er": "tester"}\n')

    assert shipper.drain_once() == 1


def test_missing_log_file_is_not_an_error(tmp_path: Path, server: str) -> None:
    shipper = make_shipper(tmp_path, server)
    assert shipper.drain_once() == 0


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------


def test_rejected_documents_are_reported_but_do_not_block_the_batch(
    tmp_path: Path, server: str
) -> None:
    BulkRecorder.reject_ids = {"evt-0002"}
    log = tmp_path / "monitor.json"
    write_log(log, [make_event(1), make_event(2), make_event(3)])

    shipper = make_shipper(tmp_path, server)
    accepted = shipper.drain_once()

    assert accepted == 2, "the two good documents should still count as shipped"


def test_batching_splits_large_backlogs(tmp_path: Path, server: str) -> None:
    log = tmp_path / "monitor.json"
    write_log(log, [make_event(i) for i in range(1, 8)])

    shipper = make_shipper(tmp_path, server)
    shipper.batch_size = 3
    assert shipper.drain_once() == 7
    assert len(BulkRecorder.bodies) == 3, "seven events at batch size 3 is three requests"


# ---------------------------------------------------------------------------
# Contract with the dashboards
# ---------------------------------------------------------------------------


def test_shipped_documents_carry_every_field_the_dashboards_aggregate_on(
    tmp_path: Path, server: str
) -> None:
    """The dashboard panels aggregate on these exact fields.

    If the proxy stops emitting one, the corresponding panel silently renders
    empty, so the contract is asserted here as well as in test_dashboards.py.
    """
    log = tmp_path / "monitor.json"
    write_log(log, [make_event(1)])

    make_shipper(tmp_path, server).drain_once()

    doc = json.loads(BulkRecorder.bodies[0].decode().splitlines()[1])
    dashboard_fields = {
        "request_id",
        "blocked",
        "obfuscated",
        "secrets_in_completion",
        "attack_type",
        "severity",
        "response_status",
        "@timestamp",
        "technique",
        "user",
        "source_ip",
        "prompt_tokens",
    }
    missing = dashboard_fields - set(doc)
    assert not missing, f"shipped document is missing dashboard fields: {missing}"


def test_index_template_declares_every_schema_field() -> None:
    """The mapping must cover the documented schema, or fields land unmapped."""
    template = json.loads(
        (
            Path(__file__).resolve().parent.parent
            / "config"
            / "opensearch"
            / "promptshield-template.json"
        ).read_text()
    )
    mapped = set(template["template"]["mappings"]["properties"])
    assert mapped == SCHEMA_FIELDS, (
        f"template/schema drift. missing={SCHEMA_FIELDS - mapped} extra={mapped - SCHEMA_FIELDS}"
    )


def test_index_template_targets_the_shipped_index_pattern() -> None:
    template = json.loads(
        (
            Path(__file__).resolve().parent.parent
            / "config"
            / "opensearch"
            / "promptshield-template.json"
        ).read_text()
    )
    assert template["index_patterns"] == ["promptshield-*"]
    assert template["template"]["mappings"]["dynamic"] == "false", (
        "dynamic mapping must stay off so an attacker-controlled field name "
        "cannot expand the mapping"
    )


def test_unwritable_registry_degrades_instead_of_crashing(
    tmp_path: Path, server: str
) -> None:
    """The audit volume is mounted read-only, so the default registry is unwritable.

    The offset must fall back to memory rather than raise. Losing it only means
    the log is re-shipped after a restart, which is safe because event_id is the
    document _id.
    """
    log_dir = tmp_path / "ro"
    log_dir.mkdir()
    log = log_dir / "monitor.json"
    log.write_text(json.dumps(make_event(1)) + "\n", encoding="utf-8")

    shipper = Shipper(
        log_path=log,
        endpoint=server,
        index="promptshield",
        registry=log.with_suffix(log.suffix + ".offset"),
    )

    from unittest.mock import patch

    with patch.object(
        Path,
        "write_text",
        side_effect=OSError("simulated read-only registry"),
    ):
        assert shipper.drain_once() == 1, "shipping must still succeed"

    assert shipper._memory_offset is not None, "offset should fall back to memory"

    # A second pass must not re-ship, proving the in-memory offset is used.
    with log.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(make_event(2)) + "\n")

    assert shipper.drain_once() == 1
