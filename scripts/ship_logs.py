#!/usr/bin/env python3
"""Ship the LLM-Monitor audit log into OpenSearch as `promptshield-*`.

The proxy writes one JSON object per line to a local file. Nothing else in the
lab reads that file except the Wazuh manager, so without this shipper the
`promptshield-*` index exists but is never populated and every dashboard panel
bound to it renders empty.

This tails the audit log and bulk-indexes new lines. It is deliberately small
and dependency-free:

    python scripts/ship_logs.py \
        --log /var/log/promptshield/monitor.json \
        --opensearch http://opensearch:9200

Design notes:

* **Registry file.** The byte offset of the last shipped line is persisted, so a
  restart does not re-index the whole history. Deleting the registry forces a
  full re-ship.
* **Rotation.** If the file shrinks below the stored offset it was truncated or
  rotated, so the offset resets to zero rather than skipping to the end.
* **Idempotent document IDs.** The audit event's `event_id` becomes the OpenSearch
  `_id`, so re-shipping a line updates in place instead of duplicating.
* **Partial writes.** A line that fails to parse is skipped and counted, never
  fatal: the proxy may be mid-write when we read.

Field mapping is not applied here. The index template in
`config/opensearch/promptshield-template.json` declares the types; see
`docs/telemetry-schema.md` for what each field means.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

DEFAULT_LOG = "/var/log/promptshield/monitor.json"
DEFAULT_ENDPOINT = "http://opensearch:9200"
DEFAULT_INDEX = "promptshield"
DEFAULT_BATCH = 500


class Shipper:
    def __init__(
        self,
        log_path: Path,
        endpoint: str,
        index: str,
        registry: Path,
        batch_size: int = DEFAULT_BATCH,
        timeout: float = 10.0,
    ) -> None:
        self.log_path = log_path
        self.endpoint = endpoint.rstrip("/")
        self.index = index
        self.registry = registry
        self.batch_size = batch_size
        self.timeout = timeout
        self.shipped = 0
        self.skipped = 0
        # Offset fallback when the registry path is not writable.
        self._memory_offset: int | None = None
        self._registry_writable = True

    # -- registry ---------------------------------------------------------
    def _read_offset(self) -> int:
        # Prefer the persisted value; fall back to the in-memory one when the
        # registry could not be written.
        try:
            return int(self.registry.read_text().strip() or 0)
        except (OSError, ValueError):
            return self._memory_offset or 0

    def _write_offset(self, offset: int) -> None:
        """Persist the offset, degrading to memory-only if the path is unwritable.

        The audit-log volume is mounted read-only into the shipper container, so
        a registry path inside it is not writable. Losing the offset only means
        the log is re-shipped after a restart; because `event_id` is used as the
        document `_id`, re-shipping updates in place rather than duplicating.
        That is wasteful but correct, so it must not be fatal.
        """
        try:
            tmp = self.registry.with_suffix(".tmp")
            tmp.write_text(str(offset))
            tmp.replace(self.registry)
            self._registry_writable = True
        except OSError as exc:
            if self._registry_writable:
                print(
                    f"[ship_logs] cannot persist offset to {self.registry}: {exc}; "
                    "continuing in memory (pass --registry to a writable path)",
                    file=sys.stderr,
                )
                self._registry_writable = False
            self._memory_offset = offset

    # -- bulk -------------------------------------------------------------
    def _bulk(self, events: list[dict]) -> int:
        """Index a batch. Returns the number of documents accepted."""
        lines: list[str] = []
        for ev in events:
            doc_id = ev.get("event_id")
            action = {"index": {"_index": self.index}}
            if doc_id:
                action["index"]["_id"] = str(doc_id)
            lines.append(json.dumps(action))
            lines.append(json.dumps(ev, default=str))
        payload = ("\n".join(lines) + "\n").encode()

        req = urllib.request.Request(  # noqa: S310 - endpoint is an explicit config value
            f"{self.endpoint}/_bulk",
            data=payload,
            headers={"Content-Type": "application/x-ndjson"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # noqa: S310
            body = json.loads(resp.read().decode())

        if body.get("errors"):
            # Report but do not fail the whole batch: a single bad document
            # should not block the rest of the telemetry.
            failed = [
                item["index"].get("error", {}).get("reason", "unknown")
                for item in body.get("items", [])
                if item.get("index", {}).get("status", 200) >= 300
            ]
            print(f"[ship_logs] {len(failed)} document(s) rejected: {failed[:3]}", file=sys.stderr)
            return len(events) - len(failed)
        return len(events)

    # -- tail -------------------------------------------------------------
    def drain_once(self) -> int:
        """Read everything currently available and ship it. Returns lines shipped."""
        if not self.log_path.exists():
            return 0

        offset = self._read_offset()
        size = self.log_path.stat().st_size
        if size < offset:
            print(
                f"[ship_logs] log rotated or truncated ({size} < {offset}); restarting",
                file=sys.stderr,
            )
            offset = 0

        if size == offset:
            return 0

        batch: list[dict] = []
        total = 0
        with self.log_path.open("r", encoding="utf-8", errors="replace") as fh:
            fh.seek(offset)
            for line in fh:
                # A trailing line without a newline is a partial write. Leave it
                # for the next pass by not advancing past it.
                if not line.endswith("\n"):
                    break
                offset += len(line.encode("utf-8", errors="replace"))
                line = line.strip()
                if not line:
                    continue
                try:
                    ev = json.loads(line)
                except json.JSONDecodeError:
                    self.skipped += 1
                    continue
                if not isinstance(ev, dict):
                    self.skipped += 1
                    continue
                batch.append(ev)
                if len(batch) >= self.batch_size:
                    total += self._bulk(batch)
                    batch = []
            if batch:
                total += self._bulk(batch)

        self.shipped += total
        self._write_offset(offset)
        return total

    def run(self, follow: bool, interval: float) -> None:
        while True:
            self.drain_once()
            if not follow:
                break
            time.sleep(interval)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--log", default=os.environ.get("AUDIT_LOG", DEFAULT_LOG))
    ap.add_argument("--opensearch", default=os.environ.get("OPENSEARCH_URL", DEFAULT_ENDPOINT))
    ap.add_argument("--index", default=os.environ.get("INDEX_PREFIX", DEFAULT_INDEX).rstrip("-*"))
    ap.add_argument("--registry", default=None, help="offset file; defaults to <log>.offset")
    ap.add_argument("--batch", type=int, default=DEFAULT_BATCH)
    ap.add_argument("--follow", action="store_true", help="keep tailing instead of one pass")
    ap.add_argument("--interval", type=float, default=5.0)
    ap.add_argument(
        "--ensure-template", action="store_true", help="install the index template first"
    )
    ap.add_argument(
        "--template",
        default=str(
            Path(__file__).resolve().parent.parent
            / "config"
            / "opensearch"
            / "promptshield-template.json"
        ),
    )
    args = ap.parse_args(argv)

    log_path = Path(args.log)
    registry = (
        Path(args.registry) if args.registry else log_path.with_suffix(log_path.suffix + ".offset")
    )
    registry.parent.mkdir(parents=True, exist_ok=True)

    shipper = Shipper(log_path, args.opensearch, args.index, registry, batch_size=args.batch)

    if args.ensure_template:
        tmpl = json.loads(Path(args.template).read_text(encoding="utf-8"))
        name = tmpl.pop("_meta_name", "promptshield")
        req = urllib.request.Request(  # noqa: S310
            f"{shipper.endpoint}/_index_template/{name}",
            data=json.dumps(tmpl).encode(),
            headers={"Content-Type": "application/json"},
            method="PUT",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310
            print(f"[ship_logs] template {name}: HTTP {resp.status}")

    try:
        shipper.run(follow=args.follow, interval=args.interval)
    except KeyboardInterrupt:
        print("[ship_logs] stopped")
    except urllib.error.URLError as exc:
        print(f"[ship_logs] cannot reach {shipper.endpoint}: {exc}", file=sys.stderr)
        return 1

    print(f"[ship_logs] shipped={shipper.shipped} skipped={shipper.skipped} registry={registry}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
