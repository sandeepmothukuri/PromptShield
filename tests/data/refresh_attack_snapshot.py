#!/usr/bin/env python3
"""Refresh tests/data/attack_enterprise_snapshot.json from the live MITRE feed.

The snapshot keeps CI hermetic - validation does not need network access - while
remaining auditable. Run this when MITRE publishes a new ATT&CK release, then
review the diff: renamed or retired techniques will show up as changes here and
as failures in tests/test_attack_mappings.py.

    python tests/data/refresh_attack_snapshot.py
"""

from __future__ import annotations

import datetime
import json
import sys
import urllib.request
from pathlib import Path

SOURCE = (
    "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
)
OUT = Path(__file__).with_name("attack_enterprise_snapshot.json")


def main() -> int:
    print(f"fetching {SOURCE}")
    with urllib.request.urlopen(SOURCE, timeout=180) as resp:
        bundle = json.load(resp)

    techniques: dict[str, str] = {}
    tactics: dict[str, str] = {}
    for obj in bundle["objects"]:
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        refs = obj.get("external_references", [])
        if not refs:
            continue
        eid = refs[0].get("external_id")
        if obj.get("type") == "attack-pattern" and eid:
            techniques[eid] = obj["name"]
        elif obj.get("type") == "x-mitre-tactic" and eid:
            tactics[eid] = obj["name"]

    snapshot = {
        "source": SOURCE,
        "generated": datetime.datetime.now(datetime.UTC).date().isoformat(),
        "note": (
            "Snapshot of MITRE ATT&CK Enterprise techniques and tactics. "
            "Refresh with: python tests/data/refresh_attack_snapshot.py"
        ),
        "technique_count": len(techniques),
        "tactic_count": len(tactics),
        "techniques": techniques,
        "tactics": tactics,
    }
    OUT.write_text(json.dumps(snapshot, indent=0, sort_keys=True), encoding="utf-8")
    print(
        f"wrote {OUT.relative_to(OUT.parents[2])}: {len(techniques)} techniques, {len(tactics)} tactics"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
