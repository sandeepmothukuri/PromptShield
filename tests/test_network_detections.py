"""Structural tests for the Zeek and Suricata detection assets.

Neither `zeek` nor `suricata` is available in CI, so these tests cannot compile
the assets. They check the properties that are checkable as text, and in
particular the ones that previously failed silently:

* the Zeek script matched only the request URI, so it could never fire against
  an LLM prompt, which is sent as a JSON POST body;
* Suricata signatures were not required to declare a flow direction, so a
  response-body match could be written as a request match.

Both are real defects that a syntax check alone would not catch.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
ZEEK_SCRIPT = ROOT / "detections" / "zeek" / "llm_telemetry.zeek"
SURICATA_RULES = ROOT / "detections" / "suricata" / "promptshield.rules"


@pytest.fixture(scope="module")
def zeek_src() -> str:
    return ZEEK_SCRIPT.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def suricata_lines() -> list[str]:
    """One entry per *logical* rule.

    The shipped file wraps each signature across several physical lines with a
    trailing backslash, so continuation lines must be joined before parsing.
    Treating each physical line as a rule produces nonsense.
    """
    logical: list[str] = []
    buffer = ""
    for raw in SURICATA_RULES.read_text(encoding="utf-8").splitlines():
        line = raw.rstrip()
        if not line.strip() or line.lstrip().startswith("#"):
            if not buffer:
                continue
        if line.endswith("\\"):
            buffer += line[:-1].strip() + " "
            continue
        buffer += line.strip()
        if buffer.strip():
            logical.append(" ".join(buffer.split()))
        buffer = ""
    if buffer.strip():
        logical.append(" ".join(buffer.split()))
    return logical


# ---------------------------------------------------------------------------
# Zeek
# ---------------------------------------------------------------------------


def test_zeek_braces_are_balanced(zeek_src: str) -> None:
    """Cheap proxy for a parse check: unbalanced braces never load."""
    assert zeek_src.count("{") == zeek_src.count("}"), "unbalanced braces"
    assert zeek_src.count("(") == zeek_src.count(")"), "unbalanced parentheses"


def test_zeek_declares_a_log_stream(zeek_src: str) -> None:
    assert "Log::create_stream" in zeek_src
    assert '$path="llm"' in zeek_src, "the documented log file is llm.log"


def test_zeek_matches_the_request_body_not_only_the_uri(zeek_src: str) -> None:
    """The regression this file exists for.

    An LLM prompt arrives in a JSON POST body. A script that only inspects
    `unescaped_URI` logs every request as benign.
    """
    assert "event http_entity_data" in zeek_src, "no request-body handler"
    assert "event http_message_done" in zeek_src, "body is never finalised"

    # The body handler must feed the marker matcher.
    body_handler = zeek_src[zeek_src.index("event http_entity_data") :]
    body_handler = body_handler[: body_handler.index("\nevent ", 10)]
    assert "match_markers" in body_handler, "http_entity_data does not evaluate markers"


def test_zeek_body_accumulation_is_bounded(zeek_src: str) -> None:
    """Unbounded accumulation turns a token flood into a memory problem."""
    assert "max_body_bytes" in zeek_src
    assert re.search(r"max_body_bytes\s*:\s*count\s*=\s*\d+", zeek_src)
    assert "&redef" in zeek_src


def test_zeek_state_is_cleaned_up_per_connection(zeek_src: str) -> None:
    """Accumulation state must not leak across connections."""
    assert "delete states[c$uid]" in zeek_src
    assert "event connection_state_remove" in zeek_src, "no fallback cleanup handler"


def test_zeek_host_matching_tolerates_a_port(zeek_src: str) -> None:
    """The proxy is reached as `llm-monitor:8080`, not bare `llm-monitor`."""
    assert "strip_port" in zeek_src
    # Both request and reply paths must use it.
    assert zeek_src.count("strip_port(") >= 3, "strip_port must be defined and used in both paths"


def test_zeek_markers_are_lowercase(zeek_src: str) -> None:
    """Matching lowercases the haystack, so an uppercase marker never fires."""
    block = zeek_src[zeek_src.index("injection_markers") :]
    block = block[: block.index("} &redef;")]
    markers = re.findall(r'"([^"]+)"', block)
    assert markers, "no markers found"
    bad = [m for m in markers if m != m.lower()]
    assert not bad, f"markers must be lowercase to match a lowercased haystack: {bad}"


def test_zeek_extensibility_points_are_redefable(zeek_src: str) -> None:
    """Operators extend the script from site/local.zeek without editing it."""
    assert "global llm_hosts" in zeek_src
    assert "global injection_markers" in zeek_src
    assert zeek_src.count("&redef") >= 3


def test_zeek_documented_fields_are_all_declared(zeek_src: str) -> None:
    """docs/network-detection.md documents the llm.log columns."""
    documented = {
        "ts",
        "uid",
        "id_orig_h",
        "id_resp_h",
        "host",
        "uri",
        "method",
        "status_code",
        "body_len",
        "suspicious",
        "reason",
    }
    record = zeek_src[zeek_src.index("type Info: record {") :]
    record = record[: record.index("};")]
    declared = set(re.findall(r"^\s{8}(\w+):", record, re.M))
    missing = documented - declared
    assert not missing, f"documented but not declared in Info: {missing}"


# ---------------------------------------------------------------------------
# Suricata
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def parsed_rules(suricata_lines: list[str]) -> list[dict]:
    out = []
    for ln in suricata_lines:
        header, _, options = ln.partition("(")
        # header is "alert http any any -> any any"; the addressing tuple is not
        # asserted here, only the action and protocol.
        action, proto, *_addressing = header.split()
        opts = {}
        for part in re.findall(r'([a-z_.]+):\s*"?([^;"]*)"?', options.rstrip(")")):
            opts.setdefault(part[0], []).append(part[1].strip())
        out.append({"raw": ln, "action": action, "proto": proto, "opts": opts})
    return out


def test_suricata_rules_exist(parsed_rules: list[dict]) -> None:
    assert len(parsed_rules) == 7, f"expected 7 signatures, found {len(parsed_rules)}"


def test_suricata_sids_are_unique_and_in_range(parsed_rules: list[dict]) -> None:
    sids = [int(r["opts"]["sid"][0]) for r in parsed_rules]
    assert len(sids) == len(set(sids)), "duplicate SID"
    for sid in sids:
        assert 9000001 <= sid <= 9000099, f"SID {sid} outside the documented lab range"


def test_suricata_every_rule_has_required_metadata(parsed_rules: list[dict]) -> None:
    for r in parsed_rules:
        for key in ("sid", "rev", "msg"):
            assert key in r["opts"], f"{r['raw'][:60]} missing {key}"
        assert "classtype" in r["opts"], f"SID {r['opts']['sid'][0]} missing classtype"


def test_suricata_rules_declare_flow_direction(parsed_rules: list[dict]) -> None:
    """A content match without flow can fire on the wrong direction."""
    for r in parsed_rules:
        if "content" in r["opts"]:
            assert "flow" in r["opts"], f"SID {r['opts']['sid'][0]} matches content without flow"


def test_suricata_mitre_metadata_uses_real_techniques(parsed_rules: list[dict]) -> None:
    """The `metadata: mitre ...` pairs are what the mapping tests read."""
    from tests.test_attack_mappings import TECHNIQUES

    seen: set[str] = set()
    for r in parsed_rules:
        for value in r["opts"].get("metadata", []):
            # Metadata is a comma-separated list, so tokens carry trailing
            # commas; strip punctuation before matching an ID.
            for tok in (t.strip(",;") for t in value.split()):
                if re.fullmatch(r"T\d{4}(?:\.\d{3})?", tok):
                    assert tok in TECHNIQUES, f"SID {r['opts']['sid'][0]} cites unknown {tok}"
                    seen.add(tok)
    assert seen, "no ATT&CK technique metadata found on any signature"


def test_suricata_technique_metadata_matches_the_sigma_rules(parsed_rules: list[dict]) -> None:
    """Both layers must cite real techniques, and layer-specific ones must be declared.

    Suricata sees the wire, so it legitimately covers techniques that are
    invisible in the proxy audit log — DNS exfiltration is the clear case. The
    Sigma rules see the audit log, so they cover attack types that never touch
    the network. Neither set is a subset of the other.

    What this test enforces is that any technique cited by only one layer is
    explicitly declared below, so an accidental citation cannot slip in
    unexplained.
    """
    from tests.test_attack_mappings import TECHNIQUES

    suricata_ids = set()
    for r in parsed_rules:
        for value in r["opts"].get("metadata", []):
            for tok in (t.strip(",;") for t in value.split()):
                if re.fullmatch(r"T\d{4}(?:\.\d{3})?", tok):
                    assert tok in TECHNIQUES, f"SID {r['opts']['sid'][0]} cites unknown {tok}"
                    suricata_ids.add(tok)
    assert suricata_ids, "no technique metadata parsed from Suricata rules"

    sigma_ids = set()
    for rule in (ROOT / "detections" / "sigma").glob("*.yml"):
        text = rule.read_text(encoding="utf-8")
        sigma_ids.update(
            m.upper() for m in re.findall(r"attack\.(t\d{4}(?:\.\d{3})?)", text.lower())
        )

    # Visible only on the wire: hex-encoded DNS queries. The audit log never
    # sees them, so no Sigma rule can cover this. The corresponding Sigma rule
    # is documented as planned in ROADMAP.md, pending indexed Zeek DNS logs.
    wire_only = {"T1048.003"}
    # Visible only in the audit log: prompt content, obfuscation, token volume,
    # model output. No packet carries these once TLS is in play.
    log_only = {"T1059", "T1027", "T1552", "T1566", "T1566.002", "T1588.001", "T1499.004", "T1190"}

    unexplained_wire = suricata_ids - sigma_ids - wire_only
    assert not unexplained_wire, (
        f"Suricata cites techniques no Sigma rule covers and that are not declared "
        f"wire-only: {sorted(unexplained_wire)}"
    )

    unexplained_log = sigma_ids - suricata_ids - log_only
    assert not unexplained_log, (
        f"Sigma cites techniques no Suricata signature covers and that are not "
        f"declared log-only: {sorted(unexplained_log)}"
    )

    overlap = suricata_ids & sigma_ids
    assert overlap, "the two detection layers share no technique, which suggests drift"


def test_suricata_no_rule_is_disabled(parsed_rules: list[dict]) -> None:
    """Every shipped signature must be an alert, not a comment or a pass rule."""
    for r in parsed_rules:
        assert r["action"] == "alert", f"unexpected action {r['action']!r}"


def test_suricata_rules_load_only_promptshield_signatures(suricata_lines: list[str]) -> None:
    """Compose launches with -S, which replaces ET-open. Document the scope."""
    assert all("9000" in ln for ln in suricata_lines), "unexpected SID outside the lab block"
