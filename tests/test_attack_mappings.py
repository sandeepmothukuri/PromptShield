"""Cross-repository MITRE ATT&CK and OWASP mapping validation.

Every ATT&CK ID anywhere in the repository - Sigma tags, Wazuh rule metadata,
classifier telemetry map, documentation tables - is checked against a snapshot of
the live MITRE ATT&CK feed (tests/data/attack_enterprise_snapshot.json).

This is what stops an invented, retired or semantically wrong technique ID from
reaching the repository, and it is what caught T1059.011 ("Lua") being used for
prompt injection.
"""

from __future__ import annotations

import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "llm-monitor"))

SNAPSHOT = json.loads((ROOT / "tests" / "data" / "attack_enterprise_snapshot.json").read_text())
TECHNIQUES: dict[str, str] = SNAPSHOT["techniques"]
TACTICS: dict[str, str] = SNAPSHOT["tactics"]

# ATLAS techniques are written AML.T0051 and must not be matched as ATT&CK IDs.
TECHNIQUE_RE = re.compile(r"(?<!AML\.)(?<![A-Z])\bT\d{4}(?:\.\d{3})?\b")

# Technique IDs this repository deliberately asserts. Any ID outside this set is
# treated as a failure so new mappings must be reviewed, not slipped in.
APPROVED_TECHNIQUES = {
    "T1027": "Obfuscated jailbreak payloads evade keyword filters",
    "T1059": "The model is the interpreter executing attacker-supplied instructions",
    "T1078": "Abuse of the application's legitimate service identity via tools",
    "T1190": "Unsanitised completion consumed by a public-facing application",
    "T1195.002": "Model artifact integrity failure is a supply-chain compromise",
    "T1499.004": "Expensive-but-valid requests exhaust the application",
    "T1552": "System prompt / completion is an unsecured store of credentials",
    "T1566": "Generation of phishing content, delivery vector not yet chosen",
    "T1566.002": "Injection delivered by a link the agent retrieves",
    "T1588.001": "Requester is acquiring malware capability",
    "T1048.003": "Exfiltration over unencrypted non-C2 protocol (DNS)",
}

# T1059.011 is "Lua" in ATT&CK. It has been used incorrectly for prompt injection
# in the past and must never reappear.
FORBIDDEN_TECHNIQUES = {"T1059.011"}


def _parse_repo_xml(relative: str) -> ET.ElementTree:
    """Parse an XML file that is part of this repository.

    S314 is suppressed deliberately: the input is a version-controlled file from
    this repository, not untrusted external data, so the XML-bomb / entity
    expansion risks the rule guards against do not apply here.
    """
    return ET.parse(ROOT / relative)  # noqa: S314


def _walk_files() -> list[Path]:
    skip = {".git", "__pycache__", "node_modules", ".venv"}
    out = []
    for path in ROOT.rglob("*"):
        if not path.is_file():
            continue
        if any(part in skip for part in path.parts):
            continue
        if path.suffix in {".md", ".yml", ".yaml", ".xml", ".py", ".rules", ".zeek", ".ndjson"}:
            out.append(path)
    return out


@pytest.fixture(scope="module")
def snapshot_is_loaded() -> None:
    assert len(TECHNIQUES) > 600, "ATT&CK snapshot looks truncated"
    assert len(TACTICS) >= 14, "ATT&CK tactic snapshot looks truncated"


def test_snapshot_records_the_t1059_011_fact(snapshot_is_loaded) -> None:
    """Document the reason the forbidden list exists."""
    assert TECHNIQUES["T1059.011"] == "Lua"


# Suffixes an engine actually parses. Prose in a detection directory is not one
# of these, so it is checked as documentation instead.
_ENGINE_PARSED_SUFFIXES = {
    ".yml",
    ".yaml",
    ".xml",
    ".rules",
    ".zeek",
    ".ndjson",
    ".json",
    ".py",
    ".sh",
}


def _strip_comments(path: Path, text: str) -> str:
    """Remove comment content so only machine-read values are inspected.

    A detection asset may legitimately *explain* that a technique is not used.
    Only values the engine actually reads count as a mapping.
    """
    if path.suffix == ".xml":
        return re.sub(r"<!--.*?-->", "", text, flags=re.S)
    if path.suffix in {".yml", ".yaml", ".rules", ".zeek", ".conf", ".sh"}:
        out = []
        for line in text.splitlines():
            stripped = line.lstrip()
            if stripped.startswith("#"):
                continue
            # Trailing comment. Only cut at " #" so a '#' inside a quoted
            # detection string is preserved.
            idx = line.find(" #")
            out.append(line[:idx] if idx >= 0 else line)
        return "\n".join(out)
    return text


def test_t1059_011_is_never_used_as_a_detection_mapping() -> None:
    """T1059.011 is Lua execution and has nothing to do with prompt injection.

    Two distinct guarantees, because an earlier revision of this repository used
    the ID as a catch-all for LLM execution:

    1. It must never appear as a value in a detection asset — Sigma rule, Wazuh
       rule, Suricata signature, Zeek script, classifier, simulation, dashboard
       or hunting query. Comments are stripped first, so a file may explain that
       the ID is *not* used without tripping this.
    2. In prose it may appear only where it is being explained as excluded.
       Every prose occurrence must therefore sit in a sentence that negates it.
    """
    detection_suffixes = {".yml", ".yaml", ".xml", ".rules", ".zeek", ".ndjson"}
    detection_dirs = {"detections", "dashboards", "hunting", "datasets", "atomic_red_team"}

    misused: list[str] = []
    unexplained: list[str] = []

    for path in _walk_files():
        text = path.read_text(encoding="utf-8", errors="ignore")
        if "T1059.011" not in text:
            continue
        rel = path.relative_to(ROOT).as_posix()

        # A file is a detection asset if the engine parses it. Prose that
        # happens to live in a detection directory (e.g. the Atomic Red Team
        # index) is not, and is checked as documentation below.
        is_detection_asset = path.suffix in detection_suffixes or (
            path.suffix in _ENGINE_PARSED_SUFFIXES
            and any(part in detection_dirs for part in path.parts)
        )
        is_classifier = path.name in {"classifier.py", "proxy.py", "langchain_guard.py"}

        if is_detection_asset or is_classifier:
            # Only non-comment content counts as an actual mapping.
            if "T1059.011" in _strip_comments(path, text):
                misused.append(rel)
            continue

        if rel in _T1059_011_EXPLANATORY_FILES:
            # These files exist to document the exclusion. Requiring a negation
            # on every line would fail on the sentence that names the ID's real
            # technique, so the file only has to negate it somewhere.
            low = text.lower()
            if not any(neg in low for neg in _T1059_011_NEGATIONS):
                unexplained.append(f"{rel} (mentions it but never says it is excluded)")
            continue

        if path.suffix not in {".md", ".py"}:
            unexplained.append(f"{rel} (not documentation)")
            continue

        # Anywhere else, every occurrence must be negated in its own sentence.
        for line in text.splitlines():
            if "T1059.011" not in line:
                continue
            low = line.lower()
            if not any(neg in low for neg in _T1059_011_NEGATIONS):
                unexplained.append(f"{rel}: {line.strip()[:100]}")

    assert not misused, f"T1059.011 (Lua) is used as a detection mapping in: {misused}"
    assert not unexplained, f"T1059.011 appears without being explained as excluded: {unexplained}"


# Files whose stated purpose is to record that T1059.011 is the wrong technique.
_T1059_011_EXPLANATORY_FILES = {
    "tests/test_attack_mappings.py",
    "tests/test_sigma_rules.py",
    "docs/mitre-attack-mapping.md",
}


# Words that mark a T1059.011 mention as an explanation of why it is not used.
_T1059_011_NEGATIONS = (
    "not",
    "no ",
    "never",
    "must not",
    "nothing to do",
    "instead",
    "wrong",
    "incorrect",
    "excluded",
    "forbidden",
    "removed",
    "do not use",
    "does not",
    "cannot",
)


@pytest.mark.parametrize("tid", sorted(APPROVED_TECHNIQUES))
def test_approved_technique_exists_in_attack(tid: str) -> None:
    assert tid in TECHNIQUES, f"{tid} is not a current ATT&CK Enterprise technique"


def test_every_technique_id_in_the_repository_is_a_real_technique(snapshot_is_loaded) -> None:
    unknown: dict[str, set[str]] = {}
    for path in _walk_files():
        text = path.read_text(encoding="utf-8", errors="ignore")
        for tid in set(TECHNIQUE_RE.findall(text)):
            if tid not in TECHNIQUES:
                unknown.setdefault(tid, set()).add(path.relative_to(ROOT).as_posix())
    assert not unknown, f"non-existent ATT&CK technique IDs referenced: {unknown}"


def _asserted_mappings() -> dict[str, set[str]]:
    """Technique IDs the repository actually asserts, by source file.

    Deliberately limited to structured mapping locations - Sigma tags, Wazuh MITRE
    metadata and the classifier telemetry map. Technique IDs that appear in prose
    (a rationale explaining why a technique is *not* used) or inside an
    attack.mitre.org reference URL are documentation, not mappings.
    """
    mappings: dict[str, set[str]] = {}

    for rule_file in sorted((ROOT / "detections" / "sigma").glob("*.yml")):
        rule = yaml.safe_load(rule_file.read_text(encoding="utf-8"))
        ids = {
            t.split("attack.", 1)[1].upper() for t in rule["tags"] if re.match(r"^attack\.t\d", t)
        }
        mappings[rule_file.relative_to(ROOT).as_posix()] = ids

    tree = _parse_repo_xml("detections/wazuh/local_rules.xml")
    wazuh_ids: set[str] = set()
    for rule in tree.iter("rule"):
        for mitre in rule.findall("mitre/id"):
            wazuh_ids.add((mitre.text or "").strip())
    mappings["detections/wazuh/local_rules.xml"] = wazuh_ids

    from classifier import ATTACK_TYPES

    mappings["llm-monitor/classifier.py"] = {t for t, _ in ATTACK_TYPES.values() if t != "none"}
    return mappings


def test_no_unapproved_technique_is_asserted(snapshot_is_loaded) -> None:
    """New mappings must be added to APPROVED_TECHNIQUES with a justification."""
    unapproved: dict[str, list[str]] = {}
    for source, ids in _asserted_mappings().items():
        for tid in ids:
            if tid not in APPROVED_TECHNIQUES:
                unapproved.setdefault(tid, []).append(source)
    assert not unapproved, (
        "technique IDs asserted without a documented justification: "
        f"{ {k: sorted(v) for k, v in unapproved.items()} }"
    )


def test_suricata_metadata_uses_approved_techniques(snapshot_is_loaded) -> None:
    """Suricata rule metadata also asserts mappings, so it is validated too.

    Only the `mitre ` metadata key is inspected - technique IDs inside
    `reference:url,...` links are documentation, not mappings.
    """
    rules = (ROOT / "detections" / "suricata" / "promptshield.rules").read_text(encoding="utf-8")
    asserted = set(re.findall(r"mitre\s+(T\d{4}(?:\.\d{3})?)", rules))
    assert asserted, "no `mitre` metadata found in the Suricata rules"
    for tid in asserted:
        assert tid in TECHNIQUES, f"suricata: {tid} is not a real ATT&CK technique"
        assert tid in APPROVED_TECHNIQUES, f"suricata: {tid} is not an approved mapping"


def test_suricata_rules_are_well_formed() -> None:
    """Structural checks that stand in for `suricata -T` (no binary in CI)."""
    text = (ROOT / "detections" / "suricata" / "promptshield.rules").read_text(encoding="utf-8")
    body = re.sub(r"\\\n", " ", text)  # join line continuations
    rules = [line for line in body.splitlines() if line.strip().startswith("alert ")]
    assert len(rules) >= 7, f"expected the full signature set, found {len(rules)}"

    sids = []
    for rule in rules:
        assert rule.count("(") == rule.count(")"), f"unbalanced parentheses: {rule[:60]}"
        assert "msg:" in rule and "sid:" in rule and "classtype:" in rule
        assert rule.rstrip().endswith(")"), f"rule does not close its options: {rule[:60]}"

        sid = re.search(r"sid:(\d+);", rule)
        assert sid, f"no sid: {rule[:60]}"
        sids.append(int(sid.group(1)))

        # A response-body match must follow traffic toward the client.
        if "http.response_body" in rule:
            assert "to_client" in rule, f"response_body without to_client: {rule[:60]}"
        if "http.request_body" in rule:
            assert "to_server" in rule, f"request_body without to_server: {rule[:60]}"

    assert len(sids) == len(set(sids)), f"duplicate Suricata SIDs: {sids}"
    assert all(s >= 9000000 for s in sids), "SIDs must stay in the documented 9000000+ range"


def test_documentation_mapping_table_uses_approved_techniques(snapshot_is_loaded) -> None:
    """The ATT&CK column of the mapping doc must only assert approved techniques."""
    doc = (ROOT / "docs" / "mitre-attack-mapping.md").read_text(encoding="utf-8")
    table_ids: set[str] = set()
    for line in doc.splitlines():
        if not line.startswith("|"):
            continue
        # Only the table cells that look like a technique mapping, not prose rows.
        cells = [c.strip() for c in line.strip("|").split("|")]
        for cell in cells:
            if re.fullmatch(r"(?:`)?T\d{4}(?:\.\d{3})?(?:`)?", cell):
                table_ids.add(cell.strip("`"))
    assert table_ids, "mapping doc should contain a technique table"
    bad = {t for t in table_ids if t not in APPROVED_TECHNIQUES}
    assert not bad, f"mapping doc asserts unapproved techniques: {sorted(bad)}"


def test_classifier_attack_type_map_uses_approved_techniques() -> None:
    from classifier import ATTACK_TYPES

    for attack_type, (technique, _severity) in ATTACK_TYPES.items():
        if technique == "none":
            assert attack_type == "benign"
            continue
        assert technique in APPROVED_TECHNIQUES, f"{attack_type} maps to unapproved {technique}"
        assert technique in TECHNIQUES, f"{attack_type} maps to non-existent {technique}"


def test_wazuh_rules_only_use_approved_techniques() -> None:
    tree = _parse_repo_xml("detections/wazuh/local_rules.xml")
    seen: dict[str, list[str]] = {}
    for rule in tree.iter("rule"):
        for mitre in rule.findall("mitre/id"):
            tid = (mitre.text or "").strip()
            assert tid in TECHNIQUES, f"rule {rule.get('id')}: {tid} is not a real technique"
            assert tid in APPROVED_TECHNIQUES, f"rule {rule.get('id')}: {tid} is not approved"
            seen.setdefault(tid, []).append(rule.get("id"))
    assert seen, "no MITRE metadata found in Wazuh rules"


def test_sigma_and_wazuh_techniques_agree() -> None:
    """The Sigma tag and the Wazuh rule for one scenario must name the same technique."""
    wazuh = _parse_repo_xml("detections/wazuh/local_rules.xml")
    wazuh_by_id = {
        r.get("id"): {m.text.strip() for m in r.findall("mitre/id")} for r in wazuh.iter("rule")
    }

    mismatches = []
    for rule_file in sorted((ROOT / "detections" / "sigma").glob("*.yml")):
        rule = yaml.safe_load(rule_file.read_text(encoding="utf-8"))
        wazuh_id = str(rule.get("metadata", {}).get("wazuh_rule_id", ""))
        if not wazuh_id:
            continue
        sigma_techniques = {
            t.split("attack.", 1)[1].upper() for t in rule["tags"] if re.match(r"^attack\.t\d", t)
        }
        # 100110 and 100120 deliberately aggregate several Sigma rules, so require
        # overlap rather than equality for those.
        wazuh_techniques = wazuh_by_id.get(wazuh_id, set())
        if not (sigma_techniques & wazuh_techniques):
            mismatches.append(
                (rule_file.name, sorted(sigma_techniques), wazuh_id, sorted(wazuh_techniques))
            )

    assert not mismatches, f"Sigma/Wazuh technique disagreement: {mismatches}"


def test_classifier_technique_matches_the_sigma_rule_for_the_same_attack_type() -> None:
    """Telemetry `technique`, the Sigma tag and the Wazuh alert must line up."""
    from classifier import ATTACK_TYPES

    by_scenario: dict[str, dict] = {}
    for rule_file in sorted((ROOT / "detections" / "sigma").glob("*.yml")):
        rule = yaml.safe_load(rule_file.read_text(encoding="utf-8"))
        by_scenario[rule_file.name] = rule

    checks = {
        # attack_type -> (sigma rule file, expected technique)
        "prompt_injection": ("prompt_injection_direct.yml", "T1059"),
        "indirect_prompt_injection": ("prompt_injection_indirect_url.yml", "T1566.002"),
        "system_prompt_leak": ("system_prompt_leakage.yml", "T1552"),
        "ai_phishing": ("ai_phishing_generation.yml", "T1566"),
        "malicious_tooling": ("malicious_prompt_patterns.yml", "T1588.001"),
        "insecure_output": ("llm_insecure_output_handling.yml", "T1190"),
        "token_flood": ("llm_token_flood_dos.yml", "T1499.004"),
    }
    for attack_type, (rule_file, technique) in checks.items():
        assert ATTACK_TYPES[attack_type][0] == technique, (
            f"classifier maps {attack_type} to {ATTACK_TYPES[attack_type][0]}, expected {technique}"
        )
        tags = by_scenario[rule_file]["tags"]
        assert f"attack.{technique.lower()}" in tags, f"{rule_file} does not tag {technique}"


def test_owasp_mappings_use_the_2025_list() -> None:
    valid = {f"LLM{i:02d}" for i in range(1, 11)}
    for rule_file in sorted((ROOT / "detections" / "sigma").glob("*.yml")):
        rule = yaml.safe_load(rule_file.read_text(encoding="utf-8"))
        owasp = rule.get("metadata", {}).get("owasp_llm_2025")
        assert owasp in valid or owasp == "none-direct", f"{rule_file.name}: bad OWASP id {owasp}"


def test_tactic_names_in_docs_are_current(snapshot_is_loaded) -> None:
    """ATT&CK v19 renamed TA0005 to Stealth; docs must not say Defense Evasion."""
    doc = (ROOT / "docs" / "mitre-attack-mapping.md").read_text(encoding="utf-8")
    assert "Stealth" in doc, "mapping doc should use the v19.2 tactic name"
    assert "Defense Impairment" in doc, "mapping doc should mention the new TA0112 tactic"


# ---------------------------------------------------------------------------
# Atomic Red Team test definitions
# ---------------------------------------------------------------------------

ART_DIR = ROOT / "simulations" / "atomic_red_team"


def _load_art_files() -> dict[str, dict]:
    return {
        p.name: yaml.safe_load(p.read_text(encoding="utf-8"))
        for p in sorted(ART_DIR.glob("T*.yaml"))
    }


def test_atomic_red_team_files_exist_as_yaml_not_markdown() -> None:
    """Invoke-AtomicRedTeam loads .yaml files, not fenced blocks in prose.

    An earlier revision embedded the definitions in atomic_tests.md, so the
    documented "loadable by Invoke-AtomicRedTeam" claim was false.
    """
    files = list(ART_DIR.glob("T*.yaml"))
    assert files, "no Atomic Red Team YAML files found"

    index = (ART_DIR / "atomic_tests.md").read_text(encoding="utf-8")
    # The index must not still carry the executable definitions inline.
    assert "attack_technique:" not in index, "YAML definitions are still embedded in the markdown"


@pytest.mark.parametrize("name", sorted(p.name for p in ART_DIR.glob("T*.yaml")))
def test_atomic_red_team_file_is_schema_valid(name: str) -> None:
    doc = yaml.safe_load((ART_DIR / name).read_text(encoding="utf-8"))

    assert doc.get("attack_technique"), f"{name}: missing attack_technique"
    assert doc.get("display_name"), f"{name}: missing display_name"
    assert doc.get("atomic_tests"), f"{name}: no atomic_tests"

    # File name must match the technique it declares.
    assert name == f"{doc['attack_technique']}.yaml", f"{name} declares {doc['attack_technique']}"

    for test in doc["atomic_tests"]:
        assert test.get("name"), f"{name}: test without a name"
        assert test.get("description"), f"{name}: {test.get('name')} has no description"
        guid = test.get("auto_generated_guid", "")
        assert re.fullmatch(
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", guid
        ), f"{name}: {test.get('name')} has a malformed guid {guid!r}"
        assert test.get("supported_platforms"), f"{name}: {test['name']} declares no platforms"
        executor = test.get("executor", {})
        assert executor.get("name") in {"sh", "command_prompt", "powershell", "python"}, (
            f"{name}: unsupported executor {executor.get('name')!r}"
        )
        assert executor.get("command"), f"{name}: {test['name']} has no command"


def test_atomic_red_team_guids_are_unique() -> None:
    seen: dict[str, str] = {}
    for name, doc in _load_art_files().items():
        for test in doc["atomic_tests"]:
            guid = test["auto_generated_guid"]
            assert guid not in seen, f"guid {guid} reused in {name} and {seen[guid]}"
            seen[guid] = name
    assert len(seen) >= 6, "expected at least six atomic tests"


@pytest.mark.parametrize("name", sorted(p.name for p in ART_DIR.glob("T*.yaml")))
def test_atomic_red_team_technique_is_real_and_covered_by_sigma(
    name: str, snapshot_is_loaded
) -> None:
    """Every cited technique must exist in ATT&CK and have a Sigma rule.

    This is what prevents the Atomic layer from drifting away from the
    detection layers, which are authored independently.
    """
    doc = yaml.safe_load((ART_DIR / name).read_text(encoding="utf-8"))
    technique = doc["attack_technique"]

    assert technique in TECHNIQUES, (
        f"{name}: {technique} is not a current ATT&CK Enterprise technique"
    )

    sigma_ids = set()
    for rule in (ROOT / "detections" / "sigma").glob("*.yml"):
        text = rule.read_text(encoding="utf-8")
        sigma_ids.update(
            m.upper() for m in re.findall(r"attack\.(t\d{4}(?:\.\d{3})?)", text.lower())
        )

    assert technique in sigma_ids, (
        f"{name}: {technique} has no Sigma rule. Add one under detections/sigma/ "
        f"or remove the Atomic test."
    )


def test_atomic_red_team_commands_target_the_monitor() -> None:
    """Every executor must hit the proxy, or the test proves nothing here."""
    for name, doc in _load_art_files().items():
        for test in doc["atomic_tests"]:
            cmd = test["executor"]["command"]
            assert "8080" in cmd or "simulations/" in cmd, (
                f"{name}: {test['name']} does not target the monitor"
            )


def test_atomic_red_team_does_not_cite_rejected_techniques(snapshot_is_loaded) -> None:
    """Guard the specific mappings that were analysed and rejected."""
    rejected = {
        "T1059.011": "Lua execution, not prompt injection",
        "T1041": "exfiltration over C2, not observed here",
        "T1567": "exfiltration over web service, not observed here",
        "T1566.001": "spearphishing attachment, no delivery mechanism exercised",
        "T1027.013": "encoded file, no file involved",
        "T1499.001": "OS exhaustion, target is the application",
    }
    for name, doc in _load_art_files().items():
        assert doc["attack_technique"] not in rejected, (
            f"{name} cites {doc['attack_technique']}: {rejected[doc['attack_technique']]}"
        )
