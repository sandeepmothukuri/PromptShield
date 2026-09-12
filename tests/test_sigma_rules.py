from pathlib import Path
import json
import re
import xml.etree.ElementTree as ET

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
SIGMA_DIR = ROOT / "detections" / "sigma"
WAZUH_RULES = ROOT / "detections" / "wazuh" / "local_rules.xml"


def _parse_repo_xml(path: str) -> ET.Element:
    xml_path = ROOT / path
    text = xml_path.read_text(encoding="utf-8")
    return ET.fromstring(text)


RULE_FILES = sorted(p.name for p in SIGMA_DIR.glob("*.yml"))


def _rules() -> dict[str, dict]:
    return {
        name: yaml.safe_load((SIGMA_DIR / name).read_text(encoding="utf-8"))
        for name in RULE_FILES
    }


def test_referenced_lab_scenario_exists(name: str) -> None:
    scenario = _rules()[name].get("metadata", {}).get("lab_scenario")
    assert scenario, f"{name}: metadata.lab_scenario links the rule to a runnable simulation"
    assert (ROOT / scenario).exists(), f"{name}: lab scenario {scenario} does not exist"


def test_no_rule_uses_t1059_011() -> None:
    """T1059.011 is 'Lua' in ATT&CK - it must never be used for prompt injection."""
    for name, rule in _rules().items():
        assert "attack.t1059.011" not in rule["tags"], f"{name} uses T1059.011"
        assert (
            "T1059.011" not in str(rule.get("metadata", {}))
        ), f"{name} references T1059.011"
