"""Configuration consistency tests.

`.env.example` is documentation that executes. A variable declared there but
read by nothing is worse than an absent one, because changing it appears to do
something and does not. These tests close that gap in both directions.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
ENV_EXAMPLE = ROOT / ".env.example"
COMPOSE = ROOT / "docker-compose.yml"
_EXCLUDED_PARTS = {".git", "node_modules", ".venv", "__pycache__", "docs"}
_CERT_DIR = "config/wazuh_indexer_ssl_certs"
_ILLUSTRATIVE_IMAGES = {"docker.elastic.co/beats/filebeat:8.13.4"}


def _declared_vars() -> dict[str, str]:
    out: dict[str, str] = {}
    for line in ENV_EXAMPLE.read_text(encoding="utf-8").splitlines():
        m = re.match(r"^([A-Z][A-Z0-9_]*)=(.*)$", line)
        if m:
            out[m.group(1)] = m.group(2)
    return out


def _source_files() -> list[Path]:
    exts = {".py", ".yml", ".yaml", ".sh", ".conf", ".xml"}
    return [
        p
        for p in ROOT.rglob("*")
        if p.is_file()
        and p.suffix in exts
        and not _EXCLUDED_PARTS.intersection(p.parts)
        and p.name != ".env.example"
    ]


def _referenced_vars() -> set[str]:
    found: set[str] = set()
    patterns = (
        re.compile(r"os\.(?:environ\.get|getenv)\(\s*[\"']([A-Z][A-Z0-9_]*)"),
        re.compile(r"os\.environ\[\s*[\"']([A-Z][A-Z0-9_]*)"),
        re.compile(r"\$\{([A-Z][A-Z0-9_]*)(?::-[^}]*)?\}"),
        re.compile(r"\$\{?([A-Z][A-Z0-9_]{2,})\}?"),
    )
    for path in _source_files():
        text = path.read_text(encoding="utf-8", errors="ignore")
        for pattern in patterns:
            found.update(pattern.findall(text))
    return found


def _compose() -> dict:
    return yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))


def test_every_declared_variable_is_consumed() -> None:
    dead = sorted(set(_declared_vars()) - _referenced_vars())
    assert not dead, f".env.example declares variables nothing reads: {dead}"


def test_env_example_is_not_empty() -> None:
    assert len(_declared_vars()) >= 15, ".env.example looks truncated"


def test_llm_monitor_forwards_every_proxy_variable() -> None:
    env = _compose()["services"]["llm-monitor"]["environment"]
    forwarded = {line.split("=", 1)[0] for line in env}
    proxy_vars = set()
    for name in ("proxy.py", "classifier.py"):
        text = (ROOT / "llm-monitor" / name).read_text(encoding="utf-8")
        proxy_vars.update(
            re.findall(r"os\.(?:environ\.get|getenv)\(\s*[\"']([A-Z][A-Z0-9_]*)", text)
        )
    assert not sorted(proxy_vars - forwarded)


def test_declared_variables_are_documented_or_forwarded() -> None:
    compose_text = COMPOSE.read_text(encoding="utf-8")
    scripts = "\n".join(
        p.read_text(encoding="utf-8", errors="ignore")
        for p in (ROOT / "scripts").glob("*.py")
    ) + "\n".join(
        p.read_text(encoding="utf-8", errors="ignore")
        for p in (ROOT / "scripts").glob("*.sh")
    )
    monitor = "\n".join(
        (ROOT / "llm-monitor" / n).read_text(encoding="utf-8")
        for n in ("proxy.py", "classifier.py")
    )
    orphaned = [
        var
        for var in _declared_vars()
        if var not in compose_text and var not in scripts and var not in monitor
    ]
    assert not orphaned, f"declared but referenced nowhere: {orphaned}"


def test_every_compose_substitution_has_a_default() -> None:
    text = COMPOSE.read_text(encoding="utf-8")
    missing = re.findall(r"\$\{([A-Z][A-Z0-9_]*)\}", text)
    assert not missing, f"substitutions missing defaults: {sorted(set(missing))}"


def test_every_compose_variable_is_declared() -> None:
    declared = set(_declared_vars())
    compose = _compose()
    pattern = re.compile(r"\$\{([A-Z_][A-Z0-9_]*)(?::?-[^}]*)?\}")
    used: set[str] = set()
    for service in compose["services"].values():
        for entry in service.get("environment") or []:
            if isinstance(entry, str):
                used.update(pattern.findall(entry))
        for port in service.get("ports") or []:
            used.update(pattern.findall(str(port)))
    assert not sorted(used - declared)


def test_compose_defaults_match_env_example() -> None:
    declared = _declared_vars()
    compose = _compose()
    pattern = re.compile(r"\$\{([A-Z_][A-Z0-9_]*):-([^}]*)\}")
    drift = []
    for service_name, service in compose["services"].items():
        for entry in service.get("environment") or []:
            if not isinstance(entry, str):
                continue
            for var, default in pattern.findall(entry):
                if var in declared and declared[var] != default:
                    drift.append(f"{service_name}: {var}={default!r} != {declared[var]!r}")
    assert not drift, "compose defaults disagree with .env.example: " + "; ".join(drift)


def test_compose_images_are_pinned() -> None:
    for name, service in _compose()["services"].items():
        image = service.get("image")
        if image:
            assert not image.endswith((":latest", ":main")), f"{name} is not pinned"
            assert ":" in image, f"{name} has no image tag"


def test_compose_declares_no_duplicate_volumes() -> None:
    compose = _compose()
    names = list(compose["volumes"])
    assert len(names) == len(set(names))
    used = set()
    for service in compose["services"].values():
        for mount in service.get("volumes", []):
            if isinstance(mount, str) and not mount.startswith(("./", "/", "~")):
                used.add(mount.split(":")[0])
    assert used <= set(names)


def test_flag_threshold_is_below_classifier_threshold() -> None:
    declared = _declared_vars()
    assert float(declared["FLAG_THRESHOLD"]) < float(declared["CLASSIFIER_THRESHOLD"])


def test_shipper_registry_is_writable_in_compose() -> None:
    service = _compose()["services"]["log-shipper"]
    mounts = service["volumes"]
    readonly = [m for m in mounts if isinstance(m, str) and m.endswith(":ro")]
    assert any("monitor_logs" in m for m in readonly)
    raw = service["command"]
    command = raw if isinstance(raw, str) else " ".join(raw)
    match = re.search(r"--registry\s+(\S+)", command)
    assert match
    registry = match.group(1)
    for mount in readonly:
        target = mount.split(":")[1]
        assert not registry.startswith(target.rstrip("/") + "/")


def test_healthchecks_exist_for_services_others_depend_on() -> None:
    compose = _compose()
    for name in {"opensearch", "llm-monitor"} & set(compose["services"]):
        assert "healthcheck" in compose["services"][name]


def test_hunt2_window_is_populated_by_the_corpus() -> None:
    import json
    import sys

    declared = _declared_vars()
    floor = float(declared["FLAG_THRESHOLD"])
    block = float(declared["CLASSIFIER_THRESHOLD"])
    monitor = ROOT / "llm-monitor"
    if str(monitor) not in sys.path:
        sys.path.insert(0, str(monitor))
    import classifier

    count = 0
    for path in sorted((ROOT / "datasets").glob("*.jsonl")):
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                score = classifier.classify(json.loads(line)["prompt"]).score
                count += floor <= score < block
    assert count > 0


def test_wazuh_api_credentials_do_not_drift() -> None:
    declared = _declared_vars()
    text = (ROOT / "config" / "wazuh_dashboard" / "wazuh.yml").read_text(encoding="utf-8")
    assert f"username: {declared['WAZUH_API_USER']}" in text
    assert declared["WAZUH_API_PASSWORD"] in text


def test_indexer_credentials_match_the_shipped_hashes() -> None:
    bcrypt = pytest.importorskip("bcrypt", reason="bcrypt not installed")
    declared = _declared_vars()
    text = (ROOT / "config" / "wazuh_indexer" / "internal_users.yml").read_text(encoding="utf-8")
    hashes = dict(re.findall(r'^([a-z_-]+):\s*\n\s*hash:\s*"([^"]+)"', text, re.M))
    for user_var, pass_var in (
        ("WAZUH_INDEXER_USER", "WAZUH_INDEXER_PASSWORD"),
        ("WAZUH_DASHBOARD_USER", "WAZUH_DASHBOARD_PASSWORD"),
    ):
        user = declared[user_var]
        assert user in hashes
        assert bcrypt.checkpw(declared[pass_var].encode(), hashes[user].encode())


def test_wazuh_api_user_is_not_an_indexer_user() -> None:
    declared = _declared_vars()
    text = (ROOT / "config" / "wazuh_indexer" / "internal_users.yml").read_text(encoding="utf-8")
    hashes = dict(re.findall(r'^([a-z_-]+):\s*\n\s*hash:\s*"([^"]+)"', text, re.M))
    assert declared["WAZUH_API_USER"] not in hashes


def test_bind_mount_sources_exist_or_are_generated_certs() -> None:
    missing = []
    for name, service in _compose()["services"].items():
        for mount in service.get("volumes", []):
            if not isinstance(mount, str):
                continue
            src = mount.split(":")[0]
            if not src.startswith("./"):
                continue
            if (ROOT / src[2:]).exists() or src.startswith(f"./{_CERT_DIR}/"):
                continue
            missing.append(f"{name}: {src}")
    assert not missing, f"missing bind mounts: {missing}"


def test_certificate_mounts_reference_generator_outputs() -> None:
    certs = yaml.safe_load((ROOT / "config" / "certs.yml").read_text(encoding="utf-8"))
    nodes = []
    for group in ("indexer", "server", "dashboard"):
        for entry in certs["nodes"].get(group) or []:
            nodes.append(entry["name"])
    expected = {"root-ca.pem", "admin.pem", "admin-key.pem"}
    for node in nodes:
        expected.update({f"{node}.pem", f"{node}-key.pem"})
    unknown = []
    for name, service in _compose()["services"].items():
        for mount in service.get("volumes", []):
            if not isinstance(mount, str):
                continue
            src = mount.split(":")[0]
            if src.startswith(f"./{_CERT_DIR}/") and src.rsplit("/", 1)[-1] not in expected:
                unknown.append(f"{name}: {src}")
    assert not unknown


def test_documented_images_match_the_committed_compose_files() -> None:
    compose_images = set()
    for path in (ROOT / "docker-compose.yml", ROOT / "config" / "generate-indexer-certs.yml"):
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        for service in (data.get("services") or {}).values():
            if service.get("image"):
                compose_images.add(service["image"])
    mentioned = re.compile(r"\b([a-z0-9-]+(?:\.[a-z0-9-]+)+/[a-z0-9._/-]+:[A-Za-z0-9._-]+)\b")
    docs = [ROOT / "README.md", *sorted((ROOT / "docs").glob("*.md"))]
    unknown = []
    for doc in docs:
        for ref in mentioned.findall(doc.read_text(encoding="utf-8")):
            if ref in _ILLUSTRATIVE_IMAGES or ref.endswith((":ro", ":rw")):
                continue
            if ref not in compose_images:
                unknown.append(f"{doc.name}: {ref}")
    assert not unknown, f"documentation references unknown images: {unknown}"


def test_shebang_and_executable_bit_agree() -> None:
    bad = []
    for path in ROOT.rglob("*.py"):
        if any(part in _EXCLUDED_PARTS for part in path.parts):
            continue
        first = path.read_text(encoding="utf-8", errors="ignore").split("\n", 1)[0]
        if first.startswith("#!") and not os.access(path, os.X_OK):
            bad.append(f"{path.relative_to(ROOT)}: has shebang, not executable")
        elif os.access(path, os.X_OK) and not first.startswith("#!"):
            bad.append(f"{path.relative_to(ROOT)}: executable, no shebang")
    for path in ROOT.rglob("*.sh"):
        if any(part in _EXCLUDED_PARTS for part in path.parts):
            continue
        if not os.access(path, os.X_OK):
            bad.append(f"{path.relative_to(ROOT)}: shell script not executable")
    assert not bad, "permission/shebang mismatches:\n  " + "\n  ".join(bad)
