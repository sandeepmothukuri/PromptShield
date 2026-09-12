"""Configuration consistency tests.

`.env.example` is documentation that executes. A variable declared there but
read by nothing is worse than an absent one, because changing it appears to do
something and does not. These tests close that gap in both directions:

* every declared variable must be consumed by code, compose, or a script;
* every variable compose forwards must be declared, so `.env.example` stays a
  complete description of the tunables;
* every variable compose references must have a default, so the stack starts
  with no `.env` present.
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


def _declared_vars() -> dict[str, str]:
    out: dict[str, str] = {}
    for line in ENV_EXAMPLE.read_text(encoding="utf-8").splitlines():
        m = re.match(r"^([A-Z][A-Z0-9_]*)=(.*)$", line)
        if m:
            out[m.group(1)] = m.group(2)
    return out


def _source_files() -> list[Path]:
    exts = {".py", ".yml", ".yaml", ".sh", ".conf", ".xml"}
    files: list[Path] = []
    for path in ROOT.rglob("*"):
        if not path.is_file() or path.suffix not in exts:
            continue
        if _EXCLUDED_PARTS.intersection(path.parts):
            continue
        if path.name == ".env.example":
            continue
        files.append(path)
    return files


def _referenced_vars() -> set[str]:
    found: set[str] = set()
    patterns = (
        re.compile(r"os\.(?:environ\.get|getenv)\(\s*[\"']([A-Z][A-Z0-9_]*)"),
        re.compile(r"os\.environ\[\s*[\"']([A-Z][A-Z0-9_]*)"),
        re.compile(r"\$\{([A-Z][A-Z0-9_]*)(?::-[^}]*)?\}"),
        re.compile(r"\$\{?([A-Z][A-Z0-9_]{2,})\}?"),
    )
    for path in _source_files():
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for pat in patterns:
            found.update(pat.findall(text))
    return found


def test_every_declared_variable_is_consumed() -> None:
    declared = set(_declared_vars())
    referenced = _referenced_vars()
    dead = sorted(declared - referenced)
    assert not dead, (
        f".env.example declares variables nothing reads: {dead}. "
        "Wire them into docker-compose.yml or the code, or remove them."
    )


def test_env_example_is_not_empty() -> None:
    assert len(_declared_vars()) >= 15, ".env.example looks truncated"


def test_llm_monitor_forwards_every_proxy_variable() -> None:
    compose = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))
    env = compose["services"]["llm-monitor"]["environment"]
    forwarded = {line.split("=", 1)[0] for line in env}

    proxy_vars = set()
    for name in ("proxy.py", "classifier.py"):
        text = (ROOT / "llm-monitor" / name).read_text(encoding="utf-8")
        proxy_vars.update(
            re.findall(r"os\.(?:environ\.get|getenv)\(\s*[\"']([A-Z][A-Z0-9_]*)", text)
        )

    missing = sorted(proxy_vars - forwarded)
    assert not missing, f"llm-monitor does not forward: {missing}"


def test_declared_variables_are_documented_or_forwarded() -> None:
    compose_text = COMPOSE.read_text(encoding="utf-8")
    scripts = "\n".join(
        p.read_text(encoding="utf-8", errors="ignore") for p in (ROOT / "scripts").glob("*.py")
    ) + "\n".join(
        p.read_text(encoding="utf-8", errors="ignore") for p in (ROOT / "scripts").glob("*.sh")
    )
    monitor = "\n".join(
        (ROOT / "llm-monitor" / n).read_text(encoding="utf-8")
        for n in ("proxy.py", "classifier.py")
    )

    orphaned = []
    for var in _declared_vars():
        if var not in compose_text and var not in scripts and var not in monitor:
            orphaned.append(var)
    assert not orphaned, f"declared but referenced nowhere: {orphaned}"


def _compose() -> dict:
    return yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))


def test_every_compose_substitution_has_a_default() -> None:
    text = COMPOSE.read_text(encoding="utf-8")
    without_default = re.findall(r"\$\{([A-Z][A-Z0-9_]*)\}", text)
    assert not without_default, (
        f"substitutions missing a :- default: {sorted(set(without_default))}"
    )


def test_compose_images_are_pinned() -> None:
    for name, svc in _compose()["services"].items():
        image = svc.get("image")
        if not image:
            continue
        assert not image.endswith(":latest"), f"{name} uses :latest"
        assert not image.endswith(":main"), f"{name} uses :main"
        assert ":" in image, f"{name} has no tag at all"


def test_compose_declares_no_duplicate_volumes() -> None:
    compose = _compose()
    names = list(compose["volumes"])
    assert len(names) == len(set(names)), "duplicate volume declaration"
    declared = set(names)
    used = set()
    for svc in compose["services"].values():
        for mount in svc.get("volumes", []):
            if isinstance(mount, str) and not mount.startswith(("./", "/", "~")):
                used.add(mount.split(":")[0])
    assert used <= declared, f"undeclared volumes in use: {sorted(used - declared)}"


def test_flag_threshold_is_below_classifier_threshold() -> None:
    declared = _declared_vars()
    flag = float(declared["FLAG_THRESHOLD"])
    block = float(declared["CLASSIFIER_THRESHOLD"])
    assert flag < block, (
        f"FLAG_THRESHOLD ({flag}) must be strictly below CLASSIFIER_THRESHOLD ({block}) "
        "or the sub-threshold hunt has no window to search"
    )


def test_shipper_registry_is_writable_in_compose() -> None:
    svc = _compose()["services"]["log-shipper"]
    mounts = svc["volumes"]
    readonly = [m for m in mounts if m.endswith(":ro")]
    assert any("monitor_logs" in m for m in readonly), "audit log should be mounted read-only"

    raw = svc["command"]
    command = raw if isinstance(raw, str) else " ".join(raw)
    m = re.search(r"--registry\s+(\S+)", command)
    assert m, "shipper must pass an explicit --registry"
    registry_path = m.group(1)

    for mount in readonly:
        parts = mount.split(":")
        target = parts[1]
        assert not registry_path.startswith(target.rstrip("/") + "/"), (
            f"--registry {registry_path} is inside read-only mount {target}"
        )


def test_healthchecks_exist_for_services_others_depend_on() -> None:
    compose = _compose()
    slow = {"opensearch", "llm-monitor"}
    for name in slow & set(compose["services"]):
        assert "healthcheck" in compose["services"][name], f"{name} has no healthcheck"


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

    in_window = 0
    for path in sorted((ROOT / "datasets").glob("*.jsonl")):
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            score = classifier.classify(json.loads(line)["prompt"]).score
            if floor <= score < block:
                in_window += 1

    assert in_window > 0, (
        f"FLAG_THRESHOLD={floor} / CLASSIFIER_THRESHOLD={block} leaves the hunt-2 "
        "window empty on datasets/. Lower FLAG_THRESHOLD to a score the corpus "
        "actually produces."
    )


def test_wazuh_api_credentials_do_not_drift() -> None:
    declared = _declared_vars()
    wazuh_yml = (ROOT / "config" / "wazuh_dashboard" / "wazuh.yml").read_text(encoding="utf-8")

    api_user = declared["WAZUH_API_USER"]
    api_pass = declared["WAZUH_API_PASSWORD"]

    assert f"username: {api_user}" in wazuh_yml, (
        f"wazuh.yml does not reference WAZUH_API_USER={api_user}"
    )
    assert api_pass in wazuh_yml, (
        "wazuh.yml password does not match WAZUH_API_PASSWORD in .env.example; "
        "the dashboard would fail to authenticate to the manager API"
    )


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
        password = declared[pass_var]
        assert user in hashes, f"{user_var}={user} has no entry in internal_users.yml"
        assert bcrypt.checkpw(password.encode(), hashes[user].encode()), (
            f"{pass_var} does not match the bcrypt hash for {user}"
        )


def test_wazuh_api_user_is_not_an_indexer_user() -> None:
    declared = _declared_vars()
    text = (ROOT / "config" / "wazuh_indexer" / "internal_users.yml").read_text(encoding="utf-8")
    hashes = dict(re.findall(r'^([a-z_-]+):\s*\n\s*hash:\s*"([^"]+)"', text, re.M))
    assert declared["WAZUH_API_USER"] not in hashes, (
        "WAZUH_API_USER now appears in internal_users.yml; the manager API and "
        "the indexer have separate identity stores"
    )


_ILLUSTRATIVE_IMAGES = {
    "docker.elastic.co/beats/filebeat:8.13.4",
}

_CERT_DIR = "config/wazuh_indexer_ssl_certs"


def test_bind_mount_sources_exist_or_are_generated_certs() -> None:
    compose = _compose()
    missing = []
    for name, svc in compose["services"].items():
        for mount in svc.get("volumes", []):
            if not isinstance(mount, str):
                continue
            src = mount.split(":")[0]
            if not src.startswith("./"):
                continue
            path = ROOT / src[2:]
            if path.exists():
                continue
            if src.startswith(f"./{_CERT_DIR}/"):
                continue
            missing.append(f"{name}: {src}")
    assert not missing, (
        "bind-mount sources that do not exist and are not generated certificates: "
        f"{missing}. Docker will create them as directories."
    )


def test_certificate_mounts_reference_generator_outputs() -> None:
    certs_yml = yaml.safe_load((ROOT / "config" / "certs.yml").read_text(encoding="utf-8"))
    nodes: list[str] = []
    for group in ("indexer", "server", "dashboard"):
        for entry in certs_yml["nodes"].get(group) or []:
            nodes.append(entry["name"])

    expected = {"root-ca.pem", "admin.pem", "admin-key.pem"}
    for node in nodes:
        expected.add(f"{node}.pem")
        expected.add(f"{node}-key.pem")

    compose = _compose()
    unknown = []
    for name, svc in compose["services"].items():
        for mount in svc.get("volumes", []):
            if not isinstance(mount, str):
                continue
            src = mount.split(":")[0]
            if not src.startswith(f"./{_CERT_DIR}/"):
                continue
            fname = src.rsplit("/", 1)[-1]
            if fname not in expected:
                unknown.append(f"{name}: {fname}")

    assert not unknown, (
        f"certificate files not produced by the generator: {unknown}. "
        f"Expected one of: {sorted(expected)}"
    )


def test_documented_images_match_the_committed_compose_files() -> None:
    compose_images: set[str] = set()
    for path in (ROOT / "docker-compose.yml", ROOT / "config" / "generate-indexer-certs.yml"):
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        for svc in (data.get("services") or {}).values():
            if svc.get("image"):
                compose_images.add(svc["image"])

    mentioned = re.compile(r"\b([a-z0-9-]+(?:\.[a-z0-9-]+)+/[a-z0-9._/-]+:[A-Za-z0-9._-]+)\b")
    not_a_tag = re.compile(r":(?:ro|rw)$")
    docs = [ROOT / "README.md", *sorted((ROOT / "docs").glob("*.md"))]
    unknown: list[str] = []
    for doc in docs:
        for ref in mentioned.findall(doc.read_text(encoding="utf-8")):
            if not_a_tag.search(ref):
                continue
            if ref in _ILLUSTRATIVE_IMAGES:
                continue
            if ref not in compose_images:
                unknown.append(f"{doc.name}: {ref}")

    assert not unknown, (
        f"documentation references images no compose file uses: {unknown}. "
        f"Compose defines: {sorted(compose_images)}"
    )


def test_shebang_and_executable_bit_agree() -> None:
    bad: list[str] = []
    for path in ROOT.rglob("*.py"):
        if any(part in _EXCLUDED_PARTS for part in path.parts):
            continue
        try:
            first = path.read_text(encoding="utf-8", errors="ignore").split("\n", 1)[0]
        except OSError:
            continue
        has_shebang = first.startswith("#!")
        is_exec = os.access(path, os.X_OK)
        if has_shebang and not is_exec:
            bad.append(f"{path.relative_to(ROOT)}: has shebang, not executable")
        elif is_exec and not has_shebang:
            bad.append(f"{path.relative_to(ROOT)}: executable, no shebang")

    for path in ROOT.rglob("*.sh"):
        if any(part in _EXCLUDED_PARTS for part in path.parts):
            continue
        if not os.access(path, os.X_OK):
            bad.append(f"{path.relative_to(ROOT)}: shell script not executable")

    assert not bad, "permission/shebang mismatches:\n  " + "\n  ".join(bad)


def test_mockups_carry_visible_provenance() -> None:
    bad: list[str] = []
    for name in (
        "dashboard-overview",
        "hunting-query",
        "openwebui",
        "simulation-output",
        "suricata",
        "wazuh-alert",
        "zeek",
    ):
        path = ROOT / "docs" / "img" / f"{name}.svg"
        if not path.exists():
            continue
        text = path.read_text(encoding="utf-8")
        if "Illustrative mockup" not in text:
            bad.append(f"{name}.svg: no visible badge")
        if "<desc>" not in text:
            bad.append(f"{name}.svg: no <desc> element")

    assert not bad, "mockups missing provenance labels:\n  " + "\n  ".join(bad)


def test_mockup_facts_match_the_repository() -> None:
    import re as _re

    suricata = (ROOT / "docs" / "img" / "suricata.svg").read_text(encoding="utf-8")
    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    pinned = _re.search(r"jasonish/suricata:([0-9.]+)", compose)
    assert pinned, "suricata image pin not found in compose"
    assert f"Suricata version {pinned.group(1)}" in suricata, (
        f"suricata.svg does not name the pinned version {pinned.group(1)}"
    )

    rules = (ROOT / "detections" / "suricata" / "promptshield.rules").read_text(encoding="utf-8")
    n_sids = len(_re.findall(r"^alert\b", rules, _re.M))
    assert f"{n_sids} rules loaded" in suricata, (
        f"suricata.svg claims a rule count other than {n_sids}"
    )

    wazuh_xml = (ROOT / "detections" / "wazuh" / "local_rules.xml").read_text(encoding="utf-8")
    real_ids = set(_re.findall(r"<id>(T[0-9.]+)</id>", wazuh_xml))
    alert_svg = (ROOT / "docs" / "img" / "wazuh-alert.svg").read_text(encoding="utf-8")
    shown = set(_re.findall(r">\s*(T\d{4}(?:\.\d{3})?)\s*<", alert_svg))
    assert shown, "no technique IDs found in wazuh-alert.svg"
    assert shown <= real_ids, (
        f"wazuh-alert.svg shows techniques absent from local_rules.xml: {sorted(shown - real_ids)}"
    )


def test_compose_defaults_match_env_example() -> None:
    declared = _declared_vars()
    compose = _compose()
    default_pat = re.compile(r"\$\{([A-Z_][A-Z0-9_]*):-([^}]*)\}")

    drift: list[str] = []
    for name, svc in compose["services"].items():
        for entry in svc.get("environment") or []:
            if not isinstance(entry, str):
                continue
            for var, default in default_pat.findall(entry):
                if var not in declared:
                    continue
                if declared[var] != default:
                    drift.append(
                        f"{name}: {var} defaults to {default!r} in compose "
                        f"but {declared[var]!r} in .env.example"
                    )

    assert not drift, "compose defaults disagree with .env.example:\n  " + "\n  ".join(drift)


def test_every_compose_variable_is_declared() -> None:
    declared = _declared_vars()
    compose = _compose()
    pat = re.compile(r"\$\{([A-Z_][A-Z0-9_]*)(?::?-[^}]*)?\}")

    used: set[str] = set()
    for svc in compose["services"].values():
        for entry in svc.get("environment") or []:
            if isinstance(entry, str):
                used |= set(pat.findall(entry))
        for port in svc.get("ports") or []:
            used |= set(pat.findall(str(port)))

    undeclared = sorted(used - set(declared))
    assert not undeclared, (
        f"compose interpolates variables .env.example does not declare: {undeclared}"
    )


def test_openwebui_routes_through_the_monitor() -> None:
    compose = _compose()
    ui = compose["services"]["openwebui"]
    env = {e.split("=", 1)[0]: e.split("=", 1)[1] for e in ui["environment"]}

    assert "OPENAI_API_BASE_URL" in env, "OpenWebUI has no OpenAI-compatible backend"
    assert "llm-monitor" in env["OPENAI_API_BASE_URL"], (
        f"OpenWebUI does not point at the monitor: {env['OPENAI_API_BASE_URL']}"
    )
    assert env["OPENAI_API_BASE_URL"].endswith("/v1"), (
        "OpenWebUI requires the /v1 suffix on OPENAI_API_BASE_URL"
    )
    assert env.get("ENABLE_OLLAMA_API") == "false", (
        "OpenWebUI can still fall back to a direct, unmonitored Ollama connection"
    )
    assert "OLLAMA_BASE_URL" not in env, (
        "OLLAMA_BASE_URL would give the UI an unmonitored path to the model"
    )

    dep = ui.get("depends_on")
    deps = dep if isinstance(dep, dict) else dict.fromkeys(dep or [])
    assert "llm-monitor" in deps, "OpenWebUI must start after the monitor is healthy"


def test_proxy_exposes_the_endpoints_openwebui_needs() -> None:
    src = (ROOT / "llm-monitor" / "proxy.py").read_text(encoding="utf-8")
    for route in ('"/v1/models"', '"/v1/chat/completions"'):
        assert route in src, f"proxy does not expose {route}"
