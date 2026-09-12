"""Documentation integrity tests.

Guards the claims that are cheapest to get wrong and most embarrassing when
wrong: image paths that do not exist, links to documents that were renamed,
file references in prose that point at deleted code, and capability claims that
describe functionality the repository does not ship.

These tests parse the Markdown rather than rendering it, so they run in CI with
no browser and no Docker.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent

MARKDOWN_FILES = sorted(REPO_ROOT.rglob("*.md"))

# Directories that hold no prose worth link-checking.
_EXCLUDED_PARTS = {".git", "node_modules", ".venv", "__pycache__"}

IMAGE_PATTERN = re.compile(r"!\[(?P<alt>[^\]]*)\]\((?P<path>[^)\s]+)\)")
LINK_PATTERN = re.compile(r"(?<!!)\[(?P<text>[^\]]*)\]\((?P<path>[^)\s]+)\)")
CODE_PATTERN = re.compile(
    r"`(?P<path>[A-Za-z0-9_./-]+\.(?:py|yml|yaml|json|jsonl|xml|zeek|sh|mmd|svg|txt|md|conf))`"
)


def _tracked_markdown() -> list[Path]:
    return [p for p in MARKDOWN_FILES if not _EXCLUDED_PARTS.intersection(p.parts)]


def _is_external(target: str) -> bool:
    return target.startswith(("http://", "https://", "mailto:"))


def _is_anchor_only(target: str) -> bool:
    return target.startswith("#")


# ---------------------------------------------------------------------------
# Images
# ---------------------------------------------------------------------------


def _image_refs() -> list[tuple[Path, str]]:
    refs: list[tuple[Path, str]] = []
    for md in _tracked_markdown():
        for match in IMAGE_PATTERN.finditer(md.read_text(encoding="utf-8")):
            refs.append((md, match.group("path")))
    return refs


@pytest.mark.parametrize("md,path", _image_refs(), ids=lambda v: str(v))
def test_every_image_reference_resolves(md: Path, path: str) -> None:
    """No README or doc may point at an image that is not in the repository."""
    if _is_external(path):
        pytest.skip("external image")
    target = (md.parent / path).resolve()
    assert target.is_file(), f"{md.relative_to(REPO_ROOT)} references missing image {path}"


# Hand-drawn mockups of UI screens. These are illustrations, not diagrams
# rendered from Mermaid, so they have no .mmd source. They must still be named
# in docs/screenshots.md, which test_mockups_are_documented enforces.
MOCKUPS = {
    "dashboard-overview.svg",
    "hunting-query.svg",
    "openwebui.svg",
    "simulation-output.svg",
    "suricata.svg",
    "wazuh-alert.svg",
    "zeek.svg",
    # Redrawn from the CI workflow by hand rather than from a .mmd source.
    "sigma-ci.svg",
}


def test_diagram_sources_exist_for_every_diagram_image() -> None:
    """Every diagram image must have a committed Mermaid source."""
    img_dir = REPO_ROOT / "docs" / "img"
    diagrams_dir = REPO_ROOT / "docs" / "diagrams"
    for svg in sorted(img_dir.glob("*.svg")):
        if svg.name in MOCKUPS:
            continue
        source = diagrams_dir / f"{svg.stem}.mmd"
        assert source.is_file(), (
            f"{svg.name} has no diagram source at {source.relative_to(REPO_ROOT)}"
        )


def test_no_diagram_image_is_orphaned() -> None:
    """A committed diagram that nothing renders or references is dead weight."""
    referenced: set[str] = set()
    for md in _tracked_markdown():
        text = md.read_text(encoding="utf-8")
        for match in IMAGE_PATTERN.finditer(text):
            referenced.add(Path(match.group("path")).name)
        for match in LINK_PATTERN.finditer(text):
            referenced.add(Path(match.group("path")).name)
    for svg in sorted((REPO_ROOT / "docs" / "img").glob("*.svg")):
        if svg.name in MOCKUPS:
            continue
        assert svg.name in referenced, f"{svg.name} is not referenced from any Markdown document"


def test_mockups_are_documented() -> None:
    """A mockup must be named in the provenance page, or it is orphaned.

    Mockups are catalogued in docs/screenshots.md rather than embedded in the
    README, so the image-reference check above does not cover them. Naming them
    there is what keeps the "real vs drawn" distinction discoverable.
    """
    text = (REPO_ROOT / "docs" / "screenshots.md").read_text(encoding="utf-8")
    for name in sorted(MOCKUPS):
        assert name in text, f"{name} is not catalogued in docs/screenshots.md"


# ---------------------------------------------------------------------------
# Links
# ---------------------------------------------------------------------------


def _link_refs() -> list[tuple[Path, str]]:
    refs: list[tuple[Path, str]] = []
    for md in _tracked_markdown():
        for match in LINK_PATTERN.finditer(md.read_text(encoding="utf-8")):
            target = match.group("path")
            if not _is_external(target) and not _is_anchor_only(target):
                refs.append((md, target))
    return refs


@pytest.mark.parametrize("md,path", _link_refs(), ids=lambda v: str(v))
def test_every_internal_link_resolves(md: Path, path: str) -> None:
    """Relative links must point at something that exists."""
    clean = path.split("#", 1)[0]
    if not clean:
        pytest.skip("anchor only")
    target = (md.parent / clean).resolve()
    assert target.exists(), f"{md.relative_to(REPO_ROOT)} links to missing {clean}"


# ---------------------------------------------------------------------------
# Code paths named in prose
# ---------------------------------------------------------------------------


def _code_refs() -> list[tuple[Path, str]]:
    refs: list[tuple[Path, str]] = []
    for md in _tracked_markdown():
        for match in CODE_PATTERN.finditer(md.read_text(encoding="utf-8")):
            candidate = match.group("path")
            # Only check things that look like repo-relative paths, not bare
            # filenames mentioned in passing.
            if "/" in candidate:
                refs.append((md, candidate))
    return refs


# Roots that are filesystem paths inside a container or on a sensor host, not
# paths in this repository. Naming them in prose is correct and expected.
_NON_REPO_ROOTS = (
    "/var/",
    "/wazuh-config-mount/",
    "/etc/",
    "/usr/",
    # Literal path prefix in a skip list, not a temporary file being created.
    "/tmp/",  # noqa: S108
    "/opt/",
)


@pytest.mark.parametrize("md,path", _code_refs(), ids=lambda v: str(v))
def test_every_named_repo_path_exists(md: Path, path: str) -> None:
    """Prose that names `detections/sigma/foo.yml` must not be stale."""
    if path.startswith(_NON_REPO_ROOTS):
        pytest.skip("container or host filesystem path")
    if path.startswith("site/"):
        pytest.skip("Zeek site-relative path, resolved by the sensor image")
    target = (REPO_ROOT / path).resolve()
    if target.exists():
        return
    # Allow paths relative to the document, e.g. `../llm-monitor/classifier.py`.
    rel = (md.parent / path).resolve()
    assert rel.exists(), f"{md.relative_to(REPO_ROOT)} names missing path {path}"


# ---------------------------------------------------------------------------
# Capability claims
# ---------------------------------------------------------------------------

# Phrases that describe functionality this repository does not ship. Each was
# once asserted in documentation while being false in code, so each is checked
# by exact phrase rather than by keyword.
UNSUPPORTED_CLAIMS: dict[str, str] = {
    "converts it to a Wazuh rule": "no Sigma-to-Wazuh conversion pipeline exists",
    "sigma convert": "sigma convert cannot target Wazuh; see docs/architecture.md",
    "transformer-based classifier": "the classifier is a weighted rule engine, not a transformer",
    "LangChain guardrails filter": "langchain_guard.py is not wired into the request path",
    "production-ready": "this is a lab; the claim is not substantiated",
    "enterprise-grade": "marketing language with no defined meaning here",
    "cutting-edge": "marketing language",
}

# Words that turn a phrase above into a correct statement rather than a false
# one, e.g. "`sigma convert` cannot target Wazuh".
_NEGATIONS = ("no ", "not ", "cannot", "can't", "isn't", "never", "without ", "absent", "does not")


def _affirmative_hits(text: str, phrase: str) -> list[str]:
    """Return the phrase where it appears as a claim, not as a correction.

    A mention is treated as a correction when the sentence it sits in negates
    the claim, in either direction:

        "there is no Sigma-to-Wazuh converter"        (negation before)
        "`sigma convert -t opensearch` is not valid"  (negation after)
    """
    hits: list[str] = []
    for line in text.splitlines():
        start = 0
        while True:
            idx = line.lower().find(phrase.lower(), start)
            if idx < 0:
                break
            # Bound the sentence on both sides.
            sentence_start = max(line.rfind(".", 0, idx), line.rfind(";", 0, idx)) + 1
            sentence_end = line.find(".", idx + len(phrase))
            if sentence_end < 0:
                sentence_end = len(line)
            window = line[sentence_start:sentence_end].lower()
            if not any(neg in window for neg in _NEGATIONS):
                hits.append(line.strip())
            start = idx + len(phrase)
    return hits


def _prose_files() -> list[Path]:
    return [p for p in _tracked_markdown() if "docs/captures" not in str(p)]


@pytest.mark.parametrize("md", _prose_files(), ids=lambda p: str(p.relative_to(REPO_ROOT)))
def test_no_unsupported_capability_claims(md: Path) -> None:
    """Documentation must not claim functionality that is not implemented.

    Negated mentions are fine — `docs/architecture.md` correctly states that
    `sigma convert` cannot target Wazuh. Affirmative claims are not.
    """
    text = md.read_text(encoding="utf-8")
    offenders: list[str] = []
    for phrase, why in UNSUPPORTED_CLAIMS.items():
        for line in _affirmative_hits(text, phrase):
            offenders.append(f"{phrase!r} ({why}) in: {line[:120]}")
    assert not offenders, f"{md.relative_to(REPO_ROOT)} makes unsupported claims: {offenders}"


# Attribution patterns. Deliberately narrow: the phrase "AI-generated phishing
# campaign" describes an attack technique and must not be flagged.
ATTRIBUTION_PATTERNS: tuple[str, ...] = (
    "AI-generated by",
    "Generated by ChatGPT",
    "Generated by Claude",
    "Generated by Copilot",
    "Generated by Gemini",
    "Co-authored-by:",
    "Built with ChatGPT",
    "Built with Claude",
    "Written by AI",
    "AI assistant",
)


def test_no_ai_attribution_or_synthetic_authors() -> None:
    """Single-author repository. No AI attribution, no invented contributors."""
    for md in _tracked_markdown():
        text = md.read_text(encoding="utf-8")
        offenders = [b for b in ATTRIBUTION_PATTERNS if b.lower() in text.lower()]
        assert not offenders, f"{md.relative_to(REPO_ROOT)} contains {offenders}"


def test_no_placeholder_markers_left_in_documentation() -> None:
    """TODO/FIXME/TBD in prose is an unfinished promise."""
    markers = re.compile(r"\b(TODO|FIXME|XXX|HACK|TBD)\b")
    for md in _prose_files():
        text = md.read_text(encoding="utf-8")
        # Ignore the postmortem template, where "to be determined" is the point.
        if md.name == "_template_postmortem.md":
            continue
        hits = markers.findall(text)
        assert not hits, f"{md.relative_to(REPO_ROOT)} contains unfinished markers {hits}"


def test_no_broken_todo_markers_in_code() -> None:
    """Same, for source files."""
    markers = re.compile(r"^\s*#\s*(TODO|FIXME|XXX|HACK)\b")
    for path in sorted(REPO_ROOT.rglob("*.py")):
        if _EXCLUDED_PARTS.intersection(path.parts):
            continue
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            assert not markers.match(line), (
                f"{path.relative_to(REPO_ROOT)}:{lineno} has an unfinished marker"
            )


# ---------------------------------------------------------------------------
# Third-party marks
# ---------------------------------------------------------------------------


def test_third_party_organisations_are_not_listed_as_contributors() -> None:
    """Respect trademarks: mention, do not claim."""
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    # These names may appear as product references. They must not appear in a
    # contributors or credits section.
    marks = ["Wazuh", "OpenSearch", "Suricata", "Zeek", "Ollama", "OpenWebUI", "MITRE"]
    credits_section = re.search(
        r"(?im)^##\s*(contributors?|credits?|acknowledge?ments?|thanks)\b(.*?)(?=^##\s|\Z)", readme
    )
    if credits_section is None:
        return
    body = credits_section.group(2)
    claimed = [m for m in marks if m in body]
    assert not claimed, f"README credits section claims third-party marks: {claimed}"


def test_no_implied_endorsement() -> None:
    """Third-party marks may be named, but not claimed as endorsement.

    The README's own disclaimer — "does not claim to be affiliated with any of
    them" — is negated and must not trip this.
    """
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    banned = ["endorsed by", "an official", "in partnership with", "affiliated with"]
    offenders: list[str] = []
    for phrase in banned:
        for line in _affirmative_hits(readme, phrase):
            offenders.append(f"{phrase!r} in: {line.strip()[:120]}")
    assert not offenders, f"README implies endorsement via {offenders}"
