"""Prompt and completion classifier for the PromptShield LLM-Monitor.

The classifier is deliberately dependency-free so the lab boots without model
downloads. It is *not* a single string match: every request is normalised,
de-obfuscated, and scored by accumulating weighted indicators, so a payload that
combines two weak signals still crosses the block threshold.

Pipeline
--------
1. ``normalise``   - lowercase, collapse whitespace, strip zero-width characters.
2. ``deobfuscate`` - decode base64 / ROT13 / hex-escape blobs found inline, so
                     encoded payloads are scored on their plaintext too.
3. ``classify``    - run indicator groups over both the raw and the decoded text,
                     sum weights per attack type, return the strongest.

Scoring is capped at 1.0. A single strong indicator (weight 0.9) already exceeds
the default 0.65 block threshold; weaker indicators need to combine.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import os
import re
import unicodedata
from dataclasses import dataclass, field

# Attack type -> (MITRE ATT&CK technique, severity). The technique values are the
# same IDs tagged on the Sigma rules in detections/sigma/ so that telemetry,
# detection-as-code and alert metadata stay consistent.
ATTACK_TYPES: dict[str, tuple[str, str]] = {
    "prompt_injection": ("T1059", "high"),
    "indirect_prompt_injection": ("T1566.002", "high"),
    "jailbreak": ("T1059", "high"),
    "system_prompt_leak": ("T1552", "critical"),
    "data_exfiltration": ("T1552", "critical"),
    "ai_phishing": ("T1566", "high"),
    "malicious_tooling": ("T1588.001", "medium"),
    "token_flood": ("T1499.004", "high"),
    "insecure_output": ("T1190", "high"),
    "benign": ("none", "informational"),
}

# Weight 0.9 = one match is sufficient to block at the default threshold.
# Weight 0.45-0.55 = corroborating evidence; two matches block.
INDICATORS: dict[str, list[tuple[str, float]]] = {
    "prompt_injection": [
        (
            r"ignore (?:all |any )?(?:previous|prior|the above|above|earlier) (?:instructions|rules|context|messages)",
            0.9,
        ),
        (r"disregard (?:all\s+)?(?:prior|previous|earlier)?\s*(?:instructions|context|rules)", 0.9),
        (r"override your system prompt", 0.9),
        (r"ignore (?:all |any )?(?:the )?above\b", 0.8),
        (r"act as an unrestricted assistant", 0.7),
        (r"forget (?:your|all|any|previous|prior) instructions", 0.9),
        (r"discard previous guidance", 0.8),
        (r"new directive\s*:", 0.55),
        (r"(?:disclose|reveal|list) (?:the )?internal (?:api|endpoint|config)", 0.35),
        (r"ignore all rules", 0.9),
        (r"safety rules are suspended", 0.7),
        (r"you are now an unrestricted assistant", 0.7),
        (r"from now on,? (?:ignore|answer freely)", 0.6),
    ],
    "indirect_prompt_injection": [
        (
            r"(?:fetch|browse to|open|read|retrieve|summarize)\s+(?:this\s+)?(?:the\s+)?(?:contents of\s+)?https?://",
            0.3,
        ),
        (r"follow (?:any |the )?instructions (?:inside|in|found|therein)", 0.9),
        (r"do whatever the (?:page|document|email) says", 0.9),
        (r"execute the steps in the document", 0.8),
        (r"act on any instructions found", 0.9),
    ],
    "jailbreak": [
        (r"\bdan mode\b", 0.9),
        (r"\byou are now dan\b", 0.9),
        (r"\bdan can do anything\b", 0.9),
        (r"\bdo anything now\b", 0.9),
        (r"\baim model\b", 0.9),
        (r"\bstan:\s*strive to avoid norms\b", 0.9),
        (r"\bduke mode\b", 0.9),
        (r"\bunfiltered ai\b", 0.8),
        (r"\bdeveloper mode enabled\b", 0.8),
        (r"\bjailbreak prompt\b", 0.9),
        (r"hypothetically speaking, how would one", 0.55),
        (r"in a fictional world where", 0.5),
        (r"for educational purposes only, explain how to", 0.55),
        (r"(?:defeat|bypass|crack) (?:a |the )?(?:licence|license) check", 0.35),
        (r"where filters do not exist", 0.3),
        (r"(?:has |with )?no safety guidelines", 0.3),
        (r"roleplay as a (?:black-?hat )?hacker", 0.6),
        (r"you are a security researcher with no restrictions", 0.7),
        (
            r"pretend you (?:are an ai|have) (?:without any )?(?:restrictions|no safety guidelines)",
            0.8,
        ),
        # Control-bypass targets. Weak on their own, decisive when combined with
        # hypothetical/role-play framing above.
        (
            r"bypass (?:a |the )?(?:corporate )?(?:firewall|proxy|filter|safeguard|restriction)s?",
            0.35,
        ),
        (r"circumvent (?:the |our )?(?:security )?controls?", 0.35),
        (r"without (?:any )?(?:safety|ethical) (?:constraints|guardrails)", 0.4),
    ],
    "system_prompt_leak": [
        (r"repeat the words above starting with", 0.9),
        (r"print (?:the )?(?:text|prompt) above verbatim", 0.9),
        (r"what (?:are|were) your initial instructions", 0.9),
        (r"output the prompt that defined you", 0.9),
        (r"summarize the system message", 0.8),
        (r"reveal your system prompt", 0.9),
        (r"print your initial instructions", 0.9),
        (r"what were you told before this conversation", 0.9),
        (r"list the tools you have access to", 0.55),
    ],
    "data_exfiltration": [
        (r"\bexfiltrate\b", 0.8),
        (
            r"(?:exfiltrate|leak|dump|send|transmit).{0,80}(?:records|data|keys|credentials|emails|secrets|memo)",
            0.7,
        ),
        (r"encode the file contents in base64", 0.7),
        (r"send .{0,80}? to https?://", 0.7),
        (r"(?:summarize|repeat|echo).{0,40}including any keys", 0.7),
        (r"output the contents of /etc/(?:passwd|shadow)", 0.7),
        (r"(?:leak|dump|print) (?:the )?(?:customer|user) (?:data|records|emails)", 0.7),
    ],
    "ai_phishing": [
        (r"write a phishing email", 0.9),
        (r"write an email pretending to be", 0.8),
        (r"draft a convincing phishing", 0.9),
        (r"create a login page that looks like", 0.85),
        (r"clone the microsoft 365 sign-?in", 0.9),
        (r"craft a smishing message", 0.9),
        (r"write a fake invoice email", 0.8),
        (r"impersonate the ceo", 0.6),
        (r"pretending to be fedex", 0.6),
        (r"verify your password immediately", 0.5),
        (r"urgent (?:email|message|notice) from it support", 0.7),
        (r"requiring users to verify their password", 0.7),
        (r"from it support requiring", 0.6),
    ],
    "malicious_tooling": [
        (r"write ransomware in", 0.9),
        (r"(?:generate|give me|write|provide) a? ?reverse shell", 0.9),
        (r"powershell empire payload", 0.9),
        (r"metasploit module that", 0.9),
        (r"process hollowing example", 0.8),
        (r"create a keylogger in", 0.9),
        (r"write a crypter that", 0.9),
        (r"bypass edr using", 0.9),
        (r"evade amsi", 0.9),
        (r"disable windows defender from powershell", 0.8),
        (r"unhook etw", 0.8),
        (r"enumerate active directory", 0.55),
        (r"kerberoast script", 0.8),
        (r"mimikatz alternative in", 0.8),
        (r"dump lsass without", 0.8),
    ],
}

# Completion-side indicators: unsafe content leaving the model.
OUTPUT_INDICATORS: list[tuple[str, float]] = [
    (r"<\s*script[^>]*>", 0.85),
    (r"<\s*img[^>]+onerror\s*=", 0.9),
    (r"<\s*(?:svg|iframe|object|embed)[^>]+on(?:load|error|click)\s*=", 0.9),
    (r"javascript\s*:\s*[a-z]", 0.8),
    (r"(?:union\s+select|;\s*drop\s+table|'\s*or\s+1\s*=\s*1)", 0.85),
    (r"(?:\|\||;)\s*(?:curl|wget|nc|bash|sh)\s+", 0.6),
]

SECRET_PATTERNS: list[tuple[str, str]] = [
    (r"AKIA[0-9A-Z]{16}", "aws_access_key_id"),
    (r"(?i)aws_secret_access_key\s*[:=]\s*[A-Za-z0-9/+=]{40}", "aws_secret_access_key"),
    (r"AIza[0-9A-Za-z\-_]{35}", "google_api_key"),
    (r"sk-[A-Za-z0-9]{32,}", "openai_style_key"),
    (r"ghp_[A-Za-z0-9]{36}", "github_pat"),
    (r"github_pat_[A-Za-z0-9_]{20,}", "github_fine_grained_pat"),
    (r"xox[baprs]-[A-Za-z0-9-]{10,}", "slack_token"),
    (r"-----BEGIN [A-Z ]*PRIVATE KEY-----", "private_key"),
    (r"\b\d{3}-\d{2}-\d{4}\b", "us_ssn"),
    (r"\b4[0-9]{12}(?:[0-9]{3})?\b", "payment_card"),
]

_ZERO_WIDTH = dict.fromkeys(map(ord, "\u200b\u200c\u200d\u2060\ufeff"))
_BASE64_RE = re.compile(r"(?i)\b[a-z0-9+/]{24,}={0,2}")
_HEX_RE = re.compile(r"(?:\\x[0-9a-fA-F]{2}){3,}")

TECHNIQUE_OBFUSCATION = "T1027"

# Reporting floor. Scores at or above this are recorded in `classifier_score`
# and `detection_reason` for hunting, but are reported as attack_type="benign"
# when below CLASSIFIER_THRESHOLD so that dashboards counting attack types are
# not polluted by weak single-indicator matches.
#
# This is a separate variable from CLASSIFIER_THRESHOLD on purpose: the gap
# between them is the window hunt 2 ("Sub-threshold probing") searches. If both
# read the same value that hunt has nothing to find, so they are configured
# independently and validated at import time.
FLAG_THRESHOLD = float(os.getenv("FLAG_THRESHOLD", os.getenv("CLASSIFIER_THRESHOLD", "0.65")))


@dataclass
class Classification:
    """Result of scoring one prompt (and optionally its completion)."""

    score: float
    attack_type: str
    technique: str
    severity: str
    reasons: list[str] = field(default_factory=list)
    obfuscated: bool = False
    confidence: float = 0.0

    @property
    def is_malicious(self) -> bool:
        return self.attack_type != "benign"


def normalise(text: str) -> str:
    """Lowercase, strip zero-width characters, collapse whitespace."""
    text = unicodedata.normalize("NFKC", text)
    text = text.translate(_ZERO_WIDTH)
    text = re.sub(r"\s+", " ", text)
    return text.strip().lower()


def _try_base64(blob: str) -> str | None:
    # The scanner may capture a blob without its "=" padding, so restore it.
    padded = blob + "=" * (-len(blob) % 4)
    try:
        decoded = base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError):
        return None
    try:
        text = decoded.decode("utf-8")
    except UnicodeDecodeError:
        return None
    printable = sum(ch.isprintable() or ch.isspace() for ch in text)
    if not text or printable / len(text) < 0.85:
        return None
    return text


def deobfuscate(text: str) -> tuple[str, bool]:
    """Return (decoded_text, was_obfuscated).

    Decodes inline base64 blobs, ``\\xHH`` hex escapes and ``rot13:`` markers so
    that encoded payloads are scored on their plaintext form as well as their
    literal form.
    """
    decoded_parts: list[str] = []
    obfuscated = False

    for blob in _BASE64_RE.findall(text):
        plain = _try_base64(blob)
        if plain and re.search(r"[a-z]{4}", plain.lower()):
            decoded_parts.append(plain)
            obfuscated = True

    for run in _HEX_RE.findall(text):
        try:
            plain = binascii.unhexlify(run.replace("\\x", "")).decode("utf-8", "ignore")
        except (binascii.Error, ValueError):
            continue
        if re.search(r"[a-z]{3}", plain.lower()):
            decoded_parts.append(plain)
            obfuscated = True

    lowered = text.lower()
    if "rot13" in lowered:
        decoded_parts.append(codecs.decode(text, "rot_13"))
        obfuscated = True

    if re.search(r"(?:decode|decrypt|translate).{0,40}(?:base64|rot13|hex|leetspeak)", lowered):
        obfuscated = True

    # Join with a space, not a newline: attackers frequently hex-encode each word
    # separately, and a space reassembles the original plaintext.
    return " ".join(decoded_parts), obfuscated


def _score_text(text: str) -> tuple[dict[str, float], dict[str, list[str]]]:
    scores: dict[str, float] = {}
    hits: dict[str, list[str]] = {}
    for attack_type, patterns in INDICATORS.items():
        for pattern, weight in patterns:
            if re.search(pattern, text):
                scores[attack_type] = scores.get(attack_type, 0.0) + weight
                hits.setdefault(attack_type, []).append(pattern)
    return scores, hits


def scan_secrets(text: str) -> list[str]:
    """Return the names of credential/PII patterns present in ``text``."""
    return [name for pattern, name in SECRET_PATTERNS if re.search(pattern, text)]


def scan_output(completion: str) -> tuple[float, list[str]]:
    """Score a model completion for unsafe content. Returns (score, reasons)."""
    text = normalise(completion)
    score = 0.0
    reasons: list[str] = []
    for pattern, weight in OUTPUT_INDICATORS:
        if re.search(pattern, text):
            score += weight
            reasons.append(pattern)
    return min(score, 1.0), reasons


def classify(prompt: str, completion: str = "") -> Classification:
    """Score a request. The strongest attack type wins; weights accumulate."""
    # De-obfuscate BEFORE lowercasing: base64 and hex payloads are
    # case-sensitive, so normalising first would corrupt them.
    decoded, obfuscated = deobfuscate(prompt)
    raw = normalise(prompt)
    haystack = f"{raw}\n{normalise(decoded)}" if decoded else raw

    scores, hits = _score_text(haystack)

    attack_type = max(scores, key=lambda k: scores[k]) if scores else "benign"
    score = min(scores.get(attack_type, 0.0), 1.0)
    reasons = list(hits.get(attack_type, []))

    if score == 0.0 and completion:
        out_score, out_reasons = scan_output(completion)
        if out_score >= 0.6:
            attack_type, score, reasons = "insecure_output", out_score, out_reasons

    if score == 0.0 and len(prompt) > 32_000:
        attack_type, score = "token_flood", 0.7
        reasons = ["prompt_length_gt_32k_chars"]

    if obfuscated and attack_type != "benign":
        reasons.append("obfuscated_payload")

    if attack_type != "benign" and score < FLAG_THRESHOLD:
        # Weak signal: keep the evidence, do not assert an attack type.
        reasons.insert(0, f"below_threshold:{attack_type}")
        attack_type = "benign"

    technique, severity = ATTACK_TYPES[attack_type]
    if obfuscated and attack_type in {"jailbreak", "prompt_injection"}:
        # Encoded payloads are a stealth technique in their own right.
        technique = TECHNIQUE_OBFUSCATION

    return Classification(
        score=round(score, 3),
        attack_type=attack_type,
        technique=technique,
        severity=severity if attack_type != "benign" else "informational",
        reasons=reasons,
        obfuscated=obfuscated,
        confidence=round(score, 3),
    )


def classify_prompt(prompt: str) -> tuple[float, str]:
    """Backwards-compatible ``(score, attack_type)`` view of :func:`classify`."""
    result = classify(prompt)
    return result.score, result.attack_type
