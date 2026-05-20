"""LangChain-style input guardrail.

Kept dependency-light so the lab boots fast. Wire in `langchain.chains` and
`Constitutional AI` chains here when you want LLM-as-judge filtering.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

BLOCKLIST = [
    re.compile(r"(?i)write ransomware"),
    re.compile(r"(?i)generate a reverse shell"),
    re.compile(r"(?i)mimikatz"),
    re.compile(r"(?i)bypass EDR"),
]

SECRET_PATTERNS = [
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"sk-[A-Za-z0-9]{32,}"),
    re.compile(r"ghp_[A-Za-z0-9]{36}"),
]


@dataclass
class GuardResult:
    blocked: bool
    reason: str | None = None


def guardrail_check(prompt: str) -> GuardResult:
    for pat in BLOCKLIST:
        if pat.search(prompt):
            return GuardResult(True, f"blocklist:{pat.pattern}")
    for pat in SECRET_PATTERNS:
        if pat.search(prompt):
            return GuardResult(True, "secret_in_prompt")
    return GuardResult(False)
