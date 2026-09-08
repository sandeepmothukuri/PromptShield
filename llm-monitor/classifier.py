"""Lightweight prompt classifier.

Heuristic by default (no model download required). Returns a (score, category)
tuple where score is in [0,1] and category is one of: benign, prompt_injection,
jailbreak, data_exfiltration, ai_phishing, system_prompt_leak, token_flood.

Replace the heuristic with a real transformer (e.g., protectai/deberta-v3-base-
prompt-injection-v2) by editing the `_score` function.
"""
from __future__ import annotations

import re

PATTERNS = {
    "prompt_injection": [
        r"ignore (?:previous|the above|all prior|all) (?:instructions|rules)",
        r"disregard (?:all\s+)?(?:prior\s+)?(?:instructions|context)",
        r"override your system prompt",
        r"forget (?:your|all|previous|prior) instructions",
        r"discard previous guidance",
        r"follow any instructions inside",
    ],
    "jailbreak": [
        r"\bdan mode\b",
        r"\byou are now dan\b",
        r"\bdan can do anything\b",
        r"\bdo anything now\b",
        r"\bdeveloper mode\b",
        r"\baim model\b",
        r"\bstan:",
        r"\bunfiltered ai\b",
        r"\bblack-?hat hacker\b",
        r"bypass a corporate firewall",
        r"pretend you are an ai without (?:any )?restrictions",
    ],
    "system_prompt_leak": [
        r"repeat the words above starting with",
        r"print (?:the )?(?:text|prompt) above verbatim",
        r"what (?:are|were) your initial instructions",
    ],
    "data_exfiltration": [
        r"exfiltrate (?:via|using)",
        r"encode the file contents in base64",
    ],
    "ai_phishing": [
        r"write a phishing email",
        r"create a login page that looks like",
        r"craft a smishing message",
    ],
}


def _score(prompt: str) -> tuple[float, str]:
    p = prompt.lower()
    for category, patterns in PATTERNS.items():
        for pat in patterns:
            if re.search(pat, p):
                return 0.92, category
    if len(prompt) > 6000:
        return 0.7, "token_flood"
    return 0.05, "benign"


def classify_prompt(prompt: str) -> tuple[float, str]:
    return _score(prompt)
