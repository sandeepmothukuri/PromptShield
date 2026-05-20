"""Generate mixed benign + malicious traffic for dashboard demos."""
from __future__ import annotations

import argparse
import json
import random
import time
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parent.parent / "datasets"
FILES = ["benign_samples.jsonl", "prompt_injection_samples.jsonl", "jailbreak_samples.jsonl"]


def load() -> list[dict]:
    rows: list[dict] = []
    for f in FILES:
        rows += [json.loads(line) for line in (ROOT / f).read_text(encoding="utf-8").splitlines()]
    return rows


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default="http://localhost:8080/chat")
    ap.add_argument("--minutes", type=int, default=5)
    ap.add_argument("--rps", type=float, default=1.0)
    args = ap.parse_args()

    rows = load()
    end = time.time() + args.minutes * 60
    with httpx.Client(timeout=30) as c:
        while time.time() < end:
            row = random.choice(rows)
            c.post(args.target, json={"prompt": row["prompt"], "user": f"demo-{random.randint(1,5)}"})
            time.sleep(1.0 / args.rps)


if __name__ == "__main__":
    main()
