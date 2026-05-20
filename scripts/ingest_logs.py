"""Replay a JSONL prompt corpus through the LLM-Monitor proxy."""
from __future__ import annotations

import argparse
import json
import sys

import httpx


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", required=True)
    ap.add_argument("--target", default="http://localhost:8080/chat")
    ap.add_argument("--user", default="replay")
    args = ap.parse_args()

    sent = blocked = 0
    with open(args.dataset, encoding="utf-8") as fh, httpx.Client(timeout=30) as c:
        for line in fh:
            row = json.loads(line)
            r = c.post(args.target, json={"prompt": row["prompt"], "user": args.user})
            sent += 1
            if r.json().get("verdict") == "block":
                blocked += 1

    print(json.dumps({"sent": sent, "blocked": blocked}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
