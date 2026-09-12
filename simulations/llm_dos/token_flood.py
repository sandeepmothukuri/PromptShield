#!/usr/bin/env python3
"""LLM resource-exhaustion simulation (token flood and request burst).

Two abuse patterns are exercised against the LLM-Monitor proxy:

1. an oversized prompt above MAX_PROMPT_CHARS, which the proxy rejects with 413
2. a burst of small requests above RATE_LIMIT_REQUESTS, rejected with 429

Both are audited with attack_type=token_flood and technique T1499.004, which is
what Wazuh rule 100160 and detections/sigma/llm_token_flood_dos.yml match.
"""

from __future__ import annotations

import argparse
import json
import sys

import httpx

OVERSIZED_CHARS = 40_000


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--target", default="http://localhost:8080")
    ap.add_argument("--user", default="dos-sim")
    ap.add_argument("--burst", type=int, default=30, help="requests in the burst phase")
    args = ap.parse_args()

    results: dict[str, int] = {"oversized_blocked": 0, "burst_blocked": 0, "burst_allowed": 0}

    with httpx.Client(timeout=60) as client:
        print("[phase 1] oversized prompt")
        resp = client.post(
            f"{args.target}/chat",
            json={"prompt": "A" * OVERSIZED_CHARS, "user": args.user},
        )
        print(f"  status={resp.status_code} body={json.dumps(resp.json())[:160]}")
        if resp.status_code == 413:
            results["oversized_blocked"] = 1

        print(f"[phase 2] burst of {args.burst} requests")
        for _ in range(args.burst):
            resp = client.post(
                f"{args.target}/chat",
                json={"prompt": "Summarize the latest status update.", "user": args.user},
            )
            if resp.status_code == 429:
                results["burst_blocked"] += 1
            elif resp.status_code == 200:
                results["burst_allowed"] += 1

        print(f"  allowed={results['burst_allowed']} rate_limited={results['burst_blocked']}")

    print(json.dumps(results))
    return 0 if results["oversized_blocked"] and results["burst_blocked"] else 1


if __name__ == "__main__":
    sys.exit(main())
