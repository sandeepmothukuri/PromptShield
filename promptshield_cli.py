#!/usr/bin/env python3
"""Small command-line entry point for PromptShield-Lab smoke tests.

The lab itself is driven by the FastAPI monitor under ``llm-monitor/`` and the
repository scripts. This CLI provides a stable local entry point instead of
requiring users to guess which module or script to invoke directly.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request


def _request(url: str, payload: dict) -> tuple[int, dict]:
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        raw = resp.read().decode("utf-8")
        return resp.status, json.loads(raw)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="promptshield", description="PromptShield-Lab CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="send one prompt to the local monitor")
    scan.add_argument("prompt")
    scan.add_argument("--url", default=os.getenv("PROMPTSHIELD_URL", "http://localhost:8080"))
    scan.add_argument("--user", default="cli")

    health = sub.add_parser("health", help="check the local monitor health endpoint")
    health.add_argument("--url", default=os.getenv("PROMPTSHIELD_URL", "http://localhost:8080"))

    args = parser.parse_args(argv)

    if args.command == "health":
        try:
            with urllib.request.urlopen(f"{args.url.rstrip('/')}/healthz", timeout=5) as resp:
                print(resp.read().decode("utf-8"))
            return 0
        except urllib.error.URLError as exc:
            print(f"promptshield: health check failed: {exc}", file=sys.stderr)
            return 1

    try:
        status, data = _request(
            f"{args.url.rstrip('/')}/chat",
            {"prompt": args.prompt, "user": args.user},
        )
    except (urllib.error.URLError, json.JSONDecodeError) as exc:
        print(f"promptshield: request failed: {exc}", file=sys.stderr)
        return 1

    print(json.dumps(data, indent=2, ensure_ascii=False))
    return 0 if status < 400 else 1


if __name__ == "__main__":
    raise SystemExit(main())
