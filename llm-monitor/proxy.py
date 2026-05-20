"""PromptShield-Lab LLM-Monitor proxy.

Sits between OpenWebUI and Ollama. Every prompt is classified, optionally
blocked by LangChain guardrails, and recorded as one JSON line in the audit
log consumed by Wazuh.
"""
from __future__ import annotations

import json
import os
import time
import uuid
from pathlib import Path
from typing import Any

import httpx
from fastapi import FastAPI
from pydantic import BaseModel

from classifier import classify_prompt
from langchain_guard import guardrail_check

OLLAMA_URL = os.getenv("OLLAMA_URL", "http://ollama:11434")
LOG_PATH = Path(os.getenv("LOG_PATH", "/var/log/promptshield/monitor.json"))
THRESHOLD = float(os.getenv("CLASSIFIER_THRESHOLD", "0.65"))
LOG_PATH.parent.mkdir(parents=True, exist_ok=True)

app = FastAPI(title="PromptShield LLM-Monitor", version="0.1.0")


class ChatRequest(BaseModel):
    prompt: str
    user: str = "anonymous"
    session_id: str | None = None
    model: str = "llama3:8b"


def _audit(event: dict[str, Any]) -> None:
    event["ts"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    with LOG_PATH.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(event, ensure_ascii=False) + "\n")


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/chat")
async def chat(req: ChatRequest) -> dict[str, Any]:
    session_id = req.session_id or str(uuid.uuid4())
    score, category = classify_prompt(req.prompt)
    guard = guardrail_check(req.prompt)

    verdict = "allow"
    reason = None
    if guard.blocked:
        verdict, reason = "block", guard.reason
    elif score >= THRESHOLD:
        verdict, reason = "block", f"classifier_score={score:.2f}"

    event = {
        "user": req.user,
        "session_id": session_id,
        "model": req.model,
        "prompt": req.prompt,
        "prompt_tokens": len(req.prompt.split()),
        "classifier_score": round(score, 3),
        "category": category,
        "verdict": verdict,
        "reason": reason,
    }

    if verdict == "block":
        _audit(event)
        return {"verdict": verdict, "reason": reason, "session_id": session_id}

    async with httpx.AsyncClient(timeout=120) as client:
        r = await client.post(
            f"{OLLAMA_URL}/api/generate",
            json={"model": req.model, "prompt": req.prompt, "stream": False},
        )
        r.raise_for_status()
        completion = r.json().get("response", "")

    event["completion"] = completion
    _audit(event)
    return {"verdict": verdict, "session_id": session_id, "completion": completion}
