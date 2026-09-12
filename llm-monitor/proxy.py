"""PromptShield-Lab LLM-Monitor proxy.

Sits between a chat front-end and the model runtime. Every request is classified,
optionally blocked, and written as one JSON line to the audit log consumed by
Wazuh, OpenSearch, the Sigma rules in ``detections/sigma/`` and the dashboards.

Endpoints
---------
GET  /healthz                  liveness probe (no model dependency)
GET  /stats                    per-attack-type counters, useful for smoke tests
POST /chat                     classify -> (block | forward to model)
GET  /v1/models                OpenAI-compatible model list (front-end model picker)
POST /v1/chat/completions      OpenAI-compatible shim so OpenWebUI can be pointed here

Documented telemetry schema lives in ``docs/telemetry-schema.md``.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import threading
import time
import uuid
from collections import deque
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from classifier import ATTACK_TYPES, SECRET_PATTERNS, classify, scan_secrets

# --------------------------------------------------------------------------- #
# Configuration (see .env.example)
# --------------------------------------------------------------------------- #
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://ollama:11434")
DEFAULT_MODEL = os.getenv("DEFAULT_MODEL", "llama3:8b")
LOG_PATH = Path(os.getenv("LOG_PATH", "/var/log/promptshield/monitor.json"))
THRESHOLD = float(os.getenv("CLASSIFIER_THRESHOLD", "0.65"))
MAX_PROMPT_CHARS = int(os.getenv("MAX_PROMPT_CHARS", "32000"))
RATE_LIMIT_REQUESTS = int(os.getenv("RATE_LIMIT_REQUESTS", "20"))
RATE_LIMIT_WINDOW_SECONDS = int(os.getenv("RATE_LIMIT_WINDOW_SECONDS", "60"))
# Secure by default: a prompt can contain a real credential, and the audit log is
# shipped to a search cluster with a wider audience than the model runtime. Set
# to false only when the raw text is needed for detection tuning.
REDACT_LOGGED_SECRETS = os.getenv("REDACT_LOGGED_SECRETS", "true").lower() == "true"
MAX_LOGGED_COMPLETION_CHARS = int(os.getenv("MAX_LOGGED_COMPLETION_CHARS", "4000"))

LOG_PATH.parent.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
log = logging.getLogger("promptshield.monitor")

app = FastAPI(
    title="PromptShield LLM-Monitor",
    version="0.2.0",
    description="Prompt classification, blocking and audit telemetry for LLM traffic.",
)

# --------------------------------------------------------------------------- #
# Per-user rate limiting (sliding window). In-memory: this is a single-process
# lab service. Replace with Redis if the proxy is ever scaled out.
# --------------------------------------------------------------------------- #
_request_log: dict[str, deque[float]] = {}
_rate_lock = threading.Lock()
_counters: dict[str, int] = {}
_counter_lock = threading.Lock()
_audit_lock = threading.Lock()


class ChatRequest(BaseModel):
    """Request body accepted by ``POST /chat``."""

    prompt: str = Field(..., description="User prompt text")
    user: str = Field(default="anonymous", max_length=128)
    session_id: str | None = Field(default=None, max_length=128)
    model: str = Field(default=DEFAULT_MODEL, max_length=128)
    tools: list[str] = Field(
        default_factory=list, description="Tool names the caller wants enabled"
    )


class ChatMessage(BaseModel):
    role: str = Field(..., pattern="^(system|user|assistant|tool)$")
    content: str = ""


class ChatCompletionRequest(BaseModel):
    """OpenAI-compatible body accepted by ``POST /v1/chat/completions``."""

    model: str = Field(default=DEFAULT_MODEL, max_length=128)
    messages: list[ChatMessage] = Field(default_factory=list)
    user: str | None = Field(default=None, max_length=128)
    stream: bool = False
    session_id: str | None = Field(default=None, max_length=128)


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _utc_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _estimate_tokens(text: str) -> int:
    """Approximate token count. ~4 chars/token is the usual rule of thumb."""
    return max(1, len(text) // 4)


def _redact(text: str) -> str:
    """Mask credential-shaped substrings before they reach the audit log."""
    if not REDACT_LOGGED_SECRETS:
        return text
    for pattern, name in SECRET_PATTERNS:
        text = re.sub(pattern, f"[REDACTED:{name}]", text)
    return text


# Hard ceiling on tracked identities. The table is keyed by caller-supplied
# username, so an attacker rotating usernames would otherwise grow it without
# bound and exhaust proxy memory. When the ceiling is hit, identities whose
# window has fully expired are dropped; if that is not enough, the oldest
# entries are evicted. Losing rate-limit state for an idle identity is a lesser
# harm than an unbounded allocation.
_MAX_TRACKED_USERS = 10000


def _check_rate_limit(user: str) -> tuple[bool, int]:
    """Return (allowed, requests_in_window) for ``user``."""
    now = time.monotonic()
    cutoff = now - RATE_LIMIT_WINDOW_SECONDS
    with _rate_lock:
        window = _request_log.get(user)
        if window is None:
            if len(_request_log) >= _MAX_TRACKED_USERS:
                _evict_stale_users(cutoff)
            window = _request_log.setdefault(user, deque())
        while window and window[0] < cutoff:
            window.popleft()
        count = len(window)
        if count >= RATE_LIMIT_REQUESTS:
            return False, count
        window.append(now)
        return True, count + 1


def _evict_stale_users(cutoff: float) -> None:
    """Drop rate-limit state for identities with no activity in the window.

    Called with ``_rate_lock`` held.
    """
    stale = [u for u, w in _request_log.items() if not w or w[-1] < cutoff]
    for u in stale:
        del _request_log[u]
    if len(_request_log) >= _MAX_TRACKED_USERS:
        # Every remaining identity is still inside its window. Evict the oldest
        # by last activity rather than refuse to track anyone at all.
        ordered = sorted(_request_log, key=lambda u: _request_log[u][-1])
        for u in ordered[: len(_request_log) - _MAX_TRACKED_USERS + 1]:
            del _request_log[u]


def _bump(attack_type: str) -> None:
    with _counter_lock:
        _counters[attack_type] = _counters.get(attack_type, 0) + 1


def _audit(event: dict[str, Any]) -> None:
    """Append one JSON line to the audit log.

    Writes are serialised: the whole pipeline downstream parses these lines as
    JSON, so two concurrent requests interleaving inside a single line would
    corrupt both records and the Wazuh decoder would drop them.
    """
    line = json.dumps(event, ensure_ascii=False) + "\n"
    try:
        with _audit_lock, LOG_PATH.open("a", encoding="utf-8") as fh:
            fh.write(line)
    except OSError as exc:  # never let logging break the request path
        log.error("audit write failed: %s", exc)


def _build_event(
    *,
    request_id: str,
    session_id: str,
    user: str,
    source_ip: str,
    model: str,
    prompt: str,
    classification: Any,
    verdict: str,
    reason: str | None,
    response_status: int,
    endpoint: str,
    completion: str = "",
    blocked: bool = False,
) -> dict[str, Any]:
    """Assemble the documented telemetry record."""
    prompt_hash = hashlib.sha256(prompt.encode("utf-8")).hexdigest()
    secrets_in_prompt = scan_secrets(prompt)
    secrets_in_completion = scan_secrets(completion) if completion else []

    event: dict[str, Any] = {
        "@timestamp": _utc_now(),
        "event_id": str(uuid.uuid4()),
        "request_id": request_id,
        "session_id": session_id,
        "user": user,
        "source_ip": source_ip,
        "endpoint": endpoint,
        "provider": "ollama",
        "model": model,
        "prompt": _redact(prompt),
        "prompt_hash": prompt_hash,
        "prompt_tokens": _estimate_tokens(prompt),
        "classifier_score": classification.score,
        "confidence": classification.confidence,
        "attack_type": classification.attack_type,
        "technique": classification.technique,
        "severity": classification.severity,
        "detection_reason": reason or ";".join(classification.reasons) or None,
        "obfuscated": classification.obfuscated,
        "verdict": verdict,
        "response_status": response_status,
        "blocked": blocked,
        "secrets_in_prompt": secrets_in_prompt,
        "secrets_in_completion": secrets_in_completion,
    }
    if completion:
        trimmed = completion[:MAX_LOGGED_COMPLETION_CHARS]
        event["completion"] = _redact(trimmed)
        event["completion_truncated"] = len(completion) > MAX_LOGGED_COMPLETION_CHARS
        event["completion_tokens"] = _estimate_tokens(completion)
    return event


# --------------------------------------------------------------------------- #
# Endpoints
# --------------------------------------------------------------------------- #
@app.get("/healthz")
def healthz() -> dict[str, Any]:
    """Liveness probe. Does not touch the model runtime."""
    return {"status": "ok", "service": "promptshield-llm-monitor", "version": app.version}


@app.get("/stats")
def stats() -> dict[str, Any]:
    """Per-attack-type request counters since process start."""
    with _counter_lock:
        snapshot = dict(_counters)
    return {
        "threshold": THRESHOLD,
        "rate_limit": f"{RATE_LIMIT_REQUESTS}/{RATE_LIMIT_WINDOW_SECONDS}s",
        "counts": snapshot,
        "total": sum(snapshot.values()),
    }


def _context(request: Request) -> tuple[str, str]:
    request_id = request.headers.get("x-request-id") or str(uuid.uuid4())
    # Published on request state so the exception handler can echo the same id
    # the audit record used. Without this, a failed request returns
    # "unknown" while the audit line carries the real id, so the two cannot be
    # correlated during triage.
    request.state.request_id = request_id
    forwarded = request.headers.get("x-forwarded-for", "")
    source_ip = (
        forwarded.split(",")[0].strip()
        if forwarded
        else (request.client.host if request.client else "unknown")
    )
    return request_id, source_ip


async def _forward_to_model(model: str, prompt: str) -> str:
    """Call the model runtime. Raises HTTPException on upstream failure."""
    try:
        async with httpx.AsyncClient(timeout=120) as client:
            resp = await client.post(
                f"{OLLAMA_URL}/api/generate",
                json={"model": model, "prompt": prompt, "stream": False},
            )
            resp.raise_for_status()
            return str(resp.json().get("response", ""))
    except httpx.HTTPStatusError as exc:
        log.warning("model returned %s", exc.response.status_code)
        raise HTTPException(status_code=502, detail="model runtime returned an error") from exc
    except httpx.HTTPError as exc:
        log.warning("model unreachable: %s", exc)
        raise HTTPException(status_code=503, detail="model runtime unreachable") from exc


@app.post("/chat")
async def chat(req: ChatRequest, request: Request) -> JSONResponse:
    """Classify a prompt, block or forward it, and audit the decision."""
    request_id, source_ip = _context(request)
    session_id = req.session_id or str(uuid.uuid4())

    if not req.prompt.strip():
        raise HTTPException(status_code=422, detail="prompt must not be empty")

    oversized = len(req.prompt) > MAX_PROMPT_CHARS
    allowed, window_count = _check_rate_limit(req.user)

    if oversized:
        classification = classify(req.prompt)
        classification.attack_type = "token_flood"
        classification.technique, classification.severity = ATTACK_TYPES["token_flood"]
        classification.score = max(classification.score, 0.8)
        verdict, reason, status = "block", "prompt_exceeds_max_chars", 413
    elif not allowed:
        classification = classify(req.prompt)
        classification.attack_type = "token_flood"
        classification.technique, classification.severity = ATTACK_TYPES["token_flood"]
        classification.score = max(classification.score, 0.75)
        verdict, reason, status = (
            "block",
            f"rate_limit_exceeded:{window_count}/{RATE_LIMIT_REQUESTS}req/{RATE_LIMIT_WINDOW_SECONDS}s",
            429,
        )
    else:
        classification = classify(req.prompt)
        if classification.score >= THRESHOLD:
            verdict, reason, status = (
                "block",
                f"classifier:{classification.attack_type}:{classification.score:.2f}",
                200,
            )
        else:
            verdict, reason, status = "allow", None, 200

    _bump(classification.attack_type)
    blocked = verdict == "block"

    if blocked:
        event = _build_event(
            request_id=request_id,
            session_id=session_id,
            user=req.user,
            source_ip=source_ip,
            model=req.model,
            prompt=req.prompt,
            classification=classification,
            verdict=verdict,
            reason=reason,
            response_status=status,
            endpoint="/chat",
            blocked=True,
        )
        _audit(event)
        return JSONResponse(
            status_code=status,
            content={
                "verdict": verdict,
                "reason": reason,
                "attack_type": classification.attack_type,
                "request_id": request_id,
                "session_id": session_id,
            },
            headers={"X-Request-ID": request_id},
        )

    try:
        completion = await _forward_to_model(req.model, req.prompt)
    except HTTPException as exc:
        # The prompt was allowed but the model call failed. This still has to be
        # audited: an outage or a DoS against the model runtime is invisible to
        # the SOC if the failure path writes nothing. Re-raising keeps the 502/503
        # the caller expects, after the record exists.
        _audit(
            _build_event(
                request_id=request_id,
                session_id=session_id,
                user=req.user,
                source_ip=source_ip,
                model=req.model,
                prompt=req.prompt,
                classification=classification,
                verdict="allow",
                reason=f"upstream_failure:{exc.status_code}",
                response_status=exc.status_code,
                endpoint="/chat",
            )
        )
        raise

    # Re-score the completion: unsafe output is a separate finding from a
    # malicious prompt (OWASP LLM05 / T1190).
    output_classification = classify(req.prompt, completion)
    if output_classification.attack_type == "insecure_output":
        classification = output_classification
        reason = "unsafe_completion_content"

    event = _build_event(
        request_id=request_id,
        session_id=session_id,
        user=req.user,
        source_ip=source_ip,
        model=req.model,
        prompt=req.prompt,
        classification=classification,
        verdict="allow",
        reason=reason,
        response_status=200,
        endpoint="/chat",
        completion=completion,
    )
    _audit(event)
    return JSONResponse(
        content={
            "verdict": "allow",
            "attack_type": classification.attack_type,
            "request_id": request_id,
            "session_id": session_id,
            "completion": completion,
        },
        headers={"X-Request-ID": request_id},
    )


@app.get("/v1/models")
async def list_models() -> dict[str, Any]:
    """OpenAI-compatible model list, required by chat front-ends.

    OpenWebUI populates its model picker from this endpoint; without it the
    dropdown is empty and the OpenAI-compatible connection cannot be used. The
    upstream runtime is queried when reachable so the list reflects what can
    actually be served, and falls back to DEFAULT_MODEL when it is not.
    """
    models: list[str] = []
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            resp = await client.get(f"{OLLAMA_URL}/api/tags")
            resp.raise_for_status()
            models = [
                str(m.get("name", "")) for m in resp.json().get("models", []) if m.get("name")
            ]
    except (httpx.HTTPError, ValueError) as exc:
        log.info("model runtime not reachable for /v1/models: %s", exc)

    if not models:
        models = [DEFAULT_MODEL]

    now = int(time.time())
    return {
        "object": "list",
        "data": [
            {"id": name, "object": "model", "created": now, "owned_by": "promptshield"}
            for name in models
        ],
    }


@app.post("/v1/chat/completions")
async def chat_completions(req: ChatCompletionRequest, request: Request) -> JSONResponse:
    """OpenAI-compatible shim. Lets OpenWebUI route through the monitor."""
    request_id, source_ip = _context(request)
    if req.stream:
        raise HTTPException(status_code=400, detail="streaming is not supported by the monitor")

    user_prompt = next((m.content for m in reversed(req.messages) if m.role == "user"), "")
    if not user_prompt.strip():
        raise HTTPException(status_code=422, detail="no user message supplied")

    session_id = req.session_id or str(uuid.uuid4())
    user = req.user or "openwebui"
    classification = classify(user_prompt)
    _bump(classification.attack_type)

    if classification.score >= THRESHOLD:
        event = _build_event(
            request_id=request_id,
            session_id=session_id,
            user=user,
            source_ip=source_ip,
            model=req.model,
            prompt=user_prompt,
            classification=classification,
            verdict="block",
            reason=f"classifier:{classification.attack_type}:{classification.score:.2f}",
            response_status=200,
            endpoint="/v1/chat/completions",
            blocked=True,
        )
        _audit(event)
        return JSONResponse(
            content={
                "id": request_id,
                "object": "chat.completion",
                "created": int(time.time()),
                "model": req.model,
                "choices": [
                    {
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": (
                                "This request was blocked by PromptShield "
                                f"({classification.attack_type}). "
                                "Contact your administrator if this is unexpected."
                            ),
                        },
                        "finish_reason": "content_filter",
                    }
                ],
            },
            headers={"X-Request-ID": request_id},
        )

    try:
        completion = await _forward_to_model(req.model, user_prompt)
    except HTTPException as exc:
        # Same rationale as /chat: a failed upstream call on an allowed prompt
        # must still produce telemetry, and must keep its request_id.
        _audit(
            _build_event(
                request_id=request_id,
                session_id=session_id,
                user=user,
                source_ip=source_ip,
                model=req.model,
                prompt=user_prompt,
                classification=classification,
                verdict="allow",
                reason=f"upstream_failure:{exc.status_code}",
                response_status=exc.status_code,
                endpoint="/v1/chat/completions",
            )
        )
        raise

    event = _build_event(
        request_id=request_id,
        session_id=session_id,
        user=user,
        source_ip=source_ip,
        model=req.model,
        prompt=user_prompt,
        classification=classification,
        verdict="allow",
        reason=None,
        response_status=200,
        endpoint="/v1/chat/completions",
        completion=completion,
    )
    _audit(event)
    return JSONResponse(
        content={
            "id": request_id,
            "object": "chat.completion",
            "created": int(time.time()),
            "model": req.model,
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": completion},
                    "finish_reason": "stop",
                }
            ],
        },
        headers={"X-Request-ID": request_id},
    )


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    """Structured error body so failures are queryable in OpenSearch."""
    request_id = getattr(request.state, "request_id", None) or request.headers.get(
        "x-request-id", "unknown"
    )
    log.warning("%s %s -> %s (%s)", request.method, request.url.path, exc.status_code, exc.detail)
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": exc.detail, "request_id": request_id, "status": exc.status_code},
        headers={"X-Request-ID": request_id},
    )
