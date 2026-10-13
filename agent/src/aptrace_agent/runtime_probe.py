"""
Model-runtime determinism probe.

Sends byte-identical chat-completion requests to an OpenAI-compatible
endpoint and records whether the responses are byte-identical. No tool
loop, no ledger, no firmware semantics: it isolates the serving runtime.

The request body is serialized once; the exact bytes sent are hashed, so
"identical request" is a recorded fact rather than an assumption.
"""

from __future__ import annotations

import hashlib
import json
import time
import urllib.error
import urllib.request
from collections import Counter
from dataclasses import dataclass
from typing import Any


# What the APTrace auditor sends today (ClaimAuditor.generation()).
CURRENT = "current"
# Every sampling knob the runtime accepts, set to its non-sampling value.
EXPLICIT_GREEDY = "explicit_greedy"

GREEDY_PARAMETERS = {
    "temperature": 0.0,
    "top_p": 1.0,
    "top_k": 1,
    "min_p": 0.0,
    "repetition_penalty": 1.0,
    "presence_penalty": 0.0,
    "frequency_penalty": 0.0,
    "seed": 0,
}


def build_request(model: str, messages: list[dict[str, str]], *, config: str, max_tokens: int) -> dict[str, Any]:
    payload: dict[str, Any] = {"model": model, "messages": messages, "max_tokens": max_tokens, "temperature": 0.0}

    if config == EXPLICIT_GREEDY:
        payload.update(GREEDY_PARAMETERS)
    elif config != CURRENT:
        raise ValueError(f"unknown probe configuration {config!r}")

    return payload


def request_bytes(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256(data: bytes | str) -> str:
    return hashlib.sha256(data.encode("utf-8") if isinstance(data, str) else data).hexdigest()


@dataclass
class ProbeCall:
    index: int
    request_sha256: str
    response_sha256: str
    content: str
    completion_tokens: int | None
    prompt_tokens: int | None
    cached_tokens: int | None
    elapsed_s: float
    served_model: str | None
    system_fingerprint: str | None
    # HTTP status and body when the runtime rejected the request.
    error: str | None = None


def post(base_url: str, api_key: str, body: bytes, timeout: float = 300.0) -> tuple[dict[str, Any], float]:
    req = urllib.request.Request(
        base_url.rstrip("/") + "/chat/completions",
        data=body,
        method="POST",
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {api_key}"},
    )
    started = time.perf_counter()

    with urllib.request.urlopen(req, timeout=timeout) as response:
        payload = json.loads(response.read())

    return payload, round(time.perf_counter() - started, 3)


def run_probe(
    payload: dict[str, Any],
    *,
    repeat: int,
    send: Any,
) -> dict[str, Any]:
    """send(bytes) -> (response json, elapsed seconds)."""

    body = request_bytes(payload)
    calls: list[ProbeCall] = []

    for index in range(repeat):
        try:
            response, elapsed = send(body)
        except urllib.error.HTTPError as exc:
            detail = exc.read()[:300].decode("utf-8", "replace") if exc.fp else ""
            calls.append(ProbeCall(index, sha256(body), "", "", None, None, None, 0.0, None, None, error=f"HTTP {exc.code}: {detail}"))
            continue

        choice = (response.get("choices") or [{}])[0]
        content = (choice.get("message") or {}).get("content") or ""
        usage = response.get("usage") or {}
        details = usage.get("prompt_tokens_details") or {}
        calls.append(
            ProbeCall(
                index=index,
                request_sha256=sha256(body),
                response_sha256=sha256(content),
                content=content,
                completion_tokens=usage.get("completion_tokens"),
                prompt_tokens=usage.get("prompt_tokens"),
                cached_tokens=details.get("cached_tokens") if isinstance(details, dict) else None,
                elapsed_s=elapsed,
                served_model=response.get("model"),
                system_fingerprint=response.get("system_fingerprint"),
            )
        )

    answered = [c for c in calls if c.error is None]
    hashes = Counter(c.response_sha256 for c in answered)
    return {
        "request_sha256": sha256(body),
        "request_bytes": len(body),
        "generation": {k: v for k, v in payload.items() if k not in ("messages", "model")},
        "model": payload["model"],
        "repeat": repeat,
        "answered": len(answered),
        "errors": [c.error for c in calls if c.error],
        "distinct_responses": len(hashes),
        "byte_identical": len(hashes) == 1 and len(answered) == repeat,
        "modal_response_share": round(hashes.most_common(1)[0][1] / len(answered), 3) if answered else 0.0,
        "calls": [vars(c) for c in calls],
    }
