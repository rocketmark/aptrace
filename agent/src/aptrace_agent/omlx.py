"""
Sequential model residency through oMLX's own lifecycle endpoints.

APTrace's planner (Qwen) and terminal reviewer (Gemma) do not fit under the
oMLX memory ceiling together. oMLX evicts the least recently used idle model
before a load, but it never evicts a model with an in-flight request. That
is how the 2026-10-19 diagnostic audit failed with HTTP 507: a Qwen request
was still generating. This module makes the switch explicit and checked,
using only endpoints the oMLX server exposes:

- ``GET  /api/status``: active and waiting requests, loaded models, memory.
- ``GET  /v1/models/status``: per model, ``loaded``, ``is_loading``,
  ``pinned``, ``estimated_size``, ``max_context_window``; and the pool's
  ``final_ceiling`` and ``current_model_memory``.
- ``POST /v1/models/{id}/unload``: immediate unload. It aborts in-flight
  requests, so APTrace waits for the server to be idle first.
- ``POST /v1/models/{id}/load``: a blocking load. 507 means the memory
  admission refused it.

It is not a model manager. It never changes oMLX settings, pins, memory
limits or models. It never substitutes another model. Every transition is
re-read from the server, never assumed. Waiting is bounded, and every
failure has an explicit kind.
"""

from __future__ import annotations

import json
import os
import socket
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlparse


RESIDENCY_VERSION = "omlx-residency-v1"

# Failure kinds. "unavailable" kinds mean the model could not be made
# resident; they are not model behavior.
ENDPOINT_UNAVAILABLE = "endpoint_unavailable"
MODEL_NOT_SERVED = "model_not_served"
SERVER_BUSY = "server_busy"
PINNED_MODEL_RESIDENT = "pinned_model_resident"
UNLOAD_UNVERIFIED = "unload_unverified"
INSUFFICIENT_MEMORY = "insufficient_memory"
LOAD_FAILED = "load_failed"
LOAD_UNVERIFIED = "load_unverified"
UNEXPECTED_RESIDENCY = "unexpected_residency"


class OmlxError(Exception):
    """One failed lifecycle call: kind, HTTP status (if any), server detail."""

    def __init__(self, kind: str, detail: str, status: int | None = None) -> None:
        super().__init__(f"{kind}: {detail}" + (f" (HTTP {status})" if status else ""))
        self.kind = kind
        self.detail = detail
        self.status = status


class ResidencyError(Exception):
    """A residency transition that did not reach the verified target state."""

    def __init__(self, kind: str, detail: str, record: dict[str, Any]) -> None:
        super().__init__(f"{kind}: {detail}")
        self.kind = kind
        self.detail = detail
        self.record = record


_HTTP_KINDS = {
    401: "unauthorized",
    403: "unauthorized",
    404: MODEL_NOT_SERVED,
    409: SERVER_BUSY,
    503: ENDPOINT_UNAVAILABLE,
    507: INSUFFICIENT_MEMORY,
}

Request = Callable[[str, str, float], dict[str, Any]]


def server_root(base_url: str) -> str:
    """oMLX server root from an OpenAI base URL (``.../v1``)."""

    root = base_url.rstrip("/")
    return root[: -len("/v1")] if root.endswith("/v1") else root


def _detail(body: bytes) -> str:
    try:
        data = json.loads(body.decode("utf-8", "replace"))
    except ValueError:
        return body.decode("utf-8", "replace")[:600]

    if isinstance(data, dict):
        error = data.get("detail") or data.get("error") or data
        if isinstance(error, dict):
            error = error.get("message") or error
        return str(error)[:600]

    return str(data)[:600]


class OmlxRuntime:
    """Typed calls to the oMLX lifecycle endpoints. Local endpoints only."""

    def __init__(
        self,
        base_url: str | None = None,
        api_key: str | None = None,
        *,
        request: Request | None = None,
        status_timeout: float = 30.0,
        load_timeout: float = 900.0,
    ) -> None:
        self.base_url = base_url or os.environ.get("OMLX_BASE_URL", "http://127.0.0.1:8000/v1")
        host = urlparse(self.base_url).hostname

        if host not in {"127.0.0.1", "localhost"}:
            raise ValueError(f"refusing non-local model endpoint: {self.base_url}")

        self.root = server_root(self.base_url)
        self._api_key = api_key if api_key is not None else os.environ.get("OMLX_API_KEY", "")
        self._request = request or self._urllib_request
        self.status_timeout = status_timeout
        self.load_timeout = load_timeout

    def _urllib_request(self, method: str, path: str, timeout: float) -> dict[str, Any]:
        req = urllib.request.Request(
            self.root + path,
            method=method,
            data=b"" if method == "POST" else None,
            headers={"Authorization": f"Bearer {self._api_key}", "Content-Type": "application/json"},
        )

        try:
            with urllib.request.urlopen(req, timeout=timeout) as response:
                return json.loads(response.read() or b"{}")
        except urllib.error.HTTPError as exc:
            raise OmlxError(_HTTP_KINDS.get(exc.code, "http_error"), _detail(exc.read()), exc.code) from exc
        except (TimeoutError, socket.timeout) as exc:
            raise OmlxError("timeout", f"{method} {path} exceeded {timeout:.0f}s") from exc
        except (urllib.error.URLError, ConnectionError, OSError) as exc:
            raise OmlxError(ENDPOINT_UNAVAILABLE, f"{method} {path}: {getattr(exc, 'reason', exc)}") from exc
        except ValueError as exc:
            raise OmlxError("malformed_response", f"{method} {path}: {exc}") from exc

    def server_status(self) -> dict[str, Any]:
        return self._request("GET", "/api/status", self.status_timeout)

    def models_status(self) -> dict[str, Any]:
        return self._request("GET", "/v1/models/status", self.status_timeout)

    def load(self, model: str) -> dict[str, Any]:
        return self._request("POST", f"/v1/models/{quote(model, safe='')}/load", self.load_timeout)

    def unload(self, model: str) -> dict[str, Any]:
        return self._request("POST", f"/v1/models/{quote(model, safe='')}/unload", self.load_timeout)


def model_settings(model: str, home: str | None = None) -> dict[str, Any] | None:
    """The model's oMLX per-model settings (context window, sampling), read
    for provenance only. Secrets are not in this file and are never copied."""

    root = Path(home or os.environ.get("OMLX_HOME", "~/.omlx")).expanduser()

    try:
        settings = json.loads((root / "model_settings.json").read_text()).get("models", {}).get(model)
    except (OSError, ValueError):
        return None

    if not isinstance(settings, dict):
        return None

    keep = ("max_context_window", "max_tokens", "temperature", "top_p", "top_k", "min_p", "enable_thinking",
            "turboquant_kv_enabled", "turboquant_kv_bits", "is_pinned")
    return {k: settings[k] for k in keep if k in settings}


@dataclass(frozen=True)
class ResidencyPolicy:
    """Bounds for every wait. Latency is not optimized; waits are generous but finite."""

    idle_wait_s: float = 180.0
    poll_s: float = 2.0
    unload_attempts: int = 3
    settle_wait_s: float = 60.0
    load_attempts: int = 2


class ModelResidency:
    """
    Makes one model the only resident model, or releases it, and verifies
    the resulting server state after every transition.
    """

    def __init__(
        self,
        runtime: OmlxRuntime,
        policy: ResidencyPolicy | None = None,
        *,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.runtime = runtime
        self.policy = policy or ResidencyPolicy()
        self.sleep = sleep
        self.clock = clock

    # -- state ----------------------------------------------------------------

    def snapshot(self) -> dict[str, Any]:
        """Server residency as reported by oMLX (both status endpoints)."""

        server = self.runtime.server_status()
        pool = self.runtime.models_status()
        models = {
            m["id"]: {
                "loaded": bool(m.get("loaded")),
                "is_loading": bool(m.get("is_loading")),
                "pinned": bool(m.get("pinned")),
                "estimated_size": m.get("estimated_size"),
                "max_context_window": m.get("max_context_window"),
                "max_tokens": m.get("max_tokens"),
            }
            for m in pool.get("models", [])
            if isinstance(m, dict) and "id" in m
        }
        return {
            "loaded": sorted(i for i, m in models.items() if m["loaded"]),
            "loading": sorted(i for i, m in models.items() if m["is_loading"]),
            "active_requests": int(server.get("active_requests") or 0),
            "waiting_requests": int(server.get("waiting_requests") or 0),
            "ceiling": pool.get("final_ceiling") or server.get("model_memory_max"),
            "current_model_memory": pool.get("current_model_memory") or server.get("model_memory_used"),
            "server_version": server.get("version"),
            "models": models,
        }

    # -- transitions ----------------------------------------------------------

    def _new_record(self, operation: str, model: str) -> dict[str, Any]:
        return {"version": RESIDENCY_VERSION, "operation": operation, "model": model, "ok": False,
                "actions": [], "before": None, "after": None, "error": None}

    def _fail(self, record: dict[str, Any], kind: str, detail: str) -> ResidencyError:
        record["error"] = {"kind": kind, "detail": detail}

        try:
            record["after"] = self.snapshot()
        except OmlxError:
            pass

        return ResidencyError(kind, detail, record)

    def _act(self, record: dict[str, Any], action: str, model: str | None, call: Callable[[], Any]) -> Any:
        started = self.clock()
        entry: dict[str, Any] = {"action": action, "model": model}

        try:
            result = call()
            entry["result"] = "ok"
            return result
        except OmlxError as exc:
            entry.update(result="error", kind=exc.kind, status=exc.status, detail=exc.detail)
            raise
        finally:
            entry["elapsed_s"] = round(self.clock() - started, 3)
            record["actions"].append(entry)

    def _wait(self, record: dict[str, Any], label: str, done: Callable[[dict[str, Any]], bool], limit: float) -> dict[str, Any]:
        """Poll the snapshot until done(snapshot) or the bound; returns the last snapshot."""

        started = self.clock()
        polls = 0

        while True:
            snap = self.snapshot()
            polls += 1

            if done(snap) or self.clock() - started >= limit:
                record["actions"].append({"action": f"wait:{label}", "polls": polls, "satisfied": done(snap),
                                          "elapsed_s": round(self.clock() - started, 3)})
                return snap

            self.sleep(self.policy.poll_s)

    @staticmethod
    def _idle(snap: dict[str, Any]) -> bool:
        return snap["active_requests"] == 0 and snap["waiting_requests"] == 0 and not snap["loading"]

    def _wait_idle(self, record: dict[str, Any]) -> None:
        snap = self._wait(record, "idle", self._idle, self.policy.idle_wait_s)

        if not self._idle(snap):
            raise self._fail(record, SERVER_BUSY, f"server not idle after {self.policy.idle_wait_s:.0f}s "
                             f"(active {snap['active_requests']}, waiting {snap['waiting_requests']}, loading {snap['loading']}); "
                             "unloading would abort another client's request")

    def _unload_verified(self, record: dict[str, Any], model: str) -> None:
        for attempt in range(1, self.policy.unload_attempts + 1):
            self._wait_idle(record)

            try:
                self._act(record, "unload", model, lambda: self.runtime.unload(model))
            except OmlxError as exc:
                # 400 is "not loaded": the state check below decides.
                if exc.kind == ENDPOINT_UNAVAILABLE:
                    raise self._fail(record, ENDPOINT_UNAVAILABLE, exc.detail) from exc

            snap = self._wait(record, f"unloaded:{model}", lambda s: model not in s["loaded"], self.policy.settle_wait_s)

            if model not in snap["loaded"]:
                return

        raise self._fail(record, UNLOAD_UNVERIFIED, f"{model} still loaded after {self.policy.unload_attempts} unload attempt(s)")

    def acquire(self, model: str) -> dict[str, Any]:
        """Make `model` the only resident model, verified. Returns the transition record."""

        record = self._new_record("acquire", model)

        try:
            record["before"] = before = self.snapshot()
        except OmlxError as exc:
            raise self._fail(record, ENDPOINT_UNAVAILABLE, str(exc)) from exc

        try:
            if model not in before["models"]:
                raise self._fail(record, MODEL_NOT_SERVED, f"{model} is not served by oMLX "
                                 f"(served: {', '.join(sorted(before['models']))}); no fallback model is used")

            others = [m for m in before["loaded"] if m != model]
            pinned = [m for m in others if before["models"][m]["pinned"]]

            if pinned:
                raise self._fail(record, PINNED_MODEL_RESIDENT, f"pinned model(s) resident: {', '.join(pinned)}; "
                                 "APTrace does not change oMLX pins")

            for other in others:
                self._unload_verified(record, other)

            size = before["models"][model].get("estimated_size") or 0

            def fits(snap: dict[str, Any]) -> bool:
                if model in snap["loaded"] or not snap["ceiling"]:
                    return True
                return (snap["current_model_memory"] or 0) + size <= snap["ceiling"]

            snap = self._wait(record, "headroom", fits, self.policy.settle_wait_s)

            if not fits(snap):
                raise self._fail(record, INSUFFICIENT_MEMORY, f"{model} needs ~{size} bytes; resident "
                                 f"{snap['current_model_memory']} of ceiling {snap['ceiling']}")

            if model not in snap["loaded"]:
                last: OmlxError | None = None

                for attempt in range(1, self.policy.load_attempts + 1):
                    self._wait_idle(record)

                    try:
                        self._act(record, "load", model, lambda: self.runtime.load(model))
                        last = None
                        break
                    except OmlxError as exc:
                        last = exc

                        if exc.kind not in (INSUFFICIENT_MEMORY, SERVER_BUSY, "timeout"):
                            break

                        self._wait(record, "settle", lambda s: False, min(self.policy.settle_wait_s, 10.0))

                if last is not None:
                    kind = last.kind if last.kind in (INSUFFICIENT_MEMORY, ENDPOINT_UNAVAILABLE, MODEL_NOT_SERVED) else LOAD_FAILED
                    raise self._fail(record, kind, str(last))

            after = self._wait(record, f"loaded:{model}", lambda s: model in s["loaded"] and not s["loading"],
                               self.policy.settle_wait_s)
            record["after"] = after

            if model not in after["loaded"]:
                raise self._fail(record, LOAD_UNVERIFIED, f"{model} not reported loaded after load")

            extra = [m for m in after["loaded"] if m != model]

            if extra:
                raise self._fail(record, UNEXPECTED_RESIDENCY, f"other model(s) resident after acquire: {', '.join(extra)}")

            record["ok"] = True
            return record
        except OmlxError as exc:
            raise self._fail(record, exc.kind, str(exc)) from exc

    def release(self, model: str) -> dict[str, Any]:
        """Unload `model` if resident, verified. Returns the transition record."""

        record = self._new_record("release", model)

        try:
            record["before"] = before = self.snapshot()

            if model in before["loaded"]:
                self._unload_verified(record, model)

            record["after"] = self.snapshot()
            record["ok"] = model not in record["after"]["loaded"]

            if not record["ok"]:
                raise self._fail(record, UNLOAD_UNVERIFIED, f"{model} still loaded after release")

            return record
        except OmlxError as exc:
            raise self._fail(record, exc.kind, str(exc)) from exc


__all__ = [
    "RESIDENCY_VERSION", "OmlxRuntime", "OmlxError", "ResidencyError", "ResidencyPolicy", "ModelResidency",
    "model_settings", "server_root",
    "ENDPOINT_UNAVAILABLE", "MODEL_NOT_SERVED", "SERVER_BUSY", "PINNED_MODEL_RESIDENT", "UNLOAD_UNVERIFIED",
    "INSUFFICIENT_MEMORY", "LOAD_FAILED", "LOAD_UNVERIFIED", "UNEXPECTED_RESIDENCY",
]
