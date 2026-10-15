"""
Caller-argument provenance: for ONE register-indirect transfer site the
census inventories whose target is an incoming argument, which values the
direct callers of that function pass in that argument
(tools/census/callback_provenance.py: one call boundary, no further).

Each caller's value is CONCRETE, FINITE_TARGET_SET, FORWARDED_ARGUMENT
(the caller's own argument: the next hop is named, never taken),
MEMORY_DEPENDENT or UNKNOWN; constants are checked as Cortex-M Thumb code
pointers. A caller-supplied value is a POSSIBLE target: it is not the
callee reaching the site, an observed dispatch, or a reachable path. The
target set is CLOSED only when no other entry into the function is known.
A request names a site only; the firmware, census and bounds are bound
here.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from aptrace_agent.indirect_target import IndirectTargetInputError, census_register_indirect_sites, validate_site


ANALYSIS_NAME = "callback_argument_provenance"
ANALYSIS_VERSION = 1
TIMEOUT_SECONDS = 120
STATIC_ONE_HOP = "STATIC_ONE_HOP_CALLER_ARGUMENT"

__all__ = ["CallbackProvenance", "CallbackProvenanceRunner", "IndirectTargetInputError", "planner_summary"]


class CallbackProvenance(BaseModel):
    status: str
    site: str
    basis: str = STATIC_ONE_HOP
    instruction: str | None = None
    target_register: str | None = None
    containing_function: str | None = None
    site_pattern: str | None = None
    site_derivation_status: str | None = None
    provenance_status: str | None = None
    target_set: str | None = None
    argument_origins: list[dict[str, Any]] = Field(default_factory=list)
    candidate_targets: list[dict[str, Any]] = Field(default_factory=list)
    non_callable_values: list[str] = Field(default_factory=list)
    next_hops: list[dict[str, Any]] = Field(default_factory=list)
    caller_value_statuses: dict[str, int] = Field(default_factory=dict)
    open_reasons: list[str] = Field(default_factory=list)
    incomplete_reasons: list[str] = Field(default_factory=list)
    recorded_coverage: dict[str, Any] = Field(default_factory=dict)
    limitations: list[str] = Field(default_factory=list)
    provenance: dict[str, Any] = Field(default_factory=dict)
    planner_summary: str = ""


class CallbackProvenanceRunner:
    """
    Bounded one-hop caller-argument provenance for one census indirect site.

    APTrace binds the interpreter, census tool, census database, firmware
    identity and time bound at construction; a request names one site from
    the census's register-indirect inventory.
    """

    def __init__(
        self,
        *,
        python: Path,
        script: Path,
        firmware_key: str,
        firmware_image: Path,
        expected_sha256: str,
        db_path: Path,
        sites: Callable[[], Iterable[int]] | None = None,
        run: Callable[[list[str]], subprocess.CompletedProcess] | None = None,
    ) -> None:
        self.python = Path(python)
        self.script = Path(script)
        self.firmware_key = firmware_key
        self.firmware_image = Path(firmware_image)
        self.expected_sha256 = expected_sha256.lower()
        self.db_path = Path(db_path)
        self._sites = sites or (lambda: census_register_indirect_sites(self.db_path, self.firmware_key))
        self._cached_sites: list[int] | None = None
        self._run = run or (
            lambda argv: subprocess.run(argv, capture_output=True, text=True, timeout=TIMEOUT_SECONDS, check=False)
        )

    def sites(self) -> list[int]:
        if self._cached_sites is None:
            self._cached_sites = sorted(self._sites())

        return self._cached_sites

    def trace(self, site: Any) -> CallbackProvenance:
        address = validate_site(site, self.sites())
        name = f"0x{address:08x}"
        base = CallbackProvenance(status="failed", site=name)
        image = self.firmware_image.read_bytes() if self.firmware_image.is_file() else b""

        if hashlib.sha256(image).hexdigest() != self.expected_sha256:
            base.status = "firmware_unavailable"
            base.planner_summary = f"{name} callback provenance: firmware image missing or hash mismatch"
            return base

        argv = [str(self.python), str(self.script), self.firmware_key, "--db", str(self.db_path), "--site", name]

        try:
            proc = self._run(argv)
        except subprocess.TimeoutExpired:
            base.status = f"bounded: timeout {TIMEOUT_SECONDS}s"
            base.planner_summary = f"{name} callback provenance: analysis did not finish within {TIMEOUT_SECONDS}s; nothing concluded"
            return base

        if proc.returncode != 0:
            tail = (proc.stderr or "").strip().splitlines()[-1:] or ["no output"]
            base.planner_summary = f"{name} callback provenance: analysis failed ({tail[0][:160]})"
            return base

        try:
            result = json.loads(proc.stdout)["sites"][0]
        except (ValueError, KeyError, IndexError):
            base.planner_summary = f"{name} callback provenance: analysis emitted no result"
            return base

        if str(result.get("firmware_sha256", "")).lower() != self.expected_sha256:
            raise RuntimeError("callback provenance was produced for a different firmware image")

        if result.get("site") != name:
            raise RuntimeError(f"callback provenance answered {result.get('site')!r}, not {name!r}")

        out = CallbackProvenance(
            status="ok",
            site=name,
            instruction=result.get("instruction"),
            target_register=result.get("target_register"),
            containing_function=result.get("containing_function"),
            site_pattern=result.get("site_pattern"),
            site_derivation_status=result.get("site_derivation_status"),
            provenance_status=result.get("provenance_status"),
            target_set=result.get("target_set"),
            argument_origins=list(result.get("argument_origins") or []),
            candidate_targets=list(result.get("candidate_targets") or []),
            non_callable_values=list(result.get("non_callable_values") or []),
            next_hops=list(result.get("next_hops") or []),
            caller_value_statuses=dict(result.get("caller_value_statuses") or {}),
            open_reasons=list(result.get("open_reasons") or []),
            incomplete_reasons=list(result.get("incomplete_reasons") or []),
            recorded_coverage=dict(result.get("recorded_coverage") or {}),
            limitations=list(result.get("limitations") or []),
            provenance={
                "analysis": ANALYSIS_NAME,
                "analysis_version": ANALYSIS_VERSION,
                "engine": {"analysis": result.get("analysis"), "analysis_version": result.get("analysis_version"),
                           "site_analysis": result.get("site_analysis"), "bounds": result.get("bounds"),
                           "work": result.get("work")},
                "firmware_sha256": self.expected_sha256,
                "callers": "direct BL/B.W/B<c>.W/B transfers decoded by a halfword sweep, kept where the census "
                           "decodes an instruction; cross-checked with census edges",
                "blocks": "census basic blocks and resolved edges (Ghidra block model + Capstone sweep; heuristic boundaries)",
            },
        )
        out.planner_summary = planner_summary(out)
        return out


def _value(component: dict[str, Any]) -> str:
    kind = component.get("kind")

    if kind == "constant":
        shown = component.get("raw_value")
        return f"{shown} -> {component['target']}" if component.get("callable") else f"{shown} ({component.get('validity')})"

    if kind == "forwarded":
        return f"its own incoming {component.get('argument')}"

    if kind == "memory":
        return f"memory ({component.get('shape')})"

    return f"unknown ({component.get('reason', '')[:60]})"


def planner_summary(result: CallbackProvenance) -> str:
    """Compact, mechanically derived planner rendering."""

    if result.planner_summary:
        return result.planner_summary

    lines = [
        f"{result.site} {result.instruction} in {result.containing_function or 'unattributed code'} [{result.basis}]: "
        f"provenance {result.provenance_status}, target set {result.target_set}"
    ]

    for origin in result.argument_origins[:2]:
        lines.append(f"  target = incoming {origin.get('argument')} of {origin.get('function_entry')}; "
                     f"{len(origin.get('callers') or [])} direct caller(s)")

        for caller in (origin.get("callers") or [])[:4]:
            values = ", ".join(_value(c) for c in (caller.get("components") or [])[:3])
            lines.append(f"    {caller.get('site')} ({caller.get('transfer')}, {caller.get('caller_function') or 'unattributed'}): "
                         f"{caller.get('value_status')} {values}")

    for hop in result.next_hops[:2]:
        lines.append(f"  next hop (not taken): what callers of {hop['function_entry']} pass in {hop['argument']}")

    for reason in result.open_reasons[:2]:
        lines.append(f"  open: {reason}")

    lines.append("  a caller-supplied value is a possible target, not an observed dispatch or a reachable path")
    return "\n".join(lines)
