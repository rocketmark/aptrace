"""
Caller-grounded argument observation: which argument values actually reach
one function through which call sites, observed in a concrete replay of a
case scenario (tools/unicorn/call_observation.py over the case's own boot
recipe).

This answers a question `function_effects` cannot: that analysis is
parametric in the argument registers (or specialized to a value the caller
chooses, which is hypothetical). Observed values are concrete runtime
values under the scenario's disclosed harness assumptions, for the
contexts the scenario reached. Static call sites the scenario never
reached are reported as UNOBSERVED, never as unreachable.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field


ANALYSIS_NAME = "observed_call_arguments"
ANALYSIS_VERSION = 1
TIMEOUT_SECONDS = 300

# Evidence basis labels. A caller-grounded observation is a value that reached
# the function through an actual executed call; a hypothetical analysis (e.g.
# function_effects under an argument specialization) chooses its inputs.
CALLER_GROUNDED = "CALLER_GROUNDED_CONCRETE"

_FUNCTION_RE = re.compile(r"FUN_([0-9a-f]{8})")


class ObservationInputError(ValueError):
    """The request names something APTrace does not allow."""


class ArgumentValue(BaseModel):
    value: str
    region: str | None
    count: int
    pointee_word: str | None = None
    pointee_word_region: str | None = None
    register_name: str | None = None  # SVD name when the value is MMIO
    pointee_register_name: str | None = None  # SVD name when the pointee word is MMIO


class CallSiteObservation(BaseModel):
    call_site: str | None
    caller: str | None = None  # Ghidra containing function (heuristic boundary)
    # OBSERVED: reached in the scenario; UNOBSERVED: a static call site the
    # scenario never reached (not unreachable); DYNAMIC_ONLY: observed but
    # absent from the static call list.
    status: str
    call_kind: str | None = None  # BL / BLX_REG / OTHER (decoded from the image)
    static_target_match: bool | None = None
    hits: int = 0
    arguments: dict[str, list[ArgumentValue]] = Field(default_factory=dict)


class ObservedCallArguments(BaseModel):
    status: str
    function: str
    entry: str
    basis: str = CALLER_GROUNDED
    scenario: str | None = None
    observed_entries: int = 0
    call_sites: list[CallSiteObservation] = Field(default_factory=list)
    mmio_in_function: dict[str, Any] | None = None
    run: dict[str, Any] = Field(default_factory=dict)
    harness_assumptions: list[dict[str, Any]] = Field(default_factory=list)
    coverage: str = ""
    provenance: dict[str, Any] = Field(default_factory=dict)
    planner_summary: str = ""


def validate_request(function: Any) -> tuple[str, int]:
    match = _FUNCTION_RE.fullmatch(str(function))

    if match is None:
        raise ObservationInputError("function must be a FUN_xxxxxxxx identity")

    return f"FUN_{match.group(1)}", int(match.group(1), 16)


class ObservedCallArgumentsRunner:
    """
    Bounded concrete observation of one function's incoming arguments.

    APTrace binds the interpreter, case script, firmware identity, static
    caller source and time bound at construction; a request names one
    function and nothing else.
    """

    def __init__(
        self,
        *,
        python: Path,
        script: Path,
        firmware_key: str,
        firmware_image: Path,
        expected_sha256: str,
        entry_allowed: Callable[[int], bool],
        static_call_sites: Callable[[str], list[tuple[str, str | None]]],
        function_extent: Callable[[str], tuple[int, int] | None],
        resolve_register: Callable[[int], str | None],
        run: Callable[[list[str]], subprocess.CompletedProcess] | None = None,
    ) -> None:
        self.python = Path(python)
        self.script = Path(script)
        self.firmware_key = firmware_key
        self.firmware_image = Path(firmware_image)
        self.expected_sha256 = expected_sha256.lower()
        self.entry_allowed = entry_allowed
        self.static_call_sites = static_call_sites
        self.function_extent = function_extent
        self.resolve_register = resolve_register
        self._run = run or (
            lambda argv: subprocess.run(argv, capture_output=True, text=True, timeout=TIMEOUT_SECONDS, check=False)
        )

    def observe(self, function: Any) -> ObservedCallArguments:
        name, entry = validate_request(function)

        if not self.entry_allowed(entry):
            raise ObservationInputError(f"{name} is not a census function or vector-table handler entry")

        base = ObservedCallArguments(status="failed", function=name, entry=f"0x{entry:08x}")
        image = self.firmware_image.read_bytes() if self.firmware_image.is_file() else b""

        if hashlib.sha256(image).hexdigest() != self.expected_sha256:
            base.status = "firmware_unavailable"
            base.planner_summary = f"{name} observed arguments: firmware image missing or hash mismatch"
            return base

        if not self.python.is_file():
            base.status = "harness_unavailable"
            base.planner_summary = f"{name} observed arguments: Unicorn environment not installed"
            return base

        extent = self.function_extent(name)
        argv = [str(self.python), str(self.script), "--firmware-key", self.firmware_key, "--entry", f"0x{entry:x}"]

        if extent is not None:
            argv += ["--extent", f"0x{extent[0]:x}:0x{extent[1]:x}"]

        try:
            proc = self._run(argv)
        except subprocess.TimeoutExpired:
            base.status = f"bounded: timeout {TIMEOUT_SECONDS}s"
            base.planner_summary = f"{name} observed arguments: scenario did not finish within {TIMEOUT_SECONDS}s; nothing concluded"
            return base

        if proc.returncode != 0:
            tail = (proc.stderr or "").strip().splitlines()[-1:] or ["no output"]
            base.planner_summary = f"{name} observed arguments: harness failed ({tail[0][:160]})"
            return base

        try:
            doc = json.loads(proc.stdout)
        except ValueError:
            base.planner_summary = f"{name} observed arguments: harness emitted no JSON"
            return base

        if doc.get("firmware_sha256", "").lower() != self.expected_sha256:
            raise RuntimeError("observation was produced for a different firmware image")

        result = self._interpret(name, entry, doc, extent)
        result.provenance = {
            "analysis": ANALYSIS_NAME,
            "analysis_version": ANALYSIS_VERSION,
            "summarizer": {k: doc.get("observation", {}).get(k) for k in ("analysis", "analysis_version")},
            "engine": "Unicorn concrete execution of the case boot recipe (tools/unicorn/concrete.py)",
            "firmware_sha256": self.expected_sha256,
            "static_call_sites": "Ghidra export call references (heuristic function boundaries)",
        }
        return result

    # -- interpretation -------------------------------------------------------

    def _register(self, value: str | None, region: str | None) -> str | None:
        if value is None or region != "MMIO":
            return None

        try:
            text = self.resolve_register(int(value, 16))
        except Exception:  # advisory naming only
            return None

        return text.split(" ", 1)[0] if text else None

    def _interpret(self, name: str, entry: int, doc: dict[str, Any], extent: tuple[int, int] | None) -> ObservedCallArguments:
        status = doc.get("status", "unknown")
        observation = doc.get("observation") or {}
        static = {site.lower(): caller for site, caller in self.static_call_sites(name)}
        sites: list[CallSiteObservation] = []
        seen: set[str] = set()

        for raw in observation.get("call_sites", []):
            site = raw.get("call_site")
            arguments = {
                reg: [
                    ArgumentValue(
                        value=v["value"],
                        region=v.get("region"),
                        count=v.get("count", 0),
                        pointee_word=v.get("pointee_word"),
                        pointee_word_region=v.get("pointee_word_region"),
                        register_name=self._register(v["value"], v.get("region")),
                        pointee_register_name=self._register(v.get("pointee_word"), v.get("pointee_word_region")),
                    )
                    for v in values
                ]
                for reg, values in (raw.get("arguments") or {}).items()
            }
            key = (site or "").lower()
            seen.add(key)
            sites.append(
                CallSiteObservation(
                    call_site=site,
                    caller=static.get(key),
                    status="OBSERVED" if key in static else "DYNAMIC_ONLY",
                    call_kind=raw.get("call_kind"),
                    static_target_match=raw.get("call_kind") == "BL",
                    hits=raw.get("hits", 0),
                    arguments=arguments,
                )
            )

        for site, caller in sorted(static.items()):
            if site not in seen:
                sites.append(CallSiteObservation(call_site=site, caller=caller, status="UNOBSERVED"))

        mmio = doc.get("mmio_in_extent")
        mmio_summary = None

        if mmio is not None:
            mmio_summary = {
                "extent": mmio.get("extent"),
                "extent_source": "Ghidra function size (heuristic boundary)",
                "access_count": mmio.get("access_count"),
                "accesses": mmio.get("accesses", [])[:20],
                "log_truncated": mmio.get("log_truncated"),
            }

        unobserved = [s.call_site for s in sites if s.status == "UNOBSERVED"]
        coverage = (
            f"observed contexts only: scenario {doc.get('scenario')!r}, "
            f"{(doc.get('run') or {}).get('instructions_executed')} instructions; "
            + (f"{len(unobserved)} static call site(s) never reached: {', '.join(unobserved)}" if unobserved
               else "every static call site reached")
            + "; unobserved values or call sites are not thereby impossible"
        )

        return ObservedCallArguments(
            status=status,
            function=name,
            entry=f"0x{entry:08x}",
            scenario=doc.get("scenario"),
            observed_entries=observation.get("observed_entries", 0),
            call_sites=sites,
            mmio_in_function=mmio_summary,
            run=dict(doc.get("run") or {}, recipe_reference=(doc.get("recipe") or {}).get("reference_key"),
                     recipe_gaps=(doc.get("recipe") or {}).get("gaps")),
            harness_assumptions=list((doc.get("recipe") or {}).get("assumptions", [])),
            coverage=coverage,
        )


def planner_summary(result: ObservedCallArguments) -> str:
    """Compact, mechanically derived planner rendering."""

    if result.planner_summary:
        return result.planner_summary

    lines = [
        f"{result.function} observed arguments [{result.basis}; scenario {result.scenario}; status {result.status}]: "
        f"{result.observed_entries} entries"
    ]

    for site in result.call_sites:
        if site.status == "UNOBSERVED":
            lines.append(f"  {site.call_site} ({site.caller}): UNOBSERVED (not reached; not unreachable)")
            continue

        r0 = site.arguments.get("r0", [])
        values = "; ".join(
            f"{v.value}({v.register_name or v.region or '?'})"
            + (f"->*={v.pointee_word}({v.pointee_register_name or v.pointee_word_region or '?'})" if v.pointee_word else "")
            for v in r0[:3]
        )
        lines.append(f"  {site.call_site} ({site.caller}) {site.call_kind} x{site.hits}: r0 {values}")

    if result.mmio_in_function is not None:
        m = result.mmio_in_function
        lines.append(
            f"  MMIO accesses from code in {m['extent'][0]}..{m['extent'][1]}: {m['access_count']}"
            + (" (log truncated)" if m.get("log_truncated") else "")
        )

    lines.append(f"  harness: {len(result.harness_assumptions)} disclosed assumption(s); {result.coverage}")
    return "\n".join(lines)
