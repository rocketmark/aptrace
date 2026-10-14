"""
Caller-grounded argument observation: which argument values actually reach
one function through which call sites, observed in a concrete replay of one
registered case scenario (tools/unicorn/call_observation.py over the case's
boot recipe or one of its existing virtual-link scenarios).

This answers a question `function_effects` cannot: that analysis is
parametric in the argument registers (or specialized to a value the caller
chooses, which is hypothetical). Observed values are concrete runtime
values under the scenario's disclosed harness assumptions, for the
contexts the scenario reached. Static call sites the scenario never
reached are reported as UNOBSERVED, never as unreachable.

A request may also name a few small RAM fields to watch: every CPU store to
them in the scenario is reported with the bytes it overwrote, and argument
values pointing into them are correlated with that history. A field with no
observed store was not written in that scenario; it is not thereby
immutable. Results from different scenarios are different operations.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field


ANALYSIS_NAME = "observed_call_arguments"
ANALYSIS_VERSION = 2
TIMEOUT_SECONDS = 300
DEFAULT_SCENARIO = "boot"
MAX_WATCH_FIELDS = 8
MAX_WATCH_BYTES = 16

# Evidence basis labels. A caller-grounded observation is a value that reached
# the function through an actual executed call; a hypothetical analysis (e.g.
# function_effects under an argument specialization) chooses its inputs.
CALLER_GROUNDED = "CALLER_GROUNDED_CONCRETE"

_FUNCTION_RE = re.compile(r"FUN_([0-9a-f]{8})")
_SCENARIO_RE = re.compile(r"[a-z0-9][a-z0-9-]{0,39}")
# What a scenario of each registry kind executes, for the planner's choice.
SCENARIO_KINDS = {
    "boot-recipe": "full boot from reset into the main loop",
    "virtual-link": "short protocol slices entered mid-firmware on non-booted RAM",
}


def _short_register(name: str) -> str:
    """'SERCOM2.I2CM.CTRLA/I2CS.CTRLA/...' -> 'SERCOM2.CTRLA' when every alias names the same register."""

    aliases = name.split("/")
    leaves = {alias.rsplit(".", 1)[-1] for alias in aliases}

    if len(aliases) > 1 and len(leaves) == 1:
        return f"{aliases[0].split('.', 1)[0]}.{leaves.pop()}"

    return aliases[0]


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
    scenario_config: dict[str, Any] = Field(default_factory=dict)
    scenario_failure: str | None = None
    observed_entries: int = 0
    call_sites: list[CallSiteObservation] = Field(default_factory=list)
    mmio_in_function: dict[str, Any] | None = None
    run: dict[str, Any] = Field(default_factory=dict)
    legs: list[dict[str, Any]] = Field(default_factory=list)
    watched_fields: dict[str, Any] | None = None
    correlation: list[dict[str, Any]] = Field(default_factory=list)
    harness_assumptions: list[dict[str, Any]] = Field(default_factory=list)
    coverage: str = ""
    provenance: dict[str, Any] = Field(default_factory=dict)
    planner_summary: str = ""


def validate_request(function: Any) -> tuple[str, int]:
    match = _FUNCTION_RE.fullmatch(str(function))

    if match is None:
        raise ObservationInputError("function must be a FUN_xxxxxxxx identity")

    return f"FUN_{match.group(1)}", int(match.group(1), 16)


def validate_scenario(scenario: Any, supported: Mapping[str, Any]) -> str:
    name = DEFAULT_SCENARIO if scenario is None else scenario

    if not isinstance(name, str) or not _SCENARIO_RE.fullmatch(name) or name not in supported:
        raise ObservationInputError(f"unknown scenario {scenario!r}; supported: {', '.join(sorted(supported))}")

    return name


def validate_watch(watch: Any, ram: tuple[int, int]) -> list[dict[str, Any]]:
    """
    Canonical watched fields: [{"address": "0x...", "size": n[, "object_base": "0x..."]}].

    At most MAX_WATCH_FIELDS non-overlapping RAM fields of 1..MAX_WATCH_BYTES
    bytes. An object base, when given, must lie at or below the field.
    """

    if watch is None:
        return []

    if not isinstance(watch, (list, tuple)) or len(watch) > MAX_WATCH_FIELDS:
        raise ObservationInputError(f"watch must be a list of at most {MAX_WATCH_FIELDS} fields")

    def integer(value: Any, what: str) -> int:
        if isinstance(value, bool):
            raise ObservationInputError(f"{what} must be an integer")
        if isinstance(value, str):
            try:
                value = int(value, 0)
            except ValueError:
                raise ObservationInputError(f"{what} must be an integer") from None
        if not isinstance(value, int):
            raise ObservationInputError(f"{what} must be an integer")
        return value

    fields = []

    for item in watch:
        if not isinstance(item, Mapping) or set(item) - {"address", "size", "object_base"} or not {"address", "size"} <= set(item):
            raise ObservationInputError("each watched field has address, size and optional object_base")

        address, size = integer(item["address"], "address"), integer(item["size"], "size")

        if not 1 <= size <= MAX_WATCH_BYTES:
            raise ObservationInputError(f"watched field size must be 1..{MAX_WATCH_BYTES}")
        if not (ram[0] <= address and address + size <= ram[0] + ram[1]):
            raise ObservationInputError(f"watched field 0x{address:08x}+{size} is not inside RAM")

        field = {"address": f"0x{address:08x}", "size": size}

        if item.get("object_base") is not None:
            base = integer(item["object_base"], "object_base")
            if not ram[0] <= base <= address:
                raise ObservationInputError("object_base must be a RAM address at or below the field")
            field["object_base"] = f"0x{base:08x}"

        fields.append(field)

    fields.sort(key=lambda f: int(f["address"], 16))

    for a, b in zip(fields, fields[1:]):
        if int(a["address"], 16) + a["size"] > int(b["address"], 16):
            raise ObservationInputError("watched fields overlap")

    return fields


class ObservedCallArgumentsRunner:
    """
    Bounded concrete observation of one function's incoming arguments.

    APTrace binds the interpreter, case script, firmware identity, static
    caller source, scenario registry and time bound at construction; a
    request names one function, one registered scenario, and optionally a
    few bounded RAM fields to watch.
    """

    def supported_scenarios(self) -> list[str]:
        """Registered scenarios that execute this firmware."""

        return sorted(k for k, v in self.scenarios.items() if self.firmware_key in v.get("firmware_keys", ()))

    def scenario_note(self) -> str:
        """One line per scenario kind, for choosing among supported scenarios."""

        kinds: dict[str, list[str]] = {}

        for name in self.supported_scenarios():
            kinds.setdefault(str(self.scenarios[name].get("kind")), []).append(name)

        return "; ".join(
            f"{', '.join(names) if len(names) <= 2 else names[0].split('-')[0] + '-*'}: {SCENARIO_KINDS.get(kind, kind)}"
            for kind, names in sorted(kinds.items())
        )

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
        scenarios: Mapping[str, Mapping[str, Any]] | None = None,
        ram: tuple[int, int] = (0x20000000, 0x30000),
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
        # Registered scenario id -> registry entry; a request may name only these.
        self.scenarios = dict(scenarios or {DEFAULT_SCENARIO: {"kind": "boot-recipe", "firmware_keys": [firmware_key]}})
        self.ram = ram
        self._run = run or (
            lambda argv: subprocess.run(argv, capture_output=True, text=True, timeout=TIMEOUT_SECONDS, check=False)
        )

    def observe(self, function: Any, scenario: Any = None, watch: Any = None) -> ObservedCallArguments:
        name, entry = validate_request(function)
        scenario = validate_scenario(scenario, self.scenarios)
        fields = validate_watch(watch, self.ram)

        if not self.entry_allowed(entry):
            raise ObservationInputError(f"{name} is not a census function or vector-table handler entry")

        base = ObservedCallArguments(status="failed", function=name, entry=f"0x{entry:08x}", scenario=scenario)
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
        argv = [str(self.python), str(self.script), "--firmware-key", self.firmware_key, "--entry", f"0x{entry:x}",
                "--scenario", scenario]

        if extent is not None:
            argv += ["--extent", f"0x{extent[0]:x}:0x{extent[1]:x}"]

        for field in fields:
            argv += ["--watch", f"{field['address']}:{field['size']}" + (f"@{field['object_base']}" if "object_base" in field else "")]

        try:
            proc = self._run(argv)
        except subprocess.TimeoutExpired:
            base.status = f"bounded: timeout {TIMEOUT_SECONDS}s"
            base.planner_summary = f"{name} observed arguments ({scenario}): scenario did not finish within {TIMEOUT_SECONDS}s; nothing concluded"
            return base

        if proc.returncode != 0:
            tail = (proc.stderr or "").strip().splitlines()[-1:] or ["no output"]
            base.planner_summary = f"{name} observed arguments ({scenario}): harness failed ({tail[0][:160]})"
            return base

        try:
            doc = json.loads(proc.stdout)
        except ValueError:
            base.planner_summary = f"{name} observed arguments ({scenario}): harness emitted no JSON"
            return base

        if doc.get("firmware_sha256", "").lower() != self.expected_sha256:
            raise RuntimeError("observation was produced for a different firmware image")

        if doc.get("scenario") != scenario:
            raise RuntimeError(f"observation was produced for scenario {doc.get('scenario')!r}, not {scenario!r}")

        result = self._interpret(name, entry, doc, extent)
        result.provenance = {
            "analysis": ANALYSIS_NAME,
            "analysis_version": ANALYSIS_VERSION,
            "summarizer": {k: doc.get("observation", {}).get(k) for k in ("analysis", "analysis_version")},
            "engine": "Unicorn concrete execution of a registered case scenario (tools/unicorn/concrete.py)",
            "firmware_sha256": self.expected_sha256,
            "scenario": scenario,
            "scenario_registry_sha256": (doc.get("scenario_config") or {}).get("registry_sha256"),
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

        return _short_register(text.split(" ", 1)[0]) if text else None

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
        run = dict(doc.get("run") or {})
        config = dict(doc.get("scenario_config") or {})
        # A document from before the scenario registry is a boot-recipe run.
        config.setdefault("kind", "boot-recipe" if "recipe" in doc else None)
        scenario = doc.get("scenario")
        coverage = (
            f"observed contexts only: scenario {scenario!r} ({config.get('kind')}), "
            f"{run.get('instructions_executed')} instructions of {self.firmware_key} code; "
            + (f"{len(unobserved)} static call site(s) never reached: {', '.join(unobserved)}" if unobserved
               else "every static call site reached" if static
               else "no static call site (any caller is indirect)")
            + "; unobserved values or call sites are not thereby impossible"
        )

        if config.get("kind") == "boot-recipe":
            run.update(recipe_reference=(doc.get("recipe") or {}).get("reference_key"),
                       recipe_gaps=(doc.get("recipe") or {}).get("gaps"))
            assumptions = list((doc.get("recipe") or {}).get("assumptions", []))
        else:
            # A virtual-link leg's harness inputs are what the scenario supplied:
            # its mid-firmware entry, seeded memory/registers, stubs, forced state.
            assumptions = [
                {"kind": "scenario-leg", "addr": leg["entry"], "leg": leg["leg"],
                 "detail": (f"entry {leg['entry']} ({'fresh' if leg['fresh'] else 'continued'} state); "
                            f"{len(leg.get('seeds') or [])} seeded range(s), {len(leg.get('reg_seed') or [])} register seed(s), "
                            f"{len(leg.get('stub_calls') or [])} stub(s)"
                            + (f", forced {leg['forced']}" if leg.get("forced") else ""))}
                for leg in doc.get("legs") or [] if leg.get("observed")
            ]

        correlation = []

        for group in doc.get("correlation") or []:
            group = dict(group)
            group["pointee_words"] = [
                dict(w, register_name=self._register(w["word"], w.get("region"))) for w in group.get("pointee_words", [])
            ]
            correlation.append(group)

        return ObservedCallArguments(
            status=status,
            function=name,
            entry=f"0x{entry:08x}",
            scenario=scenario,
            scenario_config=config,
            scenario_failure=doc.get("scenario_failure"),
            observed_entries=observation.get("observed_entries", 0),
            call_sites=sites,
            mmio_in_function=mmio_summary,
            run=run,
            legs=list(doc.get("legs") or []),
            watched_fields=doc.get("watched_fields"),
            correlation=correlation,
            harness_assumptions=assumptions,
            coverage=coverage,
        )


def planner_summary(result: ObservedCallArguments) -> str:
    """Compact, mechanically derived planner rendering."""

    if result.planner_summary:
        return result.planner_summary

    kind = result.scenario_config.get("kind")
    observed = [s for s in result.call_sites if s.status != "UNOBSERVED"]
    unreached = [s for s in result.call_sites if s.status == "UNOBSERVED"]
    r0 = {v.value: v for s in observed for v in s.arguments.get("r0", [])}
    # The first line is the digest: a bounded planner view may show nothing else.
    digest = [f"{len(observed)} call site(s) reached, {len(unreached)} unreached"]

    if r0:
        values = sorted(r0.values(), key=lambda v: v.value)
        digest.append("r0 " + ", ".join(f"{v.value}({v.register_name or v.region or '?'})" for v in values[:3])
                      + (f" +{len(values) - 3}" if len(values) > 3 else ""))
        words = sorted({(v.pointee_word, v.pointee_register_name or v.pointee_word_region or "?") for v in values if v.pointee_word})
        if words:
            digest.append("word at r0 " + ", ".join(f"{w}({n} content)" for w, n in words[:3]))

    if not result.observed_entries:
        digest.append("not entered in this scenario: nothing about its accesses was observed")
    elif result.mmio_in_function is not None:
        digest.append(f"MMIO accesses from its code {result.mmio_in_function['access_count']}")

    lines = [
        f"{result.function} observed arguments [{result.basis}; scenario {result.scenario} ({kind}); "
        f"status {result.status}]: {result.observed_entries} entries in "
        f"{result.run.get('instructions_executed')} instructions; " + "; ".join(digest)
    ]

    if result.scenario_failure:
        lines.append(f"  scenario failed: {result.scenario_failure[:160]}")

    for site in result.call_sites:
        if site.status == "UNOBSERVED":
            lines.append(f"  {site.call_site} ({site.caller}): UNOBSERVED (not reached; not unreachable)")
            continue

        r0 = site.arguments.get("r0", [])
        values = "; ".join(
            f"{v.value}({v.register_name or v.region or '?'})"
            + (f"->*={v.pointee_word}({v.pointee_register_name or v.pointee_word_region or '?'} content)" if v.pointee_word else "")
            for v in r0[:3]
        )
        lines.append(f"  {site.call_site} ({site.caller}) {site.call_kind} x{site.hits}: r0 {values}")

    if result.mmio_in_function is not None:
        m = result.mmio_in_function
        lines.append(
            f"  MMIO accesses from code in {m['extent'][0]}..{m['extent'][1]}: {m['access_count']}"
            + (" (log truncated)" if m.get("log_truncated") else "")
        )

    if result.watched_fields:
        for field in result.watched_fields.get("fields", [])[:4]:
            init = field.get("initialization")
            lines.append(
                f"  field {field['name']}: {field['writes']} store(s)"
                + (f", initialized to {init['new']} by {init['function'] or init['pc']}" if init else ", never set")
                + ("; changed later" if field.get("changed_after_initialization") else "; no later change observed")
            )
        if not result.watched_fields.get("complete", True):
            lines.append(f"  watched stores incomplete: {result.watched_fields.get('dropped_writes')} dropped")

    for group in result.correlation[:3]:
        lines.append(
            f"  {group['call_site']} {group['register']}={group['value']}({group['value_region']}) is field "
            f"{group['field']}: {group['field_state']}"
        )

    lines.append(f"  harness: {len(result.harness_assumptions)} disclosed assumption(s); {result.coverage}")
    return "\n".join(lines)
