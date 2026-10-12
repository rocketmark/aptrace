from __future__ import annotations

import hashlib
import json
import re
import subprocess
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field


ANALYSIS_NAME = "function_effects"
ANALYSIS_VERSION = 1

# APTrace-owned bounds.
MAX_SPECIALIZATIONS = 2
TIMEOUT_SECONDS = 300
SPECIALIZABLE = ("r0", "r1", "r2", "r3")

_FUNCTION_RE = re.compile(r"FUN_([0-9a-f]{8})")


class EffectsInputError(ValueError):
    """The request names something APTrace does not allow."""


class AccessFact(BaseModel):
    kind: str
    pc: str | None
    width: int | None
    address: str  # concrete hex, or "parametric"
    depends_on: list[str] = Field(default_factory=list)
    served_from_flash: bool = False
    region: str | None = None  # RAW concrete region or SOLVER-proven region
    register_name: str | None = None
    guard: str = "always"  # always / conditional / ... (SOLVER when queried)


class SpecializedFact(BaseModel):
    assumption: str
    pc: str | None
    kind: str
    address: str | None
    register_name: str | None
    guard: str | None


class FunctionEffectsResult(BaseModel):
    """
    Effects of one function, from Macaw discovery and Crucible simulation
    (RAW) plus What4/Z3 queries over those terms (SOLVER).

    RAW facts hold for all inputs under the harness assumptions listed.
    SOLVER facts are proved over the raw terms, optionally under an
    explicit argument specialization; they are not concrete runtime values.
    """

    status: str
    function: str
    entry: str
    # "complete", or "bounded: ..." when the raw simulation did not cover
    # the whole function (e.g. a computed control transfer modeled as an
    # opaque call, so code reachable only through it was never simulated).
    coverage: str = "complete"
    specialize: dict[str, str] = Field(default_factory=dict)
    blocks: int | None = None
    inputs_used: list[str] = Field(default_factory=list)
    reads: int = 0
    writes: int = 0
    calls: list[dict[str, Any]] = Field(default_factory=list)
    accesses: list[AccessFact] = Field(default_factory=list)
    return_depends_on: list[str] = Field(default_factory=list)
    return_bit_valued: str | None = None  # SOLVER: proven / refuted / unknown
    specialized: list[SpecializedFact] = Field(default_factory=list)
    harness_assumptions: list[str] = Field(default_factory=list)
    raw: dict[str, Any] = Field(default_factory=dict)
    solver: dict[str, Any] = Field(default_factory=dict)
    provenance: dict[str, Any] = Field(default_factory=dict)
    planner_summary: str = ""


def validate_request(function: Any, specialize: Any) -> tuple[str, int, dict[str, int]]:
    """Accept only a function identity and bounded argument specializations."""

    match = _FUNCTION_RE.fullmatch(str(function))

    if match is None:
        raise EffectsInputError("function must be a FUN_xxxxxxxx identity")

    if specialize is None:
        specialize = {}

    if not isinstance(specialize, Mapping):
        raise EffectsInputError("specialize must map argument registers to integers")

    unknown = sorted(set(specialize) - set(SPECIALIZABLE))

    if unknown:
        raise EffectsInputError(f"cannot specialize {', '.join(unknown)}; only r0-r3")

    if len(specialize) > MAX_SPECIALIZATIONS:
        raise EffectsInputError(f"at most {MAX_SPECIALIZATIONS} specializations")

    values: dict[str, int] = {}

    for register, value in specialize.items():
        if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 0xFFFFFFFF:
            raise EffectsInputError(f"{register} must be an integer in 0..0xffffffff")

        values[register] = value

    return f"FUN_{match.group(1)}", int(match.group(1), 16), dict(sorted(values.items()))


class FunctionEffectsRunner:
    """
    Bounded, APTrace-configured function-effects analysis.

    APTrace binds the analysis binary, firmware image and its hash, target
    geometry, cache location and time bound at construction. A request
    names one function and optional argument specializations; nothing else
    reaches the command line.
    """

    def __init__(
        self,
        *,
        binary: Path,
        firmware_image: Path,
        expected_sha256: str,
        mmio_window: tuple[int, int],
        cache_dir: Path,
        entry_allowed: Callable[[int], bool],
        resolve_register: Callable[[int], str | None],
        run: Callable[[list[str]], subprocess.CompletedProcess] | None = None,
    ) -> None:
        self.binary = Path(binary)
        self.firmware_image = Path(firmware_image)
        self.expected_sha256 = expected_sha256.lower()
        self.mmio_window = mmio_window
        self.cache_dir = Path(cache_dir)
        self.entry_allowed = entry_allowed
        self.resolve_register = resolve_register
        self._run = run or (
            lambda argv: subprocess.run(argv, capture_output=True, text=True, timeout=TIMEOUT_SECONDS, check=False)
        )

    def analyze(self, function: Any, specialize: Any = None) -> FunctionEffectsResult:
        name, entry, specs = validate_request(function, specialize)

        if not self.entry_allowed(entry):
            raise EffectsInputError(f"{name} is not a census function or vector-table handler entry")

        spec_text = {k: f"0x{v:x}" for k, v in specs.items()}
        base = FunctionEffectsResult(status="failed", function=name, entry=f"0x{entry:08x}", specialize=spec_text)

        image = self.firmware_image.read_bytes() if self.firmware_image.is_file() else b""

        if hashlib.sha256(image).hexdigest() != self.expected_sha256:
            base.status = "firmware_unavailable"
            base.planner_summary = f"{name} effects: firmware image missing or hash mismatch"
            return base

        key = "_".join([self.expected_sha256[:16], f"{entry:08x}"] + [f"{k}{v:x}" for k, v in specs.items()])
        prefix = self.cache_dir / key
        raw_path = prefix.with_suffix(".raw.json")
        enriched_path = prefix.with_suffix(".enriched.json")
        failed_path = prefix.with_suffix(".failed.json")
        cached = enriched_path.is_file()

        if not cached and failed_path.is_file():
            # A bounded failure is deterministic for this firmware, entry and
            # specialization; do not spend the time bound again.
            recorded = json.loads(failed_path.read_text())
            base.status = recorded["status"]
            base.coverage = f"bounded: {recorded['status']}"
            base.planner_summary = recorded["summary"] + " (cached)"
            return base

        if not cached:
            if not self.binary.is_file():
                base.status = "analysis_binary_unavailable"
                base.planner_summary = f"{name} effects: aptrace binary not built"
                return base

            self.cache_dir.mkdir(parents=True, exist_ok=True)
            argv = [str(self.binary), "function-effects", str(self.firmware_image), f"0x{entry:x}"]
            argv += [f"{k}=0x{v:x}" for k, v in specs.items()]
            argv.append(f"out={prefix}")

            try:
                proc = self._run(argv)
            except subprocess.TimeoutExpired:
                base.status = f"bounded: timeout {TIMEOUT_SECONDS}s"
                base.coverage = base.status
                base.planner_summary = (
                    f"{name} effects: no result within the {TIMEOUT_SECONDS}s bound "
                    "(likely an input-dependent loop); nothing concluded"
                )
                failed_path.write_text(json.dumps({"status": base.status, "summary": base.planner_summary}))
                return base

            if proc.returncode != 0 or not raw_path.is_file():
                base.status = "failed"
                base.coverage = "bounded: failed"
                tail = (proc.stderr or "").strip().splitlines()[-1:] or ["no output"]
                base.planner_summary = f"{name} effects: analysis failed ({tail[0][:160]})"
                base.raw = {"stderr_tail": (proc.stderr or "")[-2000:]}
                failed_path.write_text(json.dumps({"status": base.status, "summary": base.planner_summary}))
                return base

        raw = json.loads(raw_path.read_text())
        enriched = json.loads(enriched_path.read_text()) if enriched_path.is_file() else {}
        result = self._interpret(name, entry, spec_text, raw, enriched)
        result.provenance = {
            "analysis": ANALYSIS_NAME,
            "analysis_version": ANALYSIS_VERSION,
            "engine": "Macaw discovery + Crucible simulation (raw); What4/Z3 (solver)",
            "firmware_sha256": self.expected_sha256,
            "raw_artifact": str(raw_path),
            "enriched_artifact": str(enriched_path) if enriched else None,
            "cached": cached,
            "mmio_window": [f"0x{self.mmio_window[0]:x}", f"0x{self.mmio_window[1]:x}"],
        }
        return result

    # -- interpretation -------------------------------------------------------

    def _region(self, value: int, regions: list[dict[str, str]]) -> str | None:
        for region in regions:
            base, size = int(region["base"], 16), int(region["size"], 16)

            if base <= value < base + size:
                return region["region"]

        return None

    def _register(self, value: int) -> str | None:
        try:
            text = self.resolve_register(value)
        except Exception:  # advisory naming only
            return None

        return text.split(" ", 1)[0] if text else None

    def _interpret(
        self,
        name: str,
        entry: int,
        specialize: dict[str, str],
        raw: dict[str, Any],
        enriched: dict[str, Any],
    ) -> FunctionEffectsResult:
        regions = raw.get("regions", [])
        window = next((r for r in regions if r.get("region") == "MMIO"), None)

        if window is not None and (int(window["base"], 16), int(window["size"], 16)) != tuple(self.mmio_window):
            raise RuntimeError(
                f"function-effects MMIO window {window} disagrees with census geometry {self.mmio_window}"
            )

        solver = enriched.get("solver_derived_facts", {}) if enriched else {}
        solver_accesses = {item.get("index"): item for item in solver.get("accesses", [])}
        inputs = lambda names: [v.replace("arg_", "").replace("in_", "") for v in names if v.startswith(("arg_", "in_"))]  # noqa: E731

        accesses: list[AccessFact] = []
        specialized: list[SpecializedFact] = []

        for index, access in enumerate(raw.get("accesses", []), start=1):
            address = access.get("address", {})
            concrete = address.get("concrete")
            fact = AccessFact(
                kind=access.get("kind", "?"),
                pc=access.get("pc"),
                width=access.get("width_bytes"),
                address=concrete or "parametric",
                depends_on=inputs(address.get("free_vars", [])),
                served_from_flash=bool(access.get("served_from_concrete_readonly")),
            )

            if access.get("is_stack_block"):
                fact.region = "STACK"
            elif concrete:
                value = int(concrete, 16)
                fact.region = self._region(value, regions)
                fact.register_name = self._register(value) if fact.region == "MMIO" else None

            enrich = solver_accesses.get(index, {})

            if fact.region is None:
                proven = [r["region"] for r in enrich.get("region_membership_under_guard", []) if r.get("membership") == "proven"]
                fact.region = f"{proven[0]} (solver)" if proven else None

            guard = enrich.get("guard_status", {}).get("status")
            fact.guard = guard or ("always" if access.get("guard", {}).get("concrete") is True else "unqueried")
            accesses.append(fact)

            for spec in enrich.get("specializations", []):
                uniq = spec.get("address_uniqueness", {})
                value = uniq.get("value") if uniq.get("outcome") == "unique" else None
                region = self._region(int(value, 16), regions) if value else None

                if concrete or not value:
                    continue

                specialized.append(
                    SpecializedFact(
                        assumption=spec.get("additional_assumption", "?"),
                        pc=fact.pc,
                        kind=fact.kind,
                        address=value,
                        register_name=self._register(int(value, 16)) if region == "MMIO" else region,
                        guard=spec.get("guard_status", {}).get("status"),
                    )
                )

        ret = raw.get("return_r0") or {}
        ret_solver = solver.get("return_r0") or {}
        counts = raw.get("counts", {})
        computed = list(dict.fromkeys(
            call.get("pc") for call in raw.get("calls", []) if not call.get("target_concrete")
        ))
        status = raw.get("status", "unknown")
        reasons = []

        if not status.startswith("complete"):
            reasons.append(status)

        if computed:
            reasons.append(
                f"computed control transfer(s) at {', '.join(computed[:3])} modeled as "
                "opaque calls; code reachable only through them was not simulated"
            )

        coverage = "bounded: " + "; ".join(reasons) if reasons else "complete"

        return FunctionEffectsResult(
            status=status,
            coverage=coverage,
            function=name,
            entry=f"0x{entry:08x}",
            specialize=specialize,
            blocks=raw.get("macaw_blocks"),
            inputs_used=inputs(raw.get("inputs_referenced", [])),
            reads=counts.get("reads", 0),
            writes=counts.get("writes", 0),
            calls=[
                {
                    "pc": call.get("pc"),
                    "target": call.get("target_concrete"),
                    "args": call.get("args_concrete"),
                }
                for call in raw.get("calls", [])
            ],
            accesses=accesses,
            return_depends_on=inputs(ret.get("free_vars", [])) + (
                ["memory"] if "globalMemoryBytes" in ret.get("free_vars", []) else []
            ),
            return_bit_valued=ret_solver.get("bit_valued"),
            specialized=specialized,
            harness_assumptions=list(raw.get("assumptions", [])),
            raw=raw,
            solver=enriched,
        )


def planner_summary(result: FunctionEffectsResult) -> str:
    """Compact, mechanically derived planner rendering."""

    if result.planner_summary:
        return result.planner_summary

    def where(access: AccessFact) -> str:
        if access.address != "parametric":
            label = access.register_name or access.region or "?"
            return f"{access.address}({label})"

        base = f"addr<-{'+'.join(access.depends_on) or 'state'}"
        return base + (f" in {access.region}" if access.region else "")

    # One line per (kind, pc) site: a polling loop repeats a site many times.
    sites: dict[tuple[str, str | None], AccessFact] = {}

    for access in result.accesses:
        sites.setdefault((access.kind, access.pc), access)

    accesses = list(sites.values())
    reads = [a for a in accesses if a.kind == "read"]
    writes = [a for a in accesses if a.kind == "write"]
    mmio = [a for a in accesses if a.region and a.region.startswith("MMIO")]
    flash = [a for a in reads if a.served_from_flash or (a.region or "").startswith("FLASH")]
    conditional = [a for a in accesses if a.guard == "conditional"]
    spec = ",".join(f"{k}={v}" for k, v in result.specialize.items())

    coverage = "complete" if result.coverage == "complete" else result.coverage
    lines = [
        f"{result.function} effects [RAW {coverage}; {result.blocks} blocks]: "
        f"inputs {','.join(result.inputs_used) or 'none'}; {result.reads} reads, {result.writes} writes "
        f"at {len(accesses)} sites, {len(result.calls)} calls"
    ]

    if mmio:
        lines.append("  MMIO: " + "; ".join(f"{a.kind} @{a.pc} {where(a)} guard={a.guard}" for a in mmio[:3]))

    other = [a for a in accesses if a not in mmio][:4]

    if other:
        lines.append(
            "  other: "
            + "; ".join(f"{a.kind} @{a.pc} {where(a)}" + (" [flash]" if a in flash else "") for a in other)
        )

    if writes and not any(w in mmio for w in writes):
        lines.append(f"  writes: {len(writes)} (none to MMIO)")

    if result.calls:
        call_sites = list(dict.fromkeys(f"@{c['pc']}->{c['target'] or 'computed'}" for c in result.calls))
        lines.append("  call sites: " + "; ".join(call_sites[:4]))

    ret = f"return r0 depends on {'+'.join(result.return_depends_on) or 'nothing symbolic'}"

    if result.return_bit_valued:
        ret += f"; [SOLVER] return in {{0,1}}: {result.return_bit_valued}"

    lines.append("  " + ret)

    if conditional:
        lines.append(f"  [SOLVER] {len(conditional)} access(es) conditional on input-derived guards")

    specialized = sorted(result.specialized, key=lambda item: item.register_name in (None, "FLASH", "RAM"))

    for item in specialized[:3]:
        lines.append(
            f"  [SOLVER {item.assumption}] {item.kind} @{item.pc} -> {item.address}"
            + (f" {item.register_name}" if item.register_name else "")
            + (f" guard={item.guard}" if item.guard else "")
        )

    if spec and not result.specialized:
        lines.append(f"  [SOLVER {spec}] no parametric access specialized to a unique address")

    return "\n".join(lines)
