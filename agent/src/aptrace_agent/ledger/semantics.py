"""
Deterministic evidence semantics for the research ledger.

Maps an evidence result to the strongest grade it can support and to the
limitations it carries, using only classifications the producing APTrace
analyses already emit (census confidence, PathStatus, result limitations).
No model is involved.
"""

from __future__ import annotations

import re
from typing import Any

from aptrace_agent.census_graph import (
    NO_KNOWN_PATH_LIMITATION,
    RESOLVED_INDIRECT_LIMITATION,
)
from aptrace_agent.ledger.models import (
    GRADE_RANK,
    ClaimType,
    EvidenceGrade,
    Limitation,
)


COMPUTED_POINTER_WRITES = "COMPUTED_POINTER_WRITES_NOT_EXCLUDED"
NO_KNOWN_PATH_BOUNDED = "NO_KNOWN_PATH_IS_NOT_UNREACHABILITY"
UNRESOLVED_FRONTIER = "UNRESOLVED_INDIRECT_FRONTIER"
FUNCTION_BOUNDARIES = "FUNCTION_BOUNDARIES_HEURISTIC"
MMIO_USAGE_SET = "PERIPHERAL_SET_IS_MMIO_USAGE"
STRUCTURAL_USAGE = "STRUCTURAL_USAGE_NOT_DEVICE_IDENTITY"
DOCUMENTARY = "DOCUMENTARY_NOT_FIRMWARE_DERIVED"
EFFECTS_BOUNDED = "EFFECTS_COVERAGE_BOUNDED"
SOURCE_AGREEMENT_STRUCTURAL = "SOURCE_AGREEMENT_IS_STRUCTURAL"
SOURCES_NOT_INDEPENDENT = "AGREEMENT_SOURCES_NOT_INDEPENDENT"
HARNESS_ASSUMPTIONS = "CONCRETE_HARNESS_ASSUMPTIONS"
OBSERVED_CONTEXTS_ONLY = "OBSERVED_CONTEXTS_ONLY"
UNOBSERVED_CALL_SITES = "UNOBSERVED_CALL_SITES_NOT_UNREACHABLE"
OBSERVATION_TRUNCATED = "OBSERVATION_TRUNCATED"
HYPOTHETICAL_SPECIALIZATION = "HYPOTHETICAL_ARGUMENT_SPECIALIZATION"

_FUNCTION_RE = re.compile(r"FUN_[0-9a-f]{8}")

# Absolute-negative wording. Applied only when supporting evidence is a
# bounded negative (NO_KNOWN_PATH); a deterministic guard, not semantics.
ABSOLUTE_NEGATIVE_RE = re.compile(
    r"\b(unreachable|never reach\w*|cannot (?:be )?reach\w*|can ?not (?:be )?reach\w*|"
    r"no path exists|no possible path|impossible to reach|dead code|is isolated from)\b",
    re.IGNORECASE,
)

_NEGATED_RE = re.compile(r"\b(not|no proof|without|rather than|instead of)\b", re.IGNORECASE)


def asserts_absolute_negative(text: str) -> bool:
    """
    True if the text asserts an absolute negative (e.g. unreachability).

    A mention negated just before it ("not a proof that no path exists",
    "NO_KNOWN_PATH, not unreachability") is a disclaimer, not an assertion.
    Deterministic wording guard only; typed claim_type checks come first.
    """

    for match in ABSOLUTE_NEGATIVE_RE.finditer(text):
        if not _NEGATED_RE.search(text[max(0, match.start() - 40) : match.start()]):
            return True

    return False


_STRUCTURAL_TEXT = (
    "Census structure is statically derived from Ghidra references; function "
    "boundaries and attribution are heuristic."
)


# Execution metadata that varies between identical analyses (e.g. a cache
# hit versus a fresh run) and is not evidence. Removed before hashing.
VOLATILE_RESULT_FIELDS: dict[str, tuple[tuple[str, ...], ...]] = {
    "function_effects": (("provenance", "cached"),),
}


def _without(value: Any, path: tuple[str, ...]) -> Any:
    if not isinstance(value, dict) or path[0] not in value:
        return value

    if len(path) == 1:
        return {key: item for key, item in value.items() if key != path[0]}

    return {**value, path[0]: _without(value[path[0]], path[1:])}


def canonical_result(tool: str, result: dict[str, Any]) -> dict[str, Any]:
    """The evidence form of a result: volatile execution metadata removed."""

    for path in VOLATILE_RESULT_FIELDS.get(tool, ()):
        result = _without(result, path)

    return result


def _min_grade(*grades: EvidenceGrade) -> EvidenceGrade:
    return min(grades, key=lambda g: GRADE_RANK[g])


def _edge_grade(edges: list[dict[str, Any]]) -> EvidenceGrade | None:
    grades = []

    for edge in edges:
        try:
            grades.append(EvidenceGrade(str(edge.get("confidence", "")).upper()))
        except ValueError:
            grades.append(EvidenceGrade.UNKNOWN)

    return _min_grade(*grades) if grades else None


def evidence_grade(tool: str, result: dict[str, Any]) -> tuple[EvidenceGrade, str]:
    """(strongest supportable grade, basis) for one deterministic result."""

    edges = result.get("resolved_indirect_edges") or []
    edge = _edge_grade(edges)

    if tool == "census_usb_inventory":
        if result.get("status") != "ok":
            return EvidenceGrade.UNKNOWN, f"usb inventory status {result.get('status')}"

        if edge is not None:
            return _min_grade(EvidenceGrade.STRONG, edge), f"census structure; resolved_indirect confidence {edge}"

        return EvidenceGrade.STRONG, "census static structure (heuristic function boundaries)"

    if tool == "census_peripheral_usage":
        if result.get("status") != "ok":
            return EvidenceGrade.UNKNOWN, f"census status {result.get('status')}"

        return EvidenceGrade.STRONG, "census constant-address MMIO references (heuristic function boundaries)"

    if tool == "census_common_paths":
        status = result.get("status")

        if status == "NO_KNOWN_PATH":
            return EvidenceGrade.BOUNDED, "NO_KNOWN_PATH within census hop bound"

        if status in ("KNOWN_COMMON_PATH", "SHARED_UTILITIES_ONLY"):
            grade = EvidenceGrade.STRONG if edge is None else _min_grade(EvidenceGrade.STRONG, edge)
            return grade, f"census strong graph path ({status})"

        return EvidenceGrade.UNKNOWN, f"common paths status {status}"

    if tool in ("function_disassembly", "callsite_context", "pin_table_entry"):
        return EvidenceGrade.EXACT, "decoded from the hash-verified firmware image"

    if tool == "function_facts":
        return EvidenceGrade.STRONG, "Ghidra call graph (heuristic boundaries)"

    if tool == "function_effects":
        status = str(result.get("status", ""))

        if status.startswith("complete"):
            return EvidenceGrade.STRONG, "symbolic extraction, not solver-confirmed"

        return EvidenceGrade.BOUNDED, f"function effects {status or 'unknown'}"

    if tool == "observed_call_arguments":
        status = str(result.get("status", ""))

        if (status == "ok" or status.startswith("bounded")) and result.get("observed_entries"):
            return EvidenceGrade.STRONG, "concrete execution under disclosed harness assumptions; observed contexts only"

        if status == "ok":
            return EvidenceGrade.BOUNDED, "function not entered within the scenario bound"

        return EvidenceGrade.UNKNOWN, f"observed call arguments {status or 'unknown'}"

    if tool == "search_case_evidence":
        return EvidenceGrade.PROBABLE, "case documents (documentary)"

    if tool == "structural_source_agreement":
        if result.get("status") != "ok" or "CONFLICT" in (result.get("status_counts") or {}):
            return EvidenceGrade.UNKNOWN, "source agreement contains a structural CONFLICT or failed"

        return EvidenceGrade.STRONG, "static structural agreement between code-discovery sources (heuristic boundaries)"

    return EvidenceGrade.UNKNOWN, f"no grade semantics for {tool}"


def _label_parts(label: Any) -> list[str]:
    return [part for part in str(label or "").split("+") if part]


def evidence_limitations(tool: str, arguments: dict[str, Any], result: dict[str, Any]) -> list[tuple[str, str]]:
    """Mechanical (code, text) limitations a result carries."""

    out: dict[str, str] = {}

    if result.get("resolved_indirect_edges"):
        out[COMPUTED_POINTER_WRITES] = RESOLVED_INDIRECT_LIMITATION

    if tool.startswith("census_"):
        out[FUNCTION_BOUNDARIES] = _STRUCTURAL_TEXT

    if tool == "census_peripheral_usage":
        out[STRUCTURAL_USAGE] = (
            "Structural usage does not identify what external device is attached "
            "to the peripheral; that requires hardware-routing evidence."
        )

    if tool == "census_common_paths":
        if result.get("status") == "NO_KNOWN_PATH":
            out[NO_KNOWN_PATH_BOUNDED] = NO_KNOWN_PATH_LIMITATION

        if result.get("frontier_total"):
            out[UNRESOLVED_FRONTIER] = (
                f"{result['frontier_total']} unresolved indirect transfer site(s) in the explored "
                "region; paths through them are unknown."
            )

        for side in ("left_label", "right_label"):
            for part in _label_parts(arguments.get(side)):
                if _FUNCTION_RE.fullmatch(part) or part.upper().startswith("IRQ:"):
                    continue

                out[f"{MMIO_USAGE_SET}:{part}"] = (
                    f"Set {part!r} is the census structural set for {part} (constant-address "
                    "register/MMIO users), not a semantic subsystem, event, or interrupt-dispatch path."
                )

    if tool == "function_effects" and not str(result.get("status", "")).startswith("complete"):
        out[EFFECTS_BOUNDED] = f"Function effects coverage is bounded: {result.get('status')}."

    if tool == "function_effects" and arguments.get("specialize"):
        spec = ", ".join(f"{k}={v:#x}" if isinstance(v, int) else f"{k}={v}" for k, v in sorted(arguments["specialize"].items()))
        out[HYPOTHETICAL_SPECIALIZATION] = (
            f"Specialized facts assume {spec}, chosen by the requester; they are hypothetical, not "
            "caller-grounded runtime values, and do not show that any caller supplies that value."
        )

    if tool == "structural_source_agreement":
        out[FUNCTION_BOUNDARIES] = _STRUCTURAL_TEXT
        out[SOURCE_AGREEMENT_STRUCTURAL] = (
            "Source agreement is structural consistency between analysis sources about where code and "
            "functions are; it does not establish behavior, and a source coverage gap is not negative evidence."
        )

        if any(source.get("derived_from") for source in result.get("sources", [])):
            derived = ", ".join(f"{s['source']} <- {s['derived_from']}" for s in result["sources"] if s.get("derived_from"))
            out[SOURCES_NOT_INDEPENDENT] = f"Not every agreeing source is independent ({derived})."

    if tool == "observed_call_arguments":
        out[HARNESS_ASSUMPTIONS] = (
            f"Concrete values were observed under {len(result.get('harness_assumptions') or [])} disclosed "
            "harness assumption(s) of the scenario recipe; they are firmware-produced only within that harness."
        )
        out[OBSERVED_CONTEXTS_ONLY] = (
            "Only argument values and call sites the scenario reached are reported; other values or "
            "contexts are not thereby impossible."
        )
        unobserved = [s.get("call_site") for s in result.get("call_sites") or [] if s.get("status") == "UNOBSERVED"]

        if unobserved:
            out[UNOBSERVED_CALL_SITES] = (
                f"Static call site(s) {', '.join(map(str, unobserved))} were never reached in the scenario; "
                "their argument values are unknown, not excluded."
            )

        if str(result.get("status", "")).startswith("bounded"):
            out[OBSERVATION_TRUNCATED] = f"The scenario observation was truncated: {result.get('status')}."

        if result.get("mmio_in_function") is not None:
            out[FUNCTION_BOUNDARIES] = "The MMIO cross-check extent is a Ghidra function boundary (heuristic)."

    if tool == "search_case_evidence":
        out[DOCUMENTARY] = "Case documents are prior human findings, not firmware-derived evidence."

    return sorted(out.items())


def inherited_limitations(artifacts: list[Any]) -> list[Limitation]:
    """Limitations a claim inherits from its supporting evidence artifacts."""

    by_code: dict[str, Limitation] = {}

    for artifact in artifacts:
        for limitation in artifact.limitations:
            existing = by_code.get(limitation.code)
            sources = (existing.source_evidence_ids if existing else []) + [artifact.evidence_id]
            by_code[limitation.code] = Limitation(
                text=limitation.text,
                code=limitation.code,
                source_evidence_ids=sorted(set(sources)),
            )

    return [by_code[code] for code in sorted(by_code)]


def grade_ceiling(claim_type: ClaimType, artifacts: list[Any]) -> EvidenceGrade:
    """
    Strongest grade the supporting evidence permits for a claim.

    A claim may be as strong as its strongest supporting derivation, never
    stronger. A bounded negative supports a NO_KNOWN_PATH claim at the
    strength of the graph it was computed over (STRONG), nothing else.
    """

    best = EvidenceGrade.UNKNOWN

    for artifact in artifacts:
        grade = artifact.grade

        if grade == EvidenceGrade.BOUNDED and claim_type == ClaimType.NO_KNOWN_PATH:
            grade = EvidenceGrade.STRONG

        if GRADE_RANK[grade] > GRADE_RANK[best]:
            best = grade

    return best
