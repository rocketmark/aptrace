"""
Bounded adversarial audit of one ClaimVersion.

The auditor model sees only the claim, its proposed grade, scope,
assumptions, limitations, and compact deterministic summaries of its
evidence. It never sees the investigator's transcript or reasoning. It
may request a few typed APTrace analyses from a fixed allowlist; APTrace
validates every argument, executes the operation, and records it.

The audit verdict is a recorded artifact. It never changes claim state:
only the APTrace verifier does that.
"""

from __future__ import annotations

import json
import os
import re
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from aptrace_agent.ledger.hashing import digest
from aptrace_agent.ledger.models import (
    AuditRecord,
    AuditStep,
    AuditVerdict,
    ClaimVersion,
    FollowUpRequest,
)
from aptrace_agent.ledger.operations import LedgerOperationRunner
from aptrace_agent.ledger.store import ResearchLedger, new_id, now
from aptrace_agent.research.controller import _prefill_rejected
from aptrace_agent.research.projection import clip, known_functions, summarize_observation
from aptrace_agent.schemas import EvidenceObservation
from aptrace_agent.source_agreement import AGREEMENT_SEMANTICS


# audit-v0.1: verdict allowed at any decision.
# audit-v0.2: APTrace requires one falsification analysis before a verdict
#             (v0.1 rubber-stamped every claim on its first decision).
# audit-v0.3: verdicts must state an explicit scope_check; tool failures are
#             labeled as tool coverage gaps, not firmware evidence.
# audit-v0.4: only a successful new evidence operation satisfies the
#             falsification requirement (rejected, duplicate, invalid, or
#             failing requests do not); compact evidence shows structured
#             pointer provenance (writer, store, registration callsite, raw
#             and canonical values, forwarding); APTrace records structural
#             source agreement for the code the evidence names; every audit
#             records a deterministic audit-input fingerprint.
# audit-v0.5: claims with structured semantics show their typed predicate and
#             APTrace's deterministic semantic-check results; only claims
#             that pass deterministic verification (phases A-C) are audited
#             in the normal pipeline.
AUDIT_TEMPLATE_VERSION = "audit-v0.5"
DEFAULT_AUDIT_MODEL = "gemma-4-26b-a4b-it-4bit"

_FUNCTION_RE = re.compile(r"FUN_[0-9a-f]{8}")
_PERIPHERAL_RE = re.compile(r"[A-Z][A-Z0-9_]{0,23}")
_IRQ_RE = re.compile(r"IRQ:([A-Z][A-Z0-9_]{1,23})")
_EVIDENCE_RE = re.compile(r"EV-[0-9a-f]{16}")

EVIDENCE_DIGEST_CHARS = 1600
RESULT_CHARS = 3200


SYSTEM_PROMPT = """You are an independent adversarial auditor of firmware reverse-engineering claims.
Another investigator proposed the claim you are given. You have not seen its reasoning and must not
assume the claim is correct. Your job is to try to falsify it using the recorded deterministic
evidence and, when needed, a few additional typed APTrace analyses. You never run code yourself:
you request an analysis and APTrace validates and executes it.

Audit discipline:
- Check every entity, address, role and relationship in the assertion against concrete evidence
  fields. A function or address that appears in the evidence in a different role does not support
  the claim.
- Check the proposed grade. A claim may not be stronger than its strongest supporting derivation
  (EXACT > STRONG > PROBABLE > BOUNDED).
- Check scope. Evidence about one set, bound, or kind of relationship does not establish a claim
  about a different set, bound, or kind of relationship.
- Absence of a known path is bounded evidence, never proof of unreachability.
- Limitations carried by the evidence must remain true of the claim.
- Before any verdict you must make at least one analysis request chosen to falsify the claim:
  test an entity, set, bound, or relationship the assertion depends on. Only an analysis that
  APTrace actually executes counts; rejected, duplicate, or invalid requests do not.
- A failed or empty tool result is a tool coverage gap, not evidence about the firmware.
- A source that lacks code another source has is a coverage gap of that source. Sources that
  disagree on function boundaries are a structural disagreement, not a contradiction of the claim.
  Only deterministic results that establish incompatible values for the same fact contradict it.

Verdicts:
- SUPPORTED: the evidence supports the exact assertion, at the proposed grade, within its stated
  scope and limitations.
- CHALLENGED: some part of the assertion, its grade, or its scope is contradicted or not supported
  by the evidence.
- UNRESOLVED: the available evidence cannot decide.

Respond with exactly one JSON object and nothing else."""


RESPONSE_FORMAT = """RESPONSE FORMAT (one JSON object):
To request one analysis:
{"action": "request", "tool": "<tool name>", "arguments": {...}, "purpose": "<what you are trying to falsify>"}
To finish:
{"action": "verdict", "verdict": "SUPPORTED" | "CHALLENGED" | "UNRESOLVED",
 "scope_check": "<for each function set, bound, or relationship the evidence uses: is it exactly the one the assertion names?>",
 "reasoning": "<concise>", "challenges": ["<each specific problem>"],
 "evidence_inspected": ["EV-..."], "contradictory_evidence": ["EV-..."],
 "limitations": ["<limitations that apply to the claim>"],
 "follow_up_requests": [{"question": "<evidence that would decide>", "suggested_tool": "<tool or null>"}]}"""


class ToolRejected(ValueError):
    """A request APTrace refused to execute. kind: duplicate,
    invalid_arguments, unavailable_tool."""

    def __init__(self, message: str, kind: str = "invalid_arguments") -> None:
        super().__init__(message)
        self.kind = kind


# Executed-operation outcomes that satisfy the falsification requirement.
FALSIFYING_OUTCOMES = frozenset({"executed:success", "executed:coverage_gap"})

# Runner errors that mean the analysis source lacks the requested entity:
# a legitimate coverage-gap result rather than a harness failure.
_COVERAGE_GAP_ERRORS = ("KeyError", "LookupError", "FileNotFoundError")

_GAP_SOURCE = {
    "function_facts": "Ghidra export",
    "function_disassembly": "Ghidra export",
    "function_effects": "function-effects analysis",
}


class _Request(BaseModel):
    model_config = ConfigDict(extra="ignore")

    action: Literal["request"]
    tool: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    purpose: str = ""


class _Verdict(BaseModel):
    model_config = ConfigDict(extra="ignore")

    action: Literal["verdict"]
    verdict: AuditVerdict
    scope_check: str = Field(min_length=1)
    reasoning: str
    challenges: list[str] = Field(default_factory=list)
    evidence_inspected: list[str] = Field(default_factory=list)
    contradictory_evidence: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    follow_up_requests: list[FollowUpRequest] = Field(default_factory=list)

    @field_validator("verdict", mode="before")
    @classmethod
    def _upper(cls, value: Any) -> Any:
        return value.strip().upper() if isinstance(value, str) else value

    @field_validator("follow_up_requests", mode="before")
    @classmethod
    def _coerce_requests(cls, value: Any) -> Any:
        if not isinstance(value, list):
            return value

        return [{"question": item} if isinstance(item, str) else item for item in value]

    @field_validator("challenges", "evidence_inspected", "contradictory_evidence", "limitations", mode="before")
    @classmethod
    def _strings(cls, value: Any) -> Any:
        if isinstance(value, list):
            return [item if isinstance(item, str) else json.dumps(item) for item in value]

        return value


def parse_decision(content: str) -> _Request | _Verdict:
    """Parse one auditor decision; raises ValueError with a correction message."""

    text = (content or "").strip()
    fenced = re.search(r"```(?:json)?\s*(.*?)```", text, re.DOTALL | re.IGNORECASE)

    if fenced:
        text = fenced.group(1).strip()

    start, end = text.find("{"), text.rfind("}")

    if start < 0 or end <= start:
        raise ValueError("response contained no JSON object")

    try:
        payload = json.loads(text[start : end + 1])
    except json.JSONDecodeError as exc:
        raise ValueError(f"response was not valid JSON ({exc.msg})") from exc

    if not isinstance(payload, dict):
        raise ValueError("response JSON was not an object")

    action = payload.get("action")

    try:
        if action == "request":
            return _Request.model_validate(payload)

        if action == "verdict":
            return _Verdict.model_validate(payload)
    except ValidationError as exc:
        first = exc.errors()[0]
        raise ValueError(f"invalid {action}: {'.'.join(map(str, first['loc']))}: {first['msg']}") from exc

    raise ValueError('action must be "request" or "verdict"')


def _observation(ledger: ResearchLedger, evidence_id: str) -> EvidenceObservation:
    artifact = ledger.evidence(evidence_id)

    try:
        result, _ok = ledger.load_blob(artifact.result_sha256)
    except KeyError:
        result = {"planner_summary": f"(result not present locally; recorded summary) {artifact.summary}"}

    return EvidenceObservation(id=evidence_id, tool=artifact.tool, arguments=artifact.arguments, result=result)


def _compact_arguments(arguments: dict[str, Any]) -> str:
    shown = {}

    for key, value in arguments.items():
        if key in ("left", "right") and "left_label" in arguments:
            continue  # resolved member lists; the labels identify the sets

        shown[key] = value

    return clip(json.dumps(shown, sort_keys=True), 160)


MAX_PROVENANCE_EDGES = 3


def _resolved_edges(result: Any) -> list[dict[str, Any]]:
    edges = result.get("resolved_indirect_edges") if isinstance(result, dict) else None
    return [edge for edge in edges or [] if isinstance(edge, dict)]


def _fn_of(address: str | None, containing: dict[str, str]) -> str:
    function = containing.get(str(address).lower()) if address else None
    return f" in {function}" if function else ""


def pointer_provenance(edge: dict[str, Any], containing: dict[str, str] | None = None) -> str:
    """Compact structured provenance of one resolved RAM function-pointer edge."""

    containing = containing or {}
    raw, canonical = edge.get("raw_value"), edge.get("canonical_target")
    thumb = ""

    try:
        if raw and canonical and int(raw, 16) & ~1 == int(canonical, 16) and int(raw, 16) != int(canonical, 16):
            thumb = " (Thumb bit cleared)"
    except ValueError:
        pass

    lines = [
        f"consumer: indirect transfer at {edge.get('site')} in {edge.get('from_function')} loads RAM slot {edge.get('slot')}",
        f"writer: {edge.get('writer') or '(unattributed)'}, store instruction {edge.get('store')}",
    ]

    if edge.get("callsite"):
        lines.append(
            f"registration: callsite {edge.get('callsite')}{_fn_of(edge.get('callsite'), containing)} "
            f"passes {edge.get('arg_reg') or 'an argument'} = raw pointer {raw}"
        )

    lines.append(f"raw pointer {raw} -> canonical target {canonical}{thumb} = {edge.get('to_function')}")

    if edge.get("terminal_target") and edge.get("terminal_target") != canonical:
        lines.append(f"forwarding: {edge.get('to_function')} forwards to {edge.get('terminal_target')}")

    lines.append(f"edge grade {edge.get('confidence')}; derivation {edge.get('derivation') or 'unspecified'}")
    return "\n".join(lines)


def evidence_digest(
    ledger: ResearchLedger,
    evidence_id: str,
    limit: int = EVIDENCE_DIGEST_CHARS,
    containing: dict[str, str] | None = None,
) -> str:
    artifact = ledger.evidence(evidence_id)
    observation = _observation(ledger, evidence_id)
    body = summarize_observation(observation, limit=limit)
    limitations = "\n".join(f"    - [{item.code}] {item.text}" for item in artifact.limitations)
    edges = _resolved_edges(observation.result)
    provenance = ""

    if edges:
        rendered = [
            "    - " + pointer_provenance(edge, containing).replace("\n", "\n      ")
            for edge in edges[:MAX_PROVENANCE_EDGES]
        ]
        more = f"\n    (+{len(edges) - MAX_PROVENANCE_EDGES} more edges)" if len(edges) > MAX_PROVENANCE_EDGES else ""
        provenance = "  resolved pointer provenance (structured fields of this evidence):\n" + "\n".join(rendered) + more + "\n"

    return (
        f"[{evidence_id}] {artifact.tool}({_compact_arguments(artifact.arguments)}) "
        f"grade={artifact.grade.value} ({artifact.grade_basis})\n"
        f"  {body.replace(chr(10), chr(10) + '  ')}\n"
        + provenance
        + (f"  carried limitations:\n{limitations}" if limitations else "")
    )


# -- structural source agreement ----------------------------------------------

MAX_AGREEMENT_ADDRESSES = 16


def agreement_targets(ledger: ResearchLedger, evidence_ids: Sequence[str]) -> dict[str, str]:
    """Code addresses named by the evidence's resolved pointer edges, with roles."""

    roles: dict[str, str] = {}

    def add(address: Any, role: str) -> None:
        if isinstance(address, str) and re.fullmatch(r"0x[0-9a-fA-F]{1,8}", address):
            key = f"0x{int(address, 16):08x}"
            roles.setdefault(key, role)

    for evidence_id in evidence_ids:
        if not ledger.has_evidence(evidence_id):
            continue

        for edge in _resolved_edges(_observation(ledger, evidence_id).result):
            match = _FUNCTION_RE.fullmatch(str(edge.get("from_function", "")))
            add(f"0x{match.group(0)[4:]}" if match else None, "consumer function entry")
            add(edge.get("site"), "indirect transfer site")
            add(edge.get("canonical_target"), "canonical pointer target")
            add(edge.get("terminal_target"), "forwarding target")
            add(edge.get("store"), "pointer store instruction")
            add(edge.get("callsite"), "registration callsite")

    return dict(list(sorted(roles.items()))[:MAX_AGREEMENT_ADDRESSES])


def containing_functions(ledger: ResearchLedger, agreement_evidence_id: str | None) -> dict[str, str]:
    """address -> census containing function, from recorded agreement evidence."""

    if not agreement_evidence_id or not ledger.has_evidence(agreement_evidence_id):
        return {}

    result, _ok = ledger.evidence_result(agreement_evidence_id)
    out: dict[str, str] = {}

    for entry in result.get("agreements", []):
        for observation in entry.get("observations", []):
            if observation.get("source") == "census" and observation.get("function"):
                out[str(entry["address"]).lower()] = observation["function"]

    return out


def agreement_digest(ledger: ResearchLedger, evidence_id: str, roles: dict[str, str]) -> str:
    artifact = ledger.evidence(evidence_id)
    result, _ok = ledger.evidence_result(evidence_id)
    sources = "; ".join(
        f"{s['source']} {str(s.get('version') or 'n/a')[:12]}" + (f" (derived from {s['derived_from']})" if s.get("derived_from") else "")
        for s in result.get("sources", [])
    )
    lines = [f"[{evidence_id}] structural_source_agreement grade={artifact.grade.value}; sources: {sources}"]

    for entry in result.get("agreements", []):
        groups: dict[str, list[str]] = {}

        for observation in entry.get("observations", []):
            if not observation.get("available"):
                continue

            if observation.get("recognizes_code"):
                key = f"{observation.get('function')} [{observation.get('start')},{observation.get('end')})"
                groups.setdefault(key, []).append(observation["source"])

        seen = "; ".join(f"{'/'.join(names)} {key}" for key, names in groups.items()) or "no source has code here"
        extra = []

        if entry.get("block_agreement") in ("SUBSET", "DISAGREE"):
            extra.append(f"block coverage {entry['block_agreement'].lower()}")

        if entry.get("coverage_gaps"):
            extra.append(", ".join(entry["coverage_gaps"]))

        role = roles.get(str(entry.get("address")).lower(), "")
        lines.append(
            f"  {entry.get('address')}{f' ({role})' if role else ''}: {entry.get('status')} [{entry.get('relation')}] — {seen}"
            + (f"; {'; '.join(extra)}" if extra else "")
        )

    lines.append(f"  semantics: {AGREEMENT_SEMANTICS}")
    return "\n".join(lines)


@dataclass
class AuditBudget:
    max_decisions: int = 5
    max_tool_requests: int = 4
    max_tokens: int = 1200


@dataclass
class AuditToolbox:
    """
    Typed allowlist of APTrace analyses the auditor may request.

    No shell, SQL, solver input, path, executable, or free file access is
    reachable from here: every tool maps to one existing APTrace operation
    with APTrace-validated arguments.
    """

    ledger: ResearchLedger
    runner: LedgerOperationRunner
    audit_id: str
    claim: ClaimVersion
    peripherals: Sequence[str] = ()
    irq_handlers: Callable[[str], list[str]] | None = None
    case_search: bool = False
    visible: list[str] = field(default_factory=list)
    executed: set[str] = field(default_factory=set)
    inspected: list[str] = field(default_factory=list)
    # address -> census containing function (from recorded source agreement)
    containing: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for evidence_id in self.claim.supporting_evidence_ids + self.claim.contradictory_evidence_ids + self.visible:
            if self.ledger.has_evidence(evidence_id) and evidence_id not in self.visible:
                self.visible.append(evidence_id)

        for evidence_id in self.visible:
            artifact = self.ledger.evidence(evidence_id)
            self.executed.add(self._key(artifact.tool, artifact.arguments))

    # -- description ----------------------------------------------------------

    def names(self) -> list[str]:
        names = [
            "inspect_evidence",
            "function_facts",
            "function_disassembly",
            "analyze_peripheral",
            "analyze_usb_interface",
            "find_common_paths",
            "analyze_function_effects",
            "replay_evidence",
        ]

        if self.case_search:
            names.append("search_case_evidence")

        return names

    def describe(self) -> str:
        lines = [
            '- inspect_evidence {"evidence_id": "EV-...", "field": optional top-level result key}: full structured result field of listed evidence',
            '- function_facts {"function": "FUN_xxxxxxxx"}: Ghidra callers/callees of a function named in evidence',
            '- function_disassembly {"function": "FUN_xxxxxxxx"}: decoded instructions of a function named in evidence',
            '- analyze_peripheral {"peripheral": "<NAME>"}: census functions using one MCU peripheral\'s registers',
            '- analyze_usb_interface {}: USB register users, IRQ handlers, descriptors, resolved indirect edges',
            '- find_common_paths {"left": [...], "right": [...]}: do two function sets converge in the census call graph? '
            'Members: analyzed peripheral names (e.g. "USB"), FUN_ names from evidence, or "IRQ:<PREFIX>" for the '
            "interrupt-vector handlers whose interrupt name starts with PREFIX",
            '- analyze_function_effects {"function": "FUN_...", "r0": optional int, "r1": optional int}: symbolic MMIO/RAM effects',
            '- replay_evidence {"evidence_id": "EV-..."}: re-run the analysis that produced listed evidence and compare its result hash',
        ]

        if self.case_search:
            lines.append('- search_case_evidence {"query": "<1-3 terms>"}: lexical search of case documents (documentary)')

        return "\n".join(lines)

    # -- validation helpers ---------------------------------------------------

    @staticmethod
    def _key(tool: str, arguments: dict[str, Any]) -> str:
        return digest({"tool": tool, "arguments": arguments})

    def _known_functions(self) -> set[str]:
        return set(known_functions(_observation(self.ledger, e) for e in self.visible))

    def _function(self, arguments: dict[str, Any], tool: str, extra: Sequence[str] = ()) -> str:
        unexpected = sorted(set(arguments) - {"function", *extra})

        if unexpected:
            raise ToolRejected(f"{tool} does not accept {', '.join(unexpected)}")

        function = str(arguments.get("function", "")).strip()

        if not _FUNCTION_RE.fullmatch(function) or function not in self._known_functions():
            raise ToolRejected(f"{tool} requires a FUN_xxxxxxxx name that appears in the listed evidence")

        return function

    def _visible_evidence(self, arguments: dict[str, Any], tool: str, extra: Sequence[str] = ()) -> str:
        unexpected = sorted(set(arguments) - {"evidence_id", *extra})

        if unexpected:
            raise ToolRejected(f"{tool} does not accept {', '.join(unexpected)}")

        evidence_id = str(arguments.get("evidence_id", "")).strip()

        if evidence_id not in self.visible:
            raise ToolRejected(f"{tool} requires one of the listed evidence ids: {', '.join(self.visible) or 'none'}")

        return evidence_id

    def _set_functions(self) -> dict[str, list[str]]:
        sets: dict[str, list[str]] = {}

        for evidence_id in self.visible:
            artifact = self.ledger.evidence(evidence_id)

            if artifact.tool == "census_peripheral_usage":
                result, _ok = self.ledger.load_blob(artifact.result_sha256)
                functions = [f.get("function") for f in result.get("functions", []) if f.get("function")]

                if functions:
                    sets[str(artifact.arguments.get("peripheral"))] = functions

            if artifact.tool == "census_usb_inventory":
                result, _ok = self.ledger.load_blob(artifact.result_sha256)

                if result.get("functions"):
                    sets["USB"] = list(dict.fromkeys(sets.get("USB", []) + result["functions"]))

        return sets

    def _resolve_set(self, items: Any) -> tuple[list[str], str]:
        if not isinstance(items, list) or not 1 <= len(items) <= 4:
            raise ToolRejected("find_common_paths sets need 1-4 members")

        functions: list[str] = []
        labels: list[str] = []
        known = self._known_functions()

        for item in items:
            name = str(item).strip()
            upper = name.upper()
            sets = self._set_functions()
            irq = _IRQ_RE.fullmatch(upper)

            if irq:
                handlers = self.irq_handlers(irq.group(1)) if self.irq_handlers else []

                if not handlers:
                    raise ToolRejected(f"no interrupt-vector handlers for interrupt names starting {irq.group(1)}")

                functions.extend(handlers)
                labels.append(upper)
            elif upper in sets:
                functions.extend(sets[upper])
                labels.append(upper)
            elif upper in self.peripherals:
                # Resolve an unanalyzed catalog peripheral through its census
                # usage, recorded as an input invocation of this request.
                _inv, artifact = self.runner.run(
                    self.audit_id, "census_peripheral_usage", {"peripheral": upper, "limit": 25}
                )

                if artifact is None:
                    raise ToolRejected(f"census usage of {upper} could not be computed")

                self.visible.append(artifact.evidence_id)
                resolved = self._set_functions().get(upper)

                if not resolved:
                    raise ToolRejected(f"peripheral {upper} has no census functions")

                functions.extend(resolved)
                labels.append(upper)
            elif _FUNCTION_RE.fullmatch(name) and name in known:
                functions.append(name)
                labels.append(name)
            else:
                raise ToolRejected(
                    f"unknown set member {name[:40]!r}; use peripheral names, IRQ:<PREFIX>, or FUN_ names from evidence"
                )

        return list(dict.fromkeys(functions)), "+".join(labels)[:40]

    # -- validation -----------------------------------------------------------

    def validate(self, tool: str, arguments: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        """(APTrace operation, validated arguments). Raises ToolRejected."""

        if tool not in self.names():
            raise ToolRejected(f"tool {tool!r} is not available; choose one of: {', '.join(self.names())}", kind="unavailable_tool")

        if not isinstance(arguments, dict):
            raise ToolRejected("arguments must be a JSON object")

        if tool == "inspect_evidence":
            evidence_id = self._visible_evidence(arguments, tool, extra=("field",))
            fld = arguments.get("field")

            if fld is not None:
                result, _ok = self.ledger.evidence_result(evidence_id)

                if not isinstance(fld, str) or fld not in result:
                    raise ToolRejected(f"field must be one of: {', '.join(sorted(result))}")

            return "inspect_evidence", {"evidence_id": evidence_id, "field": fld}

        if tool == "replay_evidence":
            return "replay_evidence", {"evidence_id": self._visible_evidence(arguments, tool)}

        if tool == "function_facts":
            return "function_facts", {"function": self._function(arguments, tool)}

        if tool == "function_disassembly":
            return "function_disassembly", {"function": self._function(arguments, tool)}

        if tool == "analyze_peripheral":
            unexpected = sorted(set(arguments) - {"peripheral"})
            peripheral = str(arguments.get("peripheral", "")).strip().upper()

            if unexpected or not _PERIPHERAL_RE.fullmatch(peripheral) or peripheral not in self.peripherals:
                raise ToolRejected("analyze_peripheral requires one census catalog peripheral name, e.g. TCC1")

            return "census_peripheral_usage", {"peripheral": peripheral, "limit": 25}

        if tool == "analyze_usb_interface":
            if arguments:
                raise ToolRejected("analyze_usb_interface takes no arguments")

            return "census_usb_inventory", {}

        if tool == "find_common_paths":
            unexpected = sorted(set(arguments) - {"left", "right"})

            if unexpected:
                raise ToolRejected(f"find_common_paths accepts only left and right, not {', '.join(unexpected)}")

            left, left_label = self._resolve_set(arguments.get("left"))
            right, right_label = self._resolve_set(arguments.get("right"))
            return "census_common_paths", {"left": left, "right": right, "left_label": left_label, "right_label": right_label}

        if tool == "analyze_function_effects":
            function = self._function(arguments, tool, extra=("r0", "r1"))
            specialize: dict[str, int] = {}

            for register in ("r0", "r1"):
                value = arguments.get(register)

                if value is None:
                    continue

                if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 0xFFFFFFFF:
                    raise ToolRejected(f"{register} must be an integer in 0..4294967295")

                specialize[register] = value

            return "function_effects", {"function": function, "specialize": specialize}

        if tool == "search_case_evidence":
            query = str(arguments.get("query", "")).strip()

            if set(arguments) - {"query"} or not 2 <= len(query) <= 120:
                raise ToolRejected("search_case_evidence takes one query of 2..120 characters")

            return "search_case_evidence", {"query": query, "max_results": 6, "purpose": "audit"}

        raise ToolRejected(f"unsupported tool {tool!r}")

    # -- execution ------------------------------------------------------------

    def execute(self, tool: str, arguments: dict[str, Any]) -> tuple[str, str | None, str | None, str]:
        """
        Validate, dedupe and run one request:
        (result text, invocation id, evidence id, outcome).
        Raises ToolRejected for requests APTrace refuses to execute.
        """

        operation, validated = self.validate(tool, arguments)
        key = self._key(operation, validated)

        if key in self.executed:
            raise ToolRejected(
                f"duplicate request: {tool} with these arguments was already answered; it does not count as an "
                "analysis. Choose a different check or give a verdict",
                kind="duplicate",
            )

        if operation == "inspect_evidence":
            self.executed.add(key)
            evidence_id = validated["evidence_id"]
            result, ok = self.ledger.evidence_result(evidence_id)
            value = result if validated["field"] is None else {validated["field"]: result[validated["field"]]}
            self.inspected.append(evidence_id)
            integrity = "" if ok else " [INTEGRITY FAILURE: stored result hash mismatch]"
            return clip(json.dumps(value, sort_keys=True, default=str), RESULT_CHARS) + integrity, None, evidence_id, "executed:success"

        if operation == "replay_evidence":
            self.executed.add(key)
            artifact = self.ledger.evidence(validated["evidence_id"])
            replay = self.runner.replay(artifact.invocation_id, run_id=self.audit_id)
            text = (
                f"replay of {artifact.evidence_id} ({artifact.tool}): "
                + ("MATCH (identical result hash)" if replay.matches else "MISMATCH " + "; ".join(replay.differences))
                + (f"; input drift: {sorted(replay.input_drift)}" if replay.input_drift else "")
            )
            outcome = "executed:success" if replay.replay.status == "ok" else "executed:tool_error"
            return text, replay.replay.invocation_id, replay.replay.evidence_id, outcome

        self.executed.add(key)
        invocation, artifact = self.runner.run(self.audit_id, operation, validated, input_evidence_ids=self.visible)

        if artifact is None:
            error = invocation.error or ""

            if error.startswith(_COVERAGE_GAP_ERRORS):
                source = _GAP_SOURCE.get(operation, "this APTrace analysis source")
                return (
                    f"COVERAGE GAP ({source}): {tool} could not answer: {error}. This is a gap in that analysis "
                    "source, not evidence about the firmware and not contradictory evidence; other sources "
                    "(census, Ghidra export, Macaw) can differ in what code they cover.",
                    invocation.invocation_id,
                    None,
                    "executed:coverage_gap",
                )

            return (
                f"TOOL ERROR (an APTrace harness failure, not evidence about the firmware; it does not count "
                f"as an analysis): {tool} failed: {error}",
                invocation.invocation_id,
                None,
                "executed:tool_error",
            )

        self.executed.add(self._key(artifact.tool, artifact.arguments))

        if artifact.evidence_id not in self.visible:
            self.visible.append(artifact.evidence_id)

        if operation == "function_disassembly":
            result, _ok = self.ledger.load_blob(artifact.result_sha256)
            listing = "\n".join(
                f"  {i.get('address')} {i.get('mnemonic')} {i.get('operands', '')}".rstrip()
                for i in result.get("instructions", [])[:60]
            )
            body = f"[{artifact.evidence_id}] {result.get('name')} entry={result.get('entry')} bounds={result.get('bounds_source')}\n{listing}"
            return clip(body, RESULT_CHARS), invocation.invocation_id, artifact.evidence_id, "executed:success"

        return (
            evidence_digest(self.ledger, artifact.evidence_id, limit=RESULT_CHARS, containing=self.containing),
            invocation.invocation_id,
            artifact.evidence_id,
            "executed:success",
        )


def build_audit_context(
    ledger: ResearchLedger,
    claim: ClaimVersion,
    *,
    agreement_evidence_id: str | None = None,
    agreement_roles: dict[str, str] | None = None,
    agreement_error: str | None = None,
    semantic_checks: str = "",
) -> str:
    """Compact, independent audit context: no investigator narrative."""

    objective = None

    if claim.run_id:
        try:
            objective = ledger.run(claim.run_id).objective
        except KeyError:
            objective = None

    def bullets(items: Sequence[str]) -> str:
        return "\n".join(f"  - {item}" for item in items) if items else "  (none)"

    dependencies = []

    for key in claim.depends_on:
        try:
            dependency = ledger.claim(key)
            dependencies.append(f"{key} [{ledger.state(key).value}] {dependency.assertion}")
        except KeyError:
            dependencies.append(f"{key} [MISSING]")

    containing = containing_functions(ledger, agreement_evidence_id)

    def evidence(ids: Sequence[str]) -> str:
        rendered = []

        for evidence_id in ids:
            if ledger.has_evidence(evidence_id):
                rendered.append(evidence_digest(ledger, evidence_id, containing=containing))
            else:
                rendered.append(f"[{evidence_id}] NOT FOUND IN THE APTRACE LEDGER")

        return "\n".join(rendered) if rendered else "  (none)"

    if agreement_evidence_id:
        agreement = agreement_digest(ledger, agreement_evidence_id, agreement_roles or {})
    elif agreement_error:
        agreement = f"  (unavailable: {agreement_error}; a coverage gap of APTrace, not evidence about the firmware)"
    else:
        agreement = "  (no code addresses named by structured evidence)"

    semantics = ""

    if claim.semantics is not None:
        semantics = (
            f"STRUCTURED SEMANTICS (authoritative for APTrace verification): {claim.semantics.summary()}\n"
            + (f"APTRACE DETERMINISTIC SEMANTIC CHECKS: {semantic_checks}\n" if semantic_checks else "")
        )

    return f"""AUDIT TARGET: claim {claim.key}
{f"INVESTIGATION OBJECTIVE: {objective}" + chr(10) if objective else ""}CLAIM SUBJECT: {claim.subject}
ASSERTION: {claim.assertion}
{semantics}CLAIM TYPE: {claim.claim_type.value}
PROPOSED GRADE: {claim.proposed_grade.value}
SCOPE: {claim.scope or "(not stated)"}
ASSUMPTIONS:
{bullets(claim.assumptions)}
LIMITATIONS ON RECORD:
{bullets([f"[{item.code}] {item.text}" if item.code else item.text for item in claim.limitations])}
DEPENDS ON:
{bullets(dependencies)}

SUPPORTING EVIDENCE (deterministic APTrace results, compact):
{evidence(claim.supporting_evidence_ids)}

CONTRADICTORY EVIDENCE ON RECORD:
{evidence(claim.contradictory_evidence_ids)}

STRUCTURAL SOURCE AGREEMENT (recorded by APTrace for the code addresses the evidence names; structural only):
{agreement}"""


def _claim_identity(claim: ClaimVersion) -> dict[str, Any]:
    # Absent semantics are omitted so pre-semantics claim identities are unchanged.
    exclude = {"created_at"} | ({"semantics"} if claim.semantics is None else set())
    return claim.model_dump(mode="json", exclude=exclude)


def audit_input_fingerprint(
    ledger: ResearchLedger,
    claim: ClaimVersion,
    *,
    context: str,
    agreement_evidence_id: str | None,
    model: str,
    generation: dict[str, Any],
    tools: dict[str, Any],
    budget: dict[str, Any],
) -> tuple[str, dict[str, str]]:
    """
    Deterministic identity of the exact audit input, with per-component
    hashes so a changed fingerprint can be attributed (claim, evidence,
    projection, source agreement, template, model, generation, tools,
    budget). Contains no timestamps or audit ids.
    """

    def evidence_identity(ids: Sequence[str]) -> list[Any]:
        return [
            [e, ledger.evidence(e).result_sha256] if ledger.has_evidence(e) else [e, None]
            for e in ids
        ]

    components = {
        "claim": digest(_claim_identity(claim)),
        "limitations": digest([item.model_dump(mode="json") for item in claim.limitations]),
        "evidence": digest(
            {
                "supporting": evidence_identity(claim.supporting_evidence_ids),
                "contradictory": evidence_identity(claim.contradictory_evidence_ids),
            }
        ),
        "source_agreement": digest(evidence_identity([agreement_evidence_id]) if agreement_evidence_id else None),
        "context": digest(context),
        "template": digest({"version": AUDIT_TEMPLATE_VERSION, "system": SYSTEM_PROMPT, "format": RESPONSE_FORMAT}),
        "model": digest(model),
        "generation": digest(generation),
        "tools": digest(tools),
        "budget": digest(budget),
    }
    return "AI-" + digest(components)[:16], {k: v[:16] for k, v in components.items()}


class ClaimAuditor:
    def __init__(
        self,
        *,
        ledger: ResearchLedger,
        runner: LedgerOperationRunner,
        client: Any | None = None,
        model: str | None = None,
        budget: AuditBudget | None = None,
        peripherals: Sequence[str] = (),
        irq_handlers: Callable[[str], list[str]] | None = None,
        case_search: bool = False,
        retry_delay: float = 3.0,
        generation: dict[str, Any] | None = None,
    ) -> None:
        if client is None:
            from openai import OpenAI

            client = OpenAI(
                base_url=os.environ["OMLX_BASE_URL"],
                api_key=os.environ["OMLX_API_KEY"],
                max_retries=0,
                timeout=240.0,
            )

        self.ledger = ledger
        self.runner = runner
        self.client = client
        self.model = model or os.environ.get("APTRACE_REVIEW_MODEL", DEFAULT_AUDIT_MODEL)
        self.budget = budget or AuditBudget()
        self.peripherals = tuple(peripherals)
        self.irq_handlers = irq_handlers
        self.case_search = case_search
        self.retry_delay = retry_delay
        # Explicit extra sampling parameters sent to the runtime (e.g. top_k,
        # seed); part of the audit-input fingerprint.
        self.extra_generation = dict(generation or {})

    def generation(self) -> dict[str, Any]:
        return {"temperature": 0.0, "max_tokens": self.budget.max_tokens, **self.extra_generation}

    def _create(self, messages: list[dict[str, str]]) -> Any:
        return self.client.chat.completions.create(model=self.model, messages=messages, **self.generation())

    def _source_agreement(self, audit_id: str, claim: ClaimVersion) -> tuple[str | None, dict[str, str], str | None]:
        """Record structural source agreement for the code the evidence names."""

        roles = agreement_targets(self.ledger, claim.supporting_evidence_ids + claim.contradictory_evidence_ids)

        if not roles:
            return None, roles, None

        invocation, artifact = self.runner.run(audit_id, "structural_source_agreement", {"addresses": sorted(roles)})

        if artifact is None:
            return None, roles, invocation.error or "source agreement failed"

        return artifact.evidence_id, roles, None

    def audit(self, key: str, *, batch_id: str | None = None, diagnostic: bool = False, semantic_checks: str = "") -> AuditRecord:
        claim = self.ledger.claim(key)
        audit_id = new_id("A")
        started = now()
        agreement_id, roles, agreement_error = self._source_agreement(audit_id, claim)
        toolbox = AuditToolbox(
            ledger=self.ledger,
            runner=self.runner,
            audit_id=audit_id,
            claim=claim,
            peripherals=self.peripherals,
            irq_handlers=self.irq_handlers,
            case_search=self.case_search,
            visible=[agreement_id] if agreement_id else [],
            containing=containing_functions(self.ledger, agreement_id),
        )
        context = build_audit_context(
            self.ledger,
            claim,
            agreement_evidence_id=agreement_id,
            agreement_roles=roles,
            agreement_error=agreement_error,
            semantic_checks=semantic_checks,
        )
        first = (
            f"{context}\n\nAVAILABLE APTRACE ANALYSES:\n{toolbox.describe()}\n\n{RESPONSE_FORMAT}\n\n"
            f"BUDGET: at most {self.budget.max_decisions} decisions including the verdict, "
            f"at most {self.budget.max_tool_requests} executed analyses."
        )
        budgets = {
            "max_decisions": self.budget.max_decisions,
            "max_tool_requests": self.budget.max_tool_requests,
            "max_tokens": self.budget.max_tokens,
            "temperature": 0.0,
        }
        fingerprint, components = audit_input_fingerprint(
            self.ledger,
            claim,
            context=first,
            agreement_evidence_id=agreement_id,
            model=self.model,
            generation=self.generation(),
            tools={
                "names": toolbox.names(),
                "description": toolbox.describe(),
                "peripherals": sorted(self.peripherals),
                "case_search": self.case_search,
            },
            budget={"max_decisions": self.budget.max_decisions, "max_tool_requests": self.budget.max_tool_requests},
        )
        messages: list[dict[str, str]] = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": first},
        ]
        steps: list[AuditStep] = []
        counts = {"requested": 0, "rejected": 0, "executed": 0, "successful": 0, "coverage_gap": 0, "tool_error": 0, "parse_failure": 0, "verdict_rejected": 0}
        served: set[str] = set()
        fingerprints: set[str] = set()
        verdict: _Verdict | None = None
        termination = "decision_budget_exhausted"

        for number in range(1, self.budget.max_decisions + 1):
            final = number == self.budget.max_decisions or counts["executed"] >= self.budget.max_tool_requests

            if final and number > 1:
                messages[-1]["content"] += "\n\nFINAL DECISION: no analyses remain. Return your verdict JSON now."

            decision: _Request | _Verdict | None = None

            for attempt in range(2):
                chars = sum(len(m["content"]) for m in messages)
                step = dict(number=number, attempt=attempt, request_chars=chars, request_messages=len(messages))

                try:
                    response = self._create(messages)
                    rejected = _prefill_rejected(response)
                except Exception as exc:
                    if not _prefill_rejected(exc):
                        steps.append(AuditStep(**step, action="error", error=f"{type(exc).__name__}: {exc}"[:400]))
                        termination = "model_error"
                        break

                    response, rejected = None, True

                if rejected:
                    steps.append(AuditStep(**step, action="error", error="prefill_memory_exceeded"))
                    time.sleep(self.retry_delay)
                    continue

                usage = getattr(response, "usage", None)
                choices = getattr(response, "choices", None) or []
                content = (getattr(choices[0].message, "content", None) or "") if choices else ""

                for value, bucket in ((getattr(response, "model", None), served), (getattr(response, "system_fingerprint", None), fingerprints)):
                    if isinstance(value, str) and value:
                        bucket.add(value)

                step.update(
                    prompt_tokens=getattr(usage, "prompt_tokens", None),
                    completion_tokens=getattr(usage, "completion_tokens", None),
                    raw_response=content[:4000],
                )

                try:
                    decision = parse_decision(content)
                except ValueError as exc:
                    counts["parse_failure"] += 1
                    steps.append(AuditStep(**step, action="invalid", rejection=str(exc), outcome="parse_failure", counts_as_falsification=False))
                    messages += [
                        {"role": "assistant", "content": content[:2000]},
                        {"role": "user", "content": f"That response did not satisfy the format: {exc}. Reply with exactly one JSON object as specified."},
                    ]
                    continue

                if isinstance(decision, _Verdict) and counts["successful"] == 0 and not final and self.budget.max_tool_requests > 0:
                    counts["verdict_rejected"] += 1
                    steps.append(
                        AuditStep(
                            **step,
                            action="invalid",
                            rejection="verdict before any successful falsification analysis",
                            outcome="verdict_rejected",
                            counts_as_falsification=False,
                        )
                    )
                    messages += [
                        {"role": "assistant", "content": content[:2000]},
                        {
                            "role": "user",
                            "content": "REJECTED verdict: before a verdict, at least one analysis chosen to falsify "
                            "the claim must be executed by APTrace (test an entity, set, bound, or relationship the "
                            "assertion depends on). Rejected, duplicate, or invalid requests do not count. "
                            "Reply with one request JSON object.",
                        },
                    ]
                    decision = None
                    break

                if isinstance(decision, _Request) and final:
                    counts["requested"] += 1
                    counts["rejected"] += 1
                    steps.append(
                        AuditStep(
                            **step,
                            action="invalid",
                            tool=decision.tool,
                            arguments=decision.arguments,
                            rejection="analysis requested after budget",
                            outcome="rejected:budget",
                            counts_as_falsification=False,
                        )
                    )
                    messages += [
                        {"role": "assistant", "content": content[:2000]},
                        {"role": "user", "content": "No analyses remain. Return your verdict JSON now."},
                    ]
                    decision = None
                    continue

                messages.append({"role": "assistant", "content": content[:2000]})
                break

            if termination == "model_error":
                break

            if decision is None:
                continue

            if isinstance(decision, _Verdict):
                steps.append(AuditStep(**step, action="verdict"))
                verdict = decision
                termination = "verdict"
                break

            counts["requested"] += 1

            try:
                text, invocation_id, evidence_id, outcome = toolbox.execute(decision.tool, decision.arguments)
                counts["executed"] += 1
                falsifying = outcome in FALSIFYING_OUTCOMES

                if falsifying:
                    counts["successful"] += 1

                if outcome == "executed:coverage_gap":
                    counts["coverage_gap"] += 1
                elif outcome == "executed:tool_error":
                    counts["tool_error"] += 1

                steps.append(
                    AuditStep(
                        **step,
                        action="request",
                        tool=decision.tool,
                        arguments=decision.arguments,
                        invocation_id=invocation_id,
                        evidence_id=evidence_id,
                        result_summary=text[:1200],
                        outcome=outcome,
                        counts_as_falsification=falsifying,
                    )
                )
                reply = f"RESULT of {decision.tool}:\n{text}"
            except ToolRejected as exc:
                counts["rejected"] += 1
                steps.append(
                    AuditStep(
                        **step,
                        action="request",
                        tool=decision.tool,
                        arguments=decision.arguments,
                        rejection=str(exc),
                        outcome=f"rejected:{exc.kind}",
                        counts_as_falsification=False,
                    )
                )
                reply = f"REJECTED {decision.tool} (not executed; does not count as an analysis): {exc}"

            remaining = self.budget.max_decisions - number
            messages.append(
                {
                    "role": "user",
                    "content": f"{reply}\n\nBUDGET: {remaining} decision(s) left, "
                    f"{max(0, self.budget.max_tool_requests - counts['executed'])} analysis request(s) left.",
                }
            )

        visible = set(toolbox.visible)
        satisfied = counts["successful"] > 0 or self.budget.max_tool_requests == 0
        model_verdict: AuditVerdict | None = None

        if verdict is None:
            record_verdict = AuditVerdict.UNRESOLVED
            reasoning = f"No valid verdict was produced ({termination}); APTrace recorded UNRESOLVED."
            synthesized = True
            payload: dict[str, Any] = {}
        elif not satisfied:
            # A verdict without any executed falsification analysis is not
            # an audit result; the model's verdict is kept for inspection.
            model_verdict = verdict.verdict
            record_verdict = AuditVerdict.UNRESOLVED
            termination = "verdict_without_successful_falsification"
            reasoning = (
                f"The auditor returned {verdict.verdict.value} without any successful falsification analysis; "
                f"APTrace recorded UNRESOLVED. Model reasoning: {verdict.reasoning}"
            )
            synthesized = True
            payload = verdict.model_dump()
        else:
            record_verdict = verdict.verdict
            reasoning = verdict.reasoning
            synthesized = False
            payload = verdict.model_dump()

        cited = [e for e in payload.get("evidence_inspected", []) if e in visible]
        inspected = list(dict.fromkeys(cited + toolbox.inspected + [s.evidence_id for s in steps if s.evidence_id]))

        record = AuditRecord(
            audit_id=audit_id,
            claim_version=claim.key,
            model=self.model,
            template_version=AUDIT_TEMPLATE_VERSION,
            started_at=started,
            ended_at=now(),
            termination_reason=termination,
            budgets=budgets,
            allowed_tools=toolbox.names(),
            initial_context=first,
            steps=steps,
            verdict=record_verdict,
            reasoning=reasoning,
            scope_check=payload.get("scope_check", ""),
            challenges=payload.get("challenges", []),
            evidence_inspected=inspected,
            contradictory_evidence=[e for e in payload.get("contradictory_evidence", []) if e in visible],
            limitations=payload.get("limitations", []),
            follow_up_requests=[FollowUpRequest.model_validate(f) for f in payload.get("follow_up_requests", [])],
            verdict_synthesized=synthesized,
            input_fingerprint=fingerprint,
            input_components=components,
            source_agreement_evidence=agreement_id,
            falsification={**counts, "satisfied": satisfied},
            model_verdict=model_verdict,
            runtime={"served_models": sorted(served), "system_fingerprints": sorted(fingerprints)},
            batch_id=batch_id,
            diagnostic=diagnostic,
        )
        return self.ledger.record_audit(record)
