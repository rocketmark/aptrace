"""
Call relations: which control transfers between functions the cited
evidence establishes, and whether a claim's call assertion stays within
them. Shared by claim admission (research/admission.py), typed semantics
(claim_semantics.verify_semantics) and verification phase B.

Edges are read from structured result fields only:

  DIRECT_CALL           function_facts callers/callees (Ghidra call
                        references); decoded BL/BLX immediates
                        (function_disassembly, callsite_context); the static
                        call sites observed_call_arguments lists; the decoded
                        BL callers callback_argument_provenance lists
  TAIL_TRANSFER         decoded B/B.W/B<c>(.W) immediates leaving the decoded
                        function (function_disassembly); decoded tail callers
                        callback_argument_provenance lists
  ESTABLISHED_INDIRECT  indirect_call_target STATICALLY_ESTABLISHED with an
                        ESTABLISHED derivation; census resolved_indirect
                        edges of EXACT/STRONG confidence
  POTENTIAL_INDIRECT    any other indirect_call_target candidate (or weaker
                        resolved edge), with the condition its result states;
                        a callback_argument_provenance target, conditional on
                        the caller site that passes it (never categorical, even
                        for a closed caller set)
  OBSERVED_DISPATCH     observed_call_arguments call sites reached (hits > 0)
                        in the result's scenario

Nothing else is an edge: naming both functions in one result, a table entry,
a function pointer, or a missing edge. An indirect site without a derived
target is recorded as unresolved.

What an assertion needs:

  categorical edge   a static edge (direct, tail, established indirect)
  possible edge      a static or observed edge, or a potential one whose
                     condition the claim restates (conditional wording plus
                     an address the condition names: vtable, slot, store)
  observed edge      an observed dispatch in a scenario the claim names
  "always", "every execution"  never supported
  reachability       a path of cited edges from the stated source; a target
                     alone needs an observed entry in a named scenario, or
                     census reachability stated for the census analysis
  absence            contradicted by any cited edge; otherwise supported only
                     as a statement about the recorded analysis

Every target of a disjunction ("calls B or C") must be supported on its own.
A categorical claim is never admitted because a weaker form would be; it is
rejected with the condition or scope it omits, and nothing is rewritten.

Prose is classified by a conservative pattern parser (parse_assertions; forms
in docs/claim-call-relations.md). Call wording without identifiable endpoints
is noted CALL_RELATION_UNCHECKED and stays an untyped hypothesis, which
admission caps at PROBABLE.
"""

from __future__ import annotations

import re
from collections import deque
from dataclasses import dataclass, field
from typing import Any

from aptrace_agent.ledger.claim_checks import (
    CALL_ABSENCE_NOT_ESTABLISHED,
    CALL_ABSENCE_SCOPED,
    CALL_CONDITION_OMITTED,
    CALL_KIND_MISMATCH,
    CALL_REACHABILITY_UNSUPPORTED,
    CALL_RELATION_CHECKED,
    CALL_RELATION_UNCHECKED,
    CALL_RELATION_UNSUPPORTED,
    CALL_SCOPE_EXCEEDED,
    CALL_SITE_MISMATCH,
    CALL_SOURCE_MISMATCH,
    CALL_TARGET_MISMATCH,
    CALL_TARGET_UNRESOLVED,
    GRADE_ABOVE_CEILING,
    NOTE,
    PATTERN,
    REJECT,
)
from aptrace_agent.ledger.claim_semantics import CallEdgeKind, CallRelation, CheckCode, SemanticCheck, addr, fun, to_int
from aptrace_agent.ledger.models import GRADE_RANK, ClaimDiagnostic, EvidenceGrade


K = CallEdgeKind
STATIC = frozenset({K.DIRECT_CALL, K.TAIL_TRANSFER, K.ESTABLISHED_INDIRECT})
# Evidence edge kinds that support a typed relation of each kind.
SUPPORTS: dict[CallEdgeKind, frozenset[CallEdgeKind]] = {
    K.DIRECT_CALL: frozenset({K.DIRECT_CALL}),
    K.TAIL_TRANSFER: frozenset({K.TAIL_TRANSFER}),
    K.ESTABLISHED_INDIRECT: frozenset({K.ESTABLISHED_INDIRECT}),
    K.POTENTIAL_INDIRECT: frozenset({K.POTENTIAL_INDIRECT, K.ESTABLISHED_INDIRECT}),
    K.OBSERVED_DISPATCH: frozenset({K.OBSERVED_DISPATCH}),
}
# Evidence edge kinds a prose assertion of each modality may rest on.
MODALITY_KINDS = {
    "categorical": STATIC,
    "possible": STATIC | {K.POTENTIAL_INDIRECT, K.OBSERVED_DISPATCH},
    "observed": frozenset({K.OBSERVED_DISPATCH}),
}
MAX_PATH_EDGES = 8


# -- facts from structured evidence ---------------------------------------------


@dataclass(frozen=True)
class CallEdge:
    source: int | None
    target: int
    kind: CallEdgeKind
    evidence_id: str
    site: int | None = None
    conditions: tuple[str, ...] = ()
    condition_addresses: frozenset[int] = frozenset()
    scenario: str | None = None

    def describe(self) -> str:
        source = fun(self.source) if self.source is not None else "an unattributed site"
        site = f" at {addr(self.site)}" if self.site is not None else ""
        scope = f" [{'; '.join(self.conditions)}]" if self.conditions else ""
        scope += f" [scenario {self.scenario}]" if self.scenario else ""
        return f"{self.evidence_id}: {source} -> {addr(self.target)}{site} {self.kind.value}{scope}"


@dataclass(frozen=True)
class UnresolvedSite:
    source: int | None
    site: int
    evidence_id: str


@dataclass
class CallFacts:
    edges: list[CallEdge] = field(default_factory=list)
    unresolved: list[UnresolvedSite] = field(default_factory=list)
    # function -> (evidence id, caller count, truncated): results listing its callers
    callers_listed: dict[int, tuple[str, int, bool]] = field(default_factory=dict)
    # function -> evidence id of a result enumerating its direct calls
    callees_listed: dict[int, str] = field(default_factory=dict)
    # function -> [(scenario, evidence id)] where it was concretely entered
    entered: dict[int, list[tuple[str, str]]] = field(default_factory=dict)
    # function -> [(census reachability status, evidence id)]
    census_reach: dict[int, list[tuple[str, str]]] = field(default_factory=dict)
    # instruction address -> function the cited evidence places it in
    site_owner: dict[int, int] = field(default_factory=dict)
    grades: dict[str, EvidenceGrade] = field(default_factory=dict)


# A branch operand: a decoded immediate (#0x...) or a canonical function symbol.
_IMMEDIATE_RE = re.compile(r"#(0x[0-9a-fA-F]+)|(FUN_[0-9a-fA-F]{8})")
_BRANCH_RE = re.compile(r"b(?:eq|ne|cs|hs|cc|lo|mi|pl|vs|vc|hi|ls|ge|lt|gt|le|al)?(?:\.w|\.n)?")
_ADDRESS_RE = re.compile(r"\b0x[0-9a-fA-F]+\b")
# Addresses below this are offsets or slot indexes, not condition identities.
_MIN_CONDITION_ADDRESS = 0x100


def _int(value: Any) -> int | None:
    try:
        return None if value in (None, "") else to_int(value)
    except ValueError:
        return None


def _addresses(text: str) -> set[int]:
    return {v for v in (int(m, 16) for m in _ADDRESS_RE.findall(text)) if v >= _MIN_CONDITION_ADDRESS}


def _decoded(facts: CallFacts, evidence_id: str, source: int | None, result: dict[str, Any], extent: int | None) -> None:
    for instruction in result.get("instructions") or []:
        if source is not None and (at := _int(instruction.get("address"))) is not None:
            facts.site_owner.setdefault(at, source)

        match = _IMMEDIATE_RE.fullmatch(str(instruction.get("operands", "")).strip())

        if match is None or source is None:
            continue

        mnemonic = str(instruction.get("mnemonic", "")).lower()
        target, site = to_int(match[1] or match[2]), _int(instruction.get("address"))

        if mnemonic in ("bl", "blx"):
            facts.edges.append(CallEdge(source, target, K.DIRECT_CALL, evidence_id, site))
        elif _BRANCH_RE.fullmatch(mnemonic) and extent is not None and not source <= target < source + extent:
            facts.edges.append(CallEdge(source, target, K.TAIL_TRANSFER, evidence_id, site))


def _indirect(facts: CallFacts, evidence_id: str, result: dict[str, Any]) -> None:
    source, site = _int(result.get("containing_function")), _int(result.get("site"))
    derivation = result.get("derivation_status")
    established = result.get("resolution_status") == "STATICALLY_ESTABLISHED" and derivation == "ESTABLISHED"
    targets = [c for c in result.get("candidate_targets") or [] if c.get("is_code_pointer") and _int(c.get("target")) is not None]
    slots = {v for p in result.get("patterns") or [] if (v := _int(p.get("slot_addr"))) is not None}

    if site is not None and source is not None:
        facts.site_owner.setdefault(site, source)

    if site is not None and (result.get("resolution_status") == "UNRESOLVED" or not targets):
        facts.unresolved.append(UnresolvedSite(source, site, evidence_id))

    for candidate in targets:
        target = _int(candidate["target"])
        assert target is not None

        if established:
            facts.edges.append(CallEdge(source, target, K.ESTABLISHED_INDIRECT, evidence_id, site))
            continue

        basis = str(candidate.get("basis") or "")
        conditions = tuple(c for c in (basis, "" if derivation == "ESTABLISHED" else f"target derivation {derivation}") if c)
        named = {v for key in ("vtable", "entry_addr") if (v := _int(candidate.get(key))) is not None}
        facts.edges.append(
            CallEdge(source, target, K.POTENTIAL_INDIRECT, evidence_id, site, conditions or (f"resolution {result.get('resolution_status')}",),
                     frozenset(named | _addresses(basis) | slots))
        )


def _callback(facts: CallFacts, evidence_id: str, result: dict[str, Any]) -> None:
    source, site = _int(result.get("containing_function")), _int(result.get("site"))

    if site is not None and source is not None:
        facts.site_owner.setdefault(site, source)

    for origin in result.get("argument_origins") or []:
        entry = _int(origin.get("function_entry"))

        for caller in origin.get("callers") or []:
            frm, at = _int(caller.get("caller_function")), _int(caller.get("site"))

            if entry is not None and frm is not None:
                kind = K.DIRECT_CALL if caller.get("transfer_kind") == "call" else K.TAIL_TRANSFER
                facts.edges.append(CallEdge(frm, entry, kind, evidence_id, at))

    targets = result.get("candidate_targets") or []

    if site is not None and not targets:
        facts.unresolved.append(UnresolvedSite(source, site, evidence_id))

    for candidate in targets:
        target = _int(candidate.get("target"))

        if target is None:
            continue

        for via in candidate.get("via") or []:
            caller_site, caller_fn = _int(via.get("caller_site")), _int(via.get("caller_function"))
            condition = (f"IF entered from caller site {via.get('caller_site')} "
                         f"({via.get('caller_function') or 'unattributed'}) passing {', '.join(candidate.get('raw_values') or [])} "
                         f"in {via.get('argument')}")
            named = {v for v in (caller_site, caller_fn, _int(via.get("def_addr"))) if v is not None}
            facts.edges.append(CallEdge(source, target, K.POTENTIAL_INDIRECT, evidence_id, site,
                                        (condition, *(via.get("conditions") or [])[:2]), frozenset(named)))


def _observed(facts: CallFacts, evidence_id: str, arguments: dict[str, Any], result: dict[str, Any]) -> None:
    if str(result.get("status", "")).startswith(("unsupported", "scenario_failed")):
        return

    target = _int(result.get("entry") or result.get("function") or arguments.get("function"))
    scenario = str(result.get("scenario") or arguments.get("scenario") or "boot")

    if target is None:
        return

    for site in result.get("call_sites") or []:
        source, address, status = _int(site.get("caller")), _int(site.get("call_site")), site.get("status")

        if status in ("OBSERVED", "DYNAMIC_ONLY") and site.get("hits", 0) > 0:
            facts.edges.append(CallEdge(source, target, K.OBSERVED_DISPATCH, evidence_id, address, scenario=scenario))

        # OBSERVED and UNOBSERVED sites are the static (Ghidra) call sites.
        if status in ("OBSERVED", "UNOBSERVED") and source is not None:
            facts.edges.append(CallEdge(source, target, K.DIRECT_CALL, evidence_id, address))

    if result.get("observed_entries"):
        facts.entered.setdefault(target, []).append((scenario, evidence_id))


def extract_call_facts(evidence: list[tuple[Any, dict[str, Any]]]) -> CallFacts:
    """Call edges, unresolved sites and enumerations in structured evidence."""

    facts = CallFacts()

    for artifact, result in evidence:
        evidence_id, tool, arguments = artifact.evidence_id, artifact.tool, artifact.arguments or {}

        if getattr(artifact, "grade", None) is not None:
            facts.grades[evidence_id] = EvidenceGrade(artifact.grade)

        if tool == "function_facts":
            # The canonical FUN_ name is the function identity; entry only when no name parses.
            entry = next((v for v in (_int(result.get("name")), _int(result.get("entry")), _int(arguments.get("function"))) if v is not None), None)

            if entry is None:
                continue

            callers = result.get("callers") or []

            for caller in callers:
                facts.edges.append(CallEdge(_int(caller.get("function")), entry, K.DIRECT_CALL, evidence_id, _int(caller.get("address"))))

            for callee in result.get("callees") or []:
                if (target := _int(callee.get("function"))) is not None:
                    facts.edges.append(CallEdge(entry, target, K.DIRECT_CALL, evidence_id, _int(callee.get("address"))))

            facts.callers_listed[entry] = (evidence_id, len(callers), bool(result.get("callers_truncated")))

            if not result.get("callees_truncated"):
                facts.callees_listed.setdefault(entry, evidence_id)

        elif tool == "function_disassembly":
            entry = _int(result.get("entry") or arguments.get("function"))
            extent = result.get("bytes_decoded") or result.get("bytes_requested")
            _decoded(facts, evidence_id, entry, result, extent if isinstance(extent, int) else None)

            if entry is not None and result.get("complete"):
                facts.callees_listed.setdefault(entry, evidence_id)

        elif tool == "callsite_context":
            _decoded(facts, evidence_id, _int(result.get("function") or arguments.get("function")), result, None)

        elif tool == "indirect_call_target" and result.get("status") == "ok":
            _indirect(facts, evidence_id, result)

        elif tool == "callback_argument_provenance" and result.get("status") == "ok":
            _callback(facts, evidence_id, result)

        elif tool == "observed_call_arguments":
            _observed(facts, evidence_id, arguments, result)

        for edge in result.get("resolved_indirect_edges") or []:
            source, target = _int(edge.get("from_function")), _int(edge.get("canonical_target"))

            if target is None:
                continue

            confidence = str(edge.get("confidence", "")).upper()
            kind = K.ESTABLISHED_INDIRECT if confidence in ("EXACT", "STRONG") else K.POTENTIAL_INDIRECT
            conditions = () if kind == K.ESTABLISHED_INDIRECT else (f"census resolution confidence {confidence or 'unknown'}",)
            facts.edges.append(CallEdge(source, target, kind, evidence_id, _int(edge.get("site")), conditions))

        if tool.startswith("census_"):
            for item in result.get("functions") or []:
                status = (item.get("reachability") or {}).get("status") if isinstance(item, dict) else None

                if status and (entry := _int(item.get("function"))) is not None:
                    facts.census_reach.setdefault(entry, []).append((str(status), evidence_id))

    # A dynamically observed site has no static caller; attribute it only where
    # other cited evidence places that instruction in a function.
    facts.edges = [
        CallEdge(facts.site_owner[e.site], e.target, e.kind, e.evidence_id, e.site, e.conditions, e.condition_addresses, e.scenario)
        if e.source is None and e.site in facts.site_owner
        else e
        for e in facts.edges
    ]
    return facts


# -- checking -------------------------------------------------------------------


@dataclass
class Finding:
    code: str
    passed: bool
    relation: str
    detail: str
    evidence_ids: list[str] = field(default_factory=list)
    kind: str | None = None


@dataclass(frozen=True)
class Scope:
    """What the asserting claim states about one relation."""

    kinds: frozenset[CallEdgeKind]
    # Conditional wording is present (prose) / conditions are stated (typed).
    conditional: bool = False
    # Text whose addresses must cover a potential edge's condition.
    condition_text: str = ""
    # Observed dispatches must be in a scenario this text names (None: any).
    scenario_text: str | None = None
    universal: bool = False
    typed_kind: CallEdgeKind | None = None


def _relation(source: int | None, target: int | None, site: int | None) -> str:
    left = fun(source) if source is not None else "(unstated source)"
    right = fun(target) if target is not None else "(unstated target)"
    return f"{left} -> {right}" + (f" at {addr(site)}" if site is not None else "")


def _names_scenario(text: str, scenario: str | None) -> bool:
    return bool(scenario) and re.search(rf"(?<![\w-]){re.escape(str(scenario))}(?![\w-])", text, re.IGNORECASE) is not None


def _satisfied(edge: CallEdge, scope: Scope) -> bool:
    if edge.kind in STATIC:
        return True

    if edge.kind == K.OBSERVED_DISPATCH:
        return scope.scenario_text is None or _names_scenario(scope.scenario_text, edge.scenario)

    return scope.conditional and (not edge.condition_addresses or bool(edge.condition_addresses & _addresses(scope.condition_text)))


def _shown(edges: list[CallEdge], limit: int = 4) -> str:
    text = "; ".join(e.describe() for e in edges[:limit])
    return text + (f"; +{len(edges) - limit} more" if len(edges) > limit else "")


def _context(source: int | None, target: int, facts: CallFacts) -> str:
    """What the cited evidence does show about the two endpoints."""

    parts: list[str] = []

    if source is not None and (out := [e for e in facts.edges if e.source == source]):
        parts.append(f"edges from {fun(source)}: {_shown(out)}")

    if into := [e for e in facts.edges if e.target == target]:
        parts.append(f"edges into {addr(target)}: {_shown(into)}")

    if target in facts.callers_listed:
        evidence_id, count, truncated = facts.callers_listed[target]

        if count == 0:
            parts.append(f"{evidence_id} lists no callers of {fun(target)}")
        elif truncated:
            parts.append(f"{evidence_id}'s caller list of {fun(target)} is truncated")

    return "; ".join(parts) if parts else "the cited evidence records no edge touching either endpoint"


def _missing(source: int | None, target: int, site: int | None, facts: CallFacts) -> Finding:
    relation = _relation(source, target, site)
    pair = [e for e in facts.edges if e.target == target and (source is None or e.source == source)]

    def fail(code: str, detail: str, edges: list[Any] = ()) -> Finding:
        return Finding(code, False, relation, detail, sorted({e.evidence_id for e in edges}))

    if site is not None:
        if sited := [e for e in pair if e.site is not None]:
            return fail(CALL_SITE_MISMATCH, f"cited evidence has this transfer only at another site: {_shown(sited)}", sited)

        if pair:
            return fail(CALL_SITE_MISMATCH, f"cited evidence records this transfer without its site, so the named site is not established: {_shown(pair)}", pair)

        at_site = [e for e in facts.edges if e.site == site and (source is None or e.source in (source, None))]

        if at_site:
            return fail(CALL_TARGET_MISMATCH, f"cited evidence gives the transfer at {addr(site)} other targets: {_shown(at_site)}", at_site)

        if unresolved := [u for u in facts.unresolved if u.site == site]:
            return fail(CALL_TARGET_UNRESOLVED, f"{unresolved[0].evidence_id} derives no target for the transfer at {addr(site)}; a transfer to {addr(target)} there is undetermined, not established", unresolved)

    if source is not None:
        others = [e for e in facts.edges if e.target == target and e.source is not None and e.source != source]

        if others:
            return fail(CALL_SOURCE_MISMATCH, f"cited evidence reaches {addr(target)} from other functions only: {_shown(others)}", others)

        if unresolved := [u for u in facts.unresolved if u.source == source]:
            sites = ", ".join(addr(u.site) for u in unresolved)
            return fail(
                CALL_TARGET_UNRESOLVED,
                f"the cited evidence derives no target for {fun(source)}'s indirect transfer(s) at {sites}; whether they reach {addr(target)} is undetermined, not established ({_context(source, target, facts)})",
                unresolved,
            )

        if source in facts.callees_listed and any(e.source == source for e in facts.edges):
            evidence_id = facts.callees_listed[source]
            return Finding(
                CALL_TARGET_MISMATCH, False, relation,
                f"{evidence_id} enumerates {fun(source)}'s direct calls and {addr(target)} is not among them "
                f"({_context(source, target, facts)}); an indirect call to it would need indirect-target evidence",
                [evidence_id],
            )

    return Finding(
        CALL_RELATION_UNSUPPORTED, False, relation,
        f"no cited evidence connects {fun(source) if source is not None else 'any source'} to {addr(target)} "
        f"({_context(source, target, facts)}); naming both functions in cited results is not an edge",
        sorted({e.evidence_id for e in facts.edges if e.target == target or e.source == source}),
    )


def check_edge(source: int | None, target: int, site: int | None, scope: Scope, facts: CallFacts) -> Finding:
    """One asserted transfer against the cited edges, at the claim's scope."""

    relation = _relation(source, target, site)

    if scope.universal:
        return Finding(
            CALL_SCOPE_EXCEEDED, False, relation,
            "the claim asserts the transfer on every execution; static edges show a transfer instruction exists and "
            "observations show it was taken in one scenario, and no APTrace analysis establishes it is always taken",
        )

    matches = [e for e in facts.edges if e.target == target and (source is None or e.source == source) and (site is None or e.site == site)]

    if not matches:
        return _missing(source, target, site, facts)

    usable = [e for e in matches if e.kind in scope.kinds]
    satisfied = [e for e in usable if _satisfied(e, scope)]

    if satisfied:
        best = sorted(satisfied, key=lambda e: (e.kind not in STATIC, e.kind != K.OBSERVED_DISPATCH))
        return Finding(CALL_RELATION_CHECKED, True, relation, f"supported by {_shown(best)}", sorted({e.evidence_id for e in best}), best[0].kind.value)

    weaker = usable or matches
    potential = [e for e in weaker if e.kind == K.POTENTIAL_INDIRECT]
    observed = [e for e in weaker if e.kind == K.OBSERVED_DISPATCH]
    ids = sorted({e.evidence_id for e in weaker})

    if potential:
        conditions = "; ".join(dict.fromkeys(c for e in potential for c in e.conditions))
        names = ", ".join(addr(a) for a in sorted({a for e in potential for a in e.condition_addresses}))
        return Finding(
            CALL_CONDITION_OMITTED, False, relation,
            f"the cited evidence shows {addr(target)} only as a potential target ({_shown(potential)}); it holds only under: {conditions}. "
            f"State the claim as conditional and name its condition{f' ({names})' if names else ''}; "
            "a potential target is not a dispatch and does not make its caller reachable",
            ids,
        )

    if observed:
        scenarios = ", ".join(sorted({str(e.scenario) for e in observed}))
        return Finding(
            CALL_SCOPE_EXCEEDED, False, relation,
            f"the cited evidence observed this transfer only in scenario(s) {scenarios} ({_shown(observed)}); "
            "scope the claim to the scenario it was observed in; an observation is not every execution",
            ids,
        )

    if scope.typed_kind is not None:
        return Finding(
            CALL_KIND_MISMATCH, False, relation,
            f"the claim states {scope.typed_kind.value}; the cited evidence shows {_shown(matches)}", ids,
        )

    return Finding(
        CALL_RELATION_UNSUPPORTED, False, relation,
        f"the claim states an observed transfer; the cited evidence has only static edges ({_shown(matches)}), no observation", ids,
    )


def _path(source: int, target: int, edges: list[CallEdge]) -> list[CallEdge] | None:
    queue: deque[tuple[int, list[CallEdge]]] = deque([(source, [])])
    seen = {source}

    while queue:
        node, path = queue.popleft()

        if len(path) >= MAX_PATH_EDGES:
            continue

        for edge in edges:
            if edge.source != node or edge.target in seen:
                continue

            if edge.target == target:
                return path + [edge]

            seen.add(edge.target)
            queue.append((edge.target, path + [edge]))

    return None


_CENSUS_SCOPE_RE = re.compile(r"\b(census|statically|static\w*|recorded analysis|call[- ]?graph|in the (?:recorded |cited )?analysis)\b", re.IGNORECASE)


def check_reach(source: int | None, target: int, scope: Scope, text: str, facts: CallFacts) -> Finding:
    """A path from `source` (or, with no source, any established root) to `target`."""

    relation = _relation(source, target, None)

    if scope.universal:
        return Finding(CALL_SCOPE_EXCEEDED, False, relation, "the claim asserts reachability on every execution; no APTrace analysis establishes that")

    if source is None:
        entered = [(s, e) for s, e in facts.entered.get(target, []) if _names_scenario(text, s)]

        if entered:
            return Finding(CALL_RELATION_CHECKED, True, relation, f"entered concretely in scenario {entered[0][0]} ({entered[0][1]})", [entered[0][1]], K.OBSERVED_DISPATCH.value)

        census = [(s, e) for s, e in facts.census_reach.get(target, []) if s == "DEFINITELY_REACHABLE"]

        if census and _CENSUS_SCOPE_RE.search(text):
            return Finding(CALL_RELATION_CHECKED, True, relation, f"census static reachability {census[0][0]} ({census[0][1]}), stated for that analysis", [census[0][1]], "CENSUS_REACHABILITY")

        known = [f"{e}: census {s}" for s, e in facts.census_reach.get(target, [])] + [f"{e}: entered in scenario {s}" for s, e in facts.entered.get(target, [])]
        return Finding(
            CALL_REACHABILITY_UNSUPPORTED, False, relation,
            f"the claim asserts {fun(target)} is reachable without a root the cited evidence connects it to"
            + (f"; the cited evidence has {'; '.join(known)}: name the scenario, or state the census result as the census's static analysis" if known else "")
            + "; a call edge into a function does not make the function, or its caller, reachable",
            sorted({e for _, e in facts.census_reach.get(target, []) + facts.entered.get(target, [])}),
        )

    usable = [e for e in facts.edges if e.kind in scope.kinds and _satisfied(e, scope)]
    path = _path(source, target, usable)

    if path:
        return Finding(CALL_RELATION_CHECKED, True, relation, "cited path: " + " => ".join(e.describe() for e in path), sorted({e.evidence_id for e in path}), "PATH")

    weaker = _path(source, target, facts.edges)
    detail = (
        "the only cited path uses edges the claim's scope does not cover: " + " => ".join(e.describe() for e in weaker)
        + "; state its conditions or scenario"
        if weaker
        else f"no path of cited edges leads from {fun(source)} to {addr(target)} ({_context(source, target, facts)})"
    )
    return Finding(CALL_REACHABILITY_UNSUPPORTED, False, relation, detail, sorted({e.evidence_id for e in weaker or []}))


_ABSENCE_SCOPE_RE = re.compile(
    r"\b(observed|recorded|cited|known|census|call[- ]?graph|static(?:ally)?|in the (?:recorded |cited |symbolic )?analysis|"
    r"not established|undetermined|unresolved|unknown)\b",
    re.IGNORECASE,
)


def check_absence(source: int | None, target: int, text: str, facts: CallFacts) -> Finding:
    relation = _relation(source, target, None)
    edges = [e for e in facts.edges if e.target == target and (source is None or e.source == source)]

    if edges:
        return Finding(CALL_ABSENCE_NOT_ESTABLISHED, False, relation, f"cited evidence shows the transfer the claim denies: {_shown(edges)}", sorted({e.evidence_id for e in edges}))

    gaps = ["a call graph holds Ghidra call references over heuristic function boundaries and omits indirect transfers it did not resolve"]

    if facts.unresolved:
        gaps.append(f"the cited evidence has {len(facts.unresolved)} indirect site(s) with no derived target")

    if target in facts.callers_listed and facts.callers_listed[target][2]:
        gaps.append(f"{facts.callers_listed[target][0]}'s caller list is truncated")

    if _ABSENCE_SCOPE_RE.search(text):
        return Finding(CALL_ABSENCE_SCOPED, True, relation, "absence stated for the recorded analysis only: " + "; ".join(gaps))

    return Finding(
        CALL_ABSENCE_NOT_ESTABLISHED, False, relation,
        "no APTrace analysis establishes that a call cannot happen: " + "; ".join(gaps)
        + ". Scope the claim to the recorded analysis (e.g. 'no recorded caller')",
    )


# -- prose classification -----------------------------------------------------------

_ENTITY = r"FUN_[0-9a-fA-F]{8}|0x[0-9a-fA-F]+"
_TOKEN_RE = re.compile(rf"(?P<entity>\b(?:{_ENTITY})\b)|(?P<word>[A-Za-z][A-Za-z\-]*)|(?P<comma>,)")
_CLAUSE_RE = re.compile(r"[;.](?=\s|$)|[()]|\b(?:but|while|whereas|however|though|although|yet)\b|,\s*(?=(?:which|this|that)\b)", re.IGNORECASE)

_MOD = r"(?:can|may|might|could|would|will|does|did|also|only|then|directly|indirectly|conditionally|potentially|possibly|eventually|always|sometimes)"
_NEG = r"(?:does\s+not|doesn't|do\s+not|don't|did\s+not|didn't|never|cannot|can\s+not|can't|will\s+not|won't|may\s+not|could\s+not|couldn't)"
_ACT = (
    r"tail[- ]?call(?:s|ed)?|tail[- ]?branch(?:es|ed)?\s+to|calls?(?:\s+into)?|called(?!\s+(?:by|from)\b)|invok(?:es?|ed)|"
    r"dispatch(?:es|ed)?\s+(?:to|into)|transfer(?:s|red)?\s+control\s+to|branch(?:es|ed)?\s+to|jump(?:s|ed)?\s+to|"
    r"tail[- ]?calling|calling|invoking|dispatching\s+(?:to|into)|transferring\s+control\s+to|branching\s+to|jumping\s+to"
)
_ACT_BASE = r"(?:tail[- ]?call|call|invoke|dispatch|transfer\s+control|branch|jump|reach)(?:s|es|ed)?(?:\s+(?:to|into))?"
_NOUN_AFTER = r"(?!\s+(?:site|sites|graph|target|targets|instruction|instructions|chain|path|edge|edges|count|counts|stack|frame)\b)"

# (form, pattern) in priority order; an earlier form wins an overlapping span.
_FORMS: list[tuple[str, re.Pattern[str]]] = [
    ("absence_target", re.compile(r"\b(?:has|have|had)\s+no\s+(?:(?:known|recorded|static|direct|indirect|census|cited)\s+)*callers?\b", re.IGNORECASE)),
    ("absence_passive", re.compile(rf"\b(?:is|are|was|were|be|been)\s+(?:not|never)\s+(?:{_MOD}\s+)?(?:called|invoked|tail[- ]?called|dispatched\s+to|reached)(?:\s+(?:by|from))?\b", re.IGNORECASE)),
    ("absence_active", re.compile(rf"\b{_NEG}\s+(?:{_MOD}\s+)?(?:{_ACT_BASE})\b", re.IGNORECASE)),
    ("passive", re.compile(rf"\b(?:is|are|was|were|be|been|being|gets?|got)\s+(?:(?P<pmod>{_MOD}|observed\s+(?:being|to\s+be))\s+)?(?:called|invoked|tail[- ]?called|dispatched)\s+(?:by|from)\b", re.IGNORECASE)),
    ("passive", re.compile(r"\b(?:is|are|was|were|be)\s+(?:a|an|the|one)\s+(?P<pmod>(?:(?:possible|potential|candidate|conditional|direct|indirect|tail|dispatch|call|observed)\s+){0,3})(?:callee|target|destination)\s+of\b", re.IGNORECASE)),
    ("reach_passive", re.compile(rf"\b(?:is|are|was|were|be|been)\s+(?:(?P<pmod>{_MOD}|\w+ly)\s+)?(?:reachable|reached)\s+(?:from|by)\b", re.IGNORECASE)),
    ("reach_target", re.compile(r"\b(?:is|are|was|were|be|been)\s+(?:(?P<pmod>\w+)\s+)?(?:reachable|reached)\b", re.IGNORECASE)),
    ("reach", re.compile(rf"\b(?:(?P<amod>{_MOD})\s+){{0,2}}reach(?:es)?\b", re.IGNORECASE)),
    ("active", re.compile(rf"\b(?:(?P<amod>{_MOD})\s+){{0,2}}(?:{_ACT})\b{_NOUN_AFTER}", re.IGNORECASE)),
]

_POSSIBLE_RE = re.compile(r"\b(can|may|might|could|would|potentially|possibly|possible|potential|candidate|conditional(?:ly)?|if|provided|assuming|depending|depends|unless)\b", re.IGNORECASE)
_CONDITION_RE = re.compile(r"\b(if|when|provided|assuming|depending|depends|unless|conditional(?:ly)?|only\s+with|requires?)\b", re.IGNORECASE)
_OBSERVED_RE = re.compile(r"\b(observed|observation|during|at\s+runtime|scenario|concretely|executed|was\s+taken)\b", re.IGNORECASE)
_UNIVERSAL_RE = re.compile(r"\b(always|unconditionally|whenever|every\s+(?:execution|time|run|path|call|invocation|boot)|all\s+executions|on\s+every\s+path|in\s+all\s+cases|each\s+time)\b", re.IGNORECASE)
_HEDGE_RE = re.compile(r"\b(whether|not\s+(?:been\s+)?(?:established|shown|determined|proven)|unestablished|unproven|undetermined|unclear|open\s+question|no\s+evidence)\b", re.IGNORECASE)

# Words between a subject and its verb that keep them adjacent.
_SKIP_LEFT = {
    "s", "which", "that", "it", "itself", "then", "also", "only", "both", "each", "in", "turn",
    "is", "are", "was", "were", "been", "being", "observed", "seen", "found", "shown", "to",
}
# A word before an entity that makes it an object, not a subject.
_OBJECT_MARKERS = {
    "by", "from", "of", "to", "for", "in", "at", "via", "through", "with", "into", "than", "written", "stored",
    "registered", "installed", "loaded", "passed", "returned", "constructed", "allocated",
}
# Nouns that make "the <noun> at 0x..." name code at that address.
_CODE_NOUNS = {"thunk", "code", "function", "stub", "routine", "handler", "body", "entry", "trampoline", "veneer"}
# Words that, within two words before an entity, keep it from being an endpoint.
_NOT_ENDPOINT = {
    "via", "through", "slot", "vtable", "table", "vptr", "receiver", "receiver's", "written", "stored", "registered", "installed",
    "loaded", "passed", "of", "offset", "pointer", "word", "constant", "value", "argument",
}
_SITE_MARKERS = {"at", "site", "callsite", "instruction"}
_TARGET_FILLER = {"the", "a", "an", "code", "function", "thunk", "routine", "handler", "entry", "stub", "address", "target", "body", "at", "into", "to", "s"}
# A subordinate clause after the targets: its entities are conditions.
_STOP_RIGHT = {"if", "when", "which", "that", "because", "since", "whose", "depending", "unless", "where", "provided", "assuming", "only", "while"}

_SITE_LEFT_RES = (
    re.compile(rf"(?P<fn>FUN_[0-9a-fA-F]{{8}})(?:\s*'s)?\s+(?:[\w-]+\s+){{0,3}}?(?:call|branch|transfer|dispatch|site|callsite|instruction|blx|bx)\s+at\s+(?P<site>0x[0-9a-fA-F]+)\s*,?\s*$", re.IGNORECASE),
    re.compile(rf"(?:call|branch|transfer|dispatch|site|callsite|instruction|blx|bx)(?:\s+[\w-]+)?\s+at\s+(?P<site>0x[0-9a-fA-F]+)\s+(?:in|of)\s+(?P<fn>FUN_[0-9a-fA-F]{{8}})\s*,?\s*$", re.IGNORECASE),
    re.compile(rf"(?:call|branch|transfer|dispatch|site|callsite|instruction)\s+(?:in|of)\s+(?P<fn>FUN_[0-9a-fA-F]{{8}})\s+at\s+(?P<site>0x[0-9a-fA-F]+)\s*,?\s*$", re.IGNORECASE),
)


@dataclass
class _Token:
    text: str
    start: int
    end: int
    entity: bool
    comma: bool = False

    @property
    def word(self) -> str:
        return "" if self.entity else self.text.lower()


@dataclass(frozen=True)
class CallAssertion:
    form: str  # edge | reach | absence
    sources: tuple[int, ...]
    targets: tuple[int, ...]
    site: int | None
    modality: str  # categorical | possible | observed
    universal: bool
    clause: str


def _tokens(text: str) -> list[_Token]:
    return [_Token(m.group(0), m.start(), m.end(), m.lastgroup == "entity", m.lastgroup == "comma") for m in _TOKEN_RE.finditer(text)]


def _left(clause: str, tokens: list[_Token], start: int) -> tuple[list[int], int | None]:
    """Subject entities directly before a verb, and a site the subject phrase names."""

    for pattern in _SITE_LEFT_RES:
        if match := pattern.search(clause[:start]):
            return [to_int(match["fn"])], to_int(match["site"])

    before = [t for t in tokens if t.end <= start]
    i, found = len(before) - 1, []

    while i >= 0:
        token = before[i]

        if token.entity:
            found.append(to_int(token.text))
            i -= 1

            if i >= 0 and (before[i].comma or before[i].word in ("and", "or")):
                i -= 1
                continue

            break

        if token.word in _SKIP_LEFT and not found:
            i -= 1
            continue

        break

    if not found:
        return [], None

    marker = before[i].word if i >= 0 else ""

    if marker == "at" and i >= 1 and before[i - 1].word in _CODE_NOUNS:
        return found[::-1], None

    return ([], None) if marker in _OBJECT_MARKERS else (found[::-1], None)


def _right(tokens: list[_Token], end: int, *, passive: bool) -> tuple[list[int], int | None]:
    """Endpoint entities after a verb (targets; sources for a passive) and a named site."""

    after = [t for t in tokens if t.start >= end]
    endpoints: list[int] = []
    site = None
    filler_only = True

    for index, token in enumerate(after):
        if token.word in _STOP_RIGHT:
            break

        if not token.entity:
            if token.word not in _TARGET_FILLER and token.word not in ("and", "or") and not token.comma:
                filler_only = False
            continue

        previous = {t.word for t in after[max(0, index - 2) : index]}
        value = to_int(token.text)

        if token.text.lower().startswith("0x"):
            # In passive position an address is where the call is, not who calls.
            if passive and (previous & ({"by", "from"} | _SITE_MARKERS) or filler_only):
                site = site if site is not None else value
            elif not passive and filler_only and not endpoints:
                endpoints.append(value)
            elif previous & _SITE_MARKERS and site is None:
                site = value
        elif not previous & _NOT_ENDPOINT:
            endpoints.append(value)

        filler_only = False

    return endpoints, site


def _modality(clause: str, modifier: str) -> str:
    if _OBSERVED_RE.search(clause) or "observed" in modifier.lower():
        return "observed"

    if _POSSIBLE_RE.search(modifier) or _CONDITION_RE.search(clause):
        return "possible"

    return "categorical"


def parse_assertions(text: str) -> tuple[list[CallAssertion], list[str]]:
    """
    Call assertions in prose (forms in the module docstring), and clauses
    with call wording whose endpoints could not be identified.
    """

    assertions: list[CallAssertion] = []
    unchecked: list[str] = []
    bounds = [0] + [m.end() for m in _CLAUSE_RE.finditer(text)] + [len(text)]

    for a, b in zip(bounds, bounds[1:]):
        clause = text[a:b]

        if not re.search(_ENTITY, clause):
            continue

        tokens = _tokens(clause)
        spans: list[tuple[int, int, str, re.Match[str]]] = []

        for form, pattern in _FORMS:
            for match in pattern.finditer(clause):
                if not any(match.start() < e and s < match.end() for s, e, _, _ in spans):
                    spans.append((match.start(), match.end(), form, match))

        if spans and _HEDGE_RE.search(clause):
            unchecked.append(f"{clause.strip()!r}: stated as undetermined")
            continue

        for start, end, form, match in sorted(spans, key=lambda s: s[0]):
            modifier = " ".join(v for v in (match.groupdict().get("amod"), match.groupdict().get("pmod")) if v)
            modality = _modality(clause, modifier + " " + match.group(0))
            universal = bool(_UNIVERSAL_RE.search(clause))
            left, left_site = _left(clause, tokens, start)

            if form == "reach_target":
                if (match.groupdict().get("pmod") or "").lower() in ("not", "never", "un"):
                    continue
                if left:
                    assertions.append(CallAssertion("reach", (), tuple(left), None, modality, universal, clause.strip()))
                    continue
            elif form == "absence_target":
                if left:
                    assertions.append(CallAssertion("absence", (), tuple(left), None, modality, False, clause.strip()))
                    continue
            elif form in ("passive", "absence_passive", "reach_passive"):
                sources, site = _right(tokens, end, passive=True)
                kind = {"passive": "edge", "absence_passive": "absence", "reach_passive": "reach"}[form]

                if left and (sources or site is not None or kind == "absence"):
                    assertions.append(CallAssertion(kind, tuple(sources), tuple(left), site, modality, universal, clause.strip()))
                    continue
            else:
                targets, site = _right(tokens, end, passive=False)
                kind = {"absence_active": "absence", "reach": "reach"}.get(form, "edge")

                if left and targets:
                    assertions.append(CallAssertion(kind, tuple(left), tuple(targets), site if site is not None else left_site, modality, universal, clause.strip()))
                    continue

            unchecked.append(f"{clause.strip()!r}: no identifiable {'source and target' if not left else 'counterpart'} for {match.group(0).strip()!r}")

    return assertions, unchecked


# -- diagnostics ----------------------------------------------------------------------


def _ceiling(finding: Finding, facts: CallFacts) -> EvidenceGrade | None:
    grades = [facts.grades[e] for e in finding.evidence_ids if e in facts.grades]
    return max(grades, key=lambda g: GRADE_RANK[g]) if grades else None


def _diagnostic(finding: Finding, basis: str) -> ClaimDiagnostic:
    severity = NOTE if finding.passed else REJECT
    detail = (f"{finding.relation}: " + finding.detail)[:900]
    return ClaimDiagnostic(code=finding.code, severity=severity, detail=detail, value=finding.relation, evidence_ids=finding.evidence_ids, basis=basis)


def _grade_diagnostic(finding: Finding, facts: CallFacts, grade: EvidenceGrade | str | None, basis: str) -> ClaimDiagnostic | None:
    if grade is None or not finding.passed or finding.code != CALL_RELATION_CHECKED:
        return None

    ceiling = _ceiling(finding, facts)

    if ceiling is None or GRADE_RANK[EvidenceGrade(grade)] <= GRADE_RANK[ceiling]:
        return None

    return ClaimDiagnostic(
        code=GRADE_ABOVE_CEILING, severity=REJECT, value=str(EvidenceGrade(grade).value), basis=basis, evidence_ids=finding.evidence_ids,
        detail=f"{finding.relation}: the call relation rests on {', '.join(finding.evidence_ids)}, which permit at most {ceiling.value}",
    )


def assertion_findings(assertion: CallAssertion, facts: CallFacts) -> list[Finding]:
    scope = Scope(
        kinds=MODALITY_KINDS[assertion.modality],
        conditional=bool(_POSSIBLE_RE.search(assertion.clause)),
        condition_text=assertion.clause,
        scenario_text=assertion.clause if assertion.modality == "observed" else None,
        universal=assertion.universal,
    )
    out: list[Finding] = []

    for target in assertion.targets:
        for source in assertion.sources or (None,):
            if assertion.form == "absence":
                out.append(check_absence(source, target, assertion.clause, facts))
            elif assertion.form == "reach":
                out.append(check_reach(source, target, scope, assertion.clause, facts))
            else:
                out.append(check_edge(source, target, assertion.site, scope, facts))

    return out


def call_diagnostics(assertion: str, evidence: list[tuple[Any, dict[str, Any]]], *, grade: EvidenceGrade | str | None = None) -> list[ClaimDiagnostic]:
    """Call relations asserted in prose, checked against the cited evidence."""

    assertions, unchecked = parse_assertions(assertion)
    out: list[ClaimDiagnostic] = []

    if assertions:
        facts = extract_call_facts(evidence)

        for item in assertions:
            for finding in assertion_findings(item, facts):
                out.append(_diagnostic(finding, PATTERN))

                if extra := _grade_diagnostic(finding, facts, grade, PATTERN):
                    out.append(extra)

    for note in unchecked:
        out.append(
            ClaimDiagnostic(
                code=CALL_RELATION_UNCHECKED, severity=NOTE, basis=PATTERN,
                detail=f"call wording APTrace could not check: {note}; the claim stays an unchecked hypothesis",
            )
        )

    return list({(d.code, d.detail): d for d in out}.values())


def typed_finding(relation: CallRelation, evidence: list[tuple[Any, dict[str, Any]]]) -> tuple[Finding, CallFacts]:
    facts = extract_call_facts(evidence)
    scope = Scope(
        kinds=SUPPORTS[relation.kind],
        conditional=bool(relation.conditions),
        condition_text=" ".join(relation.conditions),
        scenario_text=relation.scenario if relation.kind == K.OBSERVED_DISPATCH else None,
        typed_kind=relation.kind,
    )
    return check_edge(to_int(relation.source), to_int(relation.target), None if relation.site is None else to_int(relation.site), scope, facts), facts


_CHECK_CODES = {
    CALL_SITE_MISMATCH: CheckCode.RELATION_MISMATCH,
    CALL_TARGET_MISMATCH: CheckCode.RELATION_MISMATCH,
    CALL_SOURCE_MISMATCH: CheckCode.RELATION_MISMATCH,
    CALL_KIND_MISMATCH: CheckCode.RELATION_MISMATCH,
    CALL_CONDITION_OMITTED: CheckCode.SCOPE_MISMATCH,
    CALL_SCOPE_EXCEEDED: CheckCode.SCOPE_MISMATCH,
}


def typed_call_checks(relation: CallRelation, evidence: list[tuple[Any, dict[str, Any]]]) -> list[SemanticCheck]:
    """CALL_RELATION semantics as semantic checks (claim_semantics.verify_semantics)."""

    finding, _facts = typed_finding(relation, evidence)
    return [
        SemanticCheck(
            code=CheckCode.CONSISTENT if finding.passed else _CHECK_CODES.get(finding.code, CheckCode.RELATION_UNSUPPORTED),
            passed=finding.passed,
            field="call",
            claimed=relation.summary(),
            evidence_value=finding.kind,
            evidence_id=finding.evidence_ids[0] if finding.evidence_ids else None,
            detail=f"{finding.code}: {finding.detail}"[:900],
            diagnostic=None if finding.passed else finding.code,
        )
    ]


def typed_grade_diagnostics(relation: CallRelation, evidence: list[tuple[Any, dict[str, Any]]], grade: EvidenceGrade | str) -> list[ClaimDiagnostic]:
    """A typed relation may be no stronger than the evidence supporting its edge."""

    finding, facts = typed_finding(relation, evidence)
    extra = _grade_diagnostic(finding, facts, grade, "structured")
    return [extra] if extra else []


__all__ = [
    "CallAssertion",
    "CallEdge",
    "CallFacts",
    "Finding",
    "MODALITY_KINDS",
    "STATIC",
    "SUPPORTS",
    "call_diagnostics",
    "check_absence",
    "check_edge",
    "check_reach",
    "extract_call_facts",
    "parse_assertions",
    "typed_call_checks",
    "typed_grade_diagnostics",
]
