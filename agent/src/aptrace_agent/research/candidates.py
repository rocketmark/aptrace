"""
Claim candidates: typed facts APTrace derives deterministically from
session evidence, for the planner to select by id.

Three decisions stay apart:

- extraction (here): which typed facts the recorded evidence establishes.
  Facts come from the same structured readers the verifier uses
  (claim_semantics.extract_facts); grades from the evidence grade rules
  (semantics.evidence_grade, grade_ceiling). Nothing here reads model text,
  and nothing here writes to any ledger.
- selection (ResearchController): the planner names candidate ids that
  matter for the objective. It cannot change a candidate: the controller
  resolves each id against these immutable records.
- admission and verification: a selected candidate becomes a proposal and
  passes research/admission.py like any other; the recorder creates no
  claim when an equivalent claim already exists. Verification is unchanged.

Extractors (deliberately few):

- peripheral-role: FUNCTION_ROLE MMIO_USER for a census constant-address
  MMIO site, a USB inventory register user, or an unspecialized
  function-effects access at a concrete MMIO address; FUNCTION_ROLE
  ADDRESS_CONSTANT_LOADER for a census entry with constant loads and no
  access fact of any source for that function. An access observed only
  under argument specialization or at an input-dependent address is
  withheld: FUNCTION_ROLE cannot state its condition.
- resolved-pointer: RESOLVED_FUNCTION_POINTER from a census
  resolved_indirect edge; withheld when edges for one slot disagree.

Not extracted (no typed predicate represents them accurately): call-site
relations, bounded effects observations (no MMIO site observed,
input-dependent addresses), and negative assertions.

Candidate identity is "K-" + 12 hex of a digest over the generator
version, claim type, semantics, grade and the content identity (tool,
arguments, canonical result) of the supporting evidence. A historical
result reused by reference and a fresh identical execution therefore
give the same id; session numbering does not enter it.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Collection, Iterable
from dataclasses import dataclass
from types import SimpleNamespace
from typing import Any

from aptrace_agent.ledger.claim_checks import ENTITY_UNKNOWN, PERIPHERAL_UNKNOWN
from aptrace_agent.ledger.claim_semantics import (
    ClaimSemantics,
    FunctionRole,
    FunctionRoleClaim,
    Predicate,
    ResolvedPointer,
    addr,
    extract_facts,
    fun,
    verify_semantics,
)
from aptrace_agent.ledger.hashing import digest
from aptrace_agent.ledger.models import CandidateWithheld, ClaimCandidate, ClaimState, ClaimType, EvidenceGrade
from aptrace_agent.ledger.semantics import canonical_result, evidence_grade, grade_ceiling


GENERATOR = "candidates-v1"
DEFAULT_LIMIT = 5
CANDIDATE_ID_RE = re.compile(r"K-[0-9A-Za-z]+")

ROLE_EXTRACTOR = "peripheral-role"
POINTER_EXTRACTOR = "resolved-pointer"

# Withheld-fact codes (CandidateWithheld.code).
ROLE_CONFLICT = "ROLE_CONFLICT"
POINTER_CONFLICT = "POINTER_CONFLICT"
ACCESS_UNDER_ASSUMPTION = "ACCESS_UNDER_ASSUMPTION"
GRADE_INSUFFICIENT = "GRADE_INSUFFICIENT"
SEMANTICS_UNSUPPORTED = "SEMANTICS_UNSUPPORTED"

# A candidate is a positive fact; bounded and unknown evidence support none.
_FACT_GRADES = (EvidenceGrade.EXACT, EvidenceGrade.STRONG, EvidenceGrade.PROBABLE)
_FUNCTION_RE = re.compile(r"\bFUN_[0-9a-f]{8}\b")
_PERIPHERAL_RE = re.compile(r"\b[A-Z]{2,6}\d{1,2}\b")
_POINTER_FUNCTIONS = ("writer", "registration_caller", "indirect_caller")
_KIND_ORDER = {"MMIO_USER": 0, "RESOLVED_FUNCTION_POINTER": 1, "ADDRESS_CONSTANT_LOADER": 2}
_NOT_SUPPORT = "does not establish this fact and records no conflicting role or pointer fact for it"


@dataclass(frozen=True)
class SeededEvidence:
    """Session evidence of a followed seeded lead (follow-up sessions)."""

    session_id: str
    description: str
    # The function the lead extends from and the lead's own function argument.
    functions: frozenset[str]


@dataclass(frozen=True)
class CandidateSet:
    # Ranked, deduplicated by semantics.
    candidates: tuple[ClaimCandidate, ...]
    withheld: tuple[CandidateWithheld, ...]

    def offer(self, limit: int) -> tuple[tuple[ClaimCandidate, ...], tuple[str, ...]]:
        """(offered, ids omitted by the limit), in rank order."""

        return self.candidates[:limit], tuple(c.candidate_id for c in self.candidates[limit:])

    def find(self, candidate_id: str) -> ClaimCandidate | None:
        return next((c for c in self.candidates if c.candidate_id == candidate_id), None)


@dataclass
class _Draft:
    extractor: str
    subject: str
    claim_type: str
    semantics: ClaimSemantics
    support: list[str]
    assertion: str
    scope: str
    assumptions: list[str]
    limitations: list[str]
    # Non-supporting evidence that limits the fact: session id -> reason.
    limiting: dict[str, str]


def seeded_evidence(session: Any) -> list[SeededEvidence]:
    """Followed seeded leads of a follow-up session; [] for standalone sessions."""

    continuity = getattr(session, "continuity", None)

    if continuity is None:
        return []

    out: list[SeededEvidence] = []

    for lead_id, (_tool, arguments, description) in continuity.seeded.items():
        followed = continuity.followed.get(lead_id)

        if followed is None:
            continue

        functions = {f for f in (continuity.anchors.get(lead_id), arguments.get("function")) if isinstance(f, str)}
        out.append(SeededEvidence(session_id=followed[0], description=description, functions=frozenset(functions)))

    return out


def evidence_identity(tool: str, arguments: dict[str, Any], result: dict[str, Any]) -> str:
    """Content identity of one observation, independent of session numbering."""

    return digest({"tool": tool, "arguments": arguments, "result": canonical_result(tool, result)})


def _graded(observations: Iterable[Any]) -> dict[str, tuple[Any, dict[str, Any]]]:
    out: dict[str, tuple[Any, dict[str, Any]]] = {}

    for observation in observations:
        grade, _basis = evidence_grade(observation.tool, observation.result)

        if grade == EvidenceGrade.UNKNOWN:
            # A failed or ungraded analysis supports nothing.
            continue

        artifact = SimpleNamespace(
            evidence_id=observation.id, tool=observation.tool, arguments=observation.arguments, grade=grade,
            reused_from=getattr(observation, "reused_from", None),
        )
        out[observation.id] = (artifact, observation.result)

    return out


def _census_entry(result: dict[str, Any], function: str) -> dict[str, Any]:
    return next((item for item in result.get("functions", []) if item.get("function") == function), {})


def _parametric_inputs(result: dict[str, Any]) -> list[str]:
    return sorted({i for a in result.get("accesses", []) if a.get("address") == "parametric" for i in a.get("depends_on", [])})


def _mmio_accesses(result: dict[str, Any], peripheral: str | None) -> list[dict[str, Any]]:
    out = []

    for access in result.get("accesses", []):
        register = str(access.get("register_name") or "")
        attributed = register.split(".", 1)[0].upper() or None

        if str(access.get("region") or "").startswith("MMIO") and attributed == peripheral:
            out.append(access)

    return out


def _effects_access_problem(artifact: Any, result: dict[str, Any], peripheral: str | None) -> str | None:
    """Why an effects MMIO access cannot be an unconditional MMIO_USER fact, or None."""

    specialization = artifact.arguments.get("specialize") or result.get("specialize") or result.get("specialized") or {}

    if specialization:
        return (
            f"MMIO access observed only under the analysis specialization {specialization}; "
            "that is a harness assumption, and FUNCTION_ROLE cannot state the condition"
        )

    accesses = _mmio_accesses(result, peripheral)
    concrete = [a for a in accesses if a.get("address") not in (None, "parametric") and not a.get("depends_on")]

    if not concrete:
        inputs = sorted({i for a in accesses for i in a.get("depends_on", [])})
        return f"MMIO access address depends on unresolved input(s) {', '.join(inputs) or 'unknown'}"

    return None


def _effects_limits(function: str, graded: dict[str, tuple[Any, dict[str, Any]]]) -> tuple[dict[str, str], list[str]]:
    """Effects evidence of a function that limits role facts about it: ({id: reason}, limitations)."""

    limiting: dict[str, str] = {}
    texts: list[str] = []

    for evidence_id, (artifact, result) in graded.items():
        if artifact.tool != "function_effects" or str(result.get("function") or artifact.arguments.get("function")) != function:
            continue

        notes = []

        if inputs := _parametric_inputs(result):
            notes.append(
                f"accesses whose addresses depend on {', '.join(inputs)}; their values in reachable callers are not "
                "established, so a register access is neither established nor excluded"
            )

        if result.get("coverage") not in (None, "complete"):
            notes.append(f"coverage is {result.get('coverage')!r}, not complete")

        if notes:
            limiting[evidence_id] = "limits, does not support: function-effects analysis has " + "; ".join(notes)
            texts.append(f"The function-effects analysis of {function} has " + "; ".join(notes) + ".")

    return limiting, texts


def _peripheral_roles(facts: Any, graded: dict[str, tuple[Any, dict[str, Any]]], withheld: list[CandidateWithheld]) -> list[_Draft]:
    roles = (FunctionRole.MMIO_USER, FunctionRole.ADDRESS_CONSTANT_LOADER)
    groups: dict[tuple[int, str | None], dict[FunctionRole, set[str]]] = {}

    for fact in facts.roles:
        if fact.role in roles:
            groups.setdefault((fact.entry, fact.peripheral), {}).setdefault(fact.role, set()).add(fact.evidence_id)

    # MMIO accesses no peripheral was attributed to may be accesses of any.
    unattributed = {entry: found.get(FunctionRole.MMIO_USER, set()) for (entry, peripheral), found in groups.items() if peripheral is None}
    drafts: list[_Draft] = []

    for (entry, peripheral), found in sorted(groups.items(), key=lambda item: (item[0][0], item[0][1] or "")):
        function = fun(entry)
        access_ids = sorted(found.get(FunctionRole.MMIO_USER, set()))
        qualified: list[str] = []

        for evidence_id in access_ids:
            artifact, result = graded[evidence_id]
            problem = _effects_access_problem(artifact, result, peripheral) if artifact.tool == "function_effects" else None

            if problem is None:
                qualified.append(evidence_id)
            else:
                withheld.append(
                    CandidateWithheld(code=ACCESS_UNDER_ASSUMPTION, fact=f"{function} MMIO_USER {peripheral or 'MMIO'}", detail=problem, evidence_ids=[evidence_id])
                )

        if qualified:
            drafts.append(_access_draft(function, peripheral, qualified, graded))

        loaders = sorted(found.get(FunctionRole.ADDRESS_CONSTANT_LOADER, set()))

        if not loaders or peripheral is None:
            continue

        conflicting = sorted(set(access_ids) | (unattributed.get(entry, set()) if peripheral is not None else set()))

        if conflicting:
            withheld.append(
                CandidateWithheld(
                    code=ROLE_CONFLICT,
                    fact=f"{function} ADDRESS_CONSTANT_LOADER {peripheral}",
                    detail=(
                        f"the census lists {function} for {peripheral} address constants only, but other evidence records an "
                        "MMIO access in it; an address-constant-loader fact would misstate that"
                    ),
                    evidence_ids=loaders + conflicting,
                )
            )
            continue

        drafts.append(_loader_draft(function, peripheral, loaders, graded))

    return drafts


def _access_draft(function: str, peripheral: str | None, support: list[str], graded: dict[str, tuple[Any, dict[str, Any]]]) -> _Draft:
    details: list[str] = []
    sources: list[str] = []
    assumptions: list[str] = []
    limitations = [
        f"A register access site is structural: it does not show which executions reach it, how often, or which values {function} "
        "reads or writes."
    ]

    for evidence_id in support:
        artifact, result = graded[evidence_id]

        if artifact.tool == "census_peripheral_usage":
            sites = sorted({f"{s.get('direction', 'access').lower()} {s.get('address')}" for s in _census_entry(result, function).get("mmio_sites", [])})
            details.append("census constant-address MMIO site(s): " + (", ".join(sites[:4]) or "listed"))
            sources.append("static census references (Ghidra reference manager), heuristic function boundaries")
        elif artifact.tool == "census_usb_inventory":
            details.append("USB interface inventory register user")
            sources.append("static census USB interface inventory, heuristic function boundaries")
        elif artifact.tool == "function_effects":
            accesses = [a for a in _mmio_accesses(result, peripheral) if a.get("address") != "parametric" and not a.get("depends_on")]
            shown = sorted({f"{a.get('kind', 'access')} {a.get('address')}" for a in accesses})
            details.append("function-effects access(es): " + ", ".join(shown[:4]))
            sources.append("symbolic function-effects analysis without argument specialization (Macaw/Crucible), not solver-confirmed")
            assumptions += [str(x) for x in result.get("harness_assumptions", [])]

            if any(a.get("guard") not in (None, "always-true") for a in accesses):
                limitations.append("Some observed accesses are conditional on input-derived guards.")

    target = f"{peripheral} registers" if peripheral else "MMIO registers no peripheral was attributed to"
    return _Draft(
        extractor=ROLE_EXTRACTOR,
        subject=function,
        claim_type=ClaimType.BEHAVIOR.value,
        semantics=ClaimSemantics(
            predicate=Predicate.FUNCTION_ROLE,
            function_role=FunctionRoleClaim(function=function, role=FunctionRole.MMIO_USER, peripheral=peripheral),
        ),
        support=support,
        assertion=f"{function} accesses {target} ({'; '.join(details)}).",
        scope="; ".join(dict.fromkeys(sources)),
        assumptions=list(dict.fromkeys(assumptions)),
        limitations=limitations,
        limiting={},
    )


def _loader_draft(function: str, peripheral: str, support: list[str], graded: dict[str, tuple[Any, dict[str, Any]]]) -> _Draft:
    values: set[str] = set()

    for evidence_id in support:
        _artifact, result = graded[evidence_id]
        values |= {str(load.get("value")) for load in _census_entry(result, function).get("constant_loads", []) if load.get("value")}

    limiting, effect_limits = _effects_limits(function, graded)
    shown = ", ".join(sorted(values)[:4]) or "its base address"
    return _Draft(
        extractor=ROLE_EXTRACTOR,
        subject=function,
        claim_type=ClaimType.STRUCTURE.value,
        semantics=ClaimSemantics(
            predicate=Predicate.FUNCTION_ROLE,
            function_role=FunctionRoleClaim(function=function, role=FunctionRole.ADDRESS_CONSTANT_LOADER, peripheral=peripheral),
        ),
        support=support,
        assertion=(
            f"{function} loads {peripheral} address constant {shown} from its literal pool; the census records no "
            "constant-address MMIO site in it. Loading an address is not a register access."
        ),
        scope=f"census_peripheral_usage static analysis of {peripheral} (Ghidra references and flash-word scan); heuristic function boundaries",
        assumptions=[],
        limitations=[
            f"Does not establish or exclude a {peripheral} register access by {function}: the census does not attribute accesses "
            "through a base-address register to a peripheral.",
            *effect_limits,
        ],
        limiting=limiting,
    )


def _resolved_pointers(facts: Any, withheld: list[CandidateWithheld]) -> list[_Draft]:
    by_slot: dict[int, list[Any]] = {}

    for fact in facts.pointers:
        if "slot" in fact.values:
            by_slot.setdefault(fact.values["slot"], []).append(fact)

    drafts: list[_Draft] = []

    for slot, found in sorted(by_slot.items()):
        merged: dict[str, int] = {}
        conflict: list[str] = []

        for fact in found:
            for name, value in fact.values.items():
                if merged.setdefault(name, value) != value:
                    conflict.append(name)

        support = sorted({f.evidence_id for f in found} | {source for f in found for source in f.sources.values()})

        if conflict:
            withheld.append(
                CandidateWithheld(
                    code=POINTER_CONFLICT, fact=f"RESOLVED_FUNCTION_POINTER slot {addr(slot)}",
                    detail=f"supporting edges disagree on {', '.join(sorted(set(conflict)))}", evidence_ids=support,
                )
            )
            continue

        fields = {name: (fun(value) if name in _POINTER_FUNCTIONS else addr(value)) for name, value in merged.items()}
        pointer = ResolvedPointer(**fields)
        parts = [f"RAM function-pointer slot {pointer.slot} resolves to {pointer.canonical_target or 'an unrecorded target'}"]

        if pointer.raw_pointer:
            parts.append(f"(raw pointer {pointer.raw_pointer})")
        if pointer.writer:
            parts.append(f"written by {pointer.writer}" + (f" at {pointer.writer_instruction}" if pointer.writer_instruction else ""))
        if pointer.registration_callsite:
            parts.append(f"via the call at {pointer.registration_callsite}" + (f" in {pointer.registration_caller}" if pointer.registration_caller else ""))

        text = " ".join(parts) + "."

        if pointer.indirect_site:
            text += f" The indirect transfer at {pointer.indirect_site}" + (f" in {pointer.indirect_caller}" if pointer.indirect_caller else "") + " loads it."
        if pointer.forwarding_target:
            text += f" The target forwards to {pointer.forwarding_target}."

        drafts.append(
            _Draft(
                extractor=POINTER_EXTRACTOR,
                subject=pointer.slot,
                claim_type=ClaimType.RESOLUTION.value,
                semantics=ClaimSemantics(predicate=Predicate.RESOLVED_FUNCTION_POINTER, resolved_pointer=pointer),
                support=support,
                assertion=text,
                scope="census resolved_indirect edge (static); stores through computed pointers are not excluded",
                assumptions=[],
                limitations=[],
                limiting={},
            )
        )

    return drafts


def _withhold(draft: _Draft, code: str, detail: str, evidence_ids: list[str]) -> CandidateWithheld:
    return CandidateWithheld(code=code, fact=draft.semantics.summary(), detail=detail, evidence_ids=evidence_ids)


def generate_candidates(
    observations: Iterable[Any],
    *,
    objective: str = "",
    seeded: Iterable[SeededEvidence] = (),
    function_exists: Callable[[str], bool] | None = None,
    peripherals: Collection[str] | None = None,
    existing: Callable[[ClaimSemantics], list[str]] | None = None,
) -> CandidateSet:
    """
    Ranked claim candidates from observations (objects with id, tool,
    arguments, result and optional reused_from). Pure: no ledger access
    except through the optional existing-claim lookup, which only reads.
    """

    observations = list(observations)
    by_id = {o.id: o for o in observations}
    graded = _graded(observations)
    facts = extract_facts(list(graded.values()))
    withheld: list[CandidateWithheld] = []
    drafts = _peripheral_roles(facts, graded, withheld) + _resolved_pointers(facts, withheld)
    seeded = list(seeded)
    known = None if peripherals is None else {p.upper() for p in peripherals}
    out: dict[str, ClaimCandidate] = {}

    for draft in drafts:
        support = [e for e in draft.support if e in graded and graded[e][0].grade in _FACT_GRADES]
        pairs = [graded[e] for e in support]
        named = list(dict.fromkeys(_FUNCTION_RE.findall(draft.assertion)))

        if not support:
            withheld.append(_withhold(draft, GRADE_INSUFFICIENT, "no supporting evidence of grade PROBABLE or stronger", draft.support))
            continue

        unknown = [name for name in named if function_exists is not None and not function_exists(name)]

        if unknown:
            withheld.append(_withhold(draft, ENTITY_UNKNOWN, f"not a known function of this firmware: {', '.join(unknown)}", support))
            continue

        unknown = [p for p in dict.fromkeys(_PERIPHERAL_RE.findall(draft.assertion)) if known is not None and p not in known]

        if unknown:
            withheld.append(_withhold(draft, PERIPHERAL_UNKNOWN, f"not a known peripheral: {', '.join(unknown)}", support))
            continue

        grade = grade_ceiling(ClaimType(draft.claim_type), [a for a, _ in pairs])

        if grade not in _FACT_GRADES:
            withheld.append(_withhold(draft, GRADE_INSUFFICIENT, f"supporting evidence permits at most {grade.value}", support))
            continue

        failed = [c for c in verify_semantics(draft.semantics, draft.claim_type, pairs) if not c.passed]

        if failed:
            # Defensive: an extractor must never offer what the verifier rejects.
            withheld.append(_withhold(draft, SEMANTICS_UNSUPPORTED, "; ".join(f"{c.code.value}: {c.detail}" for c in failed), support))
            continue

        considered = {e: reason for e, reason in draft.limiting.items() if e not in support}

        for item in seeded:
            if item.functions & set(named) and item.session_id not in support and item.session_id not in considered and item.session_id in by_id:
                considered[item.session_id] = f"{by_id[item.session_id].tool} evidence {_NOT_SUPPORT}"

        key = draft.semantics.model_dump_json()

        if key in out:
            continue

        candidate_id = "K-" + digest(
            {
                "generator": GENERATOR,
                "claim_type": draft.claim_type,
                "semantics": draft.semantics.model_dump(mode="json"),
                "grade": grade.value,
                "evidence": sorted(evidence_identity(by_id[e].tool, by_id[e].arguments, by_id[e].result) for e in support),
            }
        )[:12]
        out[key] = ClaimCandidate(
            candidate_id=candidate_id,
            extractor=draft.extractor,
            subject=draft.subject,
            claim_type=draft.claim_type,
            semantics=draft.semantics,
            grade=grade.value,
            assertion=draft.assertion,
            scope=draft.scope,
            assumptions=draft.assumptions,
            limitations=draft.limitations,
            supporting_evidence_ids=support,
            prior_evidence_ids=[r for e in support if (r := getattr(by_id[e], "reused_from", None))],
            considered=dict(sorted(considered.items(), key=lambda kv: _session_order(kv[0]))),
            seeded_leads=[s.description for s in seeded if s.session_id in support or s.session_id in considered],
            existing_claims=list(existing(draft.semantics)) if existing is not None else [],
        )

    return CandidateSet(candidates=tuple(sorted(out.values(), key=_ranker(objective))), withheld=tuple(withheld))


def _session_order(evidence_id: str) -> tuple[int, str]:
    return (int(evidence_id[1:]), evidence_id) if evidence_id[1:].isdigit() else (1 << 30, evidence_id)


def _ranker(objective: str) -> Callable[[ClaimCandidate], tuple]:
    """Deterministic relevance order: objective entities, seeded leads, novelty, kind, id."""

    functions = set(_FUNCTION_RE.findall(objective))
    peripherals = set(_PERIPHERAL_RE.findall(objective.upper()))

    def rank(candidate: ClaimCandidate) -> tuple:
        role = candidate.semantics.function_role
        kind = role.role.value if role is not None else candidate.semantics.predicate.value
        return (
            0 if set(_FUNCTION_RE.findall(candidate.assertion)) & functions else 1,
            0 if role is not None and role.peripheral in peripherals else 1,
            0 if candidate.seeded_leads else 1,
            1 if candidate.existing_claims else 0,
            _KIND_ORDER.get(kind, 9),
            candidate.candidate_id,
        )

    return rank


def equivalent_claims(ledger: Any, semantics: ClaimSemantics | dict[str, Any] | None) -> list[tuple[str, str]]:
    """
    (key, state) of existing claim versions with identical typed semantics,
    except SUPERSEDED ones. Typed semantics are what verification checks,
    so two claims with equal semantics assert the same fact. Read only.
    """

    if semantics is None:
        return []

    if isinstance(semantics, dict):
        semantics = ClaimSemantics.model_validate(semantics)

    out: list[tuple[str, str]] = []

    for claim in ledger.all_claim_versions():
        if claim.semantics != semantics:
            continue

        state = ledger.state(claim.key)

        if state != ClaimState.SUPERSEDED:
            out.append((claim.key, state.value))

    return out


def candidates_for_run(
    ledger: Any,
    run_id: str,
    *,
    function_exists: Callable[[str], bool] | None = None,
    peripherals: Collection[str] | None = None,
) -> CandidateSet:
    """
    Read-only preview: candidates from a recorded run's evidence (its own
    and the historical evidence it reused by reference), named by durable
    id. Invalidated or tampered evidence is skipped. Writes nothing.
    """

    from aptrace_agent.ledger.store import EVIDENCE_VALID

    run = ledger.run(run_id)
    reused = [r.evidence_id for r in run.continuity.reused] if run.continuity else []
    observations = []

    for evidence_id in dict.fromkeys([*reused, *run.evidence_ids]):
        if not ledger.has_evidence(evidence_id) or ledger.evidence_state(evidence_id) != EVIDENCE_VALID:
            continue

        artifact = ledger.evidence(evidence_id)

        if not ledger.has_blob(artifact.result_sha256):
            continue

        result, intact = ledger.load_blob(artifact.result_sha256)

        if intact and isinstance(result, dict):
            observations.append(SimpleNamespace(id=evidence_id, tool=artifact.tool, arguments=artifact.arguments, result=result, reused_from=None))

    return generate_candidates(
        observations, objective=run.objective, function_exists=function_exists, peripherals=peripherals,
        existing=lambda semantics: [f"{key} {state}" for key, state in equivalent_claims(ledger, semantics)],
    )


def proposal_for(candidate: ClaimCandidate) -> dict[str, Any]:
    """The admission proposal of a selected candidate, built only from the candidate record."""

    return {
        "subject": candidate.subject,
        "assertion": candidate.assertion,
        "claim_type": candidate.claim_type,
        "grade": candidate.grade,
        "evidence_ids": list(candidate.supporting_evidence_ids),
        "semantics": candidate.semantics.model_dump(mode="json"),
        "omissions": dict(candidate.considered),
        "limitations": list(candidate.limitations),
        "scope": candidate.scope,
        "assumptions": list(candidate.assumptions),
        "candidate_id": candidate.candidate_id,
        "derivation": f"claim candidate {candidate.candidate_id} ({candidate.extractor}, {GENERATOR}), selected by the planner",
        "raw": f"select {candidate.candidate_id}",
    }


def render(offered: Iterable[ClaimCandidate], omitted: int = 0, width: int = 260) -> str:
    """Bounded candidate list for the planner: id, grade, type and generated text."""

    lines = []

    for candidate in offered:
        text = candidate.assertion if len(candidate.assertion) <= width else candidate.assertion[: width - 3] + "..."
        # A plain sentence: with a bracketed or comma-separated annotation the
        # local runtime rejected the planner's tool call (incomplete_tool_call)
        # in measured replays.
        recorded = "".join(f" Already recorded as claim {key} in state {state}." for key, _, state in (e.partition(" ") for e in candidate.existing_claims))
        lines.append(f"{candidate.candidate_id} {candidate.grade} {candidate.claim_type}: {text}{recorded}")

    if omitted:
        lines.append(f"({omitted} lower-ranked candidate(s) not shown)")

    return "\n".join(lines)


def parse_selection(text: Any, offered: Collection[str]) -> tuple[list[str], list[str]]:
    """
    (selected offered ids in order, invalid tokens). Only K- tokens are
    read; each must be an offered id exactly. Nothing is reinterpreted.
    """

    if not isinstance(text, str):
        return [], ([str(text)[:80]] if text not in (None, "", []) else [])

    selected: list[str] = []
    invalid: list[str] = []

    for token in CANDIDATE_ID_RE.findall(text):
        if token in offered:
            if token not in selected:
                selected.append(token)
        elif token not in invalid:
            invalid.append(token)

    stripped = text.strip().strip(".").lower()

    if not selected and not invalid and stripped not in ("", "none", "no", "n/a"):
        invalid.append(text.strip()[:80])

    return selected, invalid


__all__ = [
    "ACCESS_UNDER_ASSUMPTION",
    "CandidateSet",
    "DEFAULT_LIMIT",
    "GENERATOR",
    "GRADE_INSUFFICIENT",
    "POINTER_CONFLICT",
    "ROLE_CONFLICT",
    "SEMANTICS_UNSUPPORTED",
    "SeededEvidence",
    "candidates_for_run",
    "equivalent_claims",
    "evidence_identity",
    "generate_candidates",
    "parse_selection",
    "proposal_for",
    "render",
    "seeded_evidence",
]
