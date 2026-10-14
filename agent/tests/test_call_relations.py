"""
Call-relation admission (ledger/call_relations.py): asserted calls,
dispatches, reachability and call absence must be supported by cited edges
at the asserted kind and scope, for prose and typed CALL_RELATION claims
alike.

Synthetic firmware: S calls T directly at 0x5010 and tail-branches to U at
0x5040; S's indirect site 0x5020 can reach V only if the receiver's vptr is
0x00020000 (W if it is 0x00020100); R's indirect site 0x9010 is unresolved.
The exact indirect-dispatch trial failure is replayed against its recorded
evidence in cases/performing-rigs/test/test_call_admission.py.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from aptrace_agent.ledger.call_relations import call_diagnostics, extract_call_facts, parse_assertions
from aptrace_agent.ledger.claim_semantics import CallEdgeKind, ClaimSemantics, SemanticCheck
from aptrace_agent.ledger.models import ClaimState, ClaimType, VerificationRecord
from aptrace_agent.ledger.policy import ClaimClass, claim_class
from aptrace_agent.ledger.store import ResearchLedger
from aptrace_agent.ledger.verifier import ClaimVerifier
from aptrace_agent.research import LeadFollower, LeadRegistry, ResearchSession
from aptrace_agent.research.admission import admit
from aptrace_agent.research.candidates import generate_candidates, proposal_for
from aptrace_agent.schemas import EvidenceObservation

from ledger_support import FakeExecutor
from test_claim_quality import codes, first_new_evidence, follow_up, usb_session
from test_continuity import Planner
from test_followups import CALLERS, GAP, world  # noqa: F401  (world is a fixture)


S, T, U, V, W, R, X = (f"FUN_{a:08x}" for a in (0x5000, 0x6000, 0x7000, 0x8000, 0x8100, 0x9000, 0xA000))
VTABLE_V, VTABLE_W = "0x00020000", "0x00020100"


def facts(name, callers=(), callees=(), truncated=False):
    return {
        "name": name, "entry": "0x" + name[4:],
        "callers": [{"function": f, "address": a} for f, a in callers], "callers_truncated": truncated,
        "callees": [{"function": f, "address": a} for f, a in callees], "callees_truncated": False,
    }


def disassembly():
    """S: bl T at 0x5010, an internal beq, blx r3 at 0x5020, a tail b.w to U at 0x5040 (S is 0x48 bytes)."""

    rows = [("0x00005010", "bl", "#0x6000"), ("0x00005014", "beq", "#0x5030"), ("0x00005020", "blx", "r3"), ("0x00005040", "b.w", "#0x7000")]
    return {
        "entry": "0x00005000", "bytes_decoded": 0x48, "bytes_requested": 0x48, "complete": True,
        "instructions": [{"address": a, "mnemonic": m, "operands": o, "size": 4} for a, m, o in rows],
    }


def indirect(site="0x00005020", containing="0x00005000", status="CONDITIONALLY_POSSIBLE", derivation="ESTABLISHED", targets=((V, VTABLE_V), (W, VTABLE_W))):
    return {
        "status": "ok", "site": site, "containing_function": containing, "instruction": "blx r3",
        "resolution_status": status, "derivation_status": derivation, "patterns": [{"pattern": "vtable-slot", "slot_offset": 0}],
        "candidate_targets": [
            {"target": "0x" + t[4:], "is_code_pointer": True, "vtable": v, "entry_addr": v, "basis": f"word at vtable {v} + 0x0, IF the receiver's vptr is {v}"}
            for t, v in targets
        ],
    }


def observed(scenario="boot", kind="BLX_REG"):
    """V entered in `scenario` from the indirect site 0x5020 (dynamic only: no static call site, so no caller)."""

    return {
        "status": "ok", "function": V, "entry": "0x00008000", "scenario": scenario, "observed_entries": 3,
        "call_sites": [{"call_site": "0x00005020", "caller": None, "status": "DYNAMIC_ONLY", "call_kind": kind, "hits": 3}],
    }


EVIDENCE = {
    "facts_T": ("function_facts", {"function": T}, facts(T, callers=[(S, "0x00005010")])),
    "facts_S": ("function_facts", {"function": S}, facts(S, callers=[(X, "0x0000a010")], callees=[(T, "0x00005010")])),
    "facts_V": ("function_facts", {"function": V}, facts(V)),
    "disasm_S": ("function_disassembly", {"function": S}, disassembly()),
    "indirect_S": ("indirect_call_target", {"site": "0x00005020"}, indirect()),
    "indirect_S_fixed": ("indirect_call_target", {"site": "0x00005020"}, indirect(status="STATICALLY_ESTABLISHED", targets=((V, VTABLE_V),))),
    "unresolved_R": ("indirect_call_target", {"site": "0x00009010"}, indirect(site="0x00009010", containing="0x00009000", status="UNRESOLVED", derivation="UNKNOWN", targets=())),
    "observed_V": ("observed_call_arguments", {"function": V, "scenario": "boot"}, observed()),
}


def session(*names):
    registry = LeadRegistry()
    s = ResearchSession(objective="calls", registry=registry, follower=LeadFollower(registry=registry, executor=FakeExecutor()))

    for number, name in enumerate(names, 1):
        tool, arguments, result = EVIDENCE[name]
        s.record(EvidenceObservation(id=f"E{number}", tool=tool, arguments=arguments, result=result))

    return s


KNOWN = {S, T, U, V, W, R, X}


def claim(text, *names, cite=None, grade="PROBABLE", claim_type="STRUCTURE", semantics=None):
    s = session(*names)
    ids = cite or [f"E{n}" for n in range(1, len(names) + 1)]
    proposal = {"subject": "", "assertion": text, "grade": grade, "claim_type": claim_type, "evidence_ids": ids, "semantics": semantics}
    return admit(proposal, s, round=1, function_exists=lambda name: name in KNOWN)


def call_codes(record, severity="reject"):
    return {c for c in codes(record, severity) if c.startswith("CALL_")}


# -- 1. the trial failure shape ----------------------------------------------------------


def test_01_target_named_without_an_edge_is_rejected():
    # The trial shape: one result shows S calling T; another lists no callers of V.
    record = claim(f"{V} is called by {S}", "facts_T", "facts_V")

    assert record.decision == "rejected"
    assert call_codes(record) == {"CALL_RELATION_UNSUPPORTED"}
    diag = next(d for d in record.diagnostics if d.code == "CALL_RELATION_UNSUPPORTED")
    assert diag.value == f"{S} -> {V}" and diag.basis == "pattern-matched"
    assert f"E2 lists no callers of {V}" in diag.detail and f"E1: {S} -> 0x00006000 at 0x00005010 DIRECT_CALL" in diag.detail
    # Verbatim retention for the correction round and the run record.
    assert record.assertion == f"{V} is called by {S}" and record.evidence_ids == ["E1", "E2"]


def test_01_a_disjunction_needs_every_target_supported():
    record = claim(f"{S} can call {T} or {V}", "facts_T", "facts_V")

    assert record.decision == "rejected"
    assert {d.value for d in record.diagnostics if d.code == "CALL_RELATION_CHECKED"} == {f"{S} -> {T}"}
    assert {d.value for d in record.diagnostics if d.code == "CALL_RELATION_UNSUPPORTED"} == {f"{S} -> {V}"}


def test_01_the_check_is_general_not_address_specific():
    # The same shape over another pair is rejected by the same rule.
    record = claim(f"{U} is called by {X}", "facts_T", "facts_V")
    assert call_codes(record) == {"CALL_RELATION_UNSUPPORTED"}


# -- 2/3. direct and tail transfers -------------------------------------------------------


@pytest.mark.parametrize("text", [f"{S} calls {T}", f"{T} is called by {S}", f"{S} calls {T} at 0x00005010", f"{S} invokes {T}"])
def test_02_direct_call_is_admitted(text):
    for evidence in ("facts_T", "disasm_S"):
        record = claim(text, evidence)
        assert record.decision == "admitted", (evidence, record.diagnostics)
        assert call_codes(record, "note") == {"CALL_RELATION_CHECKED"}


def test_03_tail_transfer_is_admitted_from_decoded_branches_only():
    record = claim(f"{S} tail-calls {U} at 0x00005040", "disasm_S")
    assert record.decision == "admitted", record.diagnostics

    # The internal beq to 0x5030 is not a transfer to another function.
    facts_ = extract_call_facts([(_artifact("E1", "function_disassembly"), disassembly())])
    assert {(e.target, e.kind) for e in facts_.edges} == {(0x6000, CallEdgeKind.DIRECT_CALL), (0x7000, CallEdgeKind.TAIL_TRANSFER)}

    # Typed: the kind matters.
    tail = {"predicate": "CALL_RELATION", "call": {"source": S, "target": U, "kind": "TAIL_TRANSFER", "site": "0x5040"}}
    as_bl = {"predicate": "CALL_RELATION", "call": {"source": S, "target": U, "kind": "DIRECT_CALL"}}
    assert claim("typed tail", "disasm_S", grade="EXACT", semantics=tail).decision == "admitted"
    wrong = claim("typed tail", "disasm_S", grade="EXACT", semantics=as_bl)
    assert wrong.decision == "rejected" and codes(wrong) == {"CALL_KIND_MISMATCH"}


# -- 4/5/6. vtable entries and conditional targets ----------------------------------------


def test_04_vtable_entry_is_not_a_call_or_reachability():
    # V is a table entry the site can load; that is not a call, and does not make V reachable.
    vtable_only = claim(f"{S} dispatches to {V} through vtable {VTABLE_V}", "indirect_S")
    assert call_codes(vtable_only) == {"CALL_CONDITION_OMITTED"}
    assert "a potential target is not a dispatch" in next(d.detail for d in vtable_only.diagnostics if d.severity == "reject")

    reachable = claim(f"{V} is reachable", "indirect_S")
    assert call_codes(reachable) == {"CALL_REACHABILITY_UNSUPPORTED"}

    # A function only named in a result (V in facts_V) is not an edge either.
    named = claim(f"{S} calls {V}", "facts_V")
    assert call_codes(named) == {"CALL_RELATION_UNSUPPORTED"}


@pytest.mark.parametrize(
    "text",
    [
        f"{S} may call {V} if the receiver's vptr is {VTABLE_V}",
        f"{S}'s indirect call at 0x00005020 can dispatch to {V} when the receiver holds vtable {VTABLE_V}",
        f"{V} is a potential target of the indirect call at 0x00005020 in {S}, if the receiver's vptr is {VTABLE_V}",
    ],
)
def test_05_conditional_target_with_its_condition_is_admitted(text):
    record = claim(text, "indirect_S")
    assert record.decision == "admitted", record.diagnostics
    note = next(d for d in record.diagnostics if d.code == "CALL_RELATION_CHECKED")
    assert "POTENTIAL_INDIRECT" in note.detail and VTABLE_V in note.detail


@pytest.mark.parametrize(
    "text",
    [
        f"{S} calls {V}",  # categorical
        f"{S} can call {V}",  # possible, condition dropped
        f"{S} may call {V} if the receiver's vptr is {VTABLE_W}",  # the other vtable's condition
    ],
)
def test_06_unconditional_claim_from_conditional_evidence_is_rejected(text):
    record = claim(text, "indirect_S")
    assert record.decision == "rejected"
    assert call_codes(record) == {"CALL_CONDITION_OMITTED"}
    assert VTABLE_V in next(d.detail for d in record.diagnostics if d.code == "CALL_CONDITION_OMITTED")


def test_06_an_established_indirect_target_needs_no_condition_and_no_rewrite():
    assert claim(f"{S} calls {V} at 0x00005020", "indirect_S_fixed").decision == "admitted"
    # Nothing is rewritten: the rejected categorical proposal keeps its text.
    rejected = claim(f"{S} calls {V}", "indirect_S")
    assert rejected.assertion == f"{S} calls {V}" and rejected.decision == "rejected"


def test_06_typed_potential_needs_conditions_and_its_grade():
    potential = {"predicate": "CALL_RELATION", "call": {"source": S, "target": V, "kind": "POTENTIAL_INDIRECT", "site": "0x5020", "conditions": [f"receiver vptr {VTABLE_V}"]}}
    assert claim("typed", "indirect_S", semantics=potential, claim_type="RESOLUTION").decision == "admitted"

    bare = {"predicate": "CALL_RELATION", "call": {"source": S, "target": V, "kind": "POTENTIAL_INDIRECT"}}
    assert codes(claim("typed", "indirect_S", semantics=bare, claim_type="RESOLUTION")) == {"SEMANTICS_INVALID"}

    established = {"predicate": "CALL_RELATION", "call": {"source": S, "target": V, "kind": "ESTABLISHED_INDIRECT"}}
    assert codes(claim("typed", "indirect_S", semantics=established, claim_type="RESOLUTION")) == {"CALL_CONDITION_OMITTED"}

    # A potential edge rests on PROBABLE evidence; other STRONG citations do not lift it.
    strong = claim("typed", "indirect_S", "facts_T", semantics=potential, claim_type="RESOLUTION", grade="STRONG")
    assert codes(strong) == {"GRADE_ABOVE_CEILING"}


# -- 7/8. observed dispatch --------------------------------------------------------------


def test_07_observed_dispatch_with_its_scenario_is_admitted():
    # The observation has no static caller; the disassembly places 0x5020 in S.
    record = claim(f"{S} was observed dispatching to {V} at 0x00005020 during the boot scenario", "observed_V", "disasm_S")
    assert record.decision == "admitted", record.diagnostics
    unattributed = claim(f"{S} was observed dispatching to {V} during the boot scenario", "observed_V")
    assert call_codes(unattributed) == {"CALL_RELATION_UNSUPPORTED"}
    assert "OBSERVED_DISPATCH" in next(d.detail for d in record.diagnostics if d.code == "CALL_RELATION_CHECKED")

    typed = {"predicate": "CALL_RELATION", "call": {"source": S, "target": V, "kind": "OBSERVED_DISPATCH", "scenario": "boot"}}
    assert claim("typed", "observed_V", "disasm_S", semantics=typed, claim_type="BEHAVIOR", grade="STRONG").decision == "admitted"
    other = {"predicate": "CALL_RELATION", "call": {"source": S, "target": V, "kind": "OBSERVED_DISPATCH", "scenario": "usb-link"}}
    assert codes(claim("typed", "observed_V", "disasm_S", semantics=other, claim_type="BEHAVIOR")) == {"CALL_SCOPE_EXCEEDED"}


@pytest.mark.parametrize(
    "text, code",
    [
        (f"{S} calls {V}", "CALL_SCOPE_EXCEEDED"),  # one scenario generalized to a static edge
        (f"{S} always calls {V}", "CALL_SCOPE_EXCEEDED"),  # every execution
        (f"{S} was observed calling {V} during the usb-link scenario", "CALL_SCOPE_EXCEEDED"),  # another scenario
        (f"{S} was observed calling {T} during boot", "CALL_RELATION_UNSUPPORTED"),  # a static edge is no observation
    ],
)
def test_08_observation_generalized_is_rejected(text, code):
    record = claim(text, "observed_V", "disasm_S")
    assert record.decision == "rejected"
    assert call_codes(record) == {code}


def test_08_static_edges_never_support_every_execution():
    assert call_codes(claim(f"{S} calls {T} on every execution", "facts_T")) == {"CALL_SCOPE_EXCEEDED"}


# -- 9/10/11/12. mismatches and unresolved targets ----------------------------------------


def test_09_source_mismatch():
    record = claim(f"{X} calls {T}", "facts_T")
    assert call_codes(record) == {"CALL_SOURCE_MISMATCH"}
    assert f"{S} -> 0x00006000" in next(d.detail for d in record.diagnostics if d.code == "CALL_SOURCE_MISMATCH")


def test_10_target_mismatch():
    # The named site goes elsewhere.
    assert call_codes(claim(f"{S} calls {V} at 0x00005010", "disasm_S")) == {"CALL_TARGET_MISMATCH"}
    # S does reach U, at another site: the site is what is wrong.
    assert call_codes(claim(f"{S} calls {U} at 0x00005010", "disasm_S")) == {"CALL_SITE_MISMATCH"}
    # The cited evidence enumerates S's direct calls and the target is not among them.
    assert call_codes(claim(f"{S} calls {W}", "facts_S")) == {"CALL_TARGET_MISMATCH"}


def test_11_call_site_mismatch():
    record = claim(f"{S} calls {T} at 0x00005040", "facts_T")
    assert call_codes(record) == {"CALL_SITE_MISMATCH"}


def test_12_unresolved_target_is_undetermined_not_established():
    record = claim(f"{R} calls {T}", "unresolved_R")
    assert call_codes(record) == {"CALL_TARGET_UNRESOLVED"}
    assert call_codes(claim(f"{R} calls {T} at 0x00009010", "unresolved_R")) == {"CALL_TARGET_UNRESOLVED"}


# -- 13. absence ----------------------------------------------------------------------


def test_13_incomplete_callgraph_cannot_prove_absence():
    assert call_codes(claim(f"{V} has no callers", "facts_V")) == {"CALL_ABSENCE_NOT_ESTABLISHED"}
    assert call_codes(claim(f"{S} never calls {V}", "facts_S", "unresolved_R")) == {"CALL_ABSENCE_NOT_ESTABLISHED"}
    # Contradicted absence.
    assert call_codes(claim(f"{S} does not call {T}", "facts_T")) == {"CALL_ABSENCE_NOT_ESTABLISHED"}

    scoped = claim(f"{V} has no recorded callers in the cited call graph", "facts_V")
    assert scoped.decision == "admitted" and call_codes(scoped, "note") == {"CALL_ABSENCE_SCOPED"}


# -- 14/15. unrelated claims and scoped hypotheses ------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        f"{T} reads the callback pointer its caller passes in r0.",
        f"The caller list of {T} has one entry.",
        f"{S} stores a callback address into RAM; the call sites were not examined.",
        f"{T} returns to its caller after 4 instructions.",
    ],
)
def test_14_unrelated_text_with_call_words_is_not_a_call_claim(text):
    record = claim(text, "facts_T")
    assert record.decision == "admitted", record.diagnostics
    assert not call_codes(record) and not call_codes(record, "note")


@pytest.mark.parametrize(
    "text",
    [
        f"Whether {S} calls {V} is not established by the cited analysis.",
        f"{S} may reach {V} if the receiver's vptr is {VTABLE_V}; no entry into that dispatch is established.",
        f"If {S} runs, it calls {T} at 0x00005010.",
    ],
)
def test_15_legitimate_scoped_hypotheses_are_admitted(text):
    record = claim(text, "indirect_S", "facts_T")
    assert record.decision == "admitted", record.diagnostics


def test_15_reachability_needs_a_cited_path_from_a_stated_root():
    assert claim(f"{X} reaches {T}", "facts_S", "facts_T").decision == "admitted"
    assert call_codes(claim(f"{X} reaches {V}", "facts_S", "indirect_S")) == {"CALL_REACHABILITY_UNSUPPORTED"}
    assert claim(f"{X} can reach {V} if the receiver's vptr is {VTABLE_V}", "facts_S", "indirect_S").decision == "admitted"
    # A function concretely entered in a named scenario; without the scenario, no root is stated.
    assert claim(f"{V} is reached during the boot scenario", "observed_V").decision == "admitted"
    assert claim(f"{V} is reachable in the boot scenario", "observed_V").decision == "admitted"
    unscoped = claim(f"{V} is reachable", "observed_V")
    assert call_codes(unscoped) == {"CALL_REACHABILITY_UNSUPPORTED"}
    assert "entered in scenario boot" in next(d.detail for d in unscoped.diagnostics if d.severity == "reject")


def test_unparsed_call_wording_is_noted_not_admitted_above_probable():
    record = claim(f"The handler calls a vtable method of {S}.", "facts_T")
    assert record.decision == "admitted" and call_codes(record, "note") == {"CALL_RELATION_UNCHECKED"}
    assert "UNTYPED_GRADE" in codes(claim(f"The handler calls a vtable method of {S}.", "facts_T", grade="STRONG"))


def test_parser_forms_are_documented_and_bounded():
    assertions, unchecked = parse_assertions(f"{S} calls {T} and {U}; {V} is called by {S} at 0x00005020. {W} has no callers")
    assert [(a.form, a.sources, a.targets) for a in assertions] == [
        ("edge", (0x5000,), (0x6000, 0x7000)),
        ("edge", (0x5000,), (0x8000,)),
        ("absence", (), (0x8100,)),
    ]
    assert assertions[1].site == 0x5020 and unchecked == []

    thunk, _ = parse_assertions(f"{S} dispatches to the thunk at 0x00005800; {T} is called from 0x00005010")
    assert [(a.sources, a.targets, a.site) for a in thunk] == [((0x5000,), (0x5800,), None), ((), (0x6000,), 0x5010)]
    # The object of a preposition is not a subject; such wording is only noted.
    noted, unchecked = parse_assertions(f"The pointer written by {S} is invoked from the handler.")
    assert noted == [] and len(unchecked) == 1


# -- 16/17. USB and EIC controls ------------------------------------------------------------


def test_16_17_usb_and_eic_controls_are_unchanged():
    session = usb_session()
    writer_as_target = {"predicate": "FUNCTION_ROLE", "function_role": {"function": "FUN_0000ccc4", "role": "CALLBACK_TARGET"}}
    proposal = {"subject": "", "assertion": "The USB callback target is FUN_0000ccc4.", "grade": "STRONG", "claim_type": "RESOLUTION", "evidence_ids": ["E1"], "semantics": writer_as_target}
    assert admit(proposal, session, round=1).decision == "rejected"

    pointer = {"predicate": "RESOLVED_FUNCTION_POINTER", "resolved_pointer": {"slot": "0x200052e8", "canonical_target": "0x0000c724", "writer": "FUN_0000ccc4"}}
    good = {**proposal, "assertion": "The RAM slot 0x200052e8 resolves to 0x0000c724, written by FUN_0000ccc4.", "semantics": pointer}
    record = admit(good, session, round=1)
    assert record.decision == "admitted" and not codes(record)

    # The census resolved_indirect edge in the USB inventory is an established indirect edge.
    edge = {"predicate": "CALL_RELATION", "call": {"source": "FUN_0000cc14", "target": "0x0000c724", "kind": "ESTABLISHED_INDIRECT", "site": "0x0000cc1a"}}
    typed = admit({**proposal, "assertion": "FUN_0000cc14 calls 0x0000c724 at 0x0000cc1a.", "semantics": edge}, session, round=1)
    prose = admit({**proposal, "assertion": "FUN_0000cc14 calls 0x0000c724 at 0x0000cc1a.", "semantics": None, "grade": "PROBABLE"}, session, round=1)
    assert typed.decision == "admitted" and prose.decision == "admitted", (typed.diagnostics, prose.diagnostics)


# -- 18. typed candidates --------------------------------------------------------------------


def test_18_candidates_do_not_generate_call_relations_and_still_admit():
    session = usb_session()
    generated = generate_candidates(session.ledger.all(), objective="USB")
    assert generated.candidates and all(c.semantics.predicate.value != "CALL_RELATION" for c in generated.candidates)

    for candidate in generated.candidates:
        record = admit(proposal_for(candidate), session, round=1)
        assert record.decision == "admitted", (candidate, record.diagnostics)


# -- 9 (integration). correction round, verifier, policy -----------------------------------------


class CorrectingPlanner(Planner):
    """Answers the claim-correction request with a different claim."""

    def __init__(self, actions, claims, corrected):
        super().__init__(actions, claims=claims)
        self.corrected = corrected

    def _create(self, **kwargs):
        if "did not admit" in "\n".join(str(m.get("content") or "") for m in kwargs["messages"]):
            self.requests.append(kwargs)
            return self._call("finish", {"reason": "corrected", "claims": self.corrected})

        return super()._create(**kwargs)


def test_correction_round_shows_call_diagnostics_and_admits_the_corrected_claim(world):
    new = first_new_evidence(world)
    ids = ",".join(f"E{n}" for n in range(1, new + 2))
    caller, site = CALLERS[0]
    planner = CorrectingPlanner(
        [("follow", caller), ("follow", CALLERS[1][0])],
        claims=f"PROBABLE STRUCTURE {ids} {caller} calls FUN_00002000",
        corrected=f"PROBABLE STRUCTURE {ids} {caller} calls {GAP} at {site}",
    )
    run, _executor, _session, _ = follow_up(world, planner, max_steps=2)
    first, second = run.claim_admission

    assert first.round == 1 and first.decision == "rejected" and any(d.code.startswith("CALL_") for d in first.diagnostics)
    correction = next(r for r in run.planner_requests if r["phase"] == "claim-correction")
    assert correction is not None
    assert second.round == 2 and second.decision == "admitted", second.diagnostics
    assert world.ledger.state(run.claim_versions[0]) == ClaimState.PROPOSED


def test_verifier_phase_b_applies_the_same_call_rule(world):
    evidence = next(e for e in world.run_a.evidence_ids if world.ledger.evidence(e).tool == "function_facts" and world.ledger.evidence(e).arguments.get("function") == GAP)
    verifier = ClaimVerifier(world.ledger, context=world.context(), replay=False)

    bad = world.ledger.propose_claim(subject="", assertion=f"{CALLERS[0][0]} calls FUN_00002000.", claim_type="STRUCTURE", proposed_grade="PROBABLE", proposed_by="operator", supporting_evidence_ids=[evidence])
    outcome = verifier.precheck(bad.key)
    check = next(c for c in outcome.record.checks if c.name == "call_relations")
    assert not check.passed and "CALL_" in check.detail and outcome.record.outcome == ClaimState.BLOCKED

    good = world.ledger.propose_claim(subject="", assertion=f"{CALLERS[0][0]} calls {GAP} at {CALLERS[0][1]}.", claim_type="STRUCTURE", proposed_grade="PROBABLE", proposed_by="operator", supporting_evidence_ids=[evidence])
    check = next(c for c in verifier.precheck(good.key).record.checks if c.name == "call_relations")
    assert check.passed


def test_policy_classes_for_call_relations():
    def semantics(kind):
        return ClaimSemantics.model_validate({"predicate": "CALL_RELATION", "call": {"source": S, "target": T, "kind": kind, "conditions": ["c"], "scenario": "boot"}})

    assert claim_class(ClaimType.STRUCTURE, semantics("DIRECT_CALL"))[0] == ClaimClass.CONTROL_FLOW
    assert claim_class(ClaimType.RESOLUTION, semantics("POTENTIAL_INDIRECT"))[0] == ClaimClass.RESOLVED_INDIRECT_CALL


# -- 19. historical evidence ----------------------------------------------------------------


def test_19_reused_evidence_supports_a_call_claim_by_its_original_identity(world):
    new = first_new_evidence(world)
    planner = Planner([("follow", CALLERS[0][0])], claims=f"PROBABLE STRUCTURE E1,E{new} {CALLERS[0][0]} calls {GAP} at {CALLERS[0][1]}")
    run, _executor, session, _ = follow_up(world, planner, max_steps=1)
    record = run.claim_admission[0]
    reused = [o for o in session.ledger.all() if o.reused_from]

    assert record.decision == "admitted", record.diagnostics
    assert [o.id for o in reused][:1] == ["E1"]
    original = session.ledger.get("E1").reused_from
    assert {"CALL_RELATION_CHECKED", "HISTORICAL_REFERENCE"} <= codes(record, "note")
    assert next(d for d in record.diagnostics if d.code == "HISTORICAL_REFERENCE").evidence_ids == [original]
    assert record.durable_evidence_ids[0] == original


# -- 20. persisted records ----------------------------------------------------------------------


CASE_LEDGER = Path(__file__).resolve().parents[2] / "cases" / "performing-rigs" / "research" / "ledger"


def _tree_digest(root: Path) -> str:
    h = hashlib.sha256()
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        h.update(str(path.relative_to(root)).encode() + b"\0" + path.read_bytes())
    return h.hexdigest()


def test_20_persisted_records_load_and_call_diagnostics_only_report():
    if not (CASE_LEDGER / "claims").is_dir():
        pytest.skip("case ledger not present")

    before = _tree_digest(CASE_LEDGER)
    ledger = ResearchLedger(CASE_LEDGER)
    report = {}

    for claim_version in ledger.all_claim_versions():
        artifacts = [ledger.evidence(e) for e in claim_version.supporting_evidence_ids if ledger.has_evidence(e)]
        evidence = [(a, r) for a in artifacts if ledger.has_blob(a.result_sha256) and isinstance(r := ledger.load_blob(a.result_sha256)[0], dict)]
        report[claim_version.key] = sorted({d.code for d in call_diagnostics(claim_version.assertion, evidence) if d.severity == "reject"})

    records = [r for c in ledger.all_claim_versions() for r in ledger.verifications_for(c.key)]
    assert records and all(isinstance(r, VerificationRecord) for r in records)
    # Older semantic checks load without the new optional diagnostic field.
    assert all(isinstance(c, SemanticCheck) and c.diagnostic is None for r in records for c in r.semantic_checks)

    # Reported, not rewritten: the historical "definitively reachable" claim is
    # recognized as unsupported; no lifecycle state or file changes.
    assert report["C9:v1"] == ["CALL_REACHABILITY_UNSUPPORTED"]
    assert all(v == [] for k, v in report.items() if k != "C9:v1"), report
    assert ledger.state("C9:v1") == ClaimState.PROPOSED
    assert _tree_digest(CASE_LEDGER) == before


def _artifact(evidence_id, tool, arguments=None, grade="EXACT"):
    from types import SimpleNamespace

    return SimpleNamespace(evidence_id=evidence_id, tool=tool, arguments=arguments or {}, grade=grade)


def test_round_trip_of_typed_semantics_is_stable():
    value = {"predicate": "CALL_RELATION", "call": {"source": "FUN_5000", "target": "0x6001", "kind": "DIRECT_CALL", "site": "0x5010"}}
    semantics = ClaimSemantics.model_validate(value)
    dumped = semantics.model_dump(mode="json")

    assert dumped["call"]["source"] == S and dumped["call"]["target"] == "0x00006001"
    assert ClaimSemantics.model_validate(json.loads(json.dumps(dumped))) == semantics
