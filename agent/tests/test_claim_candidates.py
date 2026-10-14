"""
Deterministic claim candidates (research/candidates.py) and their selection
by id in the ResearchController final-claims phase.

Fixtures are the SERCOM-shaped follow-up world of test_followups (GAP loads
the peripheral base from its literal pool and reads through r0; its callers
are the seeded leads) and the USB/EIC controls of test_claim_quality.
Numbers in test names follow the milestone's required-test list.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
from pathlib import Path

import pytest

from aptrace_agent.investigator import AutonomousInvestigationRun
from aptrace_agent.ledger.claim_semantics import FunctionRole, Predicate
from aptrace_agent.ledger.models import ClaimAdmission, ClaimState, InvestigationRun, SourceRevision
from aptrace_agent.ledger.recorder import RecordingExecutor, record_investigation
from aptrace_agent.ledger.semantics import asserts_absolute_negative
from aptrace_agent.ledger.store import now
from aptrace_agent.ledger.verifier import ClaimVerifier
from aptrace_agent.research import LeadFollower, LeadRegistry, ResearchController, ResearchSession
from aptrace_agent.research.admission import admit
from aptrace_agent.research.candidates import (
    ACCESS_UNDER_ASSUMPTION,
    ROLE_CONFLICT,
    candidates_for_run,
    generate_candidates,
    parse_selection,
    proposal_for,
    seeded_evidence,
)
from aptrace_agent.research.followups import seed_session
from aptrace_agent.research.history import HistoricalOperations
from aptrace_agent.schemas import EvidenceObservation

from ledger_support import common_paths, usb_inventory
from test_claim_quality import usb_session
from test_continuity import Planner, first_new_evidence
from test_followups import BASE, CALLERS, GAP, INIT, PERIPHERAL, SerialExecutor, census, deriver_for, effects, generate, world  # noqa: F401


class Selecting(Planner):
    """Scripted planner that also answers select_claims: `select` is text, or a function of the offered ids."""

    def __init__(self, actions=(), claims: str = "", select="none", extra=None) -> None:
        super().__init__(actions, claims)
        self.select = select
        self.extra = extra or {}

    def _create(self, **kwargs):
        if [t["function"]["name"] for t in kwargs["tools"]] != ["select_claims"]:
            return super()._create(**kwargs)

        self.requests.append(kwargs)
        prompt = kwargs["messages"][-1]["content"]
        offered = re.findall(r"^(K-[0-9a-f]{12}) ", prompt, re.MULTILINE)
        selected = self.select(offered, prompt) if callable(self.select) else self.select
        return self._call("select_claims", {"selected": selected, **self.extra})

    def selection_prompts(self) -> list[str]:
        return [r["messages"][-1]["content"] for r in self.requests if [t["function"]["name"] for t in r["tools"]] == ["select_claims"]]


def run_selecting(world, planner, *, limit=5, max_steps=2, executor=None, history=None, peripherals=(PERIPHERAL,)):
    """
    Follow-up B with candidate selection enabled; returns (recorded run,
    session, controller). Repeated runs follow up the same candidate (the
    shortlist changes once a follow-up is recorded).
    """

    candidate = followup_of(world)
    context = world.context()
    recorder = RecordingExecutor(executor or SerialExecutor())
    registry = LeadRegistry()
    session = ResearchSession(objective=candidate.objective, registry=registry, follower=LeadFollower(registry=registry, executor=recorder), deriver=deriver_for(registry))
    seed_session(session, candidate, history=history or HistoricalOperations.for_followup(world.ledger, context, candidate))
    controller = ResearchController(
        planner_client=planner, planner_model="scripted", reconciler=object(), max_steps=max_steps, claim_contract=True,
        structural_tools=("function_effects",), census_peripherals=peripherals, max_claim_candidates=limit,
    )
    result = controller.run(session)
    run = AutonomousInvestigationRun(
        objective=candidate.objective, seed_function=None, result=result, state=session.state.model_copy(deep=True),
        evidence=tuple(session.ledger.all()), continuity=session.continuity.record(max_steps=max_steps),
    )
    recorded = record_investigation(
        world.ledger, run, context=context, recorder=recorder, model="scripted", execution_config={}, planner_version="test",
        budgets={"max_steps": max_steps}, started_at=now(), ended_at=now(), source=SourceRevision(), followup=candidate.provenance(),
    )
    return recorded, session, controller


def followup_of(world):
    if not hasattr(world, "followup"):
        world.followup = generate(world).shortlist[0]

    return world.followup


def callers_planner(**kwargs) -> Selecting:
    return Selecting([("follow", CALLERS[0][0]), ("follow", CALLERS[1][0])], **kwargs)


def of(session, **kwargs):
    """Candidates of a live session, the way the controller generates them."""

    return generate_candidates(session.ledger.all(), objective=session.state.objective, seeded=seeded_evidence(session), **kwargs)


def subject(candidates, function):
    return next(c for c in candidates if c.subject == function)


def obs(id, tool, arguments, result, reused_from=None):
    return EvidenceObservation(id=id, tool=tool, arguments=arguments, result=result, reused_from=reused_from)


def census_with(*entries) -> dict:
    return {"status": "ok", "peripheral": PERIPHERAL, "functions": list(entries)}


def mmio_entry(function: str) -> dict:
    site = {"site": "0x00005010", "address": BASE, "register_name": f"{PERIPHERAL}.CTRLA", "direction": "WRITE", "width": 32, "resolution_note": None, "source": "ghidra"}
    return {"function": function, "constant_loads": [], "constant_load_count": 0, "mmio_site_count": 1, "mmio_sites": [site]}


def effects_access(function: str, *, specialize=None, address=BASE, depends_on=()) -> dict:
    result = effects(function, mmio=False)
    result["accesses"].append(
        {"address": address, "depends_on": list(depends_on), "kind": "write", "region": "MMIO", "register_name": f"{PERIPHERAL}.CTRLA", "guard": "always-true"}
    )
    result["harness_assumptions"] = ["read-only segments concrete; RAM and MMIO ranges unconstrained symbolic"]
    result["status"] = "complete"

    if specialize:
        result["specialize"] = specialize

    return result


def tree_hash(root: Path) -> str:
    h = hashlib.sha256()

    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        h.update(str(path.relative_to(root)).encode())
        h.update(path.read_bytes())

    return h.hexdigest()


# -- 1. deterministic identity --------------------------------------------------------------


def test_1_repeated_extraction_gives_identical_candidates_independent_of_session_numbering(world):
    _run, session, _ = run_selecting(world, callers_planner())
    first, second = of(session), of(session)

    assert first == second and first.candidates
    ids = [c.candidate_id for c in first.candidates]
    assert all(re.fullmatch(r"K-[0-9a-f]{12}", i) for i in ids)

    # Renumbered observations (same tools, arguments, results) give the same ids.
    shifted = [obs(f"E{100 + n}", o.tool, o.arguments, copy.deepcopy(o.result), o.reused_from) for n, o in enumerate(session.ledger.all())]
    assert [c.candidate_id for c in generate_candidates(shifted, objective=session.state.objective).candidates] == ids

    # Model prose never enters the identity: a different planner text, same evidence.
    _run2, session2, _ = run_selecting(world, callers_planner(claims="PROBABLE BEHAVIOR E1 something else entirely"))
    assert [c.candidate_id for c in of(session2).candidates] == ids


# -- 2. entities ------------------------------------------------------------------------------


def test_2_subjects_are_canonical_known_entities_and_unknown_ones_are_withheld(world):
    _run, session, _ = run_selecting(world, callers_planner())
    generated = of(session, function_exists=lambda name: name != INIT, peripherals=[PERIPHERAL])

    assert [c.subject for c in generated.candidates] == [GAP]
    assert any(w.code == "ENTITY_UNKNOWN" and INIT in w.detail for w in generated.withheld)
    assert re.fullmatch(r"FUN_[0-9a-f]{8}", generated.candidates[0].subject)

    unknown_peripheral = of(session, peripherals=["SERCOM0"])
    assert unknown_peripheral.candidates == () and {w.code for w in unknown_peripheral.withheld} == {"PERIPHERAL_UNKNOWN"}


# -- 3. constant load is not an access ------------------------------------------------------


def test_3_address_constant_load_is_a_loader_candidate_never_an_access(world):
    _run, session, _ = run_selecting(world, callers_planner())
    candidates = of(session).candidates
    gap = subject(candidates, GAP)

    assert gap.semantics.function_role.role == FunctionRole.ADDRESS_CONSTANT_LOADER
    assert gap.semantics.function_role.peripheral == PERIPHERAL and gap.claim_type == "STRUCTURE" and gap.grade == "STRONG"
    assert "Loading an address is not a register access" in gap.assertion and BASE in gap.assertion
    assert not any(c.semantics.function_role and c.semantics.function_role.role == FunctionRole.MMIO_USER for c in candidates)
    # The effects evidence with r0-dependent addresses limits, and is shown to limit, the candidate.
    effects_alias = next(o.id for o in session.ledger.all() if o.tool == "function_effects")
    assert gap.considered[effects_alias].startswith("limits, does not support") and "r0" in gap.considered[effects_alias]
    assert any("depend on r0" in text and "neither established nor excluded" in text for text in gap.limitations)


# -- 4. MMIO observations ---------------------------------------------------------------------


def test_4_structured_mmio_observations_give_scoped_access_candidates():
    census_obs = obs("E1", "census_peripheral_usage", {"peripheral": PERIPHERAL, "limit": 25}, census_with(mmio_entry("FUN_00005000")))
    effects_obs = obs("E2", "function_effects", {"function": GAP, "specialize": {}}, effects_access(GAP))
    loader_obs = obs("E3", "census_peripheral_usage", {"peripheral": PERIPHERAL, "limit": 10}, census())
    generated = generate_candidates([census_obs, effects_obs, loader_obs])
    static = subject(generated.candidates, "FUN_00005000")
    symbolic = subject(generated.candidates, GAP)

    assert static.semantics.function_role.role == FunctionRole.MMIO_USER and static.claim_type == "BEHAVIOR"
    assert static.supporting_evidence_ids == ["E1"] and "static census" in static.scope and f"write {BASE}" in static.assertion
    assert symbolic.semantics.function_role.role == FunctionRole.MMIO_USER and symbolic.semantics.function_role.peripheral == PERIPHERAL
    assert symbolic.supporting_evidence_ids == ["E2"] and "without argument specialization" in symbolic.scope
    assert symbolic.assumptions == ["read-only segments concrete; RAM and MMIO ranges unconstrained symbolic"]
    # The census lists GAP for its address constant only; with an access in evidence,
    # a loader fact would misstate it and is withheld.
    assert any(w.code == ROLE_CONFLICT and GAP in w.fact for w in generated.withheld)
    assert subject(generated.candidates, INIT).semantics.function_role.role == FunctionRole.ADDRESS_CONSTANT_LOADER


@pytest.mark.parametrize(
    "result",
    [effects_access(GAP, specialize={"r0": BASE}), effects_access(GAP, address="parametric", depends_on=["r0"])],
    ids=["specialized", "input-dependent"],
)
def test_4_conditional_mmio_accesses_are_withheld_not_generalized(result):
    generated = generate_candidates([obs("E1", "function_effects", {"function": GAP, "specialize": result.get("specialize", {})}, result)])

    assert generated.candidates == ()
    assert [w.code for w in generated.withheld] == [ACCESS_UNDER_ASSUMPTION]


# -- 5. no unsupported negatives ------------------------------------------------------------------


def test_5_no_negative_or_absence_candidate_is_generated():
    no_mmio = obs("E1", "function_effects", {"function": GAP, "specialize": {}}, effects(GAP, mmio=False))
    no_path = obs("E2", "census_common_paths", {"left_label": "IRQ:EIC", "right_label": "USB"}, common_paths({"left_label": "IRQ:EIC", "right_label": "USB"}))
    generated = generate_candidates([no_mmio, no_path, obs("E3", "census_usb_inventory", {}, usb_inventory())])

    assert {c.semantics.predicate for c in generated.candidates} == {Predicate.RESOLVED_FUNCTION_POINTER}
    assert not any(c.subject == GAP for c in generated.candidates)
    assert not any(c.semantics.path for c in generated.candidates)
    assert not any(asserts_absolute_negative(c.assertion) for c in generated.candidates)
    # The bounded NO_KNOWN_PATH result supports no candidate on its own.
    assert all(c.supporting_evidence_ids != ["E2"] for c in generated.candidates)


# -- 6. historical provenance --------------------------------------------------------------------


def test_6_historical_support_keeps_its_original_id_and_is_not_new_evidence(world):
    recorded, session, _ = run_selecting(world, callers_planner(select=lambda ids, _p: ids[0]))
    selection = recorded.candidate_selection
    gap = next(c for c in selection.offered if c.subject == GAP)
    alias = gap.supporting_evidence_ids[0]
    original = session.ledger.get(alias).reused_from

    assert original and original.startswith("EV-") and gap.prior_evidence_ids == [original]
    assert gap.durable_evidence_ids == [original]
    claim = world.ledger.claim(recorded.claim_versions[0])
    assert claim.supporting_evidence_ids == [original] and original not in recorded.evidence_ids
    admission = next(r for r in recorded.claim_admission if r.candidate_id == gap.candidate_id)
    assert "HISTORICAL_REFERENCE" in {d.code for d in admission.diagnostics}


# -- 7/8. invalid, invalidated and incompatible evidence ----------------------------------------------


def test_7_failed_or_invalidated_evidence_supports_no_candidate(world):
    failed = obs("E1", "census_peripheral_usage", {"peripheral": PERIPHERAL}, {**census(), "status": "error"})
    assert generate_candidates([failed]).candidates == ()

    census_ev = next(e for e in world.run_a.evidence_ids if world.ledger.evidence(e).tool == "census_peripheral_usage")
    world.ledger.invalidate_evidence(census_ev, reason="test")
    preview = candidates_for_run(world.ledger, world.run_a.run_id)
    assert preview.candidates == ()

    _run, session, _ = run_selecting(world, callers_planner())
    assert not any(census_ev in c.prior_evidence_ids for c in of(session).candidates)


def test_8_incompatible_analysis_version_is_not_reused_as_candidate_support(world):
    candidate = followup_of(world)
    history = HistoricalOperations(
        world.ledger, world.context(), run_ids=[candidate.source_run_id], evidence_ids=list(candidate.evidence_ids), analysis_versions={"function_effects": 2},
    )
    _run, session, _ = run_selecting(world, callers_planner(), history=history)
    reused_tools = {o.tool for o in session.ledger.all() if o.reused_from}
    gap = subject(of(session).candidates, GAP)

    assert "function_effects" not in reused_tools
    effects_ids = {o.id for o in session.ledger.all() if o.tool == "function_effects"}
    assert not (effects_ids & set(gap.supporting_evidence_ids))
    assert all(world.ledger.evidence_state(e) == "VALID" for e in gap.prior_evidence_ids)


# -- 9/10. selection by id only ---------------------------------------------------------------------


def test_9_unknown_and_unoffered_ids_are_rejected_and_recorded(world):
    recorded, _session, _ = run_selecting(world, callers_planner(select=lambda ids, _p: f"K-000000000000, {ids[0]}, FUN_00001000"), limit=1)
    by_decision = {r.decision: r for r in recorded.claim_admission if r.round > 1 or r.candidate_id}
    rejected = [r for r in recorded.claim_admission if r.decision == "rejected" and r.raw.startswith("select")]

    assert [d.code for r in rejected for d in r.diagnostics] == ["CANDIDATE_UNKNOWN"]
    assert by_decision["admitted"].candidate_id == recorded.candidate_selection.selected[0]
    assert recorded.candidate_selection.invalid == ["K-000000000000"]

    omitted = recorded.candidate_selection.omitted
    assert omitted
    recorded2, _s, _ = run_selecting(world, callers_planner(select=f"{omitted[0]}"), limit=1)
    assert [d.code for r in recorded2.claim_admission for d in r.diagnostics if d.severity == "reject"] == ["CANDIDATE_NOT_OFFERED"]
    assert recorded2.claim_versions == []

    assert parse_selection("none", {"K-aaaaaaaaaaaa"}) == ([], [])
    assert parse_selection("the first one", {"K-aaaaaaaaaaaa"}) == ([], ["the first one"])
    assert parse_selection("K-AAAAAAAAAAAA", {"K-aaaaaaaaaaaa"}) == ([], ["K-AAAAAAAAAAAA"])


def test_10_selection_response_cannot_alter_the_structured_fact(world):
    forged = {
        "semantics": {"predicate": "FUNCTION_ROLE", "function_role": {"function": GAP, "role": "MMIO_USER", "peripheral": PERIPHERAL}},
        "grade": "EXACT", "evidence_ids": ["E99"], "assertion": f"{GAP} writes {PERIPHERAL} registers.",
    }
    planner = callers_planner(select=lambda ids, _p: f"{ids[0]} as MMIO_USER, grade EXACT", extra=forged)
    recorded, _session, _ = run_selecting(world, planner)
    offered = recorded.candidate_selection.offered[0]
    claim = world.ledger.claim(recorded.claim_versions[0])

    assert claim.semantics == offered.semantics and claim.semantics.function_role.role == FunctionRole.ADDRESS_CONSTANT_LOADER
    assert claim.proposed_grade.value == offered.grade == "STRONG"
    assert claim.supporting_evidence_ids == offered.durable_evidence_ids and claim.assertion == offered.assertion
    assert claim.scope == offered.scope and claim.proposed_by == "candidate-selection:scripted"
    assert offered.candidate_id in claim.derivation


# -- 11. admission and verification stay authoritative ------------------------------------------------


def test_11_admission_and_verifier_remain_authoritative(world):
    recorded, session, _ = run_selecting(world, callers_planner(select=lambda ids, _p: ids[0]))
    gap = subject(of(session).candidates, GAP)

    # Admission still checks a candidate: tampered copies are rejected.
    assert admit(proposal_for(gap), session, round=1).decision == "admitted"
    over = admit(proposal_for(gap.model_copy(update={"grade": "EXACT"})), session, round=1)
    unexplained = admit(proposal_for(gap.model_copy(update={"considered": {}})), session, round=1)
    assert over.decision == "rejected" and "GRADE_ABOVE_CEILING" in {d.code for d in over.diagnostics}
    assert unexplained.decision == "rejected" and "EVIDENCE_OMITTED" in {d.code for d in unexplained.diagnostics}

    # Machine generation verifies nothing: the admitted claim is PROPOSED and stays held.
    key = recorded.claim_versions[0]
    assert world.ledger.state(key) == ClaimState.PROPOSED
    outcome = ClaimVerifier(world.ledger, context=world.context(), replay=False).precheck(key)
    assert outcome.record.outcome == ClaimState.PROPOSED
    assert next(c for c in outcome.record.checks if c.name == "claim_semantics").passed


# -- 12/13. duplicates and existing claims ------------------------------------------------------------


def test_12_13_duplicates_create_no_claim_version_and_existing_claims_are_untouched(world):
    first, _s, _ = run_selecting(world, callers_planner(select=lambda ids, _p: f"{ids[0]},{ids[0]}"))
    key = first.claim_versions[0]
    claim_file = world.root / "claims" / key.split(":")[0] / "v1.json"
    assert claim_file.is_file()
    before = (claim_file.read_bytes(), world.ledger.history(key), len(world.ledger.all_claim_versions()))

    assert len(first.claim_versions) == 1  # the same id twice is one selection

    planner = callers_planner(select=lambda ids, _p: ids[0])
    second, _s2, _ = run_selecting(world, planner)
    duplicate = next(r for r in second.claim_admission if r.candidate_id)

    assert second.claim_versions == [] and duplicate.decision == "duplicate" and duplicate.claim_version is None
    note = next(d for d in duplicate.diagnostics if d.code == "CLAIM_EQUIVALENT_EXISTS")
    assert note.severity == "note" and note.value == key and "unchanged" in note.detail
    assert f"Already recorded as claim {key} in state PROPOSED." in planner.selection_prompts()[0]
    assert next(c for c in second.candidate_selection.offered if c.subject == GAP).existing_claims == [f"{key} PROPOSED"]
    after = (claim_file.read_bytes(), world.ledger.history(key), len(world.ledger.all_claim_versions()))
    assert after == before and world.ledger.state(key) == ClaimState.PROPOSED


# -- 14. no ledger writes ---------------------------------------------------------------------------


def test_14_extraction_and_preview_write_nothing(world):
    _run, session, _ = run_selecting(world, callers_planner())
    before = tree_hash(world.root)

    of(session)
    candidates_for_run(world.ledger, world.run_a.run_id)
    candidates_for_run(world.ledger, _run.run_id)

    assert tree_hash(world.root) == before


# -- 15. bounded, deterministic presentation -----------------------------------------------------------


def test_15_selection_is_bounded_ranked_and_reported(world):
    entries = [census()["functions"][0]] + [
        {"function": f"FUN_0000{n:x}000", "constant_loads": [{"value": BASE}], "constant_load_count": 1, "mmio_site_count": 0, "mmio_sites": []}
        for n in range(5, 13)
    ]
    observations = [obs("E1", "census_peripheral_usage", {"peripheral": PERIPHERAL}, census_with(*entries))]
    generated = generate_candidates(observations, objective=f"Does {GAP} access {PERIPHERAL}?")
    offered, omitted = generated.offer(3)

    assert len(generated.candidates) == 9 and len(offered) == 3 and len(omitted) == 6
    assert offered[0].subject == GAP  # the objective's function ranks first
    assert generate_candidates(list(reversed(observations)), objective=f"Does {GAP} access {PERIPHERAL}?").candidates == generated.candidates

    planner = callers_planner()
    recorded, _s, _ = run_selecting(world, planner, limit=1)
    prompt = planner.selection_prompts()[0]
    selection = recorded.candidate_selection

    assert len(selection.offered) == 1 and selection.omitted and f"({len(selection.omitted)} lower-ranked candidate(s) not shown)" in prompt
    assert selection.offered[0].subject == GAP and selection.outcome == "none"
    request = next(r for r in recorded.planner_requests if r["phase"] == "candidate-selection")
    assert request["total_bytes"] < 3000 and "RESEARCH STATE" not in prompt


# -- 16. free-form hypotheses still go through admission ---------------------------------------------


def test_16_free_form_hypotheses_remain_possible_next_to_selection(world):
    new = first_new_evidence(world, followup_of(world))
    hypothesis = (
        f"PROBABLE BEHAVIOR E2,E{new},E{new + 1} {GAP} has no observed {PERIPHERAL} register access in the recorded symbolic analysis; "
        "the r0 values its callers pass are unresolved."
    )
    recorded, _s, _ = run_selecting(world, callers_planner(claims=hypothesis, select=lambda ids, _p: ids[0]))
    decisions = [(r.round, r.decision, r.candidate_id is not None) for r in recorded.claim_admission]
    claims = [world.ledger.claim(k) for k in recorded.claim_versions]

    # The free-form round is admitted on its own; selection follows as its own round.
    assert decisions == [(1, "admitted", False), (2, "admitted", True)]
    assert {c.proposed_by for c in claims} == {"investigator:scripted", "candidate-selection:scripted"}
    free = next(c for c in claims if c.proposed_by.startswith("investigator"))
    assert free.semantics is None and free.proposed_grade.value == "PROBABLE"


# -- 17/18. USB and EIC controls ------------------------------------------------------------------------


def test_17_18_usb_controls_known_good_pointer_is_a_candidate_and_known_bad_forms_never_are():
    session = usb_session()
    generated = of(session)
    pointer = next(c for c in generated.candidates if c.semantics.predicate == Predicate.RESOLVED_FUNCTION_POINTER)

    assert pointer.semantics.resolved_pointer.slot == "0x200052e8"
    assert pointer.semantics.resolved_pointer.canonical_target == "0x0000c724"
    assert pointer.semantics.resolved_pointer.writer == "FUN_0000ccc4" and pointer.grade == "STRONG"
    assert admit(proposal_for(pointer), session, round=1).decision == "admitted"
    # Never the known-bad forms: the writer as callback target, or an EIC path relation.
    roles = [(c.semantics.function_role.function, c.semantics.function_role.role) for c in generated.candidates if c.semantics.function_role]
    assert ("FUN_0000ccc4", FunctionRole.CALLBACK_TARGET) not in roles
    assert not any(c.semantics.path for c in generated.candidates)
    # EIC census entries without constant loads or MMIO sites establish no role.
    assert not any("EIC" in c.assertion for c in generated.candidates)


def test_17_pointer_edges_that_disagree_are_withheld():
    edge = usb_inventory()
    other = copy.deepcopy(edge)
    other["resolved_indirect_edges"][0]["canonical_target"] = "0x0000c800"
    generated = generate_candidates([obs("E1", "census_usb_inventory", {}, edge), obs("E2", "census_usb_inventory", {"x": 1}, other)])

    assert not any(c.semantics.resolved_pointer for c in generated.candidates)
    assert any(w.code == "POINTER_CONFLICT" for w in generated.withheld)


# -- 19. compatibility ----------------------------------------------------------------------------------


def test_19_records_without_candidates_serialize_unchanged_and_new_fields_round_trip(world):
    assert "candidate_id" not in ClaimAdmission(round=1, raw="x", decision="rejected").model_dump(mode="json")
    assert "candidate_selection" not in world.run_a.model_dump(mode="json")

    recorded, _s, _ = run_selecting(world, callers_planner(select=lambda ids, _p: ids[0]))
    raw = json.loads((world.root / "runs" / f"{recorded.run_id}.json").read_text())
    assert InvestigationRun.model_validate(raw).model_dump(mode="json") == raw
    assert raw["candidate_selection"]["outcome"] == "selected"

    # Disabled (the default): no selection request and no record.
    planner = Selecting([("follow", CALLERS[0][0])])
    candidate = followup_of(world)
    registry = LeadRegistry()
    session = ResearchSession(objective=candidate.objective, registry=registry, follower=LeadFollower(registry=registry, executor=SerialExecutor()), deriver=deriver_for(registry))
    seed_session(session, candidate, history=HistoricalOperations.for_followup(world.ledger, world.context(), candidate))
    result = ResearchController(planner_client=planner, planner_model="scripted", reconciler=object(), max_steps=1, claim_contract=True).run(session)
    assert result.candidate_selection is None and planner.selection_prompts() == []


def test_19_canonical_case_ledger_preview_is_read_only_and_finds_no_access():
    root = Path(__file__).resolve().parents[2] / "cases" / "performing-rigs" / "research" / "ledger"

    if not (root / "runs" / "R-20261013T190420-edcfa7.json").is_file():
        pytest.skip("case ledger not present")

    from aptrace_agent.ledger.store import ResearchLedger

    before = tree_hash(root)
    generated = candidates_for_run(ResearchLedger(root), "R-20261013T190420-edcfa7")

    assert tree_hash(root) == before
    target = subject(generated.candidates, "FUN_0000b4b4")
    assert target.semantics.function_role.role == FunctionRole.ADDRESS_CONSTANT_LOADER
    assert not any(c.semantics.function_role and c.semantics.function_role.role == FunctionRole.MMIO_USER for c in generated.candidates)
    assert any("depend on r0" in text for text in target.limitations)
