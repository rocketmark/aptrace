"""
Claim admission and evidence accountability (research/admission.py,
ledger/claim_checks.py) for model claim proposals.

Fixtures are the SERCOM-shaped follow-up world of test_followups and the
controller harness of test_continuity: Investigation A (recorded before
claim admission existed, like the canonical C9:v1 run) and a follow-up B
that inspects the callers of the constant-loading function GAP. Scenario
letters follow the claim-quality milestone.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from aptrace_agent.ledger.claim_checks import entity_diagnostics
from aptrace_agent.ledger.models import ClaimState, InvestigationRun
from aptrace_agent.ledger.store import ResearchLedger
from aptrace_agent.ledger.verifier import ClaimVerifier
from aptrace_agent.research import LeadFollower, LeadRegistry, ResearchController, ResearchSession
from aptrace_agent.research.admission import admit
from aptrace_agent.schemas import EvidenceObservation

from ledger_support import FakeExecutor, usb_inventory
from test_continuity import Planner, first_new_evidence, follow_up
from test_followups import CALLERS, GAP, PERIPHERAL, SerialExecutor, world  # noqa: F401  (world is a fixture)


C10 = f"STRONG BEHAVIOR {{ids}} E0000b4b4 does not read or write {PERIPHERAL} registers via r0 address; it only uses the address as a value."


def session_after_callers(world, *, mmio=False):
    """Follow-up B that follows the first two seeded call sites; returns (run, session, first new E number)."""

    new = first_new_evidence(world)
    run, _executor, session, _ = follow_up(
        world, Planner([("follow", CALLERS[0][0]), ("follow", CALLERS[1][0]), ("finish",)]), max_steps=2, executor=SerialExecutor(mmio=mmio)
    )
    return run, session, new


def alias(session, tool, **arguments):
    """Session id of the (preloaded or executed) observation of tool(arguments)."""

    return next(o.id for o in session.ledger.all() if o.tool == tool and all(o.arguments.get(k) == v for k, v in arguments.items()))


def proposal(assertion, evidence_ids, grade="PROBABLE", claim_type="BEHAVIOR", **extra):
    return {"subject": "", "assertion": assertion, "grade": grade, "claim_type": claim_type, "evidence_ids": evidence_ids, **extra}


def codes(record, severity="reject"):
    return {d.code for d in record.diagnostics if d.severity == severity}


def check(session, item, **kwargs):
    return admit(item, session, round=1, function_exists=lambda name: name.startswith("FUN_0000"), peripherals=[PERIPHERAL], **kwargs)


# -- A: malformed subject (the C10 failure) ---------------------------------------------


def test_a_c10_is_rejected_with_an_entity_diagnostic_and_never_enters_the_ledger(world):
    new = first_new_evidence(world)
    ids = ",".join(f"E{n}" for n in range(1, new + 2))
    planner = Planner([("follow", CALLERS[0][0]), ("follow", CALLERS[1][0])], claims=C10.format(ids=ids))
    claims_before = len(world.ledger.all_claim_versions())
    run, _executor, _session, _ = follow_up(world, planner, max_steps=2)
    first = run.claim_admission[0]

    assert run.claim_versions == [] and len(world.ledger.all_claim_versions()) == claims_before
    assert first.decision == "rejected" and first.raw.startswith("STRONG BEHAVIOR")
    malformed = next(d for d in first.diagnostics if d.code == "ENTITY_MALFORMED")
    assert malformed.value == "E0000b4b4" and "does not reinterpret" in malformed.detail
    assert {"UNTYPED_GRADE"} <= codes(first)
    # One bounded correction round; the identical answer is rejected again.
    assert [r.round for r in run.claim_admission] == [1, 2]
    assert [r["phase"] for r in run.planner_requests].count("claim-correction") == 1
    # The investigation evidence is recorded regardless.
    assert len(run.evidence_ids) == 2


def test_a_verifier_blocks_a_malformed_identifier_in_an_operator_claim(world):
    evidence = world.run_a.evidence_ids[0]
    claim = world.ledger.propose_claim(
        subject="E0000b4b4", assertion="E0000b4b4 loads the peripheral base.", claim_type="OTHER", proposed_grade="PROBABLE",
        proposed_by="operator", supporting_evidence_ids=[evidence],
    )
    outcome = ClaimVerifier(world.ledger, context=world.context(), replay=False).precheck(claim.key)
    entity = next(c for c in outcome.record.checks if c.name == "entity_identity")

    assert not entity.passed and "E0000b4b4" in entity.detail
    assert outcome.record.outcome == ClaimState.BLOCKED


def test_a_evidence_ids_used_as_subjects_are_rejected(world):
    # The live benchmark's admitted-by-mistake form: the subject is a session evidence id.
    _run, session, new = session_after_callers(world)
    census = alias(session, "census_peripheral_usage", peripheral=PERIPHERAL)
    record = check(session, proposal(f"E{new} loads the {PERIPHERAL} base address and E{new} does not show direct access.", [census, f"E{new}", f"E{new + 1}"]))

    assert record.decision == "rejected"
    assert [d.value for d in record.diagnostics if d.code == "ENTITY_SESSION_REFERENCE"] == [f"E{new}"]


# -- B: constant load is not an access ------------------------------------------------------


def test_b_prose_access_from_a_constant_load_is_not_established(world):
    _run, session, _new = session_after_callers(world)
    census = alias(session, "census_peripheral_usage", peripheral=PERIPHERAL)
    record = check(session, proposal(f"{GAP} accesses {PERIPHERAL} registers.", [census]))

    assert "ACCESS_NOT_ESTABLISHED" in codes(record)
    detail = next(d for d in record.diagnostics if d.code == "ACCESS_NOT_ESTABLISHED")
    assert "literal-pool load" in detail.detail and detail.basis == "pattern-matched"


def test_b_typed_mmio_user_needs_an_access_not_a_constant_load(world):
    _run, session, _new = session_after_callers(world)
    census = alias(session, "census_peripheral_usage", peripheral=PERIPHERAL)
    role = {"predicate": "FUNCTION_ROLE", "function_role": {"function": GAP, "role": "MMIO_USER", "peripheral": PERIPHERAL}}
    record = check(session, proposal(f"{GAP} uses {PERIPHERAL}.", [census], grade="STRONG", semantics=role))

    assert record.decision == "rejected"
    assert any(d.code == "SEMANTICS_INCONSISTENT" and "ADDRESS_CONSTANT_LOADER" in d.detail for d in record.diagnostics)

    loader = {"predicate": "FUNCTION_ROLE", "function_role": {"function": GAP, "role": "ADDRESS_CONSTANT_LOADER", "peripheral": PERIPHERAL}}
    callers = [o.id for o in session.ledger.all() if o.tool == "callsite_context"]
    assert check(session, proposal(f"{GAP} loads the {PERIPHERAL} base address.", [census, *callers], grade="STRONG", semantics=loader)).decision == "admitted"


def test_b_effects_mmio_access_establishes_access(world):
    _run, session, _new = session_after_callers(world, mmio=True)
    # GAP's effects are preloaded from run A (no MMIO); fresh evidence with an MMIO write:
    observation = SerialExecutor(mmio=True).execute_operation("function_effects", {"function": GAP, "specialize": {"r0": 0x40009000}}, evidence_id=session.ledger.next_id())
    observation.result["accesses"][-1]["register_name"] = f"{PERIPHERAL}.CTRLA"
    session.record(observation)
    callers = [o.id for o in session.ledger.all() if o.tool == "callsite_context"]
    record = check(session, proposal(f"{GAP} writes {PERIPHERAL} registers when r0 is the {PERIPHERAL} base.", [observation.id, *callers]))

    assert "ACCESS_NOT_ESTABLISHED" not in codes(record)


# -- C: unresolved symbolic input --------------------------------------------------------------


def test_c_categorical_absence_with_symbolic_r0_is_not_established(world):
    _run, session, _new = session_after_callers(world)
    effects = alias(session, "function_effects", function=GAP)
    callers = [o.id for o in session.ledger.all() if o.tool == "callsite_context"]
    record = check(session, proposal(f"{GAP} does not read or write {PERIPHERAL} registers.", [effects, *callers]))

    assert record.decision == "rejected" and "ABSENCE_NOT_ESTABLISHED" in codes(record)
    detail = next(d for d in record.diagnostics if d.code == "ABSENCE_NOT_ESTABLISHED").detail
    assert "depend on r0" in detail and "not established" in detail


# -- D: evidence accountability ------------------------------------------------------------------


def test_d_omitting_executed_caller_evidence_is_reported(world):
    _run, session, new = session_after_callers(world)
    census = alias(session, "census_peripheral_usage", peripheral=PERIPHERAL)
    record = check(session, proposal(f"{GAP} loads the {PERIPHERAL} base address.", [census]))
    omitted = next(d for d in record.diagnostics if d.code == "EVIDENCE_OMITTED")

    assert record.decision == "rejected"
    assert omitted.evidence_ids == [f"E{new}", f"E{new + 1}"]
    assert "[omit E#: reason]" in omitted.detail


def test_d_an_explained_omission_satisfies_accountability_but_not_a_contradiction(world):
    _run, session, new = session_after_callers(world)
    census = alias(session, "census_peripheral_usage", peripheral=PERIPHERAL)
    reason = {f"E{new}": "call sites do not bear on the constant load", f"E{new + 1}": "same"}
    explained = check(session, proposal(f"{GAP} loads the {PERIPHERAL} base address.", [census], omissions=reason))

    assert explained.decision == "admitted" and "OMISSION_EXPLAINED" in codes(explained, "note")

    # The same omission note does not rescue an assertion the evidence does not support.
    unsupported = check(session, proposal(f"{GAP} accesses {PERIPHERAL} registers.", [census], omissions=reason))
    assert unsupported.decision == "rejected" and "ACCESS_NOT_ESTABLISHED" in codes(unsupported)


# -- E: historical evidence ----------------------------------------------------------------------


def test_e_reused_evidence_keeps_its_original_identity_and_is_noted(world):
    new = first_new_evidence(world)
    planner = Planner(
        [("follow", CALLERS[0][0])],
        claims=f"PROBABLE STRUCTURE E1,E{new} {GAP} loads the {PERIPHERAL} base address.",
    )
    run, _executor, session, _ = follow_up(world, planner, max_steps=1)
    record = run.claim_admission[0]
    original = session.ledger.get("E1").reused_from

    assert record.decision == "admitted" and record.claim_version == run.claim_versions[0]
    assert record.durable_evidence_ids[0] == original and original.startswith("EV-")
    note = next(d for d in record.diagnostics if d.code == "HISTORICAL_REFERENCE")
    assert note.evidence_ids == [original] and "not new observations" in note.detail
    assert world.ledger.claim(run.claim_versions[0]).supporting_evidence_ids[0] == original
    assert original not in run.evidence_ids


# -- F: a limited hypothesis stays admissible ---------------------------------------------------------


def test_f_scoped_hypothesis_is_admitted_as_proposed_and_not_verified(world):
    new = first_new_evidence(world)
    effects_alias = "E2"  # preload order: census, effects, ...
    hypothesis = (
        f"PROBABLE BEHAVIOR {effects_alias},E{new},E{new + 1} {GAP} has no observed {PERIPHERAL} register access in the recorded "
        "symbolic analysis; the r0 values its callers pass are unresolved."
    )
    run, _executor, session, _ = follow_up(world, Planner([("follow", CALLERS[0][0]), ("follow", CALLERS[1][0])], claims=hypothesis), max_steps=2)
    assert session.ledger.get(effects_alias).tool == "function_effects"
    record = run.claim_admission[0]

    assert record.decision == "admitted", record.diagnostics
    assert "ABSENCE_SCOPED" in codes(record, "note")
    key = run.claim_versions[0]
    assert world.ledger.state(key) == ClaimState.PROPOSED

    outcome = ClaimVerifier(world.ledger, context=world.context(), replay=False).precheck(key)
    assert outcome.record.outcome != ClaimState.VERIFIED


# -- G/H: USB and EIC controls through admission ------------------------------------------------------


def usb_session():
    registry = LeadRegistry()
    session = ResearchSession(objective="USB", registry=registry, follower=LeadFollower(registry=registry, executor=FakeExecutor()))
    session.record(EvidenceObservation(id="E1", tool="census_usb_inventory", arguments={}, result=usb_inventory()))
    session.record(FakeExecutor().execute_operation("census_peripheral_usage", {"peripheral": "EIC", "limit": 25}, evidence_id="E2"))
    return session


def test_g_known_bad_usb_and_eic_claims_stay_blocked():
    session = usb_session()
    writer_as_target = {"predicate": "FUNCTION_ROLE", "function_role": {"function": "FUN_0000ccc4", "role": "CALLBACK_TARGET"}}
    bad = admit(proposal("The USB callback target is FUN_0000ccc4.", ["E1"], grade="STRONG", claim_type="RESOLUTION", semantics=writer_as_target), session, round=1)
    scope = {"predicate": "PATH_RELATION", "path": {"status": "NO_KNOWN_PATH", "left": "IRQ_ROOT_SET:EIC", "right": "INTERFACE_INVENTORY:USB"}}
    eic = admit(proposal("No path from EIC handlers to USB.", ["E1", "E2"], grade="PROBABLE", claim_type="NO_KNOWN_PATH", semantics=scope), session, round=1)

    assert bad.decision == "rejected" and any("ENTITY_ROLE_MISMATCH" in d.detail for d in bad.diagnostics)
    assert eic.decision == "rejected" and any(d.code == "SEMANTICS_INCONSISTENT" for d in eic.diagnostics)


def test_h_known_good_usb_claim_is_admitted_at_its_typed_grade():
    session = usb_session()
    pointer = {"predicate": "RESOLVED_FUNCTION_POINTER", "resolved_pointer": {"slot": "0x200052e8", "canonical_target": "0x0000c724", "writer": "FUN_0000ccc4"}}
    good = admit(
        proposal("The RAM slot 0x200052e8 resolves to 0x0000c724, written by FUN_0000ccc4.", ["E1"], grade="STRONG", claim_type="RESOLUTION", semantics=pointer),
        session, round=1,
    )

    assert good.decision == "admitted", good.diagnostics
    assert not codes(good)


# -- I: invalid model responses ------------------------------------------------------------------------


def test_i_invalid_semantics_and_garbage_are_recorded_and_bounded(world):
    junk = "not a claim at all\nSTRONG E99 FUN_00001000 nonsense"
    planner = Planner([("finish",)], claims=junk)
    run, _executor, _session, _ = follow_up(world, planner, max_steps=2)

    assert run.claim_versions == []
    assert [r.decision for r in run.claim_admission] == ["unparseable", "rejected"] * 2
    assert "EVIDENCE_REFERENCE_UNKNOWN" in codes(run.claim_admission[1])
    assert len(run.planner_requests) <= 4

    session = usb_session()
    broken = admit(proposal("x", ["E1"], semantics={"predicate": "FUNCTION_ROLE"}), session, round=1)
    assert broken.decision == "rejected" and "SEMANTICS_INVALID" in codes(broken)


def test_i_dict_claims_with_semantics_reach_admission_unchanged():
    items = [{"assertion": "a", "grade": "strong", "evidence_ids": ["E1"], "semantics": {"predicate": "X"}, "omissions": {"e2": "r"}}]
    parsed = ResearchController._sanitize_claims(items)[0]

    assert parsed["semantics"] == {"predicate": "X"} and parsed["omissions"] == {"E2": "r"}
    assert json.loads(parsed["raw"])["grade"] == "strong"


# -- J: backward compatibility -------------------------------------------------------------------------


def test_j_persisted_records_load_unchanged_and_carry_no_malformed_identifiers():
    root = Path(__file__).resolve().parents[2] / "cases" / "performing-rigs" / "research" / "ledger"

    if not (root / "claims").is_dir():
        pytest.skip("case ledger not present")

    ledger = ResearchLedger(root)

    for claim in ledger.all_claim_versions():
        assert entity_diagnostics(f"{claim.subject} {claim.assertion}") == [], claim.key

    # The case ledger holds runs from before and after claim admission
    # existed: each must round-trip unchanged, and recorded admission
    # decisions must agree with the claim versions the run created.
    for run in ledger.runs():
        raw = json.loads((root / "runs" / f"{run.run_id}.json").read_text())
        assert InvestigationRun.model_validate(raw).model_dump(mode="json") == raw

        for decision in run.claim_admission or ():
            assert (decision.claim_version in run.claim_versions) == (decision.decision == "admitted"), run.run_id


def _run_record(**extra):
    base = InvestigationRun(
        run_id="R-test", case="test", firmware_key="fw", firmware_sha256="0" * 64, context_id="X",
        objective="o", started_at="t0", ended_at="t1", termination_reason="finished",
    ).model_dump(mode="json")
    return {**base, **extra}


ADMISSION = {
    "round": 1, "raw": "PROBABLE E1 a", "decision": "admitted", "assertion": "a", "grade": "PROBABLE",
    "claim_type": "BEHAVIOR", "evidence_ids": ["E1"], "durable_evidence_ids": ["V-1"], "omissions": {},
    "diagnostics": [], "claim_version": "C1:v1",
}


def test_j_runs_with_and_without_claim_admission_round_trip_and_malformed_admission_is_rejected(tmp_path):
    good = {"R-old": _run_record(run_id="R-old"), "R-new": _run_record(run_id="R-new", claim_versions=["C1:v1"], claim_admission=[ADMISSION])}

    for run_id, raw in good.items():
        (tmp_path / "runs").mkdir(exist_ok=True)
        (tmp_path / "runs" / f"{run_id}.json").write_text(json.dumps(raw))

    loaded = {run.run_id: run.model_dump(mode="json") for run in ResearchLedger(tmp_path).runs()}
    assert loaded == good
    assert "claim_admission" not in loaded["R-old"]

    malformed = [
        {**ADMISSION, "unexpected": 1},
        {k: v for k, v in ADMISSION.items() if k != "decision"},
        {**ADMISSION, "round": "first"},
    ]

    for admission in malformed:
        (tmp_path / "runs" / "R-bad.json").write_text(json.dumps(_run_record(run_id="R-bad", claim_admission=[admission])))

        with pytest.raises(ValueError):
            ResearchLedger(tmp_path).runs()
