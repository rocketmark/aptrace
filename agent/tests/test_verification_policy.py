"""
Verification-policy gate (phase P): contradictions, structural conflicts,
and independent corroboration are evaluated mechanically before any audit
model, and no path to VERIFIED bypasses them.
"""

import argparse
import copy
import json

import pytest

from aptrace_agent import ledger_cli
from aptrace_agent.ledger.auditor import AuditBudget, ClaimAuditor
from aptrace_agent.ledger.gate import PolicyGateEvaluator, assess_policy, structural_addresses
from aptrace_agent.ledger.hashing import digest
from aptrace_agent.ledger.models import ClaimState, LifecycleEvent, VerificationCheck, VerificationRecord
from aptrace_agent.ledger.pipeline import audit_if_eligible
from aptrace_agent.ledger.policy import POLICY_ID, POLICY_VERSION, current_policy, policy_definition
from aptrace_agent.ledger.store import ResearchLedger, new_id
from aptrace_agent.ledger.verifier import ClaimVerifier

from ledger_support import FIRMWARE, INDEPENDENT_ENVELOPE, USB_EDGE, ScriptedAuditModel, irq_handlers, request, stack, verdict


SLOT = "0x200052e8"


def _auditor(ledger, runner, decisions):
    client = ScriptedAuditModel(decisions)
    auditor = ClaimAuditor(
        ledger=ledger, runner=runner, client=client, model="gemma-test",
        budget=AuditBudget(max_decisions=5, max_tool_requests=4),
        peripherals=["EIC"], irq_handlers=irq_handlers, retry_delay=0,
    )
    return auditor, client


def _supported(ledger, runner, function="FUN_0000bc44"):
    return _auditor(ledger, runner, [request("function_facts", function=function), verdict("SUPPORTED")])


def _agreement(runner, *addresses):
    _inv, artifact = runner.run("R-setup", "structural_source_agreement", {"addresses": list(addresses)})
    return artifact


def _code_claim(ledger, runner, executor, *, address="0x0000bcda", entry="0x0000bc44", envelope=INDEPENDENT_ENVELOPE, contradictory=()):
    executor.envelope = copy.deepcopy(envelope) if envelope is not None else {}
    agreement = _agreement(runner, address)
    return ledger.propose_claim(
        subject=f"code at {address}", assertion=f"Code exists at {address} in the function at {entry}.",
        claim_type="STRUCTURE", proposed_grade="STRONG", proposed_by="test",
        supporting_evidence_ids=[agreement.evidence_id], contradictory_evidence_ids=list(contradictory),
        semantics={"predicate": "CODE_PRESENCE", "code_presence": {"address": address, "function_entry": entry}},
    )


def _pointer_claim(ledger, runner, *, contradictory=(), **fields):
    _inv, usb = runner.run("R-setup", "census_usb_inventory", {})
    return ledger.propose_claim(
        subject="USB callback", assertion="Slot 0x200052e8 resolves to 0x0000c724.", claim_type="RESOLUTION",
        proposed_grade="STRONG", proposed_by="test", supporting_evidence_ids=[usb.evidence_id],
        contradictory_evidence_ids=list(contradictory),
        semantics={"predicate": "RESOLVED_FUNCTION_POINTER", "resolved_pointer": {"slot": SLOT, "canonical_target": "0xc724", **fields}},
    )


def _drifted_usb(runner, executor, **edge):
    """Record census_usb_inventory evidence whose edge differs, then restore."""

    executor.drift["census_usb_inventory"] = {"resolved_indirect_edges": [{**USB_EDGE, **edge}]}
    _inv, artifact = runner.run("R-setup", "census_usb_inventory", {})
    executor.drift.pop("census_usb_inventory")
    return artifact


def _codes(gate, *statuses):
    return [c.code for c in gate.conditions if not statuses or c.status in statuses]


def _gated(ledger, runner, key, decisions=None):
    auditor, client = _auditor(ledger, runner, decisions or [request("function_facts", function="FUN_0000bc44"), verdict("SUPPORTED")])
    gated = audit_if_eligible(key, verifier=ClaimVerifier(ledger, runner=runner), auditor=auditor)
    return gated, client


# -- 14: positive control -------------------------------------------------------


def test_independently_corroborated_code_claim_still_verifies(tmp_path):
    ledger, executor, _context, runner = stack(tmp_path)
    claim = _code_claim(ledger, runner, executor)

    gated, client = _gated(ledger, runner, claim.key)

    assert client.requests and gated.audit.verdict.value == "SUPPORTED"
    record = gated.verification.record
    assert gated.verification.current == ClaimState.VERIFIED
    assert record.gate.status == "PASSED" and record.gate.claim_class == "CODE_EXISTENCE"
    satisfied = [c for c in record.gate.conditions if c.code == "INDEPENDENT_CORROBORATION"]
    assert satisfied and satisfied[0].status == "SATISFIED" and "macaw" in satisfied[0].detail
    assert ledger.history(claim.key)[-1].refs == [record.verification_id]


# -- 1, 10: material typed contradiction ------------------------------------------


def test_material_pointer_contradiction_blocks_despite_supported_audit(tmp_path):
    ledger, executor, _context, runner = stack(tmp_path)
    contra = _drifted_usb(runner, executor, canonical_target="0x0000c800", raw_value="0x0000c801")
    claim = _pointer_claim(ledger, runner, contradictory=[contra.evidence_id])

    gated, client = _gated(ledger, runner, claim.key)

    assert gated.audit is None and client.requests == []  # model never asked
    assert ledger.state(claim.key) == ClaimState.BLOCKED
    gate = gated.precheck.record.gate
    assert gate.status == "BLOCKED"
    conflict = next(c for c in gate.conditions if c.code == "MATERIAL_CONTRADICTION")
    assert conflict.status == "CONTRADICTED" and conflict.field == "canonical_target"
    assert conflict.evidence_ids == [contra.evidence_id] and "0x0000c800" in conflict.detail

    # A SUPPORTED audit recorded anyway (direct, outside the gated pipeline)
    # cannot override the deterministic blocker.
    auditor, _client = _supported(ledger, runner, function="FUN_0000ccc4")
    auditor.audit(claim.key)
    outcome = ClaimVerifier(ledger, runner=runner).verify(claim.key)
    assert outcome.current == ClaimState.BLOCKED
    assert next(c for c in outcome.record.checks if c.name == "contradictory_evidence").severity == "block"


def test_material_contradiction_blocks_an_otherwise_eligible_claim(tmp_path):
    ledger, executor, _context, runner = stack(tmp_path)
    executor.envelope = INDEPENDENT_ENVELOPE
    executor.non_code = {"macaw": {0xBCDA}}
    contra = _agreement(runner, "0x0000bcda")  # macaw: data at 0xbcda
    executor.non_code = {}
    claim = _code_claim(ledger, runner, executor, contradictory=[contra.evidence_id])

    gated, client = _gated(ledger, runner, claim.key)

    assert client.requests == [] and ledger.state(claim.key) == ClaimState.BLOCKED
    gate = gated.precheck.record.gate
    assert gate.status == "BLOCKED" and _codes(gate, "CONTRADICTED") == ["STRUCTURAL_CONFLICT"]
    assert next(c for c in gate.conditions if c.code == "STRUCTURAL_CONFLICT").kind == "contradiction"
    # Corroboration alone was satisfied: the contradiction is what blocks.
    assert "INDEPENDENT_CORROBORATION" in _codes(gate, "SATISFIED")


# -- 2: potentially material, unclassifiable ---------------------------------------


def test_unclassifiable_contradiction_holds_with_explicit_reason(tmp_path):
    ledger, executor, _context, runner = stack(tmp_path)
    _inv, usb = runner.run("R-setup", "census_usb_inventory", {})  # names 0x0000bcda as a callsite
    claim = _code_claim(ledger, runner, executor, contradictory=[usb.evidence_id])

    gated, client = _gated(ledger, runner, claim.key)

    assert client.requests == [] and ledger.state(claim.key) == ClaimState.PROPOSED
    gate = gated.precheck.record.gate
    assert gate.status == "HELD"
    condition = next(c for c in gate.conditions if c.kind == "contradiction")
    assert condition.code == "CONTRADICTION_UNCLASSIFIABLE" and condition.status == "UNRESOLVED"
    assert "0x0000bcda" in condition.detail and condition.evidence_ids == [usb.evidence_id]


@pytest.mark.parametrize("semantics", [None, "path"])
def test_contradictions_on_unclassifiable_claim_shapes_never_pass(tmp_path, semantics):
    ledger, _executor, _context, runner = stack(tmp_path)
    _inv, usb = runner.run("R-setup", "census_usb_inventory", {})
    _inv, eic = runner.run("R-setup", "census_peripheral_usage", {"peripheral": "EIC"})
    claim = ledger.propose_claim(
        subject="s", assertion="a", claim_type="RESOLUTION" if semantics is None else "NO_KNOWN_PATH", proposed_grade="STRONG",
        proposed_by="test", supporting_evidence_ids=[usb.evidence_id], contradictory_evidence_ids=[eic.evidence_id],
    )
    gate = PolicyGateEvaluator(ledger, firmware_sha256=FIRMWARE, case="performing-rigs").evaluate(claim)

    assert next(c for c in gate.conditions if c.kind == "contradiction").status == "UNRESOLVED"


def test_contradictory_evidence_identity_is_checked(tmp_path):
    ledger, executor, _context, runner = stack(tmp_path)
    _inv, eic = runner.run("R-setup", "census_peripheral_usage", {"peripheral": "EIC"})
    ledger.invalidate_evidence(eic.evidence_id, reason="test")
    claim = _code_claim(ledger, runner, executor, contradictory=[eic.evidence_id])

    foreign = PolicyGateEvaluator(ledger, firmware_sha256="f" * 64, case="performing-rigs").contradiction(claim, eic.evidence_id, None)
    assert [c.code for c in foreign] == ["CONTRADICTION_INCOMPATIBLE_EVIDENCE"] and foreign[0].status == "UNEVALUABLE"

    outcome = ClaimVerifier(ledger, runner=runner).precheck(claim.key)
    assert outcome.record.gate.status == "UNEVALUABLE"
    assert "CONTRADICTION_EVIDENCE_INVALIDATED" in _codes(outcome.record.gate, "UNEVALUABLE")


# -- 3: unrelated contradiction ---------------------------------------------------


def test_unrelated_contradiction_does_not_block(tmp_path):
    ledger, executor, _context, runner = stack(tmp_path)
    _inv, eic = runner.run("R-setup", "census_peripheral_usage", {"peripheral": "EIC"})
    claim = _code_claim(ledger, runner, executor, contradictory=[eic.evidence_id])

    gated, _client = _gated(ledger, runner, claim.key)

    assert gated.verification.current == ClaimState.VERIFIED
    contradiction = next(c for c in gated.verification.record.gate.conditions if c.kind == "contradiction")
    assert contradiction.code == "CONTRADICTION_NOT_MATERIAL" and contradiction.status == "NOT_MATERIAL"


def test_contradiction_about_another_slot_is_not_material_to_a_pointer_claim(tmp_path):
    ledger, executor, _context, runner = stack(tmp_path)
    other = {k: "0x0000e000" for k in ("site", "canonical_target", "terminal_target", "store", "callsite")}
    contra = _drifted_usb(runner, executor, slot="0x20001000", raw_value="0x0000e001", from_function="FUN_0000e000", to_function="FUN_0000e000", writer="FUN_0000e000", **other)
    claim = _pointer_claim(ledger, runner, contradictory=[contra.evidence_id])

    gate = ClaimVerifier(ledger, runner=runner).precheck(claim.key).record.gate

    # Still held (no evidence contract for the class), but not because of it.
    assert next(c for c in gate.conditions if c.kind == "contradiction").status == "NOT_MATERIAL"
    assert gate.status == "UNEVALUABLE" and _codes(gate, "UNEVALUABLE") == ["NO_EVIDENCE_CONTRACT"]


# -- 4, 5: structural conflicts -----------------------------------------------------


def test_material_structural_conflict_blocks_before_audit(tmp_path):
    ledger, executor, _context, runner = stack(tmp_path)
    claim = _code_claim(ledger, runner, executor)
    executor.non_code = {"macaw": {0xBC44}}  # the asserted function entry

    gated, client = _gated(ledger, runner, claim.key)

    assert client.requests == [] and ledger.state(claim.key) == ClaimState.BLOCKED
    gate = gated.precheck.record.gate
    conflict = next(c for c in gate.conditions if c.code == "STRUCTURAL_CONFLICT")
    assert conflict.status == "CONTRADICTED" and conflict.field == "function_entry" and conflict.address == "0x0000bc44"
    assert conflict.evidence_ids == gate.agreement_evidence_ids[-1:]  # the gate's own recorded agreement
    assert ledger.has_evidence(conflict.evidence_ids[0])  # observations preserved as evidence


def test_structural_conflict_at_asserted_pointer_code_blocks(tmp_path):
    ledger, executor, _context, runner = stack(tmp_path)
    claim = _pointer_claim(ledger, runner)
    executor.non_code = {"macaw": {0xC724}}

    outcome = ClaimVerifier(ledger, runner=runner).precheck(claim.key)

    assert outcome.current == ClaimState.BLOCKED and outcome.record.gate.status == "BLOCKED"
    assert next(c for c in outcome.record.gate.conditions if c.code == "STRUCTURAL_CONFLICT").field == "canonical_target"


def test_structural_conflict_outside_claim_scope_does_not_block(tmp_path):
    ledger, executor, _context, runner = stack(tmp_path)
    claim = _code_claim(ledger, runner, executor)
    executor.non_code = {"macaw": {0xC5CC}}
    elsewhere = _agreement(runner, "0x0000c5cc")
    executor.non_code = {}

    gate = PolicyGateEvaluator(ledger, firmware_sha256=FIRMWARE, case="performing-rigs").evaluate(
        claim, corroborating_agreements=claim.supporting_evidence_ids, conflict_agreements=[elsewhere.evidence_id]
    )

    assert gate.status == "PASSED"
    assert next(c for c in gate.conditions if c.code == "STRUCTURAL_CONFLICT_OUT_OF_SCOPE").status == "NOT_MATERIAL"


def test_function_start_discrepancy_on_asserted_containment_holds(tmp_path):
    ledger, executor, _context, runner = stack(tmp_path)
    executor.code["macaw"] = {0xBC80: 0xBD42}  # macaw: 0xbcda is in a function at 0xbc80
    claim = _code_claim(ledger, runner, executor)

    gate = ClaimVerifier(ledger, runner=runner).precheck(claim.key).record.gate

    assert gate.status == "HELD"
    assert "FUNCTION_START_DISCREPANCY" in _codes(gate, "UNRESOLVED")


def test_conflict_without_typed_assertions_is_unresolved_not_ignored(tmp_path):
    ledger, executor, _context, runner = stack(tmp_path)
    executor.non_code = {"macaw": {0xC724}}
    conflict = _agreement(runner, "0x0000c724")
    _inv, usb = runner.run("R-setup", "census_usb_inventory", {})
    claim = ledger.propose_claim(subject="s", assertion="a", claim_type="RESOLUTION", proposed_grade="STRONG",
                                 proposed_by="test", supporting_evidence_ids=[usb.evidence_id])

    gate = PolicyGateEvaluator(ledger, firmware_sha256=FIRMWARE, case="performing-rigs").evaluate(claim, conflict_agreements=[conflict.evidence_id])

    assert "STRUCTURAL_CONFLICT_UNCLASSIFIED" in _codes(gate, "UNRESOLVED") and gate.status == "HELD"


# -- 6, 7, 8: corroboration --------------------------------------------------------


def test_missing_independent_corroboration_holds(tmp_path):
    ledger, executor, _context, runner = stack(tmp_path)
    claim = _code_claim(ledger, runner, executor, address="0x0000c724", entry="0x0000c724")  # macaw coverage gap

    gated, client = _gated(ledger, runner, claim.key)

    assert client.requests == [] and ledger.state(claim.key) == ClaimState.PROPOSED
    condition = next(c for c in gated.precheck.record.gate.conditions if c.kind == "corroboration")
    assert condition.code == "INDEPENDENT_CORROBORATION_MISSING" and condition.status == "UNMET"
    assert "macaw: COVERAGE_GAP" in condition.detail and "shared lineage" in condition.detail


def test_same_lineage_sources_are_not_corroboration(tmp_path):
    ledger, executor, _context, runner = stack(tmp_path)
    executor.code["macaw"] = None  # macaw unavailable: census + ghidra remain
    claim = _code_claim(ledger, runner, executor)

    gate = ClaimVerifier(ledger, runner=runner).precheck(claim.key).record.gate

    condition = next(c for c in gate.conditions if c.kind == "corroboration")
    assert condition.status == "UNMET" and "shared lineage" in condition.detail and "macaw: UNAVAILABLE" in condition.detail


def test_derived_source_cannot_declare_its_way_to_independence(tmp_path):
    ledger, executor, _context, runner = stack(tmp_path)
    executor.code["macaw"] = None
    envelope = copy.deepcopy(INDEPENDENT_ENVELOPE)
    envelope["census"]["lineage"] = ["census"]  # but census is derived_from ghidra
    claim = _code_claim(ledger, runner, executor, envelope=envelope)

    gate = ClaimVerifier(ledger, runner=runner).precheck(claim.key).record.gate

    assert next(c for c in gate.conditions if c.kind == "corroboration").status == "UNMET"


def test_repeated_runs_of_one_engine_are_not_corroboration(tmp_path):
    ledger, executor, _context, runner = stack(tmp_path)
    executor.code["macaw"] = None
    claim = _code_claim(ledger, runner, executor)
    again = _agreement(runner, "0x0000bcda")

    gate = PolicyGateEvaluator(ledger, firmware_sha256=FIRMWARE, case="performing-rigs").evaluate(
        claim, corroborating_agreements=[*claim.supporting_evidence_ids, again.evidence_id]
    )

    assert gate.status == "HELD" and "INDEPENDENT_CORROBORATION_MISSING" in _codes(gate)


@pytest.mark.parametrize(
    "change, code",
    [
        ({}, "INDEPENDENCE_METADATA_MISSING"),  # no envelope at all (today's real sources)
        ({"macaw": {"engine_version": None}}, "INDEPENDENCE_METADATA_MISSING"),
        ({"macaw": {"lineage": []}}, "INDEPENDENCE_METADATA_MISSING"),
        ({"macaw": {"firmware_sha256": "f" * 64}}, "INDEPENDENCE_METADATA_MISSING"),
        ({"macaw": {"assisted": True}}, "INDEPENDENT_CORROBORATION_MISSING"),
    ],
)
def test_insufficient_independence_metadata_never_satisfies(tmp_path, change, code):
    ledger, executor, _context, runner = stack(tmp_path)
    envelope = {} if not change else copy.deepcopy(INDEPENDENT_ENVELOPE)

    for source, fields in change.items():
        envelope[source].update(fields)

    claim = _code_claim(ledger, runner, executor, envelope=envelope)
    gated, client = _gated(ledger, runner, claim.key)

    assert client.requests == [] and ledger.state(claim.key) == ClaimState.PROPOSED
    condition = next(c for c in gated.precheck.record.gate.conditions if c.kind == "corroboration")
    assert condition.code == code
    assert condition.status == ("UNEVALUABLE" if code == "INDEPENDENCE_METADATA_MISSING" else "UNMET")


def test_caller_supplied_provenance_cannot_manufacture_corroboration(tmp_path):
    # Real sources declare no envelope; a caller asserts one in the tool
    # arguments and in a non-agreement result shaped like an agreement.
    ledger, executor, _context, runner = stack(tmp_path)
    forged = {"lineage": ["macaw"], "firmware_sha256": FIRMWARE, "engine_version": "macaw-9", "assisted": False}
    _inv, agreement = runner.run("R-model", "structural_source_agreement", {
        "addresses": ["0x0000bcda"],
        "sources": [{"source": "macaw", **forged}, {"source": "ghidra", **forged, "lineage": ["ghidra"]}],
        "lineage": ["macaw"],
    })
    executor.drift["function_facts"] = {"agreements": agreement and ledger.evidence_result(agreement.evidence_id)[0]["agreements"],
                                        "sources": [{"source": "macaw", **forged}, {"source": "ghidra", **forged, "lineage": ["ghidra"]}]}
    _inv, mimic = runner.run("R-model", "function_facts", {"function": "FUN_0000bc44"})
    claim = ledger.propose_claim(
        subject="code at 0x0000bcda", assertion="Code exists at 0x0000bcda in the function at 0x0000bc44.",
        claim_type="STRUCTURE", proposed_grade="STRONG", proposed_by="model",
        supporting_evidence_ids=[agreement.evidence_id, mimic.evidence_id],
        semantics={"predicate": "CODE_PRESENCE", "code_presence": {"address": "0x0000bcda", "function_entry": "0x0000bc44"}},
    )

    gated, client = _gated(ledger, runner, claim.key)

    assert client.requests == [] and ledger.state(claim.key) == ClaimState.PROPOSED
    assert all("lineage" not in s for s in ledger.evidence_result(agreement.evidence_id)[0]["sources"])
    assert mimic.evidence_id not in gated.precheck.record.gate.agreement_evidence_ids
    condition = next(c for c in gated.precheck.record.gate.conditions if c.kind == "corroboration")
    assert (condition.code, condition.status) == ("INDEPENDENCE_METADATA_MISSING", "UNEVALUABLE")


# -- structural comparison evidence identity --------------------------------------


def _evidence_files(ledger):
    return {p.name: p.read_bytes() for p in (ledger.root / "evidence").glob("*.json")}


def test_repeated_verification_reuses_structural_comparison_evidence(tmp_path):
    ledger, executor, _context, runner = stack(tmp_path)
    claim = _code_claim(ledger, runner, executor)
    verifier = ClaimVerifier(ledger, runner=runner)

    first = verifier.precheck(claim.key).record.gate
    before = _evidence_files(ledger)
    second = verifier.precheck(claim.key).record.gate

    assert len(first.agreement_evidence_ids) == 2  # the claim's own scope and the gate's (address + entry)
    assert first.agreement_evidence_ids == second.agreement_evidence_ids
    assert _evidence_files(ledger) == before


def test_changed_comparison_inputs_produce_new_structural_evidence(tmp_path):
    # The exact operation the gate records, under changed effective inputs.
    ledger, executor, context, runner = stack(tmp_path)
    claim = _code_claim(ledger, runner, executor)
    arguments = {"addresses": structural_addresses(claim)}
    compare = lambda: runner.run(new_id("VG"), "structural_source_agreement", arguments)[1].evidence_id
    baseline = compare()
    before = _evidence_files(ledger)

    assert compare() == baseline
    context.artifacts["ghidra_export"] = "d" * 64  # same result, different input artifact
    changed_input = compare()
    executor.code["macaw"] = None  # same inputs, different comparison result
    changed_result = compare()

    assert len({baseline, changed_input, changed_result}) == 3
    after = _evidence_files(ledger)
    assert {name: after[name] for name in before} == before


def test_failed_structural_analysis_is_unevaluable(tmp_path):
    ledger, executor, _context, runner = stack(tmp_path)
    claim = _code_claim(ledger, runner, executor)
    real = executor.execute_operation

    def failing(tool, arguments, *, evidence_id):
        if tool == "structural_source_agreement" and len(arguments["addresses"]) > 1:
            raise RuntimeError("macaw census missing")
        return real(tool, arguments, evidence_id=evidence_id)

    executor.execute_operation = failing
    gate = ClaimVerifier(ledger, runner=runner).precheck(claim.key).record.gate

    assert "STRUCTURAL_AGREEMENT_FAILED" in _codes(gate, "UNEVALUABLE") and gate.status == "UNEVALUABLE"


@pytest.mark.parametrize(
    "claim_type, semantics, klass",
    [
        ("RESOLUTION", None, "UNDETERMINED"),
        ("BEHAVIOR", None, "UNDETERMINED"),
        ("PATH_EXISTS", None, "CONTROL_FLOW"),
        ("NO_KNOWN_PATH", None, "BOUNDED_NEGATIVE"),
        ("STRUCTURE", {"predicate": "FUNCTION_ROLE", "function_role": {"function": "FUN_0000cc14", "role": "MMIO_USER"}}, "MEMORY_ACCESS"),
        ("STRUCTURE", {"predicate": "FUNCTION_ROLE", "function_role": {"function": "FUN_0000cc14", "role": "INTERRUPT_VECTOR_HANDLER"}}, "VECTOR_MAPPING"),
        ("RESOLUTION", {"predicate": "FUNCTION_ROLE", "function_role": {"function": "FUN_0000ccc4", "role": "WRITER"}}, "RESOLVED_INDIRECT_CALL"),
    ],
)
def test_classes_without_an_evidence_contract_are_unevaluable(tmp_path, claim_type, semantics, klass):
    ledger, _executor, _context, runner = stack(tmp_path)
    _inv, usb = runner.run("R-setup", "census_usb_inventory", {})
    claim = ledger.propose_claim(subject="s", assertion="a", claim_type=claim_type, proposed_grade="STRONG",
                                 proposed_by="test", supporting_evidence_ids=[usb.evidence_id], semantics=semantics)

    gate = PolicyGateEvaluator(ledger, firmware_sha256=FIRMWARE, case="performing-rigs").evaluate(claim)

    assert gate.claim_class == klass and gate.status == "UNEVALUABLE"
    assert _codes(gate, "UNEVALUABLE") == ["CLAIM_CLASS_UNDETERMINED" if klass == "UNDETERMINED" else "NO_EVIDENCE_CONTRACT"]


# -- 9: the gate does not bypass replay, semantics, or audit ---------------------------


def test_passing_gate_does_not_bypass_other_requirements(tmp_path):
    ledger, executor, _context, runner = stack(tmp_path)
    verifier = ClaimVerifier(ledger, runner=runner)

    unaudited = _code_claim(ledger, runner, executor)
    outcome = verifier.verify(unaudited.key)
    assert outcome.record.gate.status == "PASSED" and outcome.current == ClaimState.PROPOSED
    assert [c.name for c in outcome.record.checks if not c.passed] == ["independent_audit"]

    challenged = _code_claim(ledger, runner, executor)
    auditor, _client = _auditor(ledger, runner, [request("function_facts", function="FUN_0000bc44"), verdict("CHALLENGED", challenges=["x"])])
    auditor.audit(challenged.key)
    assert verifier.verify(challenged.key).current == ClaimState.BLOCKED

    wrong_entry = _code_claim(ledger, runner, executor, entry="0x0000bc80")
    outcome = verifier.verify(wrong_entry.key)
    assert outcome.current == ClaimState.BLOCKED and outcome.record.phases["B"] == "failed" and outcome.record.gate is None

    drifting = _code_claim(ledger, runner, executor)
    executor.drift["structural_source_agreement"] = {"status": "changed"}
    assert verifier.verify(drifting.key).current == ClaimState.STALE


# -- direct API: no transition to VERIFIED without a passing policy verification --------


def test_direct_verified_transition_requires_a_passing_policy_record(tmp_path):
    ledger, executor, _context, runner = stack(tmp_path)
    held = _code_claim(ledger, runner, executor, envelope=None)
    record = ClaimVerifier(ledger, runner=runner).verify(held.key).record
    assert record.gate.status == "UNEVALUABLE"

    with pytest.raises(PermissionError):
        ledger.transition(held.key, ClaimState.VERIFIED, actor="aptrace-verifier", reason="bypass", refs=[record.verification_id])

    # A passing verification of another claim cannot be borrowed either.
    good = _code_claim(ledger, runner, executor)
    auditor, _client = _supported(ledger, runner)
    auditor.audit(good.key)
    passing = ClaimVerifier(ledger, runner=runner).verify(good.key).record
    assert passing.outcome == ClaimState.VERIFIED

    with pytest.raises(PermissionError):
        ledger.transition(held.key, ClaimState.VERIFIED, actor="aptrace-verifier", reason="borrow", refs=[passing.verification_id])

    assert ledger.state(held.key) == ClaimState.PROPOSED


# -- 12: CLI and programmatic paths -------------------------------------------------


def _cli(monkeypatch, ledger, executor, runner, decisions):
    auditor, client = _auditor(ledger, runner, decisions)
    monkeypatch.setattr(ledger_cli, "_stack", lambda args: (executor, ledger, runner))
    monkeypatch.setattr(ledger_cli, "_auditor", lambda args, *_a: auditor)
    return client


def test_cli_paths_enforce_the_same_policy(tmp_path, monkeypatch, capsys):
    ledger, executor, _context, runner = stack(tmp_path)
    held = _code_claim(ledger, runner, executor, address="0x0000c724", entry="0x0000c724")  # macaw coverage gap
    good = _code_claim(ledger, runner, executor)
    client = _cli(monkeypatch, ledger, executor, runner, [request("function_facts", function="FUN_0000bc44"), verdict("SUPPORTED")])

    ledger_cli.handle_ledger_command(argparse.Namespace(command="audit", claims=[held.key, good.key], diagnostic=False, ledger_dir=None))
    out = capsys.readouterr().out

    assert len(client.requests) == 2  # only the eligible claim reached the model (request + verdict)
    assert "audit SKIPPED" in out and "verification policy gate HELD" in out
    assert ledger.state(held.key) == ClaimState.PROPOSED and ledger.state(good.key) == ClaimState.VERIFIED

    # Direct verify of the held claim, with a SUPPORTED audit on record.
    auditor, _client = _supported(ledger, runner, function="FUN_0000c724")
    auditor.audit(held.key)
    assert ledger.latest_audit(held.key).verdict.value == "SUPPORTED"
    ledger_cli.handle_ledger_command(argparse.Namespace(command="verify", claims=[held.key], no_replay=False, precheck=False, ledger_dir=None))
    cli_record = ledger.verifications_for(held.key)[-1]
    api_record = ClaimVerifier(ledger, runner=runner).verify(held.key).record

    assert ledger.state(held.key) == ClaimState.PROPOSED
    assert cli_record.policy == api_record.policy == current_policy()
    assert cli_record.gate.status == api_record.gate.status == "HELD"
    assert _codes(cli_record.gate) == _codes(api_record.gate) == ["INDEPENDENT_CORROBORATION_MISSING"]
    assert "gate HELD" in capsys.readouterr().out


# -- 13: policy identity -------------------------------------------------------------


def test_policy_identity_is_recorded_and_reproducible(tmp_path):
    ledger, executor, _context, runner = stack(tmp_path)
    claim = _code_claim(ledger, runner, executor)
    verifier = ClaimVerifier(ledger, runner=runner)

    precheck = verifier.precheck(claim.key).record
    full = verifier.verify(claim.key).record
    stored = json.loads((tmp_path / "ledger" / "verifications" / f"{full.verification_id}.json").read_text())

    policy = current_policy()
    assert (policy.policy_id, policy.version) == (POLICY_ID, POLICY_VERSION)
    assert policy.digest == digest(policy_definition()) == current_policy().digest
    assert precheck.policy == full.policy == full.gate.policy == policy
    assert stored["policy"] == {"policy_id": POLICY_ID, "version": POLICY_VERSION, "digest": policy.digest}

    # Same inputs, same gate (ignoring the fresh agreement evidence id).
    again = verifier.verify(claim.key).record.gate
    strip = lambda gate: [(c.code, c.status, c.field, c.address) for c in gate.conditions]
    assert strip(again) == strip(full.gate) and again.status == full.gate.status


# -- 11: historical decisions -----------------------------------------------------------


def _historical_verified(ledger, key, audit_id):
    """A VERIFIED decision as the pre-policy verifier recorded it."""

    record = ledger.record_verification(VerificationRecord(
        verification_id="V-historical", claim_version=key, at="2026-10-12T00:00:00+00:00", context_id="X-old",
        audit_id=audit_id, checks=[VerificationCheck(name="independent_audit", passed=True, severity="hold", phase="D")],
        outcome=ClaimState.VERIFIED, mode="full", phases={"A": "passed", "B": "passed", "C": "passed", "D": "passed"},
    ))
    ledger._append_event(LifecycleEvent(
        seq=len(ledger.events()) + 1, at="2026-10-12T00:00:01+00:00", subject_kind="claim", subject=key,
        state="VERIFIED", actor="aptrace-verifier", reason="all deterministic checks passed and audit SUPPORTED",
        refs=[record.verification_id],
    ))
    return record


def test_historical_verified_decisions_are_preserved_and_distinguished(tmp_path):
    ledger, _executor, _context, runner = stack(tmp_path)
    claim = _pointer_claim(ledger, runner)
    auditor, _client = _supported(ledger, runner, function="FUN_0000ccc4")
    audit = auditor.audit(claim.key)
    _historical_verified(ledger, claim.key, audit.audit_id)
    root = tmp_path / "ledger"
    snapshot = {p: p.read_bytes() for p in root.rglob("*") if p.is_file()}

    assessment = assess_policy(ledger, claim.key)

    # Read-only: nothing written, state unchanged.
    assert {p: p.read_bytes() for p in root.rglob("*") if p.is_file()} == snapshot
    assert ledger.state(claim.key) == ClaimState.VERIFIED
    assert assessment.verified_by == "V-historical" and assessment.verified_policy is None
    assert not assessment.decision_under_current_policy
    assert assessment.current.status == "UNEVALUABLE" and "before any verification policy" in assessment.summary()

    # A new verification attempt appends; it rewrites nothing.
    events_before = (root / "events.jsonl").read_text()
    outcome = ClaimVerifier(ledger, runner=runner).verify(claim.key)
    assert outcome.previous == ClaimState.VERIFIED and outcome.current == ClaimState.PROPOSED
    assert (root / "events.jsonl").read_text().startswith(events_before)
    assert (root / "verifications" / "V-historical.json").read_bytes() == snapshot[root / "verifications" / "V-historical.json"]
    assert ledger.claim(claim.key) == claim


def test_persisted_case_verifications_predate_the_policy():
    from aptrace_agent.ledger_wiring import DEFAULT_LEDGER_DIR

    if not (DEFAULT_LEDGER_DIR / "verifications").is_dir():
        pytest.skip("no case ledger in this checkout")

    ledger = ResearchLedger(DEFAULT_LEDGER_DIR)

    for key in ("C2:v2", "C5:v1"):
        if not ledger.has_claim(key):
            pytest.skip(f"{key} not in this ledger")

        assessment = assess_policy(ledger, key)
        assert assessment.verified_policy is None and not assessment.decision_under_current_policy
        assert assessment.current.status != "PASSED"
