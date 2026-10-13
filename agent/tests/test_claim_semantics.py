"""Typed claim semantics, phased deterministic verification, and the audit gate."""

import json

import pytest

from aptrace_agent.ledger.auditor import AuditBudget, ClaimAuditor
from aptrace_agent.ledger.claim_semantics import (
    CheckCode,
    ClaimSemantics,
    SetKind,
    SetScope,
    extract_facts,
    verify_semantics,
)
from aptrace_agent.ledger.models import ClaimState, ClaimVersion
from aptrace_agent.ledger.pipeline import audit_if_eligible
from aptrace_agent.ledger.report import render_report
from aptrace_agent.ledger.verifier import ClaimVerifier

from ledger_support import EIC_STUBS, USB_FUNCTIONS, ScriptedAuditModel, irq_handlers, request, stack, verdict

SLOT = "0x200052e8"


def rfp(**fields):
    return {"predicate": "RESOLVED_FUNCTION_POINTER", "resolved_pointer": {"slot": SLOT, **fields}}


def role(function, value, **context):
    return {"predicate": "FUNCTION_ROLE", "function_role": {"function": function, "role": value, **context}}


def path(status, left, right):
    return {"predicate": "PATH_RELATION", "path": {"status": status, "left": left, "right": right}}


def _usb(ledger, runner, *, agreement=True):
    _inv, usb = runner.run("R-setup", "census_usb_inventory", {})
    ids = [usb.evidence_id]

    if agreement:
        _inv, sa = runner.run("R-setup", "structural_source_agreement", {"addresses": ["0x0000bcda"]})
        ids.append(sa.evidence_id)

    return ids


def _eic_paths(ledger, runner, right_label="EIC"):
    usb_ids = _usb(ledger, runner, agreement=False)
    _inv, eic = runner.run("R-setup", "census_peripheral_usage", {"peripheral": "EIC", "limit": 25})
    right = EIC_STUBS if right_label.startswith("IRQ:") else ["FUN_0000a000", "FUN_0000a03c", "FUN_0000cbb0"]
    _inv, paths = runner.run(
        "R-setup",
        "census_common_paths",
        {"left": list(USB_FUNCTIONS), "right": right, "left_label": "USB", "right_label": right_label},
    )
    return usb_ids + [eic.evidence_id, paths.evidence_id], paths


def _semantic(ledger, ids, semantics, claim_type="RESOLUTION"):
    evidence = [(ledger.evidence(e), ledger.evidence_result(e)[0]) for e in ids]
    return verify_semantics(ClaimSemantics.model_validate(semantics), claim_type, evidence)


def _codes(checks):
    return [c.code for c in checks if not c.passed]


def _claim(ledger, ids, semantics, **overrides):
    fields = dict(
        subject="s", assertion="a", claim_type="RESOLUTION", proposed_grade="STRONG",
        proposed_by="test", supporting_evidence_ids=ids, semantics=semantics,
    )
    fields.update(overrides)
    return ledger.propose_claim(**fields)


# 1, 2, 3
def test_semantics_serialize_and_normalize():
    pointer = ClaimSemantics.model_validate(rfp(writer="0xccc4", raw_pointer="0xC725", canonical_target="FUN_0000c724"))
    function = ClaimSemantics.model_validate(role("0x0000ccc4", "WRITER", slot=SLOT))
    scope = ClaimSemantics.model_validate(path("NO_KNOWN_PATH", "INTERFACE_INVENTORY:usb", "IRQ_ROOT_SET:EIC"))

    assert pointer.resolved_pointer.writer == "FUN_0000ccc4"
    assert pointer.resolved_pointer.canonical_target == "0x0000c724"
    assert function.function_role.function == "FUN_0000ccc4"
    assert str(scope.path.left) == "INTERFACE_INVENTORY:USB"
    assert SetScope.parse("INTERRUPT_DISPATCH_SET:EIC").kind == SetKind.INTERRUPT_DISPATCH_SET

    for item in (pointer, function, scope):
        assert ClaimSemantics.model_validate_json(item.model_dump_json()) == item

    with pytest.raises(ValueError):
        ClaimSemantics.model_validate({"predicate": "FUNCTION_ROLE", "resolved_pointer": {"slot": SLOT}})


def test_claim_version_with_semantics_round_trips_through_the_ledger(tmp_path):
    ledger, _executor, _context, runner = stack(tmp_path)
    claim = _claim(ledger, _usb(ledger, runner), rfp(canonical_target="0xc724"))
    stored = ClaimVersion.model_validate_json((tmp_path / "ledger" / "claims" / claim.claim_id / "v1.json").read_text())

    assert stored.semantics == claim.semantics
    assert ledger.claim(claim.key).semantics.resolved_pointer.canonical_target == "0x0000c724"


# 4, 5, 6
def test_entity_roles_are_checked_against_structured_evidence(tmp_path):
    ledger, _executor, _context, runner = stack(tmp_path)
    ids = _usb(ledger, runner)

    assert _codes(_semantic(ledger, ids, role("FUN_0000ccc4", "WRITER", slot=SLOT))) == []
    assert _codes(_semantic(ledger, ids, role("FUN_0000bc44", "REGISTRATION_CALLER"))) == []

    writer_as_target = _semantic(ledger, ids, role("FUN_0000ccc4", "CALLBACK_TARGET"))
    assert _codes(writer_as_target) == [CheckCode.ENTITY_ROLE_MISMATCH]
    assert (writer_as_target[0].claimed, writer_as_target[0].claimed_role, writer_as_target[0].evidence_role) == ("FUN_0000ccc4", "CALLBACK_TARGET", "WRITER")
    assert writer_as_target[0].evidence_id == ids[0]

    pointer_target = _semantic(ledger, ids, rfp(canonical_target="FUN_0000ccc4"))
    assert _codes(pointer_target) == [CheckCode.ENTITY_ROLE_MISMATCH]
    assert pointer_target[0].evidence_role == "writer"

    target_as_writer = _semantic(ledger, ids, rfp(writer="FUN_0000c724"))
    assert _codes(target_as_writer) == [CheckCode.ENTITY_ROLE_MISMATCH]
    assert target_as_writer[0].evidence_role == "canonical_target"
    assert _codes(_semantic(ledger, ids, role("FUN_0000c724", "WRITER"))) == [CheckCode.ENTITY_ROLE_MISMATCH]


# 7, 8, 9, 10
def test_pointer_relations(tmp_path):
    ledger, _executor, _context, runner = stack(tmp_path)
    ids = _usb(ledger, runner)
    good = rfp(
        writer="FUN_0000ccc4", writer_instruction="0xccc6", registration_caller="FUN_0000bc44", registration_callsite="0xbcda",
        raw_pointer="0xc725", canonical_target="0xc724", forwarding_target="0xc5cc",
    )
    checks = _semantic(ledger, ids, good)

    assert _codes(checks) == [] and len(checks) == 7
    assert {c.field: c.evidence_id for c in checks}["registration_caller"] == ids[1]  # from source agreement
    assert _codes(_semantic(ledger, ids, rfp(raw_pointer="0xc727"))) == [CheckCode.RELATION_MISMATCH]
    assert _codes(_semantic(ledger, ids, rfp(canonical_target="0xc726"))) == [CheckCode.RELATION_MISMATCH]
    assert _codes(_semantic(ledger, ids, rfp(forwarding_target="0xc5ce"))) == [CheckCode.RELATION_MISMATCH]

    swapped = _semantic(ledger, ids, rfp(raw_pointer="0xc724", canonical_target="0xc725"))
    assert set(_codes(swapped)) == {CheckCode.RELATION_MISMATCH}
    assert any("swapped" in c.detail for c in swapped)

    assert _codes(_semantic(ledger, ids, rfp(slot="0x20000000"))) == [CheckCode.RELATION_UNSUPPORTED]
    # Without the agreement evidence the registration caller is not established.
    assert _codes(_semantic(ledger, ids[:1], rfp(registration_caller="FUN_0000bc44"))) == [CheckCode.RELATION_UNSUPPORTED]


# 11, 12, 13
def test_set_scope_is_typed_from_evidence_provenance(tmp_path):
    ledger, _executor, _context, runner = stack(tmp_path)
    ids, paths = _eic_paths(ledger, runner)
    fact = extract_facts([(ledger.evidence(e), ledger.evidence_result(e)[0]) for e in ids]).paths[0]

    assert [str(s) for s in fact.left] == ["INTERFACE_INVENTORY:USB"]
    assert [str(s) for s in fact.right] == ["PERIPHERAL_MMIO_USAGE:EIC"]

    ok = _semantic(ledger, ids, path("KNOWN_COMMON_PATH", "PERIPHERAL_MMIO_USAGE:EIC", "INTERFACE_INVENTORY:USB"), "PATH_EXISTS")
    assert _codes(ok) == [] and ok[0].evidence_id == paths.evidence_id

    dispatch = _semantic(ledger, ids, path("KNOWN_COMMON_PATH", "INTERFACE_INVENTORY:USB", "INTERRUPT_DISPATCH_SET:EIC"), "PATH_EXISTS")
    assert _codes(dispatch) == [CheckCode.SCOPE_MISMATCH]
    assert "PERIPHERAL_MMIO_USAGE:EIC" in dispatch[0].evidence_value


def test_broad_eic_evidence_cannot_verify_dispatch_convergence(tmp_path):
    ledger, _executor, _context, runner = stack(tmp_path)
    ids, _paths = _eic_paths(ledger, runner)
    claim = _claim(
        ledger, ids, path("KNOWN_COMMON_PATH", "INTERRUPT_DISPATCH_SET:EIC", "INTERFACE_INVENTORY:USB"), claim_type="PATH_EXISTS",
    )

    outcome = ClaimVerifier(ledger, runner=runner).verify(claim.key)

    assert outcome.current == ClaimState.BLOCKED
    assert [c.code for c in outcome.record.semantic_checks] == [CheckCode.SCOPE_MISMATCH]
    assert outcome.record.phases == {"A": "passed", "B": "failed", "C": "skipped", "D": "skipped"}
    assert outcome.record.audit_skipped


def test_members_that_differ_from_evidence_sets_are_unattributed(tmp_path):
    ledger, _executor, _context, runner = stack(tmp_path)
    usb_ids = _usb(ledger, runner, agreement=False)
    _inv, paths = runner.run("R-setup", "census_common_paths", {"left": ["FUN_0000954c"], "right": EIC_STUBS, "left_label": "USB", "right_label": "IRQ:EIC"})
    fact = extract_facts([(ledger.evidence(e), ledger.evidence_result(e)[0]) for e in usb_ids + [paths.evidence_id]]).paths[0]

    assert fact.left[0].kind == SetKind.UNATTRIBUTED
    assert any("members differ" in note for note in fact.notes)


# 14
def test_dispatcher_no_known_path_keeps_conservative_semantics(tmp_path):
    ledger, _executor, _context, runner = stack(tmp_path)
    ids, _paths = _eic_paths(ledger, runner, right_label="IRQ:EIC")
    semantics = path("NO_KNOWN_PATH", "INTERFACE_INVENTORY:USB", "IRQ_ROOT_SET:EIC")

    assert _codes(_semantic(ledger, ids, semantics, "NO_KNOWN_PATH")) == []
    assert _codes(_semantic(ledger, ids, path("KNOWN_COMMON_PATH", "INTERFACE_INVENTORY:USB", "IRQ_ROOT_SET:EIC"), "PATH_EXISTS")) == [CheckCode.RELATION_MISMATCH]
    assert CheckCode.PREDICATE_TYPE_MISMATCH in _codes(_semantic(ledger, ids, semantics, "PATH_EXISTS"))

    unreachable = _claim(ledger, ids, semantics, claim_type="NO_KNOWN_PATH", assertion="The EIC handlers are unreachable from USB.")
    outcome = ClaimVerifier(ledger, runner=runner).verify(unreachable.key)
    failed = [c.name for c in outcome.record.checks if not c.passed]
    assert outcome.current == ClaimState.BLOCKED and failed == ["no_unreachability_promotion"]


# 15, 16
def test_grade_ceiling_and_inherited_limitations_still_block(tmp_path):
    ledger, _executor, _context, runner = stack(tmp_path)
    ids = _usb(ledger, runner)
    verifier = ClaimVerifier(ledger, runner=runner)

    exact = _claim(ledger, ids, rfp(canonical_target="0xc724"), proposed_grade="EXACT")
    outcome = verifier.verify(exact.key)
    assert outcome.current == ClaimState.BLOCKED
    assert [c.name for c in outcome.record.checks if not c.passed] == ["grade_ceiling"]

    good = _claim(ledger, ids, rfp(canonical_target="0xc724"))
    dropped = ledger.supersede_claim(good.key, proposed_by="test", reason="drop limitations", limitations=[])
    stored = ClaimVersion.model_validate({**dropped.model_dump(), "version": 3, "limitations": [], "supersedes": dropped.key})
    ledger._write_once(tmp_path / "ledger" / "claims" / stored.claim_id / "v3.json", stored)
    ledger.transition(stored.key, ClaimState.PROPOSED, actor="aptrace-ledger", reason="test: limitations removed")
    outcome = verifier.verify(stored.key)
    assert outcome.current == ClaimState.BLOCKED
    assert "limitations_preserved" in [c.name for c in outcome.record.checks if not c.passed]


def _auditor(ledger, runner, decisions, **kwargs):
    client = ScriptedAuditModel(decisions)
    auditor = ClaimAuditor(
        ledger=ledger, runner=runner, client=client, model="gemma-test",
        budget=AuditBudget(max_decisions=5, max_tool_requests=4),
        peripherals=["EIC", "TCC1"], irq_handlers=irq_handlers, retry_delay=0, **kwargs,
    )
    return auditor, client


# 17, 18
def test_semantic_failure_blocks_before_the_audit_model(tmp_path):
    ledger, _executor, _context, runner = stack(tmp_path)
    ids = _usb(ledger, runner)
    bad = _claim(ledger, ids, role("FUN_0000ccc4", "CALLBACK_TARGET"), proposed_grade="EXACT", assertion="The USB callback target is FUN_0000ccc4 (EXACT).")
    auditor, client = _auditor(ledger, runner, [verdict("SUPPORTED")])

    gated = audit_if_eligible(bad.key, verifier=ClaimVerifier(ledger, runner=runner), auditor=auditor)

    assert gated.audit is None and client.requests == []
    assert ledger.state(bad.key) == ClaimState.BLOCKED
    assert {c.code for c in gated.precheck.record.semantic_checks if not c.passed} == {CheckCode.ENTITY_ROLE_MISMATCH}
    assert {"claim_semantics", "grade_ceiling"} == {c.name for c in gated.precheck.record.checks if not c.passed}
    assert ledger.audits_for(bad.key) == []


def test_valid_claim_proceeds_to_audit_and_lifecycle_decision(tmp_path):
    ledger, _executor, _context, runner = stack(tmp_path)
    good = _claim(ledger, _usb(ledger, runner), rfp(writer="FUN_0000ccc4", raw_pointer="0xc725", canonical_target="0xc724"))
    auditor, client = _auditor(ledger, runner, [request("function_facts", function="FUN_0000ccc4"), verdict("SUPPORTED")])

    gated = audit_if_eligible(good.key, verifier=ClaimVerifier(ledger, runner=runner), auditor=auditor)

    assert gated.precheck.record.mode == "precheck" and gated.precheck.current == ClaimState.PROPOSED
    assert gated.precheck.record.phases == {"A": "passed", "B": "passed", "C": "passed", "D": "skipped"}
    assert client.requests and gated.audit.verdict.value == "SUPPORTED"
    assert "STRUCTURED SEMANTICS" in gated.audit.initial_context and "CONSISTENT" in gated.audit.initial_context
    assert gated.verification.current == ClaimState.VERIFIED


# 19
def test_diagnostic_audits_are_recorded_but_never_counted(tmp_path):
    ledger, _executor, _context, runner = stack(tmp_path)
    ids = _usb(ledger, runner)
    good = _claim(ledger, ids, rfp(canonical_target="0xc724"))
    auditor, _client = _auditor(ledger, runner, [request("function_facts", function="FUN_0000ccc4"), verdict("SUPPORTED")])
    first = audit_if_eligible(good.key, verifier=ClaimVerifier(ledger, runner=runner), auditor=auditor).audit
    original = (tmp_path / "ledger" / "audits" / f"{first.audit_id}.json").read_bytes()

    diag, _client = _auditor(ledger, runner, [request("function_facts", function="FUN_0000c724"), verdict("CHALLENGED")])
    diagnostic = diag.audit(good.key, diagnostic=True)
    outcome = ClaimVerifier(ledger, runner=runner).verify(good.key)

    assert diagnostic.diagnostic and outcome.current == ClaimState.VERIFIED
    assert outcome.record.audit_id == first.audit_id
    assert (tmp_path / "ledger" / "audits" / f"{first.audit_id}.json").read_bytes() == original


# 20
def test_successor_version_preserves_supersession_and_history(tmp_path):
    ledger, _executor, _context, runner = stack(tmp_path)
    ids = _usb(ledger, runner)
    v1 = _claim(ledger, ids[:1], None)
    auditor, _client = _auditor(ledger, runner, [request("function_facts", function="FUN_0000ccc4"), verdict("CHALLENGED")])
    old = auditor.audit(v1.key)
    v2 = ledger.supersede_claim(v1.key, proposed_by="test", reason="typed semantics", supporting_evidence_ids=ids, semantics=rfp(canonical_target="0xc724"))

    assert v2.key == f"{v1.claim_id}:v2" and v2.supersedes == v1.key
    assert ledger.claim(v1.key).semantics is None and v2.semantics is not None
    assert ledger.state(v1.key) == ClaimState.SUPERSEDED
    assert [a.audit_id for a in ledger.audits_for(v1.key)] == [old.audit_id] and ledger.audits_for(v2.key) == []


# 21, 22
def test_semantic_results_persist_and_are_reported(tmp_path):
    ledger, _executor, _context, runner = stack(tmp_path)
    bad = _claim(ledger, _usb(ledger, runner), role("FUN_0000ccc4", "CALLBACK_TARGET"), proposed_grade="EXACT")
    record = ClaimVerifier(ledger, runner=runner).verify(bad.key).record
    stored = json.loads((tmp_path / "ledger" / "verifications" / f"{record.verification_id}.json").read_text())

    assert stored["semantic_checks"][0]["code"] == "ENTITY_ROLE_MISMATCH"
    assert stored["semantic_checks"][0]["evidence_role"] == "WRITER"
    assert ledger.verifications_for(bad.key)[-1].semantic_checks == record.semantic_checks

    report = render_report(ledger)
    assert "FUNCTION_ROLE(FUN_0000ccc4 is CALLBACK_TARGET)" in report
    assert "Semantic check `ENTITY_ROLE_MISMATCH`" in report
    assert "Audit model not consulted" in report
    assert "grade_ceiling" in report


# 23, 26
def test_fingerprint_covers_semantics_and_explicit_generation(tmp_path):
    ledger, _executor, _context, runner = stack(tmp_path)
    ids = _usb(ledger, runner)
    a = _claim(ledger, ids, rfp(canonical_target="0xc724"))
    b = ledger.supersede_claim(a.key, proposed_by="test", reason="add field", semantics=rfp(canonical_target="0xc724", raw_pointer="0xc725"))

    def audit(key, **kwargs):
        auditor, _client = _auditor(ledger, runner, [request("function_facts", function="FUN_0000ccc4"), verdict("UNRESOLVED")], **kwargs)
        return auditor.audit(key)

    first, second = audit(a.key), audit(b.key)
    assert first.input_components["claim"] != second.input_components["claim"]

    explicit = audit(b.key, generation={"top_k": 1, "seed": 0})
    assert explicit.input_components["generation"] != second.input_components["generation"]
    assert explicit.input_fingerprint != second.input_fingerprint
    assert explicit.budgets["max_tokens"] == second.budgets["max_tokens"]


def test_semantic_benchmark_fixture_blocks_bad_claims_deterministically(tmp_path):
    from aptrace_agent.ledger.benchmark import run_benchmark
    from aptrace_agent.ledger_wiring import BENCHMARK_DIR

    ledger, _executor, _context, runner = stack(tmp_path)
    result = run_benchmark("semantic-usb-eic", directory=BENCHMARK_DIR, ledger=ledger, runner=runner, auditor=None, irq_handlers=irq_handlers)
    outcomes = {o.label: o for o in result.claims}

    assert all(o.passed is not False for o in outcomes.values()), {k: o.expectations for k, o in outcomes.items()}
    assert outcomes["good"].final_state == "PROPOSED" and outcomes["good"].semantic_codes == []
    assert outcomes["bad"].semantic_codes == ["ENTITY_ROLE_MISMATCH"] and outcomes["bad"].audit_skipped
    assert outcomes["eic_dispatch_convergence"].semantic_codes == ["SCOPE_MISMATCH"]
