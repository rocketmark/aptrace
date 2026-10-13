"""audit-v0.4: compact provenance, source agreement, falsification counting,
audit-input fingerprints, and immutable audit history."""

import json
import shutil

import pytest

from aptrace_agent.ledger import auditor as auditor_module
from aptrace_agent.ledger.auditor import AuditBudget, ClaimAuditor, build_audit_context
from aptrace_agent.ledger.models import AuditVerdict
from aptrace_agent.ledger.stability import stability_summary
from aptrace_agent.ledger.store import LedgerImmutableError, ResearchLedger
from aptrace_agent.ledger_wiring import DEFAULT_LEDGER_DIR

from ledger_support import ScriptedAuditModel, irq_handlers, request, stack, verdict


def _auditor(ledger, runner, decisions, *, model="gemma-test", max_decisions=5):
    client = ScriptedAuditModel(decisions)
    auditor = ClaimAuditor(
        ledger=ledger,
        runner=runner,
        client=client,
        model=model,
        budget=AuditBudget(max_decisions=max_decisions, max_tool_requests=max(1, max_decisions - 1)),
        peripherals=["EIC", "TCC1", "SERCOM2"],
        irq_handlers=irq_handlers,
        retry_delay=0,
    )
    return auditor, client


def _usb_claim(ledger, runner):
    _inv, artifact = runner.run("R-setup", "census_usb_inventory", {})
    claim = ledger.propose_claim(
        subject="USB callback",
        assertion="The callback at 0x0000cc1a resolves to raw 0x0000c725, canonical 0x0000c724.",
        claim_type="RESOLUTION",
        proposed_grade="STRONG",
        proposed_by="test",
        supporting_evidence_ids=[artifact.evidence_id],
    )
    return claim, artifact


def _supported_audit(ledger, runner, claim, **kwargs):
    auditor, _client = _auditor(ledger, runner, [request("function_facts", function="FUN_0000ccc4"), verdict("SUPPORTED")], **kwargs)
    return auditor.audit(claim.key)


# 9, 10
def test_compact_summary_shows_writer_registration_and_raw_canonical_target(tmp_path):
    ledger, _executor, _context, runner = stack(tmp_path)
    claim, _artifact = _usb_claim(ledger, runner)
    audit = _supported_audit(ledger, runner, claim)
    context = audit.initial_context

    assert "consumer: indirect transfer at 0x0000cc1a in FUN_0000cc14 loads RAM slot 0x200052e8" in context
    assert "writer: FUN_0000ccc4, store instruction 0x0000ccc6" in context
    assert "registration: callsite 0x0000bcda in FUN_0000bc44 passes r0 = raw pointer 0x0000c725" in context
    assert "raw pointer 0x0000c725 -> canonical target 0x0000c724 (Thumb bit cleared) = FUN_0000c724" in context
    assert "forwarding: FUN_0000c724 forwards to 0x0000c5cc" in context
    assert "edge grade STRONG" in context
    assert "[COMPUTED_POINTER_WRITES_NOT_EXCLUDED]" in context
    # Without recorded agreement the callsite's function is not invented.
    plain = build_audit_context(ledger, claim)
    assert "registration: callsite 0x0000bcda passes r0" in plain


# 11
def test_compact_summary_includes_recorded_source_agreement(tmp_path):
    ledger, _executor, _context, runner = stack(tmp_path)
    claim, _artifact = _usb_claim(ledger, runner)
    audit = _supported_audit(ledger, runner, claim)
    agreement = ledger.evidence(audit.source_agreement_evidence)

    assert agreement.tool == "structural_source_agreement"
    assert agreement.arguments["addresses"] == ["0x0000bcda", "0x0000c5cc", "0x0000c724", "0x0000cc14", "0x0000cc1a", "0x0000ccc6"]
    assert "STRUCTURAL SOURCE AGREEMENT" in audit.initial_context
    assert "0x0000c724 (canonical pointer target): PARTIAL_AGREEMENT [CONSISTENT]" in audit.initial_context
    assert "MACAW_COVERAGE_GAP" in audit.initial_context
    assert "Only CONFLICT is contradictory structural evidence" in audit.initial_context
    assert len(audit.initial_context) < 9000


# 12
def test_duplicate_rejection_does_not_satisfy_falsification(tmp_path):
    ledger, _executor, _context, runner = stack(tmp_path)
    claim, _artifact = _usb_claim(ledger, runner)
    auditor, _client = _auditor(ledger, runner, [request("analyze_usb_interface"), verdict("SUPPORTED"), request("function_facts", function="FUN_0000ccc4"), verdict("SUPPORTED")])

    audit = auditor.audit(claim.key)

    assert [s.outcome for s in audit.steps] == ["rejected:duplicate", "verdict_rejected", "executed:success", None]
    assert audit.verdict == AuditVerdict.SUPPORTED
    assert audit.falsification["rejected"] == 1 and audit.falsification["successful"] == 1

    only_duplicates, _client = _auditor(ledger, runner, [request("analyze_usb_interface"), request("analyze_usb_interface"), verdict("SUPPORTED")], max_decisions=3)
    loophole = only_duplicates.audit(claim.key)

    assert loophole.verdict == AuditVerdict.UNRESOLVED
    assert loophole.model_verdict == AuditVerdict.SUPPORTED
    assert loophole.verdict_synthesized
    assert loophole.termination_reason == "verdict_without_successful_falsification"
    assert loophole.falsification == {**loophole.falsification, "requested": 2, "rejected": 2, "executed": 0, "successful": 0, "satisfied": False}


# 13
def test_invalid_unavailable_and_malformed_requests_do_not_count(tmp_path):
    ledger, _executor, _context, runner = stack(tmp_path)
    claim, _artifact = _usb_claim(ledger, runner)
    auditor, _client = _auditor(
        ledger,
        runner,
        [request("shell", command="ls"), "not json at all", request("function_facts", function="FUN_0000beef"), verdict("SUPPORTED")],
        max_decisions=3,
    )

    audit = auditor.audit(claim.key)
    outcomes = [s.outcome for s in audit.steps]

    assert outcomes == ["rejected:unavailable_tool", "parse_failure", "rejected:invalid_arguments", None]
    assert not any(s.counts_as_falsification for s in audit.steps)
    assert audit.verdict == AuditVerdict.UNRESOLVED and audit.model_verdict == AuditVerdict.SUPPORTED


# 14
def test_successful_new_tool_execution_counts(tmp_path):
    ledger, _executor, _context, runner = stack(tmp_path)
    claim, _artifact = _usb_claim(ledger, runner)
    audit = _supported_audit(ledger, runner, claim)

    assert audit.verdict == AuditVerdict.SUPPORTED and audit.model_verdict is None
    assert audit.steps[0].outcome == "executed:success" and audit.steps[0].counts_as_falsification
    assert audit.falsification["successful"] == 1 and audit.falsification["satisfied"]


# 15
def test_coverage_gap_counts_as_executed_but_is_not_contradictory(tmp_path):
    ledger, executor, _context, runner = stack(tmp_path)
    claim, artifact = _usb_claim(ledger, runner)
    _inv, extra = runner.run("R-setup", "function_disassembly", {"function": "FUN_0000dead"})
    claim = ledger.propose_claim(
        subject="x", assertion="y", claim_type="RESOLUTION", proposed_grade="STRONG", proposed_by="test",
        supporting_evidence_ids=[artifact.evidence_id, extra.evidence_id],
    )
    auditor, client = _auditor(ledger, runner, [request("function_facts", function="FUN_0000dead"), verdict("SUPPORTED")])

    audit = auditor.audit(claim.key)

    assert audit.steps[0].outcome == "executed:coverage_gap" and audit.steps[0].counts_as_falsification
    assert audit.verdict == AuditVerdict.SUPPORTED
    assert audit.contradictory_evidence == []
    assert audit.falsification["coverage_gap"] == 1
    assert "not contradictory evidence" in client.requests[1][-1]["content"]

    # A harness failure (not a missing entity) is executed but does not count.
    original = executor.execute_operation

    def broken(tool, arguments, *, evidence_id):
        if tool == "function_disassembly":
            raise RuntimeError("decoder crashed")
        return original(tool, arguments, evidence_id=evidence_id)

    executor.execute_operation = broken
    failing, _client = _auditor(ledger, runner, [request("function_disassembly", function="FUN_0000ccc4"), verdict("SUPPORTED")], max_decisions=2)
    harness = failing.audit(claim.key)

    assert harness.steps[0].outcome == "executed:tool_error" and not harness.steps[0].counts_as_falsification
    assert harness.verdict == AuditVerdict.UNRESOLVED


# 16, 17
def test_audit_input_fingerprint_is_deterministic_and_ignores_model_output(tmp_path):
    ledger, _executor, _context, runner = stack(tmp_path)
    claim, _artifact = _usb_claim(ledger, runner)
    first = _supported_audit(ledger, runner, claim)
    auditor, _client = _auditor(ledger, runner, [request("analyze_peripheral", peripheral="TCC1"), verdict("CHALLENGED")])
    second = auditor.audit(claim.key)

    assert first.audit_id != second.audit_id
    assert first.input_fingerprint == second.input_fingerprint
    assert first.input_fingerprint.startswith("AI-")
    assert first.input_components == second.input_components
    assert set(first.input_components) == {
        "claim", "limitations", "evidence", "source_agreement", "context", "template", "model", "generation", "tools", "budget",
    }
    assert first.started_at not in json.dumps(first.input_components)


# 18
def test_changed_evidence_changes_fingerprint(tmp_path):
    ledger, executor, _context, runner = stack(tmp_path)
    claim, artifact = _usb_claim(ledger, runner)
    before = _supported_audit(ledger, runner, claim)

    # The Macaw source now also covers the canonical target.
    executor.code["macaw"][0xC724] = 0xC72A
    after = _supported_audit(ledger, runner, claim)

    assert after.source_agreement_evidence != before.source_agreement_evidence
    assert after.input_fingerprint != before.input_fingerprint
    changed = {k for k in before.input_components if before.input_components[k] != after.input_components[k]}
    assert changed == {"source_agreement", "context"}

    # A claim version with different supporting evidence differs in its evidence component.
    _inv, eic = runner.run("R-setup", "census_peripheral_usage", {"peripheral": "EIC", "limit": 25})
    other = ledger.supersede_claim(claim.key, proposed_by="test", reason="add evidence", supporting_evidence_ids=[artifact.evidence_id, eic.evidence_id])
    third = _supported_audit(ledger, runner, other)
    assert third.input_components["evidence"] != after.input_components["evidence"]


# 19
def test_changed_template_model_or_budget_changes_fingerprint(tmp_path, monkeypatch):
    ledger, _executor, _context, runner = stack(tmp_path)
    claim, _artifact = _usb_claim(ledger, runner)
    base = _supported_audit(ledger, runner, claim)

    other_model = _supported_audit(ledger, runner, claim, model="other-model")
    other_budget = _supported_audit(ledger, runner, claim, max_decisions=4)
    monkeypatch.setattr(auditor_module, "SYSTEM_PROMPT", auditor_module.SYSTEM_PROMPT + "\n- extra rule")
    other_template = _supported_audit(ledger, runner, claim)

    assert other_model.input_components["model"] != base.input_components["model"]
    assert other_budget.input_components["budget"] != base.input_components["budget"]
    assert other_template.input_components["template"] != base.input_components["template"]
    assert len({base.input_fingerprint, other_model.input_fingerprint, other_budget.input_fingerprint, other_template.input_fingerprint}) == 4


# 20
def test_audit_records_are_immutable_history(tmp_path):
    ledger, _executor, _context, runner = stack(tmp_path)
    claim, _artifact = _usb_claim(ledger, runner)
    first = _supported_audit(ledger, runner, claim)
    path = tmp_path / "ledger" / "audits" / f"{first.audit_id}.json"
    original = path.read_bytes()

    with pytest.raises(LedgerImmutableError):
        ledger.record_audit(first.model_copy(update={"verdict": AuditVerdict.CHALLENGED}))

    _supported_audit(ledger, runner, claim)
    assert path.read_bytes() == original
    assert len(ledger.audits_for(claim.key)) == 2


# 21
HISTORICAL = "A-20261012T234455-90a51c"


@pytest.mark.skipif(not (DEFAULT_LEDGER_DIR / "audits" / f"{HISTORICAL}.json").is_file(), reason="case ledger not present")
def test_historical_stale_ghidra_audit_remains_readable(tmp_path):
    root = tmp_path / "ledger"
    shutil.copytree(DEFAULT_LEDGER_DIR, root, ignore=shutil.ignore_patterns("blobs-large"))
    ledger = ResearchLedger(root)
    audit = ledger.audit(HISTORICAL)

    assert audit.template_version == "audit-v0.3"
    assert audit.verdict == AuditVerdict.CHALLENGED
    assert audit.input_fingerprint is None and audit.falsification == {}
    assert all(step.outcome is None for step in audit.steps)
    assert sum("Function not found" in (s.result_summary or "") for s in audit.steps) == 3
    # Unchanged on disk: re-serializing the stored JSON is a no-op compare.
    stored = json.loads((root / "audits" / f"{HISTORICAL}.json").read_text())
    assert stored["audit_id"] == HISTORICAL and "input_fingerprint" not in stored

    summary = stability_summary(ledger.audits_for(audit.claim_version))
    assert summary["groups"][0]["input_fingerprint"] is None


def test_stability_summary_groups_by_fingerprint(tmp_path):
    ledger, _executor, _context, runner = stack(tmp_path)
    claim, _artifact = _usb_claim(ledger, runner)
    audits = [_supported_audit(ledger, runner, claim) for _ in range(3)]
    auditor, _client = _auditor(ledger, runner, [request("function_facts", function="FUN_0000c724"), verdict("CHALLENGED", challenges=["Tool failed to find FUN_0000c724"])])
    audits.append(auditor.audit(claim.key))

    summary = stability_summary(audits)
    group = summary["groups"][0]

    assert len(summary["groups"]) == 1
    assert group["runs"] == 4
    assert group["verdicts"] == {"CHALLENGED": 1, "SUPPORTED": 3}
    assert group["verdict_agreement"] == 0.75
    assert group["tool_sequence_agreement"] == 0.75
    assert group["challenges_citing_coverage_gaps"] == 1
