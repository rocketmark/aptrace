"""Research ledger: persistence, identity, versioning, lifecycle, staleness, report."""

import json

import pytest

from aptrace_agent.ledger.models import ClaimState, InvestigationRun, SourceRevision
from aptrace_agent.ledger.report import render_report, report_is_stale, write_report
from aptrace_agent.ledger.store import LedgerImmutableError, ResearchLedger
from aptrace_agent.ledger.verifier import ClaimVerifier

from ledger_support import FIRMWARE, stack


def _usb_evidence(runner, run_id="R-test-1"):
    _invocation, artifact = runner.run(run_id, "census_usb_inventory", {})
    return artifact


def _claim(ledger, evidence_id, **overrides):
    fields = dict(
        subject="USB callback",
        assertion="The callback at 0x0000cc1a resolves to raw 0x0000c725, canonical 0x0000c724.",
        claim_type="RESOLUTION",
        proposed_grade="STRONG",
        proposed_by="test",
        supporting_evidence_ids=[evidence_id],
    )
    fields.update(overrides)
    return ledger.propose_claim(**fields)


# 1
def test_investigation_run_serialization_round_trip(tmp_path):
    ledger, _executor, context, runner = stack(tmp_path)
    artifact = _usb_evidence(runner)
    run = InvestigationRun(
        run_id="R-test-1",
        case="performing-rigs",
        firmware_key="autopilot868",
        firmware_sha256=FIRMWARE,
        context_id=context().context_id(),
        objective="USB callback",
        model="Qwen3-Coder",
        execution_config={"temperature": 0.0},
        planner_version="controller:abc",
        budgets={"max_steps": 12},
        started_at="2026-10-12T00:00:00+00:00",
        ended_at="2026-10-12T00:01:00+00:00",
        termination_reason="planner_finished",
        parent_run_id="R-parent",
        source=SourceRevision(git_commit="112e166", dirty=True, dirty_fingerprint="f" * 16),
        evidence_ids=[artifact.evidence_id],
        planner_requests=[{"total_bytes": 4200}],
    )
    ledger.record_run(run)

    reloaded = ResearchLedger(ledger.root).run("R-test-1")
    assert reloaded == run
    assert reloaded.execution_config == {"temperature": 0.0}
    assert reloaded.source.dirty_fingerprint == "f" * 16


# 2
def test_tool_invocation_ids_are_stable_and_operation_keys_deterministic(tmp_path):
    ledger, _executor, _context, runner = stack(tmp_path)
    first, artifact = runner.run("R-a", "census_usb_inventory", {})
    again, again_artifact = runner.run("R-b", "census_usb_inventory", {})

    reloaded = ResearchLedger(ledger.root).invocation(first.invocation_id)
    assert reloaded == first
    assert first.invocation_id != again.invocation_id
    assert first.operation_key == again.operation_key
    # Identical operation + identical result -> one content-addressed artifact.
    assert artifact.evidence_id == again_artifact.evidence_id
    assert first.input_artifacts == {"census_db": "a" * 64, "svd": "c" * 64}


# 3
def test_evidence_references_survive_persistence_and_reload(tmp_path):
    ledger, _executor, _context, runner = stack(tmp_path)
    artifact = _usb_evidence(runner)
    claim = _claim(ledger, artifact.evidence_id)

    fresh = ResearchLedger(ledger.root)
    loaded = fresh.claim(claim.key)
    assert loaded.supporting_evidence_ids == [artifact.evidence_id]
    result, ok = fresh.evidence_result(artifact.evidence_id)
    assert ok and result["resolved_indirect_edges"][0]["raw_value"] == "0x0000c725"
    assert fresh.evidence(artifact.evidence_id).grade.value == "STRONG"
    assert fresh.state(claim.key) == ClaimState.PROPOSED


# 4
def test_claim_supersession_creates_new_version(tmp_path):
    ledger, _executor, _context, runner = stack(tmp_path)
    artifact = _usb_evidence(runner)
    v1 = _claim(ledger, artifact.evidence_id)

    v2 = ledger.supersede_claim(v1.key, proposed_by="test", reason="narrow scope", scope="slot 0x200052e8 only")

    assert (v2.claim_id, v2.version, v2.supersedes) == (v1.claim_id, 2, v1.key)
    assert ledger.state(v1.key) == ClaimState.SUPERSEDED
    assert ledger.state(v2.key) == ClaimState.PROPOSED
    assert ledger.claim(v1.claim_id).key == v2.key  # bare id resolves to latest
    # Inherited limitations are recomputed for the new version.
    assert {lim.code for lim in v2.limitations} == {lim.code for lim in v1.limitations}

    with pytest.raises(Exception):
        ledger.supersede_claim(v1.key, proposed_by="test", reason="stale base")


# 5
def test_historical_claim_versions_are_immutable(tmp_path):
    ledger, _executor, _context, runner = stack(tmp_path)
    artifact = _usb_evidence(runner)
    v1 = _claim(ledger, artifact.evidence_id)
    path = ledger.root / "claims" / v1.claim_id / "v1.json"
    before = path.read_text()

    ledger.supersede_claim(v1.key, proposed_by="test", reason="rewording", assertion="Reworded.")

    assert path.read_text() == before
    assert ledger.claim(v1.key).assertion == v1.assertion

    with pytest.raises(LedgerImmutableError):
        ledger._write_once(path, v1.model_copy(update={"assertion": "rewritten history"}))


def test_limitations_carried_by_evidence_are_inherited(tmp_path):
    ledger, _executor, _context, runner = stack(tmp_path)
    artifact = _usb_evidence(runner)
    claim = _claim(ledger, artifact.evidence_id, limitations=[])
    codes = {lim.code for lim in claim.limitations}

    assert "COMPUTED_POINTER_WRITES_NOT_EXCLUDED" in codes
    texts = " ".join(lim.text for lim in claim.limitations)
    assert "computed pointers are not excluded" in texts


# 13
def test_changed_evidence_hash_marks_claim_stale(tmp_path):
    ledger, _executor, _context, runner = stack(tmp_path)
    artifact = _usb_evidence(runner)
    claim = _claim(ledger, artifact.evidence_id)
    blob = ledger.blob_path(artifact.result_sha256)
    data = json.loads(blob.read_text())
    data["resolved_indirect_edges"][0]["raw_value"] = "0x0000ccc5"
    blob.write_text(json.dumps(data))

    outcome = ClaimVerifier(ledger, context=_context(), replay=False).verify(claim.key)

    assert outcome.current == ClaimState.STALE
    assert ledger.evidence_state(artifact.evidence_id) == "INVALIDATED"
    assert any(c.name == "evidence_integrity" and not c.passed for c in outcome.record.checks)


# 15
def test_dependent_claim_becomes_stale_when_dependency_superseded(tmp_path):
    ledger, _executor, _context, runner = stack(tmp_path)
    artifact = _usb_evidence(runner)
    base = _claim(ledger, artifact.evidence_id)
    middle = _claim(ledger, artifact.evidence_id, subject="m", assertion="depends on base", depends_on=[base.key])
    top = _claim(ledger, artifact.evidence_id, subject="t", assertion="depends on middle", depends_on=[middle.key])

    ledger.supersede_claim(base.key, proposed_by="test", reason="corrected")

    assert ledger.state(middle.key) == ClaimState.STALE
    assert ledger.state(top.key) == ClaimState.STALE  # transitive
    assert ledger.history(middle.key)[-1].actor == "aptrace-staleness"


def test_evidence_invalidation_propagates_to_claims_and_dependents(tmp_path):
    ledger, _executor, _context, runner = stack(tmp_path)
    artifact = _usb_evidence(runner)
    _inv, other = runner.run("R-test-1", "census_peripheral_usage", {"peripheral": "EIC", "limit": 25})
    base = _claim(ledger, artifact.evidence_id)
    dependent = _claim(ledger, other.evidence_id, subject="d", assertion="uses base", depends_on=[base.key])

    staled = ledger.invalidate_evidence(artifact.evidence_id, reason="census rebuilt")

    assert staled == [base.key, dependent.key]
    assert ledger.state(dependent.key) == ClaimState.STALE


def test_dangling_dependency_blocks_verification(tmp_path):
    ledger, _executor, context, runner = stack(tmp_path)
    artifact = _usb_evidence(runner)
    claim = _claim(ledger, artifact.evidence_id, depends_on=["C99:v1"])

    outcome = ClaimVerifier(ledger, context=context(), replay=False).verify(claim.key)
    assert outcome.current == ClaimState.BLOCKED
    assert any(c.name == "dependencies_exist" and not c.passed for c in outcome.record.checks)


# 21
def test_generated_report_is_derived_from_ledger(tmp_path):
    ledger, _executor, _context, runner = stack(tmp_path)
    artifact = _usb_evidence(runner)
    claim = _claim(ledger, artifact.evidence_id)
    path = write_report(ledger, tmp_path / "report.md")
    text = path.read_text()

    assert f"## {claim.key} — PROPOSED" in text
    assert artifact.evidence_id in text
    assert "COMPUTED_POINTER_WRITES_NOT_EXCLUDED" in text
    assert ledger.fingerprint() in text
    assert not report_is_stale(ledger, path)

    ledger.supersede_claim(claim.key, proposed_by="test", reason="change")

    assert report_is_stale(ledger, path)
    regenerated = render_report(ledger)
    assert f"## {claim.key} — SUPERSEDED" in regenerated
    assert f"{claim.claim_id}:v2" in regenerated


def test_volatile_execution_metadata_is_not_evidence(tmp_path):
    ledger, executor, _context, runner = stack(tmp_path)
    executor.drift["function_effects"] = {"status": "complete", "provenance": {"analysis": "function_effects", "cached": False}}
    first, fresh = runner.run("R-a", "function_effects", {"function": "FUN_0000cc14", "specialize": {}})
    executor.drift["function_effects"] = {"status": "complete", "provenance": {"analysis": "function_effects", "cached": True}}
    second, cached = runner.run("R-b", "function_effects", {"function": "FUN_0000cc14", "specialize": {}})

    assert fresh.evidence_id == cached.evidence_id
    assert runner.replay(first.invocation_id, run_id="RP").matches
    stored, ok = ledger.evidence_result(fresh.evidence_id)
    assert ok and "cached" not in stored["provenance"]


def test_large_results_use_the_large_blob_tier(tmp_path, monkeypatch):
    import aptrace_agent.ledger.store as store

    monkeypatch.setattr(store, "LARGE_BLOB_BYTES", 64)
    ledger, _executor, context, runner = stack(tmp_path)
    _inv, artifact = runner.run("R-a", "census_usb_inventory", {})
    path = ledger.blob_path(artifact.result_sha256)

    assert path.parent.parent.name == "blobs-large"
    claim = _claim(ledger, artifact.evidence_id)

    # Absent large blob (e.g. a fresh clone): not corruption; replay re-derives it.
    path.unlink()
    without_replay = ClaimVerifier(ledger, context=context(), replay=False).verify(claim.key)
    assert any(c.name == "evidence_available" and not c.passed for c in without_replay.record.checks)
    assert without_replay.current == ClaimState.PROPOSED
    assert ledger.evidence_state(artifact.evidence_id) == "VALID"

    with_replay = ClaimVerifier(ledger, runner=runner).verify(claim.key)
    assert next(c for c in with_replay.record.checks if c.name == "deterministic_replay").passed
    assert ledger.has_blob(artifact.result_sha256)
