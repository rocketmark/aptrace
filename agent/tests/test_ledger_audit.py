"""Adversarial audit contract, deterministic verification, and benchmarks."""

import json
from types import SimpleNamespace

import pytest

from aptrace_agent.ledger.auditor import (
    AuditBudget,
    AuditToolbox,
    ClaimAuditor,
    ToolRejected,
    build_audit_context,
    parse_decision,
)
from aptrace_agent.ledger.benchmark import run_benchmark
from aptrace_agent.ledger.models import AuditVerdict, ClaimState
from aptrace_agent.ledger.recorder import record_investigation
from aptrace_agent.ledger.store import ResearchLedger
from aptrace_agent.ledger.verifier import ClaimVerifier
from aptrace_agent.ledger_wiring import BENCHMARK_DIR
from aptrace_agent.research import ResearchController, ResearchRunResult, ResearchState, ResearchStep
from aptrace_agent.schemas import EvidenceObservation

from ledger_support import ScriptedAuditModel, irq_handlers, request, stack, verdict


def _auditor(ledger, runner, decisions, **kwargs):
    model = ScriptedAuditModel(decisions)
    auditor = ClaimAuditor(
        ledger=ledger,
        runner=runner,
        client=model,
        model="gemma-test",
        peripherals=["EIC", "TCC1", "SERCOM2"],
        irq_handlers=irq_handlers,
        retry_delay=0,
        **kwargs,
    )
    return auditor, model


def _usb_claim(ledger, runner, **overrides):
    _inv, artifact = runner.run("R-setup", "census_usb_inventory", {})
    fields = dict(
        subject="USB callback",
        assertion="The callback at 0x0000cc1a resolves to raw 0x0000c725, canonical 0x0000c724.",
        claim_type="RESOLUTION",
        proposed_grade="STRONG",
        proposed_by="test",
        supporting_evidence_ids=[artifact.evidence_id],
    )
    fields.update(overrides)
    return ledger.propose_claim(**fields), artifact


# 6
def test_audit_run_is_persisted_and_inspectable_without_rerun(tmp_path):
    ledger, _executor, _context, runner = stack(tmp_path)
    claim, artifact = _usb_claim(ledger, runner)
    auditor, _model = _auditor(
        ledger, runner, [request("inspect_evidence", evidence_id=artifact.evidence_id, field="resolved_indirect_edges"), verdict("SUPPORTED")]
    )

    audit = auditor.audit(claim.key)
    reloaded = ResearchLedger(ledger.root).audit(audit.audit_id)

    assert reloaded == audit
    assert reloaded.claim_version == claim.key
    assert reloaded.model == "gemma-test" and reloaded.template_version.startswith("audit-v")
    assert [s.action for s in reloaded.steps] == ["request", "verdict"]
    assert "0x0000c725" in reloaded.steps[0].result_summary
    assert reloaded.steps[0].prompt_tokens == 100
    assert "ASSERTION:" in reloaded.initial_context
    assert reloaded.termination_reason == "verdict"
    assert artifact.evidence_id in reloaded.evidence_inspected


def test_audit_context_excludes_investigator_reasoning(tmp_path):
    ledger, _executor, _context, runner = stack(tmp_path)
    claim, _artifact = _usb_claim(ledger, runner, derivation="SECRET-NARRATIVE: I reasoned that...")

    context = build_audit_context(ledger, claim)

    assert "SECRET-NARRATIVE" not in context
    assert claim.assertion in context
    assert "COMPUTED_POINTER_WRITES_NOT_EXCLUDED" in context


# 7
def test_structured_verdict_parsing():
    fenced = "```json\n" + json.dumps(verdict("supported", follow_up_requests=["check computed writers"])) + "\n```"
    parsed = parse_decision(fenced)
    assert parsed.verdict == AuditVerdict.SUPPORTED
    assert parsed.follow_up_requests[0].question == "check computed writers"

    assert parse_decision('noise {"action": "request", "tool": "analyze_usb_interface"} trailing').tool == "analyze_usb_interface"

    for bad in ("no json here", json.dumps(verdict("VERIFIED")), json.dumps({"action": "promote"})):
        with pytest.raises(ValueError):
            parse_decision(bad)

    missing_scope = verdict("SUPPORTED")
    del missing_scope["scope_check"]

    with pytest.raises(ValueError):
        parse_decision(json.dumps(missing_scope))


# 8
def test_invalid_auditor_tool_requests_are_rejected(tmp_path):
    ledger, executor, _context, runner = stack(tmp_path)
    claim, artifact = _usb_claim(ledger, runner)
    toolbox = AuditToolbox(ledger=ledger, runner=runner, audit_id="A-t", claim=claim, peripherals=["EIC"], irq_handlers=irq_handlers)
    calls = len(executor.calls)

    rejected = [
        ("shell", {"command": "rm -rf /"}),
        ("sql", {"query": "select 1"}),
        ("function_facts", {"function": "FUN_00001234"}),  # not in evidence
        ("function_facts", {"function": "/etc/passwd"}),
        ("function_facts", {"function": "FUN_0000cc14", "path": "/tmp/x"}),
        ("inspect_evidence", {"evidence_id": "../../etc/passwd"}),
        ("inspect_evidence", {"evidence_id": artifact.evidence_id, "field": "not_a_field"}),
        ("analyze_peripheral", {"peripheral": "NOT_A_PERIPHERAL"}),
        ("analyze_function_effects", {"function": "FUN_0000cc14", "solver_flags": "--smt"}),
        ("analyze_function_effects", {"function": "FUN_0000cc14", "r0": "0x10"}),
        ("find_common_paths", {"left": ["USB"], "right": ["IRQ:NOPE"]}),
        ("search_case_evidence", {"query": "trigger"}),  # disabled unless enabled
    ]

    for tool, arguments in rejected:
        with pytest.raises(ToolRejected):
            toolbox.validate(tool, arguments)

    assert len(executor.calls) == calls

    operation, arguments = toolbox.validate("find_common_paths", {"left": ["USB"], "right": ["IRQ:EIC"]})
    assert operation == "census_common_paths"
    assert arguments["right"] == ["FUN_0000cbb0", "FUN_0000cbb6", "FUN_0000cbbc"]
    assert arguments["right_label"] == "IRQ:EIC"


def test_rejected_request_is_recorded_and_reported_to_auditor(tmp_path):
    ledger, _executor, _context, runner = stack(tmp_path)
    claim, _artifact = _usb_claim(ledger, runner)
    auditor, model = _auditor(ledger, runner, [request("shell", command="ls"), request("function_facts", function="FUN_0000cc14"), verdict("UNRESOLVED")])

    audit = auditor.audit(claim.key)

    assert "not available" in audit.steps[0].rejection
    assert "REJECTED shell" in model.requests[1][-1]["content"]
    assert audit.steps[1].evidence_id is not None


# 9
def test_audit_decision_and_tool_budgets_are_enforced(tmp_path):
    ledger, _executor, _context, runner = stack(tmp_path)
    claim, _artifact = _usb_claim(ledger, runner)
    endless = [request("function_facts", function="FUN_0000cc14"), request("function_disassembly", function="FUN_0000cc14"),
               request("analyze_peripheral", peripheral="TCC1"), request("analyze_peripheral", peripheral="SERCOM2")] * 3
    auditor, model = _auditor(ledger, runner, endless, budget=AuditBudget(max_decisions=4, max_tool_requests=2))

    audit = auditor.audit(claim.key)

    executed = [s for s in audit.steps if s.action == "request"]
    assert len(executed) == 2
    assert max(s.number for s in audit.steps) <= 4
    assert len(model.requests) <= 4 * 2  # at most one correction retry per decision
    assert audit.verdict == AuditVerdict.UNRESOLVED
    assert audit.verdict_synthesized
    assert audit.termination_reason == "decision_budget_exhausted"
    assert ledger.state(claim.key) == ClaimState.PROPOSED


def test_verdict_requires_a_falsification_attempt_first(tmp_path):
    ledger, _executor, _context, runner = stack(tmp_path)
    claim, _artifact = _usb_claim(ledger, runner)
    auditor, _model = _auditor(ledger, runner, [verdict("SUPPORTED"), request("function_facts", function="FUN_0000ccc4"), verdict("SUPPORTED")])

    audit = auditor.audit(claim.key)

    assert audit.steps[0].rejection == "verdict before any successful falsification analysis"
    assert audit.verdict == AuditVerdict.SUPPORTED
    assert sum(s.action == "request" for s in audit.steps) == 1


def test_tool_failure_is_reported_as_coverage_gap(tmp_path):
    ledger, _executor, _context, runner = stack(tmp_path)
    claim, artifact = _usb_claim(ledger, runner)
    # Make FUN_0000dead visible as a known function via evidence.
    _inv, extra = runner.run("R-setup", "function_disassembly", {"function": "FUN_0000dead"})
    claim = ledger.propose_claim(**{**claim.model_dump(include={"subject", "assertion", "claim_type", "proposed_grade", "proposed_by"}),
                                    "supporting_evidence_ids": [artifact.evidence_id, extra.evidence_id]})
    auditor, model = _auditor(ledger, runner, [request("function_facts", function="FUN_0000dead"), verdict("UNRESOLVED")])

    audit = auditor.audit(claim.key)

    assert audit.steps[0].evidence_id is None
    assert "COVERAGE GAP (Ghidra export)" in model.requests[1][-1]["content"]
    assert "not evidence about the firmware and not contradictory evidence" in model.requests[1][-1]["content"]
    assert ledger.invocation(audit.steps[0].invocation_id).status == "error"


# 10
def test_duplicate_audit_queries_are_prevented(tmp_path):
    ledger, executor, _context, runner = stack(tmp_path)
    claim, _artifact = _usb_claim(ledger, runner)
    auditor, _model = _auditor(
        ledger,
        runner,
        [
            request("function_facts", function="FUN_0000ccc4"),
            request("function_facts", function="FUN_0000ccc4"),
            request("analyze_usb_interface"),  # already the supporting evidence
            verdict("UNRESOLVED"),
        ],
    )

    audit = auditor.audit(claim.key)

    assert [s.rejection is None for s in audit.steps if s.action == "request"] == [True, False, False]
    assert "duplicate" in audit.steps[1].rejection
    assert sum(1 for tool, _ in executor.calls if tool == "function_facts") == 1
    assert sum(1 for tool, _ in executor.calls if tool == "census_usb_inventory") == 1


# 11
def test_only_aptrace_verifier_owns_the_verified_transition(tmp_path):
    ledger, _executor, context, runner = stack(tmp_path)
    claim, _artifact = _usb_claim(ledger, runner)

    for actor in ("gemma-4-26b-a4b-it-4bit", "qwen", "auditor"):
        with pytest.raises(PermissionError):
            ledger.transition(claim.key, ClaimState.VERIFIED, actor=actor, reason="model says so")

    with pytest.raises(PermissionError):
        ledger.transition(claim.key, ClaimState.VERIFIED, actor="aptrace-ledger", reason="not the verifier")

    events_before = len(ledger.events())
    auditor, _model = _auditor(ledger, runner, [request("function_facts", function="FUN_0000ccc4"), verdict("SUPPORTED")])
    auditor.audit(claim.key)

    assert len(ledger.events()) == events_before  # an audit never transitions state
    assert ledger.state(claim.key) == ClaimState.PROPOSED

    outcome = ClaimVerifier(ledger, runner=runner).verify(claim.key)
    # Untyped: the verification policy cannot classify it, so a SUPPORTED
    # audit does not promote it, and even the verifier actor cannot mark it
    # VERIFIED without citing a passing policy verification.
    assert outcome.current == ClaimState.PROPOSED
    assert outcome.record.gate.status == "UNEVALUABLE"
    assert [c.code for c in outcome.record.gate.conditions] == ["CLAIM_CLASS_UNDETERMINED"]

    for refs in ([], [outcome.record.verification_id]):
        with pytest.raises(PermissionError):
            ledger.transition(claim.key, ClaimState.VERIFIED, actor="aptrace-verifier", reason="direct", refs=refs)

    assert ledger.state(claim.key) == ClaimState.PROPOSED


# 12
def test_invalid_evidence_reference_blocks_verification(tmp_path):
    ledger, _executor, _context, runner = stack(tmp_path)
    claim, artifact = _usb_claim(ledger, runner)
    bad = ledger.propose_claim(
        subject="x", assertion="y", claim_type="RESOLUTION", proposed_grade="STRONG", proposed_by="test",
        supporting_evidence_ids=[artifact.evidence_id, "E99"],
    )
    auditor, _model = _auditor(ledger, runner, [request("function_facts", function="FUN_0000ccc4"), verdict("SUPPORTED")])
    auditor.audit(bad.key)

    outcome = ClaimVerifier(ledger, runner=runner).verify(bad.key)

    assert outcome.current == ClaimState.BLOCKED
    failed = {c.name: c.detail for c in outcome.record.checks if not c.passed}
    assert "E99" in failed["evidence_references"]


# 14
def test_changed_deterministic_replay_prevents_verification(tmp_path):
    ledger, executor, _context, runner = stack(tmp_path)
    claim, artifact = _usb_claim(ledger, runner)
    auditor, _model = _auditor(ledger, runner, [request("function_facts", function="FUN_0000ccc4"), verdict("SUPPORTED")])
    auditor.audit(claim.key)
    executor.drift["census_usb_inventory"] = {"resolved_indirect_edges": []}

    outcome = ClaimVerifier(ledger, runner=runner).verify(claim.key)

    assert outcome.current == ClaimState.STALE
    replay = next(c for c in outcome.record.checks if c.name == "deterministic_replay")
    assert not replay.passed and "resolved_indirect_edges" in replay.detail
    assert ledger.evidence_state(artifact.evidence_id) == "INVALIDATED"


def test_input_artifact_drift_without_replay_holds_verification(tmp_path):
    ledger, _executor, context, runner = stack(tmp_path)
    claim, _artifact = _usb_claim(ledger, runner)
    auditor, _model = _auditor(ledger, runner, [request("function_facts", function="FUN_0000ccc4"), verdict("SUPPORTED")])
    auditor.audit(claim.key)
    context.artifacts["census_db"] = "d" * 64

    outcome = ClaimVerifier(ledger, runner=runner, replay=False).verify(claim.key)

    assert outcome.current == ClaimState.PROPOSED
    assert any(c.name == "input_artifacts_unchanged" and not c.passed for c in outcome.record.checks)


# 16
def test_strong_evidence_cannot_yield_exact_verified_claim(tmp_path):
    ledger, _executor, _context, runner = stack(tmp_path)
    claim, _artifact = _usb_claim(ledger, runner, proposed_grade="EXACT")
    auditor, _model = _auditor(ledger, runner, [request("function_facts", function="FUN_0000ccc4"), verdict("SUPPORTED")])
    auditor.audit(claim.key)  # even a (wrong) SUPPORTED verdict cannot promote it

    outcome = ClaimVerifier(ledger, runner=runner).verify(claim.key)

    assert outcome.current == ClaimState.BLOCKED
    grade = next(c for c in outcome.record.checks if c.name == "grade_ceiling")
    assert not grade.passed and "permits STRONG" in grade.detail


def test_dropped_evidence_limitation_blocks_verification(tmp_path):
    ledger, _executor, _context, runner = stack(tmp_path)
    claim, _artifact = _usb_claim(ledger, runner)

    # The ledger API cannot drop them: a new version re-inherits.
    v2 = ledger.supersede_claim(claim.key, proposed_by="test", reason="strip", limitations=[])
    assert "COMPUTED_POINTER_WRITES_NOT_EXCLUDED" in {lim.code for lim in v2.limitations}

    # A record written outside the API (hand-edited or imported) is caught.
    stripped = v2.model_copy(update={"claim_id": "C900", "version": 1, "supersedes": None, "limitations": []})
    ledger._write_once(ledger.root / "claims" / "C900" / "v1.json", stripped)
    ledger.transition(stripped.key, ClaimState.PROPOSED, actor="aptrace-ledger", reason="imported")
    auditor, _model = _auditor(ledger, runner, [request("function_facts", function="FUN_0000ccc4"), verdict("SUPPORTED")])
    auditor.audit(stripped.key)

    outcome = ClaimVerifier(ledger, runner=runner).verify(stripped.key)

    assert outcome.current == ClaimState.BLOCKED
    assert "COMPUTED_POINTER_WRITES_NOT_EXCLUDED" in next(c.detail for c in outcome.record.checks if c.name == "limitations_preserved")


# 17
def test_no_known_path_cannot_become_unreachable_verified_claim(tmp_path):
    ledger, _executor, _context, runner = stack(tmp_path)
    _inv, usb = runner.run("R-setup", "census_usb_inventory", {})
    _inv, paths = runner.run(
        "R-setup", "census_common_paths",
        {"left": ["FUN_0000cc14"], "right": ["FUN_0000cbb0"], "left_label": "USB", "right_label": "IRQ:EIC"},
    )
    assert paths.path_status == "NO_KNOWN_PATH" and paths.grade.value == "BOUNDED"

    def propose(claim_type, assertion):
        return ledger.propose_claim(subject="EIC vs USB", assertion=assertion, claim_type=claim_type, proposed_grade="STRONG",
                                    proposed_by="test", supporting_evidence_ids=[usb.evidence_id, paths.evidence_id])

    claims = {
        "typed": propose("UNREACHABLE", "The EIC handlers never call USB code."),
        "worded": propose("BEHAVIOR", "USB handling is unreachable from the EIC interrupt handlers."),
        "bounded": propose("NO_KNOWN_PATH", "No census path within the hop bound connects them; NO_KNOWN_PATH, not unreachability."),
    }
    verifier = ClaimVerifier(ledger, runner=runner)

    for name, claim in claims.items():
        auditor, _model = _auditor(ledger, runner, [request("function_facts", function="FUN_0000cc14"), verdict("SUPPORTED")])
        auditor.audit(claim.key)
        outcome = verifier.verify(claim.key)
        guard = next(c for c in outcome.record.checks if c.name == "no_unreachability_promotion")

        if name == "bounded":
            # Not blocked by the unreachability guard; held by the policy,
            # which needs bounded absences from two independent engines.
            assert guard.passed and outcome.current == ClaimState.PROPOSED
            assert outcome.record.gate.claim_class == "BOUNDED_NEGATIVE"
            assert {c.code for c in outcome.record.gate.conditions} == {"NO_EVIDENCE_CONTRACT"}
        else:
            assert not guard.passed and outcome.current == ClaimState.BLOCKED, name

    assert "NO_KNOWN_PATH_IS_NOT_UNREACHABILITY" in {lim.code for lim in claims["bounded"].limitations}


# 22
def test_replay_of_recorded_invocation_needs_no_model(tmp_path):
    ledger, executor, _context, runner = stack(tmp_path)
    invocation, artifact = runner.run("R-setup", "census_usb_inventory", {})

    replay = runner.replay(invocation.invocation_id, run_id="RP-test")

    assert replay.matches and replay.replay_sha256 == artifact.result_sha256
    assert replay.replay.replay_of == invocation.invocation_id
    assert ledger.invocation(replay.replay.invocation_id).status == "ok"

    executor.drift["census_usb_inventory"] = {"status": "census_stale"}
    changed = runner.replay(invocation.invocation_id, run_id="RP-test")
    assert not changed.matches and any("status" in d for d in changed.differences)


def test_case_search_is_not_replay_verifiable(tmp_path):
    ledger, _executor, _context, runner = stack(tmp_path)
    invocation, _artifact = runner.run("R-setup", "search_case_evidence", {"query": "usb"})

    assert not invocation.replayable

    with pytest.raises(ValueError):
        runner.replay(invocation.invocation_id, run_id="RP-test")


# 18-20: the real case fixtures, with a scripted auditor and a fake executor.
def _bench(tmp_path, name, decisions):
    ledger, _executor, _context, runner = stack(tmp_path)
    auditor, _model = _auditor(ledger, runner, decisions)
    result = run_benchmark(name, directory=BENCHMARK_DIR, ledger=ledger, runner=runner, auditor=auditor, irq_handlers=irq_handlers)
    return ledger, {c.label: c for c in result.claims}


def test_usb_good_claim_passes_complete_pipeline(tmp_path):
    ledger, outcomes = _bench(tmp_path, "usb-callback", [
        request("function_disassembly", function="FUN_0000ccc4"), verdict("SUPPORTED"),
        request("function_disassembly", function="FUN_0000ccc4"), verdict("CHALLENGED", challenges=["writer is not the target"]),
    ])
    good = outcomes["good"]

    # Policy v1: an untyped claim cannot be classified, so it is held before
    # the audit model; replay (phase C) still ran.
    assert good.final_state == "PROPOSED" and good.passed
    assert good.audit_skipped and good.audit_verdict is None
    assert good.gate_status == "UNEVALUABLE" and good.policy_conditions == ["CLAIM_CLASS_UNDETERMINED"]
    assert ledger.verifications_for(good.key)[-1].replay_invocation_ids


def test_bad_usb_claim_is_blocked_even_if_auditor_supports_it(tmp_path):
    # A wrong SUPPORTED verdict must not promote it: the grade machinery blocks it.
    _ledger, outcomes = _bench(tmp_path, "usb-callback", [
        request("function_disassembly", function="FUN_0000ccc4"), verdict("SUPPORTED"),
        request("function_disassembly", function="FUN_0000ccc4"), verdict("SUPPORTED"),
    ])
    bad = outcomes["bad"]

    assert bad.final_state == "BLOCKED"
    assert "grade_ceiling" in bad.failed_checks
    assert "independent_audit" not in bad.failed_checks


def test_bad_usb_claim_is_blocked_before_audit(tmp_path):
    _ledger, outcomes = _bench(tmp_path, "usb-callback", [
        request("function_disassembly", function="FUN_0000ccc4"), verdict("SUPPORTED"),
    ])
    bad = outcomes["bad"]

    assert bad.final_state == "BLOCKED" and bad.passed
    # Phase B (grade ceiling) blocks before any audit is requested.
    assert bad.audit_skipped and bad.audit_verdict is None
    assert "grade_ceiling" in bad.failed_checks and "independent_audit" not in bad.failed_checks


def test_misleading_eic_convergence_claim_is_not_verified(tmp_path):
    ledger, _executor, _context, runner = stack(tmp_path)
    auditor, model = _auditor(ledger, runner, [verdict("SUPPORTED"), verdict("SUPPORTED")])
    result = run_benchmark("eic-convergence", directory=BENCHMARK_DIR, ledger=ledger, runner=runner, auditor=auditor, irq_handlers=irq_handlers)
    outcomes = {c.label: c for c in result.claims}
    convergence = outcomes["convergence"]

    # Neither claim can meet policy v1, so the audit model is never asked.
    assert model.requests == []
    assert convergence.final_state == "PROPOSED" and convergence.passed
    assert convergence.gate_status == "UNEVALUABLE" and "NO_EVIDENCE_CONTRACT" in convergence.policy_conditions
    # Scope is preserved mechanically: the broad set's limitation is inherited.
    codes = {lim.code for lim in ledger.claim(convergence.key).limitations}
    assert "PERIPHERAL_SET_IS_MMIO_USAGE:EIC" in codes
    assert outcomes["bounded"].final_state == "PROPOSED" and outcomes["bounded"].passed


# Qwen structured claim contract (opt-in; Agent v0 default unchanged).
class _Planner:
    def __init__(self, finish_arguments):
        self.finish_arguments = finish_arguments
        self.tools = []
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))

    def _create(self, **kwargs):
        self.tools.append(kwargs["tools"])
        call = SimpleNamespace(function=SimpleNamespace(name="finish", arguments=json.dumps(self.finish_arguments)))
        return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=None, tool_calls=[call]))])


def _session_with_lead():
    from aptrace_agent.research import LeadFollower, LeadRegistry, ResearchSession
    from ledger_support import FakeExecutor

    registry = LeadRegistry()
    session = ResearchSession(objective="USB callback", registry=registry, follower=LeadFollower(registry=registry, executor=FakeExecutor()))
    lead = registry.register(kind="function", description="x", tool="function_facts", arguments={"function": "FUN_0000cc14"})
    session.state.add_lead(lead)
    return session


def test_claim_contract_is_off_by_default():
    planner = _Planner({"reason": "done", "claims": [{"assertion": "x", "grade": "STRONG", "evidence_ids": ["E1"]}]})
    controller = ResearchController(planner_client=planner, planner_model="m", reconciler=object())

    result = controller.run(_session_with_lead())

    finish = next(t for t in planner.tools[0] if t["function"]["name"] == "finish")
    assert "claims" not in finish["function"]["parameters"]["properties"]
    assert result.proposed_claims == ()


def test_claim_contract_records_sanitized_proposals():
    planner = _Planner({
        "reason": "done",
        "claims": [
            {"subject": "cb", "assertion": "Callback resolves to 0x0000c724.", "claim_type": "resolution", "grade": "strong", "evidence_ids": ["E1", 7]},
            {"assertion": "", "grade": "STRONG", "evidence_ids": []},
            {"assertion": "bad grade", "grade": "CERTAIN", "evidence_ids": []},
            "not a claim line",
            "probable no_known_path E2, E3 No census path connects A and B.",
        ],
    })
    controller = ResearchController(planner_client=planner, planner_model="m", reconciler=object(), claim_contract=True)
    keys = ("subject", "assertion", "claim_type", "grade", "evidence_ids", "limitations")

    assert [{k: c[k] for k in keys} for c in ResearchController._sanitize_claims(planner.finish_arguments["claims"])] == [{
        "subject": "cb", "assertion": "Callback resolves to 0x0000c724.", "claim_type": "RESOLUTION",
        "grade": "STRONG", "evidence_ids": ["E1", "7"], "limitations": [],
    }, {
        "subject": "", "assertion": "No census path connects A and B.", "claim_type": "NO_KNOWN_PATH",
        "grade": "PROBABLE", "evidence_ids": ["E2", "E3"], "limitations": [],
    }]

    result = controller.run(_session_with_lead())
    first = [r for r in result.claim_admission if r.round == 1]

    # Admission (research/admission.py): nothing malformed, untyped-STRONG, or
    # referencing unknown evidence reaches the ledger; every item is recorded.
    assert result.proposed_claims == ()
    assert [r.decision for r in first] == ["unparseable"] * 3 + ["rejected"] * 2
    assert {d.code for d in first[3].diagnostics} >= {"UNTYPED_GRADE", "EVIDENCE_REFERENCE_UNKNOWN"}
    assert {d.code for d in first[4].diagnostics} == {"EVIDENCE_REFERENCE_UNKNOWN"}


def test_recorder_maps_session_evidence_and_keeps_unknown_references(tmp_path):
    from ledger_support import MutableContext, usb_inventory

    ledger = ResearchLedger(tmp_path / "ledger")
    context = MutableContext()()
    run = SimpleNamespace(
        objective="USB callback",
        evidence=(EvidenceObservation(id="E1", tool="census_usb_inventory", arguments={}, result=usb_inventory()),),
        state=ResearchState(objective="USB callback"),
        result=ResearchRunResult(
            stop_reason="planner_finished",
            steps=(ResearchStep(number=1, action="usb_inventory", lead_id=None, evidence_id="E1"), ResearchStep(number=2, action="finish")),
            reconciled=False,
            proposed_claims=({"subject": "cb", "assertion": "Resolves to 0x0000c724.", "claim_type": "RESOLUTION",
                              "grade": "STRONG", "evidence_ids": ["E1", "E42"], "limitations": []},),
        ),
    )

    recorded = record_investigation(
        ledger, run, context=context, recorder=None, model="qwen-test", execution_config={}, planner_version="v",
        budgets={}, started_at="t0", ended_at="t1", source=__import__("aptrace_agent.ledger.models", fromlist=["SourceRevision"]).SourceRevision(),
    )

    claim = ledger.claim(recorded.claim_versions[0])
    durable = ledger.invocation(recorded.invocation_ids[0]).evidence_id
    assert claim.supporting_evidence_ids == [durable, "E42"]
    assert claim.run_id == recorded.run_id and claim.proposed_by == "investigator:qwen-test"
    assert ledger.invocation(recorded.invocation_ids[0]).session_evidence_id == "E1"


def test_claim_contract_accepts_one_claim_per_line():
    claims = ResearchController._sanitize_claims("STRONG RESOLUTION E2,E4 Slot resolves to 0x0000c724.\nnot a claim\nPROBABLE E1 Docs say so.")
    assert [(c["grade"], c["claim_type"], c["evidence_ids"]) for c in claims] == [
        ("STRONG", "RESOLUTION", ["E2", "E4"]), ("PROBABLE", "OTHER", ["E1"])
    ]


def test_claim_contract_requests_final_claims_after_step_budget():
    from aptrace_agent.research import LeadFollower, LeadRegistry, ResearchSession
    from ledger_support import FakeExecutor

    class Planner:
        def __init__(self):
            self.tools = []
            self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))

        def _create(self, **kwargs):
            names = [t["function"]["name"] for t in kwargs["tools"]]
            self.tools.append(names)

            if names == ["finish"]:
                name, arguments = "finish", {"reason": "budget", "claims": "STRONG E1 a"}
            else:
                name, arguments = "follow_lead", {"lead_id": kwargs["tools"][0]["function"]["parameters"]["properties"]["lead_id"]["enum"][0]}

            call = SimpleNamespace(function=SimpleNamespace(name=name, arguments=json.dumps(arguments)))
            return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=None, tool_calls=[call]))])

    registry = LeadRegistry()
    session = ResearchSession(objective="o", registry=registry, follower=LeadFollower(registry=registry, executor=FakeExecutor()))

    for function in ("FUN_00000001", "FUN_00000002"):
        session.state.add_lead(registry.register(kind="function", description="x", tool="function_facts", arguments={"function": function}))

    planner = Planner()
    result = ResearchController(planner_client=planner, planner_model="m", reconciler=object(), max_steps=1, claim_contract=True).run(session)

    assert result.stop_reason == "step_budget_exhausted"
    assert planner.tools[-1] == ["finish"]  # finish-only: no analysis offered
    # The untyped STRONG proposal is recorded, not admitted (UNTYPED_GRADE).
    assert result.proposed_claims == ()
    assert result.claim_admission[0].assertion == "a" and result.claim_admission[0].decision == "rejected"
    assert "UNTYPED_GRADE" in {d.code for d in result.claim_admission[0].diagnostics}
    # One final-claims request, then exactly one bounded correction request.
    assert [r["phase"] for r in result.planner_requests][-2:] == ["final-claims", "claim-correction"]


def test_challenged_version_cannot_be_reaudited_into_verification(tmp_path):
    ledger, _executor, _context, runner = stack(tmp_path)
    claim, _artifact = _usb_claim(ledger, runner)
    verifier = ClaimVerifier(ledger, runner=runner)

    for value in ("CHALLENGED", "SUPPORTED"):
        auditor, _model = _auditor(ledger, runner, [request("function_facts", function="FUN_0000ccc4"), verdict(value)])
        auditor.audit(claim.key)
        outcome = verifier.verify(claim.key)
        assert outcome.current == ClaimState.BLOCKED, value

    # A new version answers the challenge and is audited afresh.
    v2 = ledger.supersede_claim(claim.key, proposed_by="test", reason="address challenge", scope="narrowed")
    auditor, _model = _auditor(ledger, runner, [request("function_facts", function="FUN_0000ccc4"), verdict("SUPPORTED")])
    auditor.audit(v2.key)
    # The challenge is answered, but the untyped claim still cannot meet
    # the verification policy: PROPOSED, not VERIFIED, and no longer BLOCKED.
    outcome = verifier.verify(v2.key)
    assert outcome.current == ClaimState.PROPOSED
    assert next(c for c in outcome.record.checks if c.name == "independent_audit").passed
