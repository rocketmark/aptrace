"""
Record a completed autonomous investigation into the research ledger.

The investigator's session ledger (E1, E2, ...) stays as it is. This maps
every session observation to a durable ToolInvocation + content-addressed
EvidenceArtifact, and records the planner's structured claim proposals as
PROPOSED claim versions with session evidence references translated to
durable evidence ids. Unknown references are kept verbatim so verification
rejects them rather than APTrace silently repairing them.
"""

from __future__ import annotations

import inspect
import time
from dataclasses import dataclass, field
from typing import Any

from aptrace_agent.ledger.hashing import digest
from aptrace_agent.ledger.models import ExecutionContext, InvestigationRun, SourceRevision
from aptrace_agent.ledger.operations import DETERMINISTIC_TOOLS, input_artifacts
from aptrace_agent.ledger.store import ResearchLedger, new_id, now
from aptrace_agent.schemas import EvidenceObservation


@dataclass
class ExecutionTrace:
    session_evidence_id: str
    tool: str
    arguments: dict[str, Any]
    started_at: str
    ended_at: str
    runtime_ms: float
    error: str | None = None


@dataclass
class RecordingExecutor:
    """Executor wrapper recording timing and errors per session evidence id."""

    inner: Any
    traces: dict[str, ExecutionTrace] = field(default_factory=dict)
    failures: list[ExecutionTrace] = field(default_factory=list)

    def __getattr__(self, name: str) -> Any:
        return getattr(self.inner, name)

    def execute_operation(self, tool: str, arguments: dict, *, evidence_id: str) -> EvidenceObservation:
        started = now()
        clock = time.perf_counter()

        try:
            observation = self.inner.execute_operation(tool, arguments, evidence_id=evidence_id)
        except Exception as exc:
            self.failures.append(
                ExecutionTrace(evidence_id, tool, dict(arguments), started, now(), (time.perf_counter() - clock) * 1000, f"{type(exc).__name__}: {exc}"[:500])
            )
            raise

        self.traces[evidence_id] = ExecutionTrace(evidence_id, tool, dict(arguments), started, now(), round((time.perf_counter() - clock) * 1000, 3))
        return observation


def code_identity(*objects: Any) -> str:
    """Identity of planner/prompt/projection code, from its source text."""

    return digest([inspect.getsource(obj) for obj in objects])[:12]


def record_investigation(
    ledger: ResearchLedger,
    run: Any,
    *,
    context: ExecutionContext,
    recorder: RecordingExecutor | None,
    model: str | None,
    execution_config: dict[str, Any],
    planner_version: str,
    budgets: dict[str, Any],
    started_at: str,
    ended_at: str,
    source: SourceRevision,
    parent_run_id: str | None = None,
    work_item_id: str | None = None,
) -> InvestigationRun:
    run_id = new_id("R")
    session_to_durable: dict[str, str] = {}
    invocation_ids: list[str] = []
    traces = recorder.traces if recorder else {}
    lead_sources = {lead.id: list(lead.source_evidence_ids) for lead in run.state.leads}
    step_lead = {step.evidence_id: step.lead_id for step in run.result.steps if step.evidence_id}

    for seq, observation in enumerate(run.evidence, start=1):
        trace = traces.get(observation.id)
        sources = lead_sources.get(step_lead.get(observation.id) or "", [])
        invocation, artifact = ledger.record_invocation(
            run_id=run_id,
            seq=seq,
            tool=observation.tool,
            arguments=observation.arguments,
            context=context,
            input_artifacts=input_artifacts(context, observation.tool),
            started_at=trace.started_at if trace else started_at,
            ended_at=trace.ended_at if trace else started_at,
            runtime_ms=trace.runtime_ms if trace else 0.0,
            result=observation.result,
            input_evidence_ids=[session_to_durable.get(e, e) for e in sources],
            replayable=observation.tool in DETERMINISTIC_TOOLS,
            session_evidence_id=observation.id,
        )
        invocation_ids.append(invocation.invocation_id)

        if artifact is not None:
            session_to_durable[observation.id] = artifact.evidence_id

    for offset, failure in enumerate(recorder.failures if recorder else [], start=len(run.evidence) + 1):
        invocation, _ = ledger.record_invocation(
            run_id=run_id,
            seq=offset,
            tool=failure.tool,
            arguments=failure.arguments,
            context=context,
            input_artifacts=input_artifacts(context, failure.tool),
            started_at=failure.started_at,
            ended_at=failure.ended_at,
            runtime_ms=failure.runtime_ms,
            error=failure.error,
            session_evidence_id=failure.session_evidence_id,
        )
        invocation_ids.append(invocation.invocation_id)

    claim_keys: list[str] = []

    for proposal in getattr(run.result, "proposed_claims", ()):
        refs = [session_to_durable.get(e, e) for e in proposal.get("evidence_ids", [])]
        claim = ledger.propose_claim(
            subject=proposal.get("subject") or proposal["assertion"][:80],
            assertion=proposal["assertion"],
            claim_type=proposal.get("claim_type", "OTHER"),
            proposed_grade=proposal["grade"],
            proposed_by=f"investigator:{model}",
            supporting_evidence_ids=refs,
            limitations=proposal.get("limitations", []),
            derivation="planner finish claim proposal",
            run_id=run_id,
        )
        claim_keys.append(claim.key)

    return ledger.record_run(
        InvestigationRun(
            run_id=run_id,
            kind="investigation",
            case=context.case,
            firmware_key=context.firmware_key,
            firmware_sha256=context.firmware_sha256,
            context_id=context.context_id(),
            objective=run.objective,
            model=model,
            execution_config=execution_config,
            planner_version=planner_version,
            budgets=budgets,
            started_at=started_at,
            ended_at=ended_at,
            termination_reason=run.result.stop_reason,
            parent_run_id=parent_run_id,
            source=source,
            invocation_ids=invocation_ids,
            evidence_ids=list(dict.fromkeys(session_to_durable.values())),
            claim_versions=claim_keys,
            planner_requests=list(run.result.planner_requests),
            trajectory=[
                {"number": s.number, "action": s.action, "lead_id": s.lead_id, "evidence_id": s.evidence_id, "reason": s.reason}
                for s in run.result.steps
            ],
            work_item_id=work_item_id,
        )
    )
