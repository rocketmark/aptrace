"""
Historical-operation awareness for follow-up investigations.

A follow-up run starts from earlier research. This module lets its session
use that research by reference, without re-executing it and without
counting it as new evidence.

Three kinds of research state stay separate:

- historical analysis: ToolInvocations and evidence of earlier runs, looked
  up here (bounded to the source run and earlier attempts at the same
  follow-up; no global cache);
- current-session analysis: the session's EvidenceLedger. A historical
  result used in the session gets a session alias marked `reused_from`, so
  the planner and claim references can name it; the recorder writes no
  ToolInvocation for it and does not list it among the run's evidence;
- pending leads: ResearchState.leads. A lead is satisfied by history only
  when its own operation is historically identical and reusable; related
  analysis of the same function never resolves it.

Reuse requires, in order (the first failure is the recorded reason):

1. a deterministic, replay-verifiable tool (case-document search reads
   mutable prose and is always re-executed);
2. a successful historical invocation with stored evidence;
3. the same firmware (sha256 and key) as the current context;
4. identical input-artifact hashes for that tool, so the ledger's own
   operation_key recomputed under the current context is equal (arguments
   are compared with equivalent defaults filled in, so an omitted default
   and its explicit value are one operation; a record keyed before that
   canonicalization still matches its recorded key);
5. evidence still VALID (not invalidated by `ledger check`);
6. the stored result present and passing its content-hash integrity check;
7. for tools that declare an analysis version in their result, the same
   version as the current implementation.

Tool code changes that do not bump a declared analysis version are not
detected here; `aptrace-agent replay` compares recorded and fresh hashes.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from aptrace_agent.ledger.hashing import canonical_json
from aptrace_agent.ledger.models import (
    ContinuityRecord,
    ExecutionContext,
    OperationReuse,
    ReuseRefusal,
    SeededLeadOutcome,
    ToolInvocation,
)
from aptrace_agent.ledger.operations import DETERMINISTIC_TOOLS, input_artifacts
from aptrace_agent.ledger.semantics import canonical_arguments
from aptrace_agent.ledger.store import EVIDENCE_VALID, ResearchLedger


POLICY = "continuity-v1"
MAX_HISTORY_INVOCATIONS = 256
# Reuses that do not consume a research step; later reuses cost one step
# (still without executing anything), so decisions stay bounded.
DEFAULT_FREE_REUSES = 4
# Steps APTrace may take on the planner's behalf (top open seeded lead)
# when the planner produces no valid decision.
DEFAULT_FALLBACKS = 3


def current_analysis_versions() -> dict[str, int]:
    from aptrace_agent.call_observation import ANALYSIS_VERSION as OBSERVATION_VERSION
    from aptrace_agent.callback_provenance import ANALYSIS_VERSION as CALLBACK_PROVENANCE_VERSION
    from aptrace_agent.function_effects import ANALYSIS_VERSION
    from aptrace_agent.indirect_target import ANALYSIS_VERSION as INDIRECT_TARGET_VERSION

    return {"function_effects": ANALYSIS_VERSION, "observed_call_arguments": OBSERVATION_VERSION,
            "indirect_call_target": INDIRECT_TARGET_VERSION, "callback_argument_provenance": CALLBACK_PROVENANCE_VERSION}


def _operation(tool: str, arguments: dict[str, Any]) -> str:
    return canonical_json({"tool": tool, "arguments": canonical_arguments(tool, arguments)})


@dataclass(frozen=True)
class ReuseDecision:
    reusable: bool
    reason: str
    invocation: ToolInvocation


class HistoricalOperations:
    def __init__(
        self,
        ledger: ResearchLedger,
        context: ExecutionContext,
        *,
        run_ids: list[str],
        evidence_ids: list[str] = (),
        analysis_versions: Mapping[str, int] | None = None,
        limit: int = MAX_HISTORY_INVOCATIONS,
    ) -> None:
        self.ledger = ledger
        self.context = context
        self.analysis_versions = dict(current_analysis_versions() if analysis_versions is None else analysis_versions)
        self.run_ids = list(dict.fromkeys(run_ids))
        self.truncated = False
        ids: list[str] = []

        for run_id in self.run_ids:
            try:
                ids += ledger.run(run_id).invocation_ids
            except KeyError:
                continue

        for evidence_id in evidence_ids:
            if ledger.has_evidence(evidence_id):
                ids.append(ledger.evidence(evidence_id).invocation_id)

        ids = list(dict.fromkeys(ids))

        if len(ids) > limit:
            ids, self.truncated = ids[:limit], True

        self._index: dict[str, list[ToolInvocation]] = {}

        for invocation_id in ids:
            try:
                invocation = ledger.invocation(invocation_id)
            except KeyError:
                continue

            self._index.setdefault(_operation(invocation.tool, invocation.arguments), []).append(invocation)

        for invocations in self._index.values():
            invocations.sort(key=lambda i: (i.started_at, i.invocation_id), reverse=True)

    @classmethod
    def for_followup(cls, ledger: ResearchLedger, context: ExecutionContext, candidate: Any) -> HistoricalOperations:
        """History of a follow-up: its source run, earlier attempts at it, and its cited evidence."""

        earlier = [run.run_id for run in ledger.runs() if run.followup is not None and run.followup.followup_key == candidate.key]
        return cls(ledger, context, run_ids=[candidate.source_run_id, *earlier], evidence_ids=list(candidate.evidence_ids))

    def __len__(self) -> int:
        return sum(len(v) for v in self._index.values())

    def lookup(self, tool: str, arguments: dict[str, Any]) -> ReuseDecision | None:
        """
        None when no historical operation has this tool and these canonical
        arguments; otherwise the newest reusable one, or the newest
        candidate's refusal reason.
        """

        candidates = self._index.get(_operation(tool, arguments))

        if not candidates:
            return None

        decisions = [self._check(invocation) for invocation in candidates]
        return next((d for d in decisions if d.reusable), decisions[0])

    def _check(self, invocation: ToolInvocation) -> ReuseDecision:
        def refuse(reason: str) -> ReuseDecision:
            return ReuseDecision(False, reason, invocation)

        tool = invocation.tool

        if tool not in DETERMINISTIC_TOOLS:
            return refuse(f"{tool} is not a deterministic replay-verifiable operation")
        if invocation.status != "ok" or not invocation.evidence_id:
            return refuse(f"historical invocation {invocation.invocation_id} did not produce evidence ({invocation.status})")
        if not self.ledger.has_evidence(invocation.evidence_id):
            return refuse(f"evidence {invocation.evidence_id} is missing")

        evidence = self.ledger.evidence(invocation.evidence_id)

        if (evidence.firmware_sha256, evidence.firmware_key) != (self.context.firmware_sha256, self.context.firmware_key):
            return refuse(f"different firmware ({evidence.firmware_key} {evidence.firmware_sha256[:12]}; current {self.context.firmware_key} {self.context.firmware_sha256[:12]})")

        current = input_artifacts(self.context, tool)
        drift = sorted(name for name in set(current) | set(invocation.input_artifacts) if current.get(name) != invocation.input_artifacts.get(name))

        if drift:
            return refuse(f"input artifacts differ: {', '.join(drift)}")

        expected = ResearchLedger.operation_keys(tool, invocation.arguments, current, self.context.firmware_sha256)

        if invocation.operation_key not in expected:
            return refuse("operation identity differs under the current context")
        if self.ledger.evidence_state(evidence.evidence_id) != EVIDENCE_VALID:
            return refuse(f"evidence {evidence.evidence_id} is {self.ledger.evidence_state(evidence.evidence_id)}")
        if not self.ledger.has_blob(evidence.result_sha256):
            return refuse(f"result blob {evidence.result_sha256[:12]} unavailable locally")

        result, intact = self.ledger.load_blob(evidence.result_sha256)

        if not intact:
            return refuse(f"result blob {evidence.result_sha256[:12]} fails its integrity check")

        if tool in self.analysis_versions:
            declared = ((result or {}).get("provenance") or {}).get("analysis_version")

            if declared != self.analysis_versions[tool]:
                return refuse(f"{tool} analysis version {declared!r} differs from current {self.analysis_versions[tool]}")

        return ReuseDecision(True, f"identical operation {invocation.operation_key[:12]} under current inputs", invocation)

    def result(self, decision: ReuseDecision) -> dict[str, Any]:
        evidence = self.ledger.evidence(decision.invocation.evidence_id)
        return self.ledger.load_blob(evidence.result_sha256)[0]

    def reuse_record(self, decision: ReuseDecision, *, session_evidence_id: str, trigger: str, step: int | None) -> OperationReuse:
        invocation = decision.invocation
        return OperationReuse(
            session_evidence_id=session_evidence_id,
            evidence_id=invocation.evidence_id,
            invocation_id=invocation.invocation_id,
            source_run_id=invocation.run_id,
            tool=invocation.tool,
            arguments=dict(invocation.arguments),
            operation_key=invocation.operation_key,
            trigger=trigger,
            step=step,
        )


@dataclass
class ContinuityTracker:
    """Per-session continuity state; present only on follow-up sessions."""

    history: HistoricalOperations
    origin: str
    max_free_reuses: int = DEFAULT_FREE_REUSES
    max_fallbacks: int = DEFAULT_FALLBACKS
    reused: list[OperationReuse] = field(default_factory=list)
    refused: list[ReuseRefusal] = field(default_factory=list)
    # lead id -> (tool, arguments, description) for seeded leads
    seeded: dict[str, tuple[str, dict[str, Any], str]] = field(default_factory=dict)
    # lead id -> anchor (function or query the seeded lead extends from)
    anchors: dict[str, str] = field(default_factory=dict)
    # lead id -> (session evidence id, reused?, step)
    followed: dict[str, tuple[str, bool, int | None]] = field(default_factory=dict)
    failed: set[str] = field(default_factory=set)
    offered: set[str] = field(default_factory=set)
    preloaded: set[str] = field(default_factory=set)
    free_reuses: int = 0
    fallbacks: int = 0
    decisions: int = 0
    steps_charged: int = 0

    def refuse(self, decision: ReuseDecision, trigger: str) -> None:
        invocation = decision.invocation
        self.refused.append(ReuseRefusal(tool=invocation.tool, arguments=dict(invocation.arguments), invocation_id=invocation.invocation_id, reason=decision.reason, trigger=trigger))

    def charge(self, reused: bool) -> int:
        """Steps a completed action costs: a reuse is free up to max_free_reuses."""

        if reused and self.free_reuses < self.max_free_reuses:
            self.free_reuses += 1
            return 0

        return 1

    def open_seeded(self, state) -> list:
        return [lead for lead in state.open_leads() if lead.id in self.seeded]

    def record(self, *, max_steps: int) -> ContinuityRecord:
        outcomes: list[SeededLeadOutcome] = []
        durable = {r.session_evidence_id: r.evidence_id for r in self.reused}

        for lead_id, (tool, arguments, description) in self.seeded.items():
            followed = self.followed.get(lead_id)

            if followed:
                session_id, reused, step = followed
                outcomes.append(
                    SeededLeadOutcome(
                        tool=tool, arguments=arguments, description=description, outcome="reused" if reused else "executed",
                        session_evidence_id=session_id, evidence_id=durable.get(session_id), step=step,
                    )
                )
            else:
                outcome = "attempted-failed" if lead_id in self.failed else "offered" if lead_id in self.offered else "not-offered"
                outcomes.append(SeededLeadOutcome(tool=tool, arguments=arguments, description=description, outcome=outcome))

        return ContinuityRecord(
            policy=POLICY,
            history_runs=list(self.history.run_ids),
            history_invocations=len(self.history),
            reused=list(self.reused),
            refused=list(self.refused),
            seeded_leads=outcomes,
            budget={
                "max_steps": max_steps,
                "steps_charged": self.steps_charged,
                "decisions": self.decisions,
                "free_reuses": self.free_reuses,
                "max_free_reuses": self.max_free_reuses,
                "fallbacks": self.fallbacks,
                "max_fallbacks": self.max_fallbacks,
            },
        )


__all__ = [
    "ContinuityTracker",
    "DEFAULT_FALLBACKS",
    "DEFAULT_FREE_REUSES",
    "HistoricalOperations",
    "POLICY",
    "ReuseDecision",
    "current_analysis_versions",
]
