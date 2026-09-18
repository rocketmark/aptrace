from __future__ import annotations

from typing import Protocol

from aptrace_agent.research.leads import LeadRegistry
from aptrace_agent.schemas import EvidenceObservation


class EvidenceOperationExecutor(Protocol):
    def execute_operation(
        self,
        tool: str,
        arguments: dict,
        *,
        evidence_id: str,
    ) -> EvidenceObservation:
        ...


class LeadFollower:
    """
    Resolve and execute one APTrace-owned structural lead.

    A lead is marked FOLLOWED only after its evidence operation
    completes successfully.
    """

    def __init__(
        self,
        *,
        registry: LeadRegistry,
        executor: EvidenceOperationExecutor,
    ) -> None:
        self.registry = registry
        self.executor = executor

    def follow(
        self,
        lead_id: str,
        *,
        evidence_id: str,
    ) -> EvidenceObservation:
        action = self.registry.resolve(lead_id)

        observation = self.executor.execute_operation(
            action.tool,
            action.arguments,
            evidence_id=evidence_id,
        )

        self.registry.mark_followed(lead_id)

        return observation
