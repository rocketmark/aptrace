from __future__ import annotations

from aptrace_agent.research.derivation import (
    LeadDeriver,
    LeadGenerationIssue,
)
from aptrace_agent.research.evidence import EvidenceLedger
from aptrace_agent.research.fact_derivation import (
    StateFactDeriver,
)
from aptrace_agent.research.follow import LeadFollower
from aptrace_agent.research.leads import LeadRegistry
from aptrace_agent.research.state import ResearchState
from aptrace_agent.schemas import EvidenceObservation


class ResearchSession:
    """
    Deterministic research-session plumbing.

    This class contains no model policy. It owns authoritative evidence
    numbering, safe lead execution, and mechanical derivation of new
    research directions from evidence.
    """

    def __init__(
        self,
        *,
        objective: str,
        registry: LeadRegistry,
        follower: LeadFollower,
        ledger: EvidenceLedger | None = None,
        deriver: LeadDeriver | None = None,
        fact_deriver: StateFactDeriver | None = None,
    ) -> None:
        self.state = ResearchState(
            objective=objective
        )
        self.registry = registry
        self.follower = follower
        self.ledger = ledger or EvidenceLedger()
        self.deriver = deriver
        self.fact_deriver = (
            fact_deriver
            or StateFactDeriver()
        )
        self.derivation_issues: list[
            LeadGenerationIssue
        ] = []

    def _incorporate(
        self,
        observation: EvidenceObservation,
    ) -> None:
        self.fact_deriver.derive(
            observation,
            self.state,
        )

        if self.deriver is None:
            return

        result = self.deriver.derive(
            observation
        )

        existing_ids = {
            lead.id
            for lead in self.state.leads
        }

        for lead in result.leads:
            if lead.id in existing_ids:
                continue

            self.state.add_lead(lead)
            existing_ids.add(lead.id)

        self.derivation_issues.extend(
            result.issues
        )

    def follow_lead(
        self,
        lead_id: str,
    ) -> EvidenceObservation:
        evidence_id = self.ledger.next_id()

        observation = self.follower.follow(
            lead_id,
            evidence_id=evidence_id,
        )

        self.ledger.add(
            observation,
            state=self.state,
        )

        self._incorporate(
            observation
        )

        return observation

    def record(
        self,
        observation: EvidenceObservation,
    ) -> EvidenceObservation:
        recorded = self.ledger.add(
            observation,
            state=self.state,
        )

        self._incorporate(
            recorded
        )

        return recorded
