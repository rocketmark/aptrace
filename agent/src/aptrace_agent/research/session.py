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
from aptrace_agent.research.history import ContinuityTracker
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
        # Follow-up sessions only (research/history.py): historical
        # operations this session may use by reference.
        self.continuity: ContinuityTracker | None = None

    def _incorporate(
        self,
        observation: EvidenceObservation,
        *,
        derive_leads: bool = True,
    ) -> None:
        self.fact_deriver.derive(
            observation,
            self.state,
        )

        if self.deriver is None or not derive_leads:
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
        *,
        step: int | None = None,
        trigger: str = "lead",
    ) -> EvidenceObservation:
        evidence_id = self.ledger.next_id()
        continuity = self.continuity

        if continuity is not None:
            action = self.registry.resolve(lead_id)
            decision = continuity.history.lookup(action.tool, action.arguments)

            if decision is not None and decision.reusable:
                return self._reuse(lead_id, decision, step=step, trigger=trigger)

            if decision is not None:
                continuity.refuse(decision, trigger)

        try:
            observation = self.follower.follow(
                lead_id,
                evidence_id=evidence_id,
            )
        except Exception:
            if continuity is not None:
                continuity.failed.add(lead_id)

            raise

        if continuity is not None:
            continuity.followed[lead_id] = (observation.id, False, step)

        self.ledger.add(
            observation,
            state=self.state,
        )

        self._incorporate(
            observation
        )

        return observation

    def _reuse(self, lead_id: str, decision, *, step: int | None, trigger: str) -> EvidenceObservation:
        """Use a historical result by reference: no execution, no new evidence."""

        continuity = self.continuity
        invocation = decision.invocation
        observation = self.ledger.add(
            EvidenceObservation(
                id=self.ledger.next_id(),
                tool=invocation.tool,
                arguments=dict(invocation.arguments),
                result=continuity.history.result(decision),
                reused_from=invocation.evidence_id,
            ),
            state=self.state,
        )
        self.registry.mark_followed(lead_id)
        continuity.reused.append(continuity.history.reuse_record(decision, session_evidence_id=observation.id, trigger=trigger, step=step))
        continuity.followed[lead_id] = (observation.id, True, step)
        self._incorporate(observation)
        return observation

    def preload(self, tool: str, arguments: dict) -> EvidenceObservation | None:
        """
        Make one cited historical result visible as a reference: facts only,
        no leads (the follow-up's seeded leads are the frontier), no step.
        """

        continuity = self.continuity
        decision = continuity.history.lookup(tool, arguments) if continuity else None

        if decision is None:
            return None
        if not decision.reusable:
            continuity.refuse(decision, "preload")
            return None

        invocation = decision.invocation
        observation = self.ledger.add(
            EvidenceObservation(
                id=self.ledger.next_id(),
                tool=invocation.tool,
                arguments=dict(invocation.arguments),
                result=continuity.history.result(decision),
                reused_from=invocation.evidence_id,
            ),
            state=self.state,
        )
        continuity.reused.append(continuity.history.reuse_record(decision, session_evidence_id=observation.id, trigger="preload", step=None))
        continuity.preloaded.add(observation.id)
        self._incorporate(observation, derive_leads=False)
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
