from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from aptrace_agent.research.lead_generation import (
    CallsiteReader,
    LeadGenerationIssue,
    generate_case_search_leads_from_pin_table,
    generate_function_fact_leads,
    generate_pin_table_leads_from_callsite,
)
from aptrace_agent.research.leads import LeadRegistry
from aptrace_agent.research.state import Lead
from aptrace_agent.schemas import EvidenceObservation


@dataclass(frozen=True)
class DerivationResult:
    leads: tuple[Lead, ...]
    issues: tuple[LeadGenerationIssue, ...] = ()


class LeadDeriver:
    """
    Mechanically derive safe research directions from new evidence.

    This layer discovers available next steps. It does not decide which
    step is important; that remains a model decision.
    """

    def __init__(
        self,
        *,
        registry: LeadRegistry,
        callsite_reader: CallsiteReader,
    ) -> None:
        self.registry = registry
        self.callsite_reader = callsite_reader

    def derive(
        self,
        observation: EvidenceObservation,
    ) -> DerivationResult:
        if observation.tool == "function_facts":
            generated = generate_function_fact_leads(
                observation.result,
                evidence_id=observation.id,
                registry=self.registry,
                callsite_reader=self.callsite_reader,
            )

            return DerivationResult(
                leads=generated.leads,
                issues=generated.issues,
            )

        if observation.tool == "callsite_context":
            leads = generate_pin_table_leads_from_callsite(
                observation,
                evidence_id=observation.id,
                registry=self.registry,
            )

            return DerivationResult(
                leads=tuple(leads),
            )

        if observation.tool == "pin_table_entry":
            leads = generate_case_search_leads_from_pin_table(
                observation,
                evidence_id=observation.id,
                registry=self.registry,
            )

            return DerivationResult(
                leads=tuple(leads),
            )

        return DerivationResult(
            leads=(),
        )
