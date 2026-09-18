"""
Generic autonomous firmware research for APTrace.

APTrace owns deterministic evidence collection, provenance, safe
execution, deduplication, budgets, and structural lead resolution.

The research model chooses which research direction matters next,
proposes claims and hypotheses, identifies open questions, and decides
when sufficient evidence exists.
"""

from aptrace_agent.research.controller import (
    ResearchController,
    ResearchRunResult,
    ResearchStep,
)
from aptrace_agent.research.derivation import (
    DerivationResult,
    LeadDeriver,
)
from aptrace_agent.research.evidence import EvidenceLedger
from aptrace_agent.research.reconciliation import (
    CaseReconciler,
    EntityReconciliation,
    ReconciliationProposal,
)
from aptrace_agent.research.session import ResearchSession
from aptrace_agent.research.fact_derivation import (
    FactDerivationResult,
    StateFactDeriver,
)
from aptrace_agent.research.follow import LeadFollower
from aptrace_agent.research.lead_generation import (
    LeadGenerationIssue,
    LeadGenerationResult,
    generate_case_search_leads_from_pin_table,
    generate_function_fact_leads,
    generate_pin_table_leads_from_callsite,
)
from aptrace_agent.research.leads import (
    LeadAction,
    LeadRegistry,
)
from aptrace_agent.research.state_updates import ResearchStateUpdater
from aptrace_agent.research.state import (
    Claim,
    ClaimGrade,
    Contradiction,
    Hypothesis,
    Lead,
    LeadStatus,
    OpenQuestion,
    QuestionStatus,
    ResearchState,
)

__all__ = [
    "Claim",
    "ClaimGrade",
    "Contradiction",
    "DerivationResult",
    "EvidenceLedger",
    "FactDerivationResult",
    "Hypothesis",
    "Lead",
    "LeadAction",
    "LeadDeriver",
    "LeadFollower",
    "LeadGenerationIssue",
    "LeadGenerationResult",
    "LeadRegistry",
    "LeadStatus",
    "OpenQuestion",
    "QuestionStatus",
    "CaseReconciler",
    "EntityReconciliation",
    "ReconciliationProposal",
    "ResearchSession",
    "ResearchController",
    "ResearchRunResult",
    "ResearchStep",
    "ResearchState",
    "ResearchStateUpdater",
    "StateFactDeriver",
    "generate_case_search_leads_from_pin_table",
    "generate_function_fact_leads",
    "generate_pin_table_leads_from_callsite",
]
