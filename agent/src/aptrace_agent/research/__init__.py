"""
Generic autonomous firmware research for APTrace.

APTrace owns deterministic evidence collection, provenance, safe
execution, deduplication, budgets, and structural lead resolution.

The research model chooses which research direction matters next,
proposes claims and hypotheses, identifies open questions, and decides
when sufficient evidence exists.
"""

from aptrace_agent.research.lead_generation import (
    LeadGenerationIssue,
    LeadGenerationResult,
    generate_function_fact_leads,
)
from aptrace_agent.research.leads import (
    LeadAction,
    LeadRegistry,
)
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
    "Hypothesis",
    "Lead",
    "LeadAction",
    "LeadGenerationIssue",
    "LeadGenerationResult",
    "LeadRegistry",
    "LeadStatus",
    "OpenQuestion",
    "QuestionStatus",
    "ResearchState",
    "generate_function_fact_leads",
]
