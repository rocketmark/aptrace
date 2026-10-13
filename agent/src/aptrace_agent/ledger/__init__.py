"""
Durable research ledger, adversarial audit, and deterministic verification.

Three layers, three authorities:

- Investigation (research model): discovers, chooses analyses, proposes claims.
- Adversarial audit (audit model): challenges one claim version at a time and
  records a verdict artifact; it never changes claim state.
- Verification and knowledge management (APTrace): owns execution, evidence
  identity, claim versions and dependencies, and is the only authority that
  moves a claim to VERIFIED, BLOCKED, STALE or SUPERSEDED.
"""

from aptrace_agent.ledger.models import (
    AuditRecord,
    AuditVerdict,
    ClaimState,
    ClaimType,
    ClaimVersion,
    EvidenceArtifact,
    EvidenceGrade,
    ExecutionContext,
    InvestigationRun,
    ToolInvocation,
    VerificationRecord,
)
from aptrace_agent.ledger.operations import LedgerOperationRunner
from aptrace_agent.ledger.store import LedgerImmutableError, ResearchLedger
from aptrace_agent.ledger.verifier import ClaimVerifier

__all__ = [
    "AuditRecord",
    "AuditVerdict",
    "ClaimState",
    "ClaimType",
    "ClaimVerifier",
    "ClaimVersion",
    "EvidenceArtifact",
    "EvidenceGrade",
    "ExecutionContext",
    "InvestigationRun",
    "LedgerImmutableError",
    "LedgerOperationRunner",
    "ResearchLedger",
    "ToolInvocation",
    "VerificationRecord",
]
