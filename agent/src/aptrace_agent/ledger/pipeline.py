"""
Verification-gated audit orchestration.

claim proposed -> deterministic verification (phases A-C) -> audit model
(only if eligible) -> APTrace lifecycle decision (phase D). The audit model
is never asked about a claim APTrace already knows is structurally or
semantically invalid, or whose evidence no longer replays.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from aptrace_agent.ledger.models import AuditRecord, ClaimState
from aptrace_agent.ledger.verifier import ClaimVerifier, VerificationOutcome


@dataclass
class GatedAudit:
    precheck: VerificationOutcome
    audit: AuditRecord | None
    verification: VerificationOutcome | None
    skipped_reason: str | None = None

    @property
    def audit_skipped(self) -> bool:
        return self.audit is None or self.audit.diagnostic


def eligible(precheck: VerificationOutcome) -> bool:
    return precheck.record.phases.get("C") == "passed" and precheck.current not in (ClaimState.BLOCKED, ClaimState.STALE, ClaimState.SUPERSEDED)


def semantic_summary(precheck: VerificationOutcome) -> str:
    checks = precheck.record.semantic_checks
    return "; ".join(
        f"{c.code.value} {c.field or ''}={c.claimed or ''} [{c.evidence_id or '-'}]".strip() for c in checks
    )


def audit_if_eligible(
    key: str,
    *,
    verifier: ClaimVerifier,
    auditor: Any,
    diagnostic: bool = False,
    verify_after: bool = True,
    **audit_kwargs: Any,
) -> GatedAudit:
    precheck = verifier.precheck(key)

    if not eligible(precheck):
        failed = [c.name for c in precheck.record.checks if not c.passed and c.severity in ("block", "stale")]
        reason = f"deterministic verification {precheck.current.value}: {', '.join(failed) or 'not eligible'}"

        if not diagnostic:
            return GatedAudit(precheck=precheck, audit=None, verification=None, skipped_reason=reason)

        # A diagnostic audit is recorded for inspection but never counts.
        audit = auditor.audit(key, diagnostic=True, semantic_checks=semantic_summary(precheck), **audit_kwargs)
        return GatedAudit(precheck=precheck, audit=audit, verification=None, skipped_reason=reason)

    audit = auditor.audit(key, semantic_checks=semantic_summary(precheck), **audit_kwargs)
    verification = verifier.verify(key) if verify_after else None
    return GatedAudit(precheck=precheck, audit=audit, verification=verification)
