"""
Claim admission: the boundary between a model's claim proposal and the
research ledger.

Three decisions are kept apart:

- admission (here): is the proposal well-formed, about real entities, and
  supported by what it cites, at the grade it asks for? Admitted proposals
  become PROPOSED claim versions; rejected ones are recorded on the run
  (InvestigationRun.claim_admission) with their original text and
  diagnostics, and never become claims.
- evidentiary support of typed claims: claim_semantics.verify_semantics,
  the same function verification phase B uses.
- verification: ClaimVerifier, unchanged in role. Admission never makes a
  claim VERIFIED, and an admitted claim is only PROPOSED.

Rules (diagnostic codes in ledger/claim_checks.py):

1. references: at least one, all naming session evidence;
2. entity identity: canonical identifiers, known functions, known
   peripherals;
3. typed semantics, when given: valid and consistent with cited evidence;
   untyped prose: peripheral access/absence rules;
4. grade: within the cited evidence's ceiling (grade_ceiling); untyped
   claims are hypotheses and may be at most PROBABLE, because nothing
   checks their assertion mechanically;
5. accountability (follow-up sessions): evidence of executed or reused
   follow-up leads about a function the claim names must be cited, or its
   omission explained ([omit E#: reason]); an explanation satisfies only
   this rule;
6. historical evidence: cited reused results are noted with their
   original ids; they are prior observations, not independent ones.

Nothing is rewritten: a proposal is admitted as proposed or rejected.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Collection
from types import SimpleNamespace
from typing import Any

from pydantic import ValidationError

from aptrace_agent.ledger.claim_checks import (
    EVIDENCE_MISSING,
    EVIDENCE_OMITTED,
    EVIDENCE_REFERENCE_UNKNOWN,
    GRADE_ABOVE_CEILING,
    HISTORICAL_REFERENCE,
    NOTE,
    OMISSION_EXPLAINED,
    REJECT,
    SEMANTICS_INCONSISTENT,
    SEMANTICS_INVALID,
    UNTYPED_GRADE,
    access_diagnostics,
    entity_diagnostics,
)
from aptrace_agent.ledger.claim_semantics import ClaimSemantics, verify_semantics
from aptrace_agent.ledger.models import GRADE_RANK, ClaimAdmission, ClaimDiagnostic, ClaimType, EvidenceGrade
from aptrace_agent.ledger.semantics import evidence_grade, grade_ceiling


UNTYPED_GRADE_CAP = EvidenceGrade.PROBABLE
_FUNCTION_RE = re.compile(r"\bFUN_[0-9a-f]{8}\b")


def function_resolver(session: Any) -> Callable[[str], bool] | None:
    """Known-function test from the session's FunctionFacts reader, if any."""

    reader = getattr(getattr(session, "deriver", None), "function_facts_reader", None)

    if reader is None:
        return None

    def exists(name: str) -> bool:
        try:
            reader.function_facts(name)
        except (KeyError, ValueError):
            return False

        return True

    return exists


def _cited(session: Any, evidence_ids: list[str]) -> tuple[list[tuple[Any, dict[str, Any]]], list[str]]:
    pairs, unknown = [], []

    for evidence_id in evidence_ids:
        try:
            observation = session.ledger.get(evidence_id)
        except KeyError:
            unknown.append(evidence_id)
            continue

        grade, _basis = evidence_grade(observation.tool, observation.result)
        artifact = SimpleNamespace(evidence_id=observation.id, tool=observation.tool, arguments=observation.arguments, grade=grade, reused_from=observation.reused_from)
        pairs.append((artifact, observation.result))

    return pairs, unknown


def _accountability(session: Any, proposal: dict[str, Any], semantics: ClaimSemantics | None) -> list[ClaimDiagnostic]:
    continuity = getattr(session, "continuity", None)

    if continuity is None:
        return []

    named = set(_FUNCTION_RE.findall(f"{proposal.get('subject', '')} {proposal['assertion']}"))

    if semantics is not None and semantics.function_role is not None:
        named.add(semantics.function_role.function)

    cited = set(proposal.get("evidence_ids", []))
    omissions = proposal.get("omissions", {})
    missing: list[str] = []
    explained: list[str] = []

    for lead_id, (tool, arguments, description) in continuity.seeded.items():
        followed = continuity.followed.get(lead_id)

        if followed is None:
            continue

        relevant = continuity.anchors.get(lead_id) in named or arguments.get("function") in named
        session_id = followed[0]

        if not relevant or session_id in cited:
            continue

        if session_id in omissions:
            explained.append(f"{session_id} ({description}): {omissions[session_id]}")
        else:
            missing.append(f"{session_id} ({description})")

    out: list[ClaimDiagnostic] = []

    if missing:
        out.append(
            ClaimDiagnostic(
                code=EVIDENCE_OMITTED, severity=REJECT,
                detail="follow-up evidence about the claim's functions is neither cited nor explained: " + "; ".join(missing)
                + ". Cite it, or append [omit E#: reason]",
                evidence_ids=[m.split(" ", 1)[0] for m in missing],
            )
        )

    if explained:
        out.append(ClaimDiagnostic(code=OMISSION_EXPLAINED, severity=NOTE, detail="; ".join(explained), evidence_ids=[e.split(" ", 1)[0] for e in explained]))

    return out


def admit(
    proposal: dict[str, Any],
    session: Any,
    *,
    round: int,
    function_exists: Callable[[str], bool] | None = None,
    peripherals: Collection[str] | None = None,
) -> ClaimAdmission:
    """Admission decision for one parsed proposal (see module rules)."""

    diagnostics: list[ClaimDiagnostic] = []
    evidence_ids = list(proposal.get("evidence_ids", []))
    pairs, unknown = _cited(session, evidence_ids)

    if not evidence_ids:
        diagnostics.append(ClaimDiagnostic(code=EVIDENCE_MISSING, severity=REJECT, detail="a claim needs at least one cited evidence id"))
    if unknown:
        diagnostics.append(ClaimDiagnostic(code=EVIDENCE_REFERENCE_UNKNOWN, severity=REJECT, detail=f"unknown evidence: {', '.join(unknown)}", evidence_ids=unknown))

    text = f"{proposal.get('subject', '')} {proposal['assertion']}"
    diagnostics += entity_diagnostics(text, function_exists=function_exists, peripherals=peripherals)

    semantics = None
    claim_type = str(proposal.get("claim_type") or "OTHER")

    if proposal.get("semantics") is not None:
        try:
            semantics = ClaimSemantics.model_validate(proposal["semantics"])
        except (ValidationError, ValueError) as exc:
            diagnostics.append(ClaimDiagnostic(code=SEMANTICS_INVALID, severity=REJECT, detail=str(exc).splitlines()[0][:300]))

    if semantics is not None:
        for check in verify_semantics(semantics, claim_type, pairs):
            if not check.passed:
                diagnostics.append(
                    ClaimDiagnostic(
                        code=SEMANTICS_INCONSISTENT, severity=REJECT, detail=f"{check.code.value}: {check.detail or check.field}",
                        value=check.claimed, evidence_ids=[check.evidence_id] if check.evidence_id else [],
                    )
                )
    elif proposal.get("semantics") is None:
        diagnostics += access_diagnostics(proposal["assertion"], pairs)

    grade = EvidenceGrade(proposal["grade"])

    if pairs:
        try:
            ceiling = grade_ceiling(ClaimType(claim_type), [a for a, _ in pairs])
        except ValueError:
            ceiling = EvidenceGrade.UNKNOWN

        if GRADE_RANK[grade] > GRADE_RANK[ceiling]:
            diagnostics.append(
                ClaimDiagnostic(code=GRADE_ABOVE_CEILING, severity=REJECT, detail=f"proposed {grade.value}; cited evidence permits at most {ceiling.value}", value=grade.value)
            )

    if semantics is None and GRADE_RANK[grade] > GRADE_RANK[UNTYPED_GRADE_CAP]:
        diagnostics.append(
            ClaimDiagnostic(
                code=UNTYPED_GRADE, severity=REJECT,
                detail=f"proposed {grade.value} without typed semantics; an untyped claim is a hypothesis APTrace cannot check mechanically and may be at most {UNTYPED_GRADE_CAP.value}",
                value=grade.value,
            )
        )

    diagnostics += _accountability(session, proposal, semantics)

    historical = [(a.evidence_id, a.reused_from) for a, _ in pairs if getattr(a, "reused_from", None)]

    if historical:
        diagnostics.append(
            ClaimDiagnostic(
                code=HISTORICAL_REFERENCE, severity=NOTE,
                detail="cites prior-run results by reference (" + ", ".join(f"{s}={d}" for s, d in historical)
                + "); they are not new observations or independent corroboration",
                evidence_ids=[d for _, d in historical],
            )
        )

    rejected = any(d.severity == REJECT for d in diagnostics)
    return ClaimAdmission(
        round=round,
        raw=str(proposal.get("raw") or proposal["assertion"])[:600],
        decision="rejected" if rejected else "admitted",
        assertion=proposal["assertion"],
        grade=grade.value,
        claim_type=claim_type,
        evidence_ids=evidence_ids,
        omissions=dict(proposal.get("omissions", {})),
        diagnostics=diagnostics,
    )


def feedback(records: list[ClaimAdmission], limit: int = 900) -> str:
    """Bounded diagnostics text for one correction request."""

    lines: list[str] = []

    for record in records:
        if record.decision == "admitted":
            continue

        reasons = "; ".join(f"{d.code}: {d.detail}" for d in record.diagnostics if d.severity == REJECT) or "not in the claim format"
        lines.append(f"- {record.raw[:120]!r}: {reasons[:300]}")

    text = "\n".join(lines)
    return text if len(text) <= limit else text[: limit - 3] + "..."


__all__ = ["UNTYPED_GRADE_CAP", "admit", "feedback", "function_resolver"]
