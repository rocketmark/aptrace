"""
Repeated-audit stability measurement.

Groups recorded audits of one claim version by their audit-input
fingerprint and measures how much the auditor's output varies for an
identical input: verdicts, executed analyses, and whether challenges rest
on tool coverage gaps. Measurement only; nothing here changes claim state
or implements any multi-audit policy.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from collections.abc import Iterable
from typing import Any

from aptrace_agent.ledger.models import AuditRecord


# Heuristic indicator that a challenge rests on a tool/source coverage gap
# rather than on evidence. Evaluator-side only; never affects claim state.
COVERAGE_GAP_TEXT = re.compile(
    r"not found|could not (?:answer|find|verify|be verified|locate)|failed to (?:find|locate|verify)|"
    r"tool (?:failure|failed|error)|coverage gap|unable to (?:find|verify|locate|confirm)|"
    r"cannot (?:be )?(?:verified|confirmed|found)|missing from|no (?:function|record) (?:found|for)",
    re.IGNORECASE,
)


def _sequence(audit: AuditRecord, *, executed_only: bool) -> tuple[str, ...]:
    out = []

    for step in audit.steps:
        if step.action != "request" or step.tool is None:
            continue

        if executed_only and not (step.outcome or "").startswith("executed:"):
            continue

        out.append(f"{step.tool} {json.dumps(step.arguments, sort_keys=True)}")

    return tuple(out)


def cites_coverage_gap(audit: AuditRecord) -> bool:
    texts = list(audit.challenges)

    if audit.verdict.value != "SUPPORTED":
        texts.append(audit.reasoning)

    return any(COVERAGE_GAP_TEXT.search(text) for text in texts)


def audit_row(audit: AuditRecord) -> dict[str, Any]:
    prompt = sum(s.prompt_tokens or 0 for s in audit.steps)
    completion = sum(s.completion_tokens or 0 for s in audit.steps)
    return {
        "audit_id": audit.audit_id,
        "claim_version": audit.claim_version,
        "template_version": audit.template_version,
        "input_fingerprint": audit.input_fingerprint,
        "batch_id": audit.batch_id,
        "verdict": audit.verdict.value,
        "model_verdict": audit.model_verdict.value if audit.model_verdict else None,
        "verdict_synthesized": audit.verdict_synthesized,
        "termination_reason": audit.termination_reason,
        "scope_check": audit.scope_check,
        "requested_operations": list(_sequence(audit, executed_only=False)),
        "executed_operations": list(_sequence(audit, executed_only=True)),
        "step_outcomes": [s.outcome for s in audit.steps if s.outcome],
        "evidence_inspected": audit.evidence_inspected,
        "coverage_gaps_encountered": [
            f"{s.tool} {json.dumps(s.arguments, sort_keys=True)}" for s in audit.steps if s.outcome == "executed:coverage_gap"
        ],
        "contradictory_evidence_claimed": audit.contradictory_evidence,
        "challenges": audit.challenges,
        "challenge_cites_coverage_gap": cites_coverage_gap(audit),
        "limitations_identified": audit.limitations,
        "falsification": audit.falsification,
        "prompt_tokens": prompt,
        "completion_tokens": completion,
        "runtime": audit.runtime,
    }


def _agreement(values: list[Any]) -> float:
    if not values:
        return 0.0

    return round(Counter(values).most_common(1)[0][1] / len(values), 3)


def group_summary(audits: list[AuditRecord]) -> dict[str, Any]:
    rows = [audit_row(a) for a in audits]
    verdicts = Counter(r["verdict"] for r in rows)
    executed = [tuple(r["executed_operations"]) for r in rows]
    first_tools = [r["executed_operations"][0].split(" ", 1)[0] if r["executed_operations"] else None for r in rows]
    return {
        "claim_version": audits[0].claim_version,
        "input_fingerprint": audits[0].input_fingerprint,
        "template_version": audits[0].template_version,
        "runs": len(rows),
        "verdicts": dict(sorted(verdicts.items())),
        "modal_verdict": verdicts.most_common(1)[0][0],
        "verdict_agreement": _agreement([r["verdict"] for r in rows]),
        "model_verdicts": dict(sorted(Counter(r["model_verdict"] or r["verdict"] for r in rows).items())),
        "tool_sequence_agreement": _agreement(executed),
        "first_tool_agreement": _agreement(first_tools),
        "distinct_tool_sequences": len(set(executed)),
        "distinct_challenge_sets": len({tuple(r["challenges"]) for r in rows if r["verdict"] != "SUPPORTED"}),
        "challenges_citing_coverage_gaps": sum(1 for r in rows if r["verdict"] != "SUPPORTED" and r["challenge_cites_coverage_gap"]),
        "runs_with_coverage_gap_results": sum(1 for r in rows if r["coverage_gaps_encountered"]),
        "runs_claiming_contradictory_evidence": sum(1 for r in rows if r["contradictory_evidence_claimed"]),
        "falsification_unsatisfied": sum(1 for r in rows if r["falsification"] and not r["falsification"].get("satisfied")),
        "mean_prompt_tokens": round(sum(r["prompt_tokens"] for r in rows) / len(rows), 1),
        "mean_completion_tokens": round(sum(r["completion_tokens"] for r in rows) / len(rows), 1),
        "served_models": sorted({m for r in rows for m in r["runtime"].get("served_models", [])}),
    }


def stability_summary(audits: Iterable[AuditRecord]) -> dict[str, Any]:
    """Per-fingerprint stability groups (ordered by first audit) and rows."""

    ordered = sorted(audits, key=lambda a: a.started_at)
    groups: dict[tuple[str, str | None], list[AuditRecord]] = {}

    for audit in ordered:
        groups.setdefault((audit.claim_version, audit.input_fingerprint), []).append(audit)

    return {
        "groups": [group_summary(items) for items in groups.values()],
        "rows": [audit_row(a) for a in ordered],
    }
