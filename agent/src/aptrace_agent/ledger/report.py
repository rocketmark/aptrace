"""
Generated human-readable view of the research ledger.

The ledger is canonical; this Markdown is derived from it and carries the
ledger fingerprint it was generated from, so a stale report is detectable.
"""

from __future__ import annotations

import re
from pathlib import Path

from aptrace_agent.ledger.gate import assess_policy
from aptrace_agent.ledger.models import ClaimState
from aptrace_agent.ledger.stability import stability_summary
from aptrace_agent.ledger.store import ResearchLedger


FINGERPRINT_RE = re.compile(r"<!-- ledger-fingerprint: ([0-9a-f]+) -->")

_PHASE_ORDER = {"A": 0, "B": 1, "C": 2, "P": 3, "D": 4}

_STATE_ORDER = {
    ClaimState.VERIFIED: 0,
    ClaimState.PROPOSED: 1,
    ClaimState.BLOCKED: 2,
    ClaimState.STALE: 3,
    ClaimState.SUPERSEDED: 4,
}


def _cell(text: str) -> str:
    return " ".join(str(text).split()).replace("|", "\\|")


def render_report(ledger: ResearchLedger, *, title: str = "Research ledger report") -> str:
    fingerprint = ledger.fingerprint()
    rows = sorted(ledger.iter_current(), key=lambda item: (_STATE_ORDER[item[1]], int(item[0].claim_id[1:]), item[0].version))
    counts: dict[str, int] = {}

    for _claim, state in rows:
        counts[state.value] = counts.get(state.value, 0) + 1

    lines = [
        f"# {title}",
        "",
        f"<!-- ledger-fingerprint: {fingerprint} -->",
        "",
        "> Generated from the APTrace research ledger "
        f"(`{ledger.root.name}/`, fingerprint `{fingerprint}`). Do not edit by hand; "
        "regenerate with `aptrace-agent report`.",
        ">",
        "> **VERIFIED** means consistent with the currently recorded evidence and APTrace's "
        "deterministic checks, after an independent audit returned SUPPORTED. It is not a proof "
        "of semantic truth. Evidence grade and lifecycle state are independent. A VERIFIED decision "
        "made before the verification policy existed names no policy; its current-policy "
        "eligibility is shown separately.",
        "",
        "States: " + (", ".join(f"{k} {v}" for k, v in sorted(counts.items())) or "no claims"),
        "",
        "| Claim | State | Grade | Last audit | Assertion |",
        "|---|---|---|---|---|",
    ]

    for claim, state in rows:
        audit = ledger.latest_audit(claim.key)
        verdict = "—" if audit is None else audit.verdict.value + (" (synthesized)" if audit.verdict_synthesized else "")
        lines.append(f"| {claim.key} | {state.value} | {claim.proposed_grade.value} | {verdict} | {_cell(claim.assertion)[:160]} |")

    stable = [
        group
        for claim, _state in rows
        for group in stability_summary(ledger.audits_for(claim.key))["groups"]
        if group["runs"] >= 2 and group["input_fingerprint"]
    ]

    if stable:
        lines += [
            "",
            "## Repeated-audit stability",
            "",
            "Audits of the same claim version with the same audit-input fingerprint (identical claim, evidence, "
            "projection, source agreement, template, model, generation parameters, tools, and budget). "
            "Measurement only: verification uses the existing audit rule.",
            "",
            "| Claim | Input fingerprint | Runs | Verdicts | Verdict agreement | Executed-analysis agreement | Challenges citing coverage gaps |",
            "|---|---|---|---|---|---|---|",
        ]
        lines += [
            f"| {g['claim_version']} | `{g['input_fingerprint']}` | {g['runs']} | "
            f"{', '.join(f'{k} {v}' for k, v in g['verdicts'].items())} | {g['verdict_agreement']:.0%} | "
            f"{g['tool_sequence_agreement']:.0%} | {g['challenges_citing_coverage_gaps']} |"
            for g in stable
        ]

    for claim, state in rows:
        audit = ledger.latest_audit(claim.key)
        verifications = ledger.verifications_for(claim.key)
        lines += [
            "",
            f"## {claim.key} — {state.value}",
            "",
            f"- **Assertion:** {claim.assertion}",
            f"- **Subject:** {claim.subject}",
            f"- **Type / proposed grade:** {claim.claim_type.value} / {claim.proposed_grade.value}",
            f"- **Scope:** {claim.scope or '(not stated)'}",
            f"- **Proposed by:** {claim.proposed_by}" + (f" in run `{claim.run_id}`" if claim.run_id else ""),
        ]

        if claim.supersedes:
            lines.append(f"- **Supersedes:** {claim.supersedes}")

        if claim.semantics is not None:
            lines.append(f"- **Structured semantics (authoritative for verification):** `{claim.semantics.summary()}`")

        lines.append("- **Depends on:** " + (", ".join(claim.depends_on) or "none"))
        lines.append("- **Supporting evidence:**")

        for evidence_id in claim.supporting_evidence_ids:
            if ledger.has_evidence(evidence_id):
                artifact = ledger.evidence(evidence_id)
                lines.append(
                    f"  - `{evidence_id}` {artifact.tool} — grade {artifact.grade.value} ({artifact.grade_basis}); "
                    f"result sha256 `{artifact.result_sha256[:16]}…`; invocation `{artifact.invocation_id}`"
                )
            else:
                lines.append(f"  - `{evidence_id}` — **not found in ledger**")

        if claim.contradictory_evidence_ids:
            lines.append("- **Contradictory evidence:** " + ", ".join(f"`{e}`" for e in claim.contradictory_evidence_ids))

        if claim.assumptions:
            lines.append("- **Assumptions:**")
            lines += [f"  - {item}" for item in claim.assumptions]

        lines.append("- **Limitations:**")
        lines += [f"  - {('`' + item.code + '` ') if item.code else ''}{item.text}" for item in claim.limitations] or ["  - none recorded"]

        if audit is not None:
            lines += [
                f"- **Last audit:** `{audit.audit_id}` by `{audit.model}` ({audit.template_version}) — "
                f"**{audit.verdict.value}**{' (synthesized: ' + audit.termination_reason + ')' if audit.verdict_synthesized else ''}; "
                f"{sum(1 for s in audit.steps if s.action == 'request')} analysis request(s)",
                f"  - Reasoning: {_cell(audit.reasoning)}",
            ]
            lines += [f"  - Scope check: {_cell(audit.scope_check)}"] if audit.scope_check else []
            lines += [f"  - Challenge: {_cell(item)}" for item in audit.challenges]
            lines += [f"  - Follow-up: {_cell(item.question)}" for item in audit.follow_up_requests]
        else:
            lines.append("- **Last audit:** none")

        audits = ledger.audits_for(claim.key)

        if audits:
            lines.append("- **Audit history** (all audits of this version, oldest first; never rewritten):")

            for item in audits:
                executed = sum(1 for s in item.steps if (s.outcome or "").startswith("executed:"))
                requests = sum(1 for s in item.steps if s.action == "request")
                gaps = sum(1 for s in item.steps if s.outcome == "executed:coverage_gap") or sum(
                    1 for s in item.steps if "Function not found" in (s.result_summary or "")
                )
                lines.append(
                    f"  - `{item.audit_id}` {item.template_version} input `{item.input_fingerprint or 'not recorded (pre-v0.4)'}` → "
                    f"**{item.verdict.value}**"
                    + (f" (model said {item.model_verdict.value})" if item.model_verdict else "")
                    + f"; {requests} request(s)"
                    + (f", {executed} executed" if item.input_fingerprint else "")
                    + (f", {gaps} coverage-gap result(s)" if gaps else "")
                    + (f"; batch `{item.batch_id}`" if item.batch_id else "")
                )

        agreement_id = next((a.source_agreement_evidence for a in reversed(audits) if a.source_agreement_evidence), None)

        if agreement_id and ledger.has_evidence(agreement_id):
            result, _ok = ledger.evidence_result(agreement_id)
            lines.append(f"- **Structural source agreement** (`{agreement_id}`, latest audit context):")

            for entry in result.get("agreements", []):
                seen = ", ".join(
                    f"{o['source']}={o.get('function') or ('—' if o.get('available') else 'n/a')}"
                    for o in entry.get("observations", [])
                )
                gaps = f"; gaps {', '.join(entry['coverage_gaps'])}" if entry.get("coverage_gaps") else ""
                lines.append(f"  - {entry['address']} {entry['status']} ({entry['relation']}): {seen}{gaps}")

        if verifications:
            last = verifications[-1]
            failed = [c for c in last.checks if not c.passed]
            lines.append(
                f"- **Last verification:** `{last.verification_id}` [{last.mode}] → {last.outcome.value}"
                + (": " + "; ".join(f"{c.name} ({c.detail})" for c in failed) if failed else " (all checks passed)")
            )

            if last.phases:
                lines.append("  - Phases: " + ", ".join(f"{k} {v}" for k, v in sorted(last.phases.items(), key=lambda kv: _PHASE_ORDER.get(kv[0], 9))))

            if last.gate is not None:
                gate = last.gate
                lines.append(
                    f"  - Verification policy `{gate.policy.policy_id}` v{gate.policy.version}, class {gate.claim_class}: gate **{gate.status}**"
                )
                lines += [
                    f"    - {c.status} `{c.code}`" + (f" ({c.address})" if c.address else "") + f": {_cell(c.detail)}"
                    + (" — " + ", ".join(f"`{e}`" for e in c.evidence_ids) if c.evidence_ids else "")
                    for c in gate.conditions
                ]
            elif last.policy is None:
                lines.append("  - Verification policy: none recorded (decision predates the verification policy).")

            for item in last.semantic_checks:
                lines.append(
                    f"  - Semantic check `{item.code.value}`"
                    + (f" {item.field}={item.claimed}" if item.field else "")
                    + (f" (claimed role {item.claimed_role}; evidence role {item.evidence_role})" if item.evidence_role and not item.passed else "")
                    + (f" — `{item.evidence_id}`" if item.evidence_id else "")
                    + (f": {_cell(item.detail)}" if item.detail and not item.passed else "")
                )

            if last.audit_skipped:
                lines.append("  - Audit model not consulted: deterministic verification failed before phase D.")

        if state == ClaimState.VERIFIED:
            assessment = assess_policy(ledger, claim.key)

            if not assessment.decision_under_current_policy:
                lines.append(
                    "- **Current-policy eligibility (read-only assessment of recorded evidence; historical decision unchanged):** "
                    + _cell(assessment.summary())
                )

        history = ledger.history(claim.key)
        lines.append("- **Lifecycle:** " + " → ".join(f"{e.state} ({e.actor})" for e in history))

    return "\n".join(lines) + "\n"


def report_is_stale(ledger: ResearchLedger, path: Path) -> bool:
    if not Path(path).is_file():
        return True

    match = FINGERPRINT_RE.search(Path(path).read_text())
    return match is None or match.group(1) != ledger.fingerprint()


def write_report(ledger: ResearchLedger, path: Path, **kwargs) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_report(ledger, **kwargs))
    return path
