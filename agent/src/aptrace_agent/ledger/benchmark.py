"""
Known-answer benchmarks for investigation -> audit -> verification.

A fixture (<name>.json) lists deterministic setup operations and the claims
to propose. Expected outcomes live in a separate evaluator-only file
(<name>.expected.json) that is never shown to the auditor or investigator.
Keyword grading of audit text is a heuristic indicator of what the auditor
noticed; it never affects claim state.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from aptrace_agent.ledger.models import InvestigationRun
from aptrace_agent.ledger.operations import LedgerOperationRunner, source_revision
from aptrace_agent.ledger.pipeline import audit_if_eligible
from aptrace_agent.ledger.store import ResearchLedger, new_id, now
from aptrace_agent.ledger.verifier import ClaimVerifier


_FUNCTION_RE = re.compile(r"FUN_[0-9a-f]{8}")
_IRQ_RE = re.compile(r"IRQ:([A-Z][A-Z0-9_]{1,23})")


@dataclass
class ClaimOutcome:
    label: str
    key: str
    audit_id: str | None
    audit_verdict: str | None
    final_state: str
    failed_checks: list[str]
    expectations: dict[str, Any] = field(default_factory=dict)
    passed: bool | None = None
    audit_skipped: bool = False
    semantic_codes: list[str] = field(default_factory=list)


@dataclass
class BenchmarkResult:
    name: str
    setup_run_id: str
    evidence: dict[str, str]
    claims: list[ClaimOutcome]

    def as_dict(self) -> dict[str, Any]:
        return {
            "benchmark": self.name,
            "setup_run_id": self.setup_run_id,
            "evidence": self.evidence,
            "claims": [vars(c) for c in self.claims],
            "passed": all(c.passed is not False for c in self.claims),
        }


def load_fixture(directory: Path, name: str) -> tuple[dict[str, Any], dict[str, Any] | None]:
    fixture = json.loads((directory / f"{name}.json").read_text())
    expected_path = directory / f"{name}.expected.json"
    expected = json.loads(expected_path.read_text()) if expected_path.is_file() else None
    return fixture, expected


def _resolve_sets(
    items: list[str],
    sets: dict[str, list[str]],
    irq_handlers: Callable[[str], list[str]] | None,
) -> tuple[list[str], str]:
    functions: list[str] = []

    for item in items:
        irq = _IRQ_RE.fullmatch(item)

        if irq:
            resolved = irq_handlers(irq.group(1)) if irq_handlers else []
        elif _FUNCTION_RE.fullmatch(item):
            resolved = [item]
        else:
            resolved = sets.get(item, [])

        if not resolved:
            raise ValueError(f"benchmark set member {item!r} did not resolve")

        functions.extend(resolved)

    return list(dict.fromkeys(functions)), "+".join(items)


def run_setup(
    ledger: ResearchLedger,
    runner: LedgerOperationRunner,
    fixture: dict[str, Any],
    *,
    irq_handlers: Callable[[str], list[str]] | None = None,
    repo: Path | None = None,
) -> tuple[str, dict[str, str]]:
    run_id = new_id("R")
    started = now()
    evidence: dict[str, str] = {}
    invocations: list[str] = []
    sets: dict[str, list[str]] = {}

    for step in fixture["setup"]:
        tool = step["tool"]
        arguments = dict(step.get("arguments", {}))

        if tool == "census_common_paths":
            left, left_label = _resolve_sets(step["sets"]["left"], sets, irq_handlers)
            right, right_label = _resolve_sets(step["sets"]["right"], sets, irq_handlers)
            arguments = {"left": left, "right": right, "left_label": left_label, "right_label": right_label}

        invocation, artifact = runner.run(run_id, tool, arguments, input_evidence_ids=list(evidence.values()))
        invocations.append(invocation.invocation_id)

        if artifact is None:
            raise RuntimeError(f"benchmark setup step {step['name']} failed: {invocation.error}")

        evidence[step["name"]] = artifact.evidence_id
        result, _ok = ledger.load_blob(artifact.result_sha256)

        if tool == "census_peripheral_usage":
            sets[arguments["peripheral"]] = [f["function"] for f in result.get("functions", [])]
        elif tool == "census_usb_inventory":
            sets["USB"] = list(result.get("functions", []))

    context = runner.context()
    ledger.record_run(
        InvestigationRun(
            run_id=run_id,
            kind="benchmark-setup",
            case=context.case,
            firmware_key=context.firmware_key,
            firmware_sha256=context.firmware_sha256,
            context_id=context.context_id(),
            objective=fixture.get("objective", fixture["benchmark"]),
            started_at=started,
            ended_at=now(),
            termination_reason="setup_complete",
            source=source_revision(repo) if repo else source_revision(Path.cwd()),
            invocation_ids=invocations,
            evidence_ids=list(evidence.values()),
        )
    )
    return run_id, evidence


def propose_fixture_claims(
    ledger: ResearchLedger,
    fixture: dict[str, Any],
    evidence: dict[str, str],
    run_id: str,
) -> dict[str, str]:
    keys: dict[str, str] = {}

    for spec in fixture["claims"]:
        claim = ledger.propose_claim(
            subject=spec["subject"],
            assertion=spec["assertion"],
            claim_type=spec["claim_type"],
            proposed_grade=spec["proposed_grade"],
            proposed_by=f"benchmark-fixture:{fixture['benchmark']}",
            supporting_evidence_ids=[evidence.get(name, name) for name in spec.get("evidence", [])],
            contradictory_evidence_ids=[evidence.get(name, name) for name in spec.get("contradictory_evidence", [])],
            depends_on=[keys.get(label, label) for label in spec.get("depends_on", [])],
            scope=spec.get("scope", ""),
            assumptions=spec.get("assumptions", []),
            limitations=spec.get("limitations", []),
            derivation=spec.get("derivation", ""),
            run_id=run_id,
            semantics=spec.get("semantics"),
        )
        keys[spec["label"]] = claim.key

    return keys


def _mentions(text: str, groups: dict[str, list[str]]) -> dict[str, bool]:
    lowered = text.lower()
    return {name: any(word.lower() in lowered for word in words) for name, words in groups.items()}


def evaluate(outcome: ClaimOutcome, expected: dict[str, Any] | None, audit_text: str) -> ClaimOutcome:
    if not expected:
        return outcome

    checks: dict[str, Any] = {}

    if "final_state" in expected:
        checks["final_state"] = outcome.final_state in expected["final_state"]

    if "audit_verdict" in expected and outcome.audit_verdict is not None:
        checks["audit_verdict"] = outcome.audit_verdict in expected["audit_verdict"]

    if "must_not_be" in expected:
        checks["must_not_be"] = outcome.final_state not in expected["must_not_be"]

    for name in expected.get("verifier_failed_checks", []):
        checks[f"verifier_fails:{name}"] = name in outcome.failed_checks

    if "audit_skipped" in expected:
        checks["audit_skipped"] = outcome.audit_skipped == expected["audit_skipped"]

    for code in expected.get("semantic_failures", []):
        checks[f"semantic:{code}"] = code in outcome.semantic_codes

    if "audit_should_mention" in expected and outcome.audit_verdict is not None:
        checks["audit_mentions"] = _mentions(audit_text, expected["audit_should_mention"])

    outcome.expectations = checks
    hard = [v for k, v in checks.items() if k != "audit_mentions"]
    outcome.passed = all(hard) if hard else None
    return outcome


def run_benchmark(
    name: str,
    *,
    directory: Path,
    ledger: ResearchLedger,
    runner: LedgerOperationRunner,
    auditor: Any | None,
    irq_handlers: Callable[[str], list[str]] | None = None,
    replay: bool = True,
    repo: Path | None = None,
) -> BenchmarkResult:
    fixture, expected = load_fixture(directory, name)
    run_id, evidence = run_setup(ledger, runner, fixture, irq_handlers=irq_handlers, repo=repo)
    keys = propose_fixture_claims(ledger, fixture, evidence, run_id)
    verifier = ClaimVerifier(ledger, runner=runner, replay=replay)
    outcomes: list[ClaimOutcome] = []

    for label, key in keys.items():
        # Deterministic verification (phases A-C) gates the audit model.
        gated = audit_if_eligible(key, verifier=verifier, auditor=auditor, verify_after=False) if auditor is not None else None
        audit = None if gated is None else gated.audit
        verification = verifier.verify(key)
        audit_text = "" if audit is None else " ".join([audit.reasoning, *audit.challenges, *audit.limitations])
        outcome = ClaimOutcome(
            label=label,
            key=key,
            audit_id=None if audit is None else audit.audit_id,
            audit_verdict=None if audit is None else audit.verdict.value,
            final_state=verification.current.value,
            failed_checks=[c.name for c in verification.record.checks if not c.passed],
            audit_skipped=(gated is not None and gated.audit is None) or (gated is None and verification.record.audit_skipped),
            semantic_codes=sorted({c.code.value for c in verification.record.semantic_checks if not c.passed}),
        )
        outcomes.append(evaluate(outcome, (expected or {}).get("claims", {}).get(label), audit_text))

    return BenchmarkResult(name=name, setup_run_id=run_id, evidence=evidence, claims=outcomes)
