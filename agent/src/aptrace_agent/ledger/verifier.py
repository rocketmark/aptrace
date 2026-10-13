"""
APTrace deterministic claim verification.

This is the only component that may move a claim to VERIFIED. It checks
what APTrace can determine mechanically: evidence references, firmware
context, stored-result integrity, deterministic replay, dependency state,
grade ceilings, inherited limitations, bounded-negative scope, the
versioned verification policy (contradictions, structural conflicts,
independent corroboration; see gate.py), and the latest independent audit
verdict for the exact claim version.

VERIFIED means "consistent with the currently recorded evidence and these
deterministic checks". It does not establish semantic truth.
"""

from __future__ import annotations

from dataclasses import dataclass

from aptrace_agent.ledger.claim_semantics import SemanticCheck, verify_semantics
from aptrace_agent.ledger.gate import (
    AGREEMENT_TOOL,
    FAILING,
    MAX_STRUCTURAL_ADDRESSES,
    UNEVALUABLE,
    PolicyGateEvaluator,
    structural_addresses,
)
from aptrace_agent.ledger.models import (
    GRADE_RANK,
    AuditVerdict,
    ClaimState,
    ClaimType,
    ClaimVersion,
    ExecutionContext,
    GateCondition,
    PolicyGate,
    VerificationCheck,
    VerificationRecord,
)
from aptrace_agent.ledger.operations import LedgerOperationRunner, input_artifacts
from aptrace_agent.ledger.policy import SEVERITY, current_policy
from aptrace_agent.ledger.semantics import asserts_absolute_negative, grade_ceiling
from aptrace_agent.ledger.store import EVIDENCE_INVALIDATED, ResearchLedger, new_id, now


BLOCK = "block"
STALE = "stale"
HOLD = "hold"

# Phase P checks, one per gate condition kind.
GATE_CHECKS = {
    "class": "claim_class",
    "contradiction": "contradictory_evidence",
    "structural": "structural_conflicts",
    "corroboration": "independent_corroboration",
}


@dataclass
class VerificationOutcome:
    record: VerificationRecord
    previous: ClaimState
    current: ClaimState
    staled: list[str]


class ClaimVerifier:
    def __init__(
        self,
        ledger: ResearchLedger,
        *,
        runner: LedgerOperationRunner | None = None,
        context: ExecutionContext | None = None,
        replay: bool = True,
    ) -> None:
        if replay and runner is None:
            raise ValueError("replay verification needs an operation runner")

        self.ledger = ledger
        self.runner = runner
        self._context = context
        self.replay = replay

    def context(self) -> ExecutionContext | None:
        if self._context is not None:
            return self._context

        return self.runner.context() if self.runner is not None else None

    def precheck(self, key: str) -> VerificationOutcome:
        """
        Phases A-C and P: structural validity, deterministic semantics,
        replay/freshness, and the verification-policy gate. Run before any
        audit; a claim that fails here is BLOCKED (or STALE) or held without
        consulting the audit model.
        """

        return self.verify(key, mode="precheck")

    def verify(self, key: str, *, mode: str = "full") -> VerificationOutcome:
        """
        Phased verification:
          A structural validity (references, context, dependency references)
          B deterministic semantics (typed roles/relations/scope, grade
            ceiling, inherited limitations, bounded-negative wording)
          C replay and freshness (stored hashes, validity, replay)
          P verification policy gate (contradictory evidence, structural
            conflicts, independent corroboration for the claim class)
          D independent audit and dependency verification (full mode only)
        A failure in A or B skips the later phases; a failure in C skips P
        and D. A failure in P is final for promotion: D still reads recorded
        audits and dependencies (a CHALLENGED audit still blocks), but no
        audit verdict can override P. Precheck mode stops after P.
        """

        claim = self.ledger.claim(key)
        previous = self.ledger.state(claim.key)
        context = self.context()
        checks: list[VerificationCheck] = []
        replays: list[str] = []
        invalidated: list[tuple[str, str]] = []
        phases: dict[str, str] = {}
        semantic: list[SemanticCheck] = []
        phase = "A"

        def check(name: str, passed: bool, severity: str, detail: str = "") -> None:
            checks.append(VerificationCheck(name=name, passed=passed, severity=severity, detail=detail, phase=phase))

        def close(name: str) -> bool:
            failed = any(not c.passed and c.severity in (BLOCK, STALE) for c in checks if c.phase == name)
            phases[name] = "failed" if failed else "passed"
            return not failed

        def skip(*names: str) -> None:
            for name in names:
                phases.setdefault(name, "skipped")

        if previous in (ClaimState.SUPERSEDED, ClaimState.STALE):
            check("lifecycle_eligible", False, HOLD, f"{claim.key} is {previous.value}; propose a new version instead")
            skip("A", "B", "C", "P", "D")
            return self._finish(claim.key, previous, checks, replays, None, context, mode=mode, phases=phases, semantic=semantic, audit_skipped=True)

        # -- Phase A: structural validity ------------------------------------
        referenced = claim.supporting_evidence_ids + claim.contradictory_evidence_ids
        missing = [e for e in referenced if not self.ledger.has_evidence(e)]
        check("evidence_references", not missing, BLOCK, f"unknown evidence: {', '.join(missing)}" if missing else f"{len(referenced)} reference(s) resolve")
        check("supporting_evidence_present", bool(claim.supporting_evidence_ids), BLOCK, "a claim needs at least one supporting evidence id")

        artifacts = [self.ledger.evidence(e) for e in claim.supporting_evidence_ids if self.ledger.has_evidence(e)]
        expected_firmware = context.firmware_sha256 if context else None

        if claim.run_id:
            try:
                expected_firmware = self.ledger.run(claim.run_id).firmware_sha256
            except KeyError:
                pass

        foreign = [
            a.evidence_id
            for a in artifacts
            if (expected_firmware and a.firmware_sha256 != expected_firmware) or (context and a.case != context.case)
        ]
        check("evidence_context", not foreign, BLOCK, f"evidence from another firmware/case: {', '.join(foreign)}" if foreign else "same firmware and case")

        dangling = [dep for dep in claim.depends_on if not self.ledger.has_claim(dep) or ":v" not in dep]
        check("dependencies_exist", not dangling, BLOCK, f"dangling: {', '.join(dangling)}" if dangling else f"{len(claim.depends_on)} dependency reference(s)")
        structural_ok = close("A")

        # -- Phase B: deterministic semantics ---------------------------------
        phase = "B"

        if not structural_ok:
            skip("B", "C", "P", "D")
            return self._finish(claim.key, previous, checks, replays, None, context, mode=mode, phases=phases, semantic=semantic, audit_skipped=True)

        if claim.semantics is None:
            check("claim_semantics", True, HOLD, "no structured semantics; typed role/relation/scope checks not applicable")
        else:
            evidence = [(a, self._result(a)) for a in artifacts]
            semantic = verify_semantics(claim.semantics, claim.claim_type.value, [(a, r) for a, r in evidence if r is not None])
            failures = [c for c in semantic if not c.passed]
            check(
                "claim_semantics",
                not failures,
                BLOCK,
                "; ".join(f"{c.code.value}: {c.detail or c.field}" for c in failures)
                if failures
                else f"{claim.semantics.summary()} consistent with supporting evidence ({len(semantic)} check(s))",
            )

        if artifacts:
            ceiling = grade_ceiling(claim.claim_type, artifacts)
            ok = GRADE_RANK[claim.proposed_grade] <= GRADE_RANK[ceiling]
            check(
                "grade_ceiling",
                ok,
                BLOCK,
                f"proposed {claim.proposed_grade.value}; strongest supporting derivation permits {ceiling.value} "
                f"({', '.join(f'{a.evidence_id}={a.grade.value}' for a in artifacts)})",
            )

        required = {item.code for a in artifacts for item in a.limitations}
        present = {item.code for item in claim.limitations if item.code}
        dropped = sorted(required - present)
        check("limitations_preserved", not dropped, BLOCK, f"evidence limitations missing from claim: {', '.join(dropped)}" if dropped else f"{len(required)} inherited limitation(s) present")

        bounded = [a.evidence_id for a in artifacts if a.path_status == "NO_KNOWN_PATH"]

        if claim.claim_type == ClaimType.UNREACHABLE:
            check("no_unreachability_promotion", False, BLOCK, "no APTrace analysis establishes unreachability; NO_KNOWN_PATH is bounded")
        elif bounded and asserts_absolute_negative(claim.assertion):
            check(
                "no_unreachability_promotion",
                False,
                BLOCK,
                f"assertion states an absolute negative but {', '.join(bounded)} is NO_KNOWN_PATH (bounded)",
            )
        else:
            check("no_unreachability_promotion", True, BLOCK, "no bounded-negative promotion")

        if not close("B"):
            skip("C", "P", "D")
            return self._finish(claim.key, previous, checks, replays, None, context, mode=mode, phases=phases, semantic=semantic, audit_skipped=True)

        # -- Phase C: replay and freshness -------------------------------------
        phase = "C"
        corrupt, unavailable = [], []

        for artifact in artifacts:
            if not self.ledger.has_blob(artifact.result_sha256):
                # A large result kept out of version control; replay re-derives it.
                unavailable.append(artifact.evidence_id)
                continue

            _value, ok = self.ledger.load_blob(artifact.result_sha256)

            if not ok:
                corrupt.append(artifact.evidence_id)
                invalidated.append((artifact.evidence_id, "stored result hash no longer matches"))

        check("evidence_integrity", not corrupt, STALE, f"result hash mismatch: {', '.join(corrupt)}" if corrupt else "stored result hashes match")

        if unavailable:
            check(
                "evidence_available",
                self.replay,
                HOLD,
                f"result blob not present locally (replay {'re-derives' if self.replay else 'required'}): {', '.join(unavailable)}",
            )

        invalid = [a.evidence_id for a in artifacts if self.ledger.evidence_state(a.evidence_id) == EVIDENCE_INVALIDATED]
        check("evidence_valid", not invalid, STALE, f"invalidated evidence: {', '.join(invalid)}" if invalid else "no supporting evidence invalidated")

        drifted = []

        if context is not None:
            for artifact in artifacts:
                recorded = self.ledger.invocation(artifact.invocation_id).input_artifacts
                current = input_artifacts(context, artifact.tool)

                if recorded != current:
                    drifted.append(artifact.evidence_id)

        if self.replay and self.runner is not None:
            changed = []
            replay_run = new_id("RV")

            for artifact in artifacts:
                invocation = self.ledger.invocation(artifact.invocation_id)

                if not invocation.replayable:
                    continue

                result = self.runner.replay(invocation.invocation_id, run_id=replay_run)
                replays.append(result.replay.invocation_id)

                if not result.matches:
                    changed.append(f"{artifact.evidence_id} ({'; '.join(result.differences[:3]) or 'replay failed'})")
                    invalidated.append((artifact.evidence_id, f"deterministic replay {result.replay.invocation_id} changed the result"))

            check("deterministic_replay", not changed, STALE, f"replay changed: {', '.join(changed)}" if changed else f"{len(replays)} replay(s) identical")
        else:
            check(
                "input_artifacts_unchanged",
                not drifted,
                HOLD,
                f"inputs changed since recording (replay required): {', '.join(drifted)}" if drifted else "recorded input hashes current",
            )

        for evidence_id, reason in invalidated:
            self.ledger.invalidate_evidence(evidence_id, reason=reason)

        if not close("C"):
            skip("P", "D")
            return self._finish(claim.key, previous, checks, replays, None, context, mode=mode, phases=phases, semantic=semantic, audit_skipped=mode != "precheck")

        # -- Phase P: verification policy gate ---------------------------------
        phase = "P"
        gate = self._gate(claim, context, expected_firmware)

        for kind, name in GATE_CHECKS.items():
            items = [c for c in gate.conditions if c.kind == kind]
            failing = [c for c in items if c.status in FAILING]
            severity = BLOCK if any(SEVERITY[c.status] == BLOCK for c in failing) else HOLD

            if items:
                check(
                    name,
                    not failing,
                    severity,
                    "; ".join(f"{c.status} {c.code}: {c.detail}" + (f" [{', '.join(c.evidence_ids)}]" if c.evidence_ids else "") for c in failing)[:1500]
                    or "; ".join(f"{c.status} {c.code}: {c.detail}" for c in items)[:600],
                )

        phases["P"] = "passed" if gate.status == "PASSED" else "failed"

        if mode == "precheck":
            skip("D")
            return self._finish(claim.key, previous, checks, replays, None, context, mode=mode, phases=phases, semantic=semantic, audit_skipped=mode != "precheck", gate=gate)

        # -- Phase D: dependencies and independent audit -----------------------
        phase = "D"
        unverified = [
            f"{dep} ({self.ledger.state(dep).value})" for dep in claim.depends_on if self.ledger.state(dep) != ClaimState.VERIFIED
        ]
        check("dependencies_verified", not unverified, HOLD, f"not verified: {', '.join(unverified)}" if unverified else "all dependencies VERIFIED")

        audits = self.ledger.audits_for(claim.key, include_diagnostic=False)
        audit = audits[-1] if audits else None
        # Any challenge blocks this version for good: re-auditing until some
        # run says SUPPORTED is not allowed; answer a challenge with a new
        # claim version, which gets its own audit. Diagnostic audits never count.
        challenged = [a for a in audits if a.verdict == AuditVerdict.CHALLENGED]

        if challenged and audit is not None and audit.verdict != AuditVerdict.CHALLENGED:
            first = challenged[0]
            check("independent_audit", False, BLOCK, f"{first.audit_id} CHALLENGED this version (later {audit.audit_id} {audit.verdict.value} does not override)")
        elif audit is None:
            check("independent_audit", False, HOLD, "no audit of this exact claim version")
        elif audit.verdict == AuditVerdict.CHALLENGED:
            check("independent_audit", False, BLOCK, f"{audit.audit_id} CHALLENGED: {'; '.join(audit.challenges[:3]) or audit.reasoning[:200]}")
        elif audit.verdict == AuditVerdict.UNRESOLVED:
            check("independent_audit", False, HOLD, f"{audit.audit_id} UNRESOLVED")
        else:
            check("independent_audit", True, HOLD, f"{audit.audit_id} SUPPORTED")

        close("D")
        return self._finish(claim.key, previous, checks, replays, audit, context, mode=mode, phases=phases, semantic=semantic, audit_skipped=False, gate=gate)

    def _gate(self, claim: ClaimVersion, context: ExecutionContext | None, firmware: str | None) -> PolicyGate:
        """
        Phase P. Records structural source agreement for the claim's typed
        code addresses (when an operation runner is available), then
        evaluates the policy over it, the supporting agreement evidence
        (replay-verified in phase C), and agreement evidence audits of this
        version recorded (conflicts only).
        """

        extra: list[GateCondition] = []
        fresh: list[str] = []
        addresses = structural_addresses(claim)

        if self.runner is not None and addresses:
            if len(addresses) > MAX_STRUCTURAL_ADDRESSES:
                extra.append(GateCondition(
                    code="STRUCTURAL_SCOPE_TRUNCATED", kind="structural", status=UNEVALUABLE,
                    detail=f"{len(addresses)} asserted code addresses; structural agreement covers {MAX_STRUCTURAL_ADDRESSES}",
                ))
                addresses = addresses[:MAX_STRUCTURAL_ADDRESSES]

            invocation, artifact = self.runner.run(new_id("VG"), AGREEMENT_TOOL, {"addresses": addresses})

            if artifact is None:
                extra.append(GateCondition(
                    code="STRUCTURAL_AGREEMENT_FAILED", kind="structural", status=UNEVALUABLE,
                    evidence_ids=[], detail=f"{invocation.invocation_id}: {invocation.error or 'no result'}",
                ))
            else:
                fresh.append(artifact.evidence_id)

        supporting = [e for e in claim.supporting_evidence_ids if self.ledger.has_evidence(e) and self.ledger.evidence(e).tool == AGREEMENT_TOOL]
        audited = [a.source_agreement_evidence for a in self.ledger.audits_for(claim.key) if a.source_agreement_evidence]
        evaluator = PolicyGateEvaluator(self.ledger, firmware_sha256=firmware, case=context.case if context else None)
        return evaluator.evaluate(
            claim,
            corroborating_agreements=supporting + fresh,
            conflict_agreements=audited,
            extra_conditions=extra,
        )

    def _result(self, artifact) -> dict | None:
        try:
            result, _ok = self.ledger.load_blob(artifact.result_sha256)
        except KeyError:
            return None

        return result if isinstance(result, dict) else None

    def _finish(self, key, previous, checks, replays, audit, context, *, mode="full", phases=None, semantic=(), audit_skipped=False, gate=None) -> VerificationOutcome:
        failed = {c.severity for c in checks if not c.passed}
        current_state = self.ledger.state(key)

        if current_state in (ClaimState.SUPERSEDED, ClaimState.STALE) and "lifecycle_eligible" not in {c.name for c in checks}:
            # Evidence invalidation during this verification already staled it.
            outcome = current_state
        elif BLOCK in failed:
            outcome = ClaimState.BLOCKED
        elif STALE in failed:
            outcome = ClaimState.STALE
        elif HOLD in failed:
            outcome = current_state if current_state in (ClaimState.SUPERSEDED, ClaimState.STALE) else ClaimState.PROPOSED
        else:
            outcome = ClaimState.VERIFIED

        if mode == "precheck" and outcome not in (ClaimState.BLOCKED, ClaimState.STALE):
            # A precheck never advances a claim: it can only block or stale it.
            outcome = current_state

        record = self.ledger.record_verification(
            VerificationRecord(
                verification_id=new_id("V"),
                claim_version=key,
                at=now(),
                context_id=context.context_id() if context else "",
                audit_id=None if audit is None else audit.audit_id,
                audit_verdict=None if audit is None else audit.verdict,
                checks=checks,
                replay_invocation_ids=replays,
                outcome=outcome,
                mode=mode,
                phases=dict(phases or {}),
                semantic_checks=list(semantic),
                audit_skipped=audit_skipped,
                policy=current_policy(),
                gate=gate,
            )
        )

        staled: list[str] = []

        if outcome != self.ledger.state(key):
            failing = "; ".join(f"{c.name}: {c.detail}" for c in checks if not c.passed)[:400]
            self.ledger.transition(
                key,
                outcome,
                actor="aptrace-verifier" if outcome != ClaimState.STALE else "aptrace-staleness",
                reason=failing or "all deterministic checks and the verification policy gate passed, and audit SUPPORTED",
                refs=[record.verification_id],
            )

        if outcome in (ClaimState.BLOCKED, ClaimState.STALE):
            staled = self.ledger.propagate_staleness([key])

        return VerificationOutcome(record=record, previous=previous, current=self.ledger.state(key), staled=staled)
