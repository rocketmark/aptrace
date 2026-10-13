"""
Deterministic verification-policy gate (phase P, between replay and audit).

Evaluates, mechanically and before any audit model is consulted:

- contradictory evidence: each `contradictory_evidence_ids` entry is
  resolved, identity-checked, and classified against the claim's typed
  assertions (CONTRADICTED / UNRESOLVED / NOT_MATERIAL / UNEVALUABLE);
- structural source conflicts: a CONFLICT (affirmative non-code) at an
  address the typed claim asserts is code contradicts it; a function-start
  disagreement where the claim asserts containment is an unresolved
  discrepancy; conflicts elsewhere are recorded as not material;
- independent corroboration per the versioned policy for the claim class.

Nothing here can be waived by a model: the result is computed from typed
semantics and recorded evidence only. Missing corroboration and
unclassifiable contradictions hold the claim; they never count as success.
See docs/cross-engine-verification.md.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Any

from aptrace_agent.ledger.claim_semantics import (
    ClaimSemantics,
    Predicate,
    _maybe_int,
    addr,
    extract_facts,
)
from aptrace_agent.ledger.models import ClaimVersion, GateCondition, PolicyGate
from aptrace_agent.ledger.policy import (
    CLASS_POLICY,
    MIN_INDEPENDENT_LINEAGES,
    SOURCE_ENVELOPE_FIELDS,
    ClaimClass,
    claim_class,
    current_policy,
)
from aptrace_agent.ledger.store import EVIDENCE_INVALIDATED, ResearchLedger


AGREEMENT_TOOL = "structural_source_agreement"
# structural_source_agreement accepts at most this many addresses.
MAX_STRUCTURAL_ADDRESSES = 16

CONTRADICTED = "CONTRADICTED"
UNRESOLVED = "UNRESOLVED"
UNMET = "UNMET"
UNEVALUABLE = "UNEVALUABLE"
NOT_MATERIAL = "NOT_MATERIAL"
SATISFIED = "SATISFIED"

FAILING = frozenset({CONTRADICTED, UNRESOLVED, UNMET, UNEVALUABLE})


def _canon(value: int) -> int:
    # Declared normalization: the Thumb state bit is not part of an address.
    return value & ~1


@dataclass(frozen=True)
class MaterialAddress:
    """A code address the typed claim asserts, and the asserted containing entry."""

    field: str
    entry: int | None


def material_code(semantics: ClaimSemantics | None) -> dict[int, MaterialAddress] | None:
    """
    Code addresses a typed claim asserts. None when materiality cannot be
    established mechanically (no typed semantics, or set-scoped predicates).
    """

    if semantics is None or semantics.predicate == Predicate.PATH_RELATION:
        return None

    out: dict[int, MaterialAddress] = {}

    def add(value: str | None, name: str, entry: str | None) -> None:
        if value is not None:
            out.setdefault(_canon(_maybe_int(value)), MaterialAddress(name, None if entry is None else _canon(_maybe_int(entry))))

    if semantics.resolved_pointer is not None:
        p = semantics.resolved_pointer
        add(p.writer, "writer", p.writer)
        add(p.writer_instruction, "writer_instruction", p.writer)
        add(p.registration_caller, "registration_caller", p.registration_caller)
        add(p.registration_callsite, "registration_callsite", p.registration_caller)
        add(p.indirect_caller, "indirect_caller", p.indirect_caller)
        add(p.indirect_site, "indirect_site", p.indirect_caller)
        add(p.canonical_target, "canonical_target", None)
        add(p.forwarding_target, "forwarding_target", None)
    elif semantics.function_role is not None:
        add(semantics.function_role.function, "function", semantics.function_role.function)
    elif semantics.code_presence is not None:
        c = semantics.code_presence
        add(c.address, "address", c.function_entry)

        if c.function_entry is not None:
            add(c.function_entry, "function_entry", c.function_entry)

    return out


def _entities(semantics: ClaimSemantics | None) -> set[int]:
    """Every address or function entity a typed claim names."""

    if semantics is None:
        return set()

    values: list[str | None] = []

    if semantics.resolved_pointer is not None:
        values += list(semantics.resolved_pointer.model_dump().values())
    elif semantics.function_role is not None:
        values += [semantics.function_role.function, semantics.function_role.slot]
    elif semantics.code_presence is not None:
        values += [semantics.code_presence.address, semantics.code_presence.function_entry]

    return {_canon(v) for value in values if value is not None and (v := _maybe_int(value)) is not None}


def _mentioned(value: Any) -> set[int]:
    """Canonical addresses/function entries appearing anywhere in a JSON value."""

    out: set[int] = set()
    stack = [value]

    while stack:
        item = stack.pop()

        if isinstance(item, dict):
            stack.extend(item.values())
        elif isinstance(item, (list, tuple)):
            stack.extend(item)
        elif isinstance(item, int) and not isinstance(item, bool):
            out.add(_canon(item))
        elif isinstance(item, str) and (parsed := _maybe_int(item)) is not None:
            out.add(_canon(parsed))

    return out


def _lineage(source: dict[str, Any]) -> set[str]:
    """Declared lineage plus the engine a derived source comes from."""

    lineage = {str(item) for item in source.get("lineage") or ()}
    derived = source.get("derived_from")

    if derived:
        lineage.add(str(derived).split(":", 1)[0])

    return lineage


class PolicyGateEvaluator:
    def __init__(self, ledger: ResearchLedger, *, firmware_sha256: str | None, case: str | None) -> None:
        self.ledger = ledger
        self.firmware_sha256 = firmware_sha256
        self.case = case

    # -- helpers -------------------------------------------------------------

    def _compatible(self, artifact) -> bool:
        return (self.firmware_sha256 is None or artifact.firmware_sha256 == self.firmware_sha256) and (
            self.case is None or artifact.case == self.case
        )

    def _result(self, evidence_id: str) -> dict[str, Any] | None:
        try:
            result, ok = self.ledger.evidence_result(evidence_id)
        except KeyError:
            return None

        return result if ok and isinstance(result, dict) else None

    # -- structural ----------------------------------------------------------

    def structural(
        self, evidence_id: str, result: dict[str, Any], material: dict[int, MaterialAddress] | None, *, kind: str
    ) -> list[GateCondition]:
        conditions: list[GateCondition] = []

        for entry in result.get("agreements", []):
            address = _maybe_int(entry.get("address"))

            if address is None:
                continue

            shown = addr(address)
            status = entry.get("status")
            target = None if material is None else material.get(_canon(address))

            if status == "CONFLICT":
                if material is None:
                    conditions.append(GateCondition(
                        code="STRUCTURAL_CONFLICT_UNCLASSIFIED", kind=kind, status=UNRESOLVED, evidence_ids=[evidence_id],
                        address=shown, detail=f"{entry.get('disagreement') or 'CONFLICT'}; the claim has no typed code "
                        "assertions, so materiality cannot be established mechanically",
                    ))
                elif target is not None:
                    conditions.append(GateCondition(
                        code="STRUCTURAL_CONFLICT", kind=kind, status=CONTRADICTED, evidence_ids=[evidence_id],
                        field=target.field, address=shown,
                        detail=f"claim asserts code at {shown} ({target.field}); {entry.get('disagreement') or 'CONFLICT'}",
                    ))
                else:
                    conditions.append(GateCondition(
                        code="STRUCTURAL_CONFLICT_OUT_OF_SCOPE", kind=kind, status=NOT_MATERIAL, evidence_ids=[evidence_id],
                        address=shown, detail=f"{entry.get('disagreement') or 'CONFLICT'}; not an address the claim asserts",
                    ))
            elif target is not None and target.entry is not None and entry.get("function_start_agreement") == "DISAGREE":
                conditions.append(GateCondition(
                    code="FUNCTION_START_DISCREPANCY", kind=kind, status=UNRESOLVED, evidence_ids=[evidence_id],
                    field=target.field, address=shown,
                    detail=f"claim places {shown} in the function at {addr(target.entry)}; sources disagree on the "
                    f"containing function start ({entry.get('disagreement') or 'DISAGREE'}); no resolution recorded",
                ))

        return conditions

    # -- contradictions --------------------------------------------------------

    def contradiction(self, claim: ClaimVersion, evidence_id: str, material: dict[int, MaterialAddress] | None) -> list[GateCondition]:
        def condition(code: str, status: str, detail: str, **extra: Any) -> GateCondition:
            return GateCondition(code=code, kind="contradiction", status=status, evidence_ids=[evidence_id], detail=detail, **extra)

        if not self.ledger.has_evidence(evidence_id):
            return [condition("CONTRADICTION_UNRESOLVABLE", UNEVALUABLE, "contradictory evidence id does not resolve")]

        artifact = self.ledger.evidence(evidence_id)

        if not self._compatible(artifact):
            return [condition("CONTRADICTION_INCOMPATIBLE_EVIDENCE", UNEVALUABLE,
                              f"evidence is for firmware {artifact.firmware_sha256[:12]} / case {artifact.case}, not this claim's")]

        if self.ledger.evidence_state(evidence_id) == EVIDENCE_INVALIDATED:
            return [condition("CONTRADICTION_EVIDENCE_INVALIDATED", UNEVALUABLE, "contradictory evidence was invalidated; it can neither be classified nor dismissed")]

        result = self._result(evidence_id)

        if result is None:
            return [condition("CONTRADICTION_RESULT_UNAVAILABLE", UNEVALUABLE, "stored result unavailable or fails its hash")]

        semantics = claim.semantics

        if semantics is None:
            return [condition("CONTRADICTION_UNCLASSIFIABLE", UNRESOLVED,
                              "the claim has no typed semantics, so no contradiction can be classified mechanically")]

        if artifact.tool == AGREEMENT_TOOL:
            found = [c for c in self.structural(evidence_id, result, material, kind="contradiction") if c.status != NOT_MATERIAL]

            if found:
                return found

        found = self._typed_contradictions(semantics, artifact, result, evidence_id)

        if found:
            return found

        if semantics.predicate == Predicate.PATH_RELATION:
            return [condition("CONTRADICTION_UNCLASSIFIABLE", UNRESOLVED,
                              "no common-path result over exactly the claimed set scopes; materiality across set kinds "
                              "cannot be established mechanically")]

        named = _entities(semantics) & _mentioned([artifact.arguments, result])

        if named:
            return [condition("CONTRADICTION_UNCLASSIFIABLE", UNRESOLVED,
                              f"evidence names claimed entities ({', '.join(addr(a) for a in sorted(named))}) but no typed "
                              "fact in it contradicts or is reconciled with the claim mechanically")]

        return [condition("CONTRADICTION_NOT_MATERIAL", NOT_MATERIAL,
                          f"{artifact.tool} evidence names none of the claim's typed entities")]

    def _typed_contradictions(self, semantics: ClaimSemantics, artifact, result: dict[str, Any], evidence_id: str) -> list[GateCondition]:
        facts = extract_facts([(artifact, result)])
        out: list[GateCondition] = []

        if semantics.resolved_pointer is not None:
            slot = _maybe_int(semantics.resolved_pointer.slot)
            claimed = {k: _maybe_int(v) for k, v in semantics.resolved_pointer.claimed().items()}

            for fact in facts.pointers:
                if fact.values.get("slot") != slot:
                    continue

                for name, value in claimed.items():
                    actual = fact.values.get(name)

                    if actual is not None and actual != value:
                        out.append(GateCondition(
                            code="MATERIAL_CONTRADICTION", kind="contradiction", status=CONTRADICTED,
                            evidence_ids=[fact.evidence_id], field=name, address=addr(slot),
                            detail=f"claim {name}={addr(value)} for slot {addr(slot)}; evidence has {name}={addr(actual)}",
                        ))

        if semantics.path is not None:
            wanted = [{str(semantics.path.left)}, {str(semantics.path.right)}]

            for fact in facts.paths:
                sides = [{str(s) for s in fact.left}, {str(s) for s in fact.right}]

                if wanted in (sides, sides[::-1]) and fact.status != semantics.path.status:
                    out.append(GateCondition(
                        code="MATERIAL_CONTRADICTION", kind="contradiction", status=CONTRADICTED,
                        evidence_ids=[fact.evidence_id], field="status",
                        detail=f"claim {semantics.path.status} over {semantics.path.left} | {semantics.path.right}; "
                        f"evidence has {fact.status} over the same scopes",
                    ))

        return out

    # -- corroboration ---------------------------------------------------------

    def corroboration(self, claim: ClaimVersion, klass: ClaimClass, agreements: Sequence[str]) -> list[GateCondition]:
        policy = CLASS_POLICY[klass]

        if klass == ClaimClass.UNDETERMINED:
            return [GateCondition(code="CLAIM_CLASS_UNDETERMINED", kind="class", status=UNEVALUABLE, detail=policy["corroboration"])]

        if not policy["evidence_kinds"]:
            return [GateCondition(
                code="NO_EVIDENCE_CONTRACT", kind="corroboration", status=UNEVALUABLE,
                detail=f"{klass.value} requires {policy['corroboration']}; no ledger operation produces such evidence yet",
            )]

        assert klass == ClaimClass.CODE_EXISTENCE and claim.semantics is not None and claim.semantics.code_presence is not None
        presence = claim.semantics.code_presence
        address = _maybe_int(presence.address)
        entry = None if presence.function_entry is None else _maybe_int(presence.function_entry)
        return [self._code_corroboration(address, entry, agreements)]

    def _code_corroboration(self, address: int, entry: int | None, agreements: Sequence[str]) -> GateCondition:
        shown = addr(address)
        reasons: list[str] = []
        unevaluable = False
        covered = False

        for evidence_id in agreements:
            result = self._result(evidence_id)

            if result is None:
                continue

            sources = {s.get("source"): s for s in result.get("sources", []) if isinstance(s, dict)}

            for item in result.get("agreements", []):
                if _maybe_int(item.get("address")) != address:
                    continue

                covered = True
                qualified: list[tuple[str, set[str]]] = []

                for observation in item.get("observations", []):
                    name = observation.get("source")

                    if not observation.get("available"):
                        reasons.append(f"{name}: UNAVAILABLE{(' (' + observation['note'] + ')') if observation.get('note') else ''}")
                        continue

                    if not observation.get("recognizes_code"):
                        reasons.append(f"{name}: {'non-code' if observation.get('non_code') else 'COVERAGE_GAP'}")
                        continue

                    start = _maybe_int(observation.get("start"))

                    if entry is not None and start != entry:
                        reasons.append(f"{name}: function entry {addr(start) if start is not None else 'unknown'}, not {addr(entry)}")
                        continue

                    source = sources.get(name, {})
                    missing = [f for f in SOURCE_ENVELOPE_FIELDS if not source.get(f)]

                    if missing:
                        unevaluable = True
                        reasons.append(f"{name}: independence metadata missing ({', '.join(missing)})")
                        continue

                    if self.firmware_sha256 is not None and source.get("firmware_sha256") != self.firmware_sha256:
                        unevaluable = True
                        reasons.append(f"{name}: observed firmware {str(source.get('firmware_sha256'))[:12]} is not the claim's")
                        continue

                    if source.get("assisted"):
                        reasons.append(f"{name}: ASSISTED (received cross-engine findings); never independent")
                        continue

                    qualified.append((str(name), _lineage(source)))

                for i, (left, left_lineage) in enumerate(qualified):
                    for right, right_lineage in qualified[i + 1:]:
                        if left_lineage.isdisjoint(right_lineage):
                            return GateCondition(
                                code="INDEPENDENT_CORROBORATION", kind="corroboration", status=SATISFIED,
                                evidence_ids=[evidence_id], address=shown,
                                detail=f"{left} {sorted(left_lineage)} and {right} {sorted(right_lineage)} agree"
                                + (f" on function entry {addr(entry)}" if entry is not None else " on code"),
                            )

                if len(qualified) >= 2:
                    reasons.append(
                        "shared lineage: " + ", ".join(f"{n} {sorted(lin)}" for n, lin in qualified) + " (re-runs and derived "
                        "sources are not corroboration)"
                    )

        if not covered:
            return GateCondition(
                code="CORROBORATION_COMPARISON_MISSING", kind="corroboration", status=UNMET, address=shown,
                detail=f"no structural source-agreement comparison covers {shown}",
            )

        need = f"{MIN_INDEPENDENT_LINEAGES} disjoint lineages"
        detail = f"{shown}: {need} required; " + "; ".join(dict.fromkeys(reasons))

        if unevaluable:
            return GateCondition(code="INDEPENDENCE_METADATA_MISSING", kind="corroboration", status=UNEVALUABLE,
                                 evidence_ids=list(agreements), address=shown, detail=detail)

        return GateCondition(code="INDEPENDENT_CORROBORATION_MISSING", kind="corroboration", status=UNMET,
                             evidence_ids=list(agreements), address=shown, detail=detail)

    # -- entry point -------------------------------------------------------------

    def evaluate(
        self,
        claim: ClaimVersion,
        *,
        corroborating_agreements: Iterable[str] = (),
        conflict_agreements: Iterable[str] = (),
        extra_conditions: Iterable[GateCondition] = (),
    ) -> PolicyGate:
        """
        corroborating_agreements: replay-verified or freshly recorded
        structural agreement evidence (may satisfy corroboration and is
        checked for conflicts). conflict_agreements: other recorded
        agreement evidence for this claim version (checked for conflicts
        only, e.g. what an audit recorded).
        """

        klass, basis = claim_class(claim.claim_type, claim.semantics)
        material = material_code(claim.semantics)
        conditions: list[GateCondition] = list(extra_conditions)
        contradictory = set(claim.contradictory_evidence_ids)

        for evidence_id in claim.contradictory_evidence_ids:
            conditions += self.contradiction(claim, evidence_id, material)

        usable = []

        for evidence_id in dict.fromkeys([*corroborating_agreements, *conflict_agreements]):
            if evidence_id in contradictory or not self.ledger.has_evidence(evidence_id):
                continue

            artifact = self.ledger.evidence(evidence_id)

            if artifact.tool != AGREEMENT_TOOL or not self._compatible(artifact):
                continue

            if self.ledger.evidence_state(evidence_id) == EVIDENCE_INVALIDATED:
                continue

            result = self._result(evidence_id)

            if result is not None:
                usable.append(evidence_id)
                conditions += self.structural(evidence_id, result, material, kind="structural")

        counted = [e for e in dict.fromkeys(corroborating_agreements) if e in usable]
        conditions += self.corroboration(claim, klass, counted)
        statuses = {c.status for c in conditions}

        if CONTRADICTED in statuses:
            status = "BLOCKED"
        elif statuses & {UNRESOLVED, UNMET}:
            status = "HELD"
        elif UNEVALUABLE in statuses:
            status = "UNEVALUABLE"
        else:
            status = "PASSED"

        return PolicyGate(
            policy=current_policy(),
            claim_class=klass.value,
            class_basis=basis,
            status=status,
            conditions=conditions,
            agreement_evidence_ids=usable,
        )


def structural_addresses(claim: ClaimVersion) -> list[str]:
    """Asserted code addresses the gate asks structural agreement about."""

    material = material_code(claim.semantics)
    return [addr(a) for a in sorted(material or {})]


# -- read-only assessment of historical decisions ------------------------------


@dataclass(frozen=True)
class PolicyAssessment:
    """
    How a claim version's standing relates to the current policy. Read-only:
    nothing is recorded, no operation runs, and claim state is unchanged.
    The gate here uses recorded evidence only (no replay, no fresh
    structural agreement), so it is an assessment, not a verification.
    """

    claim_version: str
    state: str
    # The verification record the VERIFIED event cites, if VERIFIED.
    verified_by: str | None
    # Policy that decision applied; None means it predates any policy.
    verified_policy: Any
    # True only if the VERIFIED decision applied the current policy.
    decision_under_current_policy: bool
    current: PolicyGate

    def summary(self) -> str:
        policy = self.current.policy
        failing = sorted({c.code for c in self.current.conditions if c.status in FAILING})

        if self.verified_by is None:
            decided = "not VERIFIED"
        elif self.verified_policy is None:
            decided = f"VERIFIED by {self.verified_by} before any verification policy"
        else:
            decided = f"VERIFIED by {self.verified_by} under {self.verified_policy.policy_id} v{self.verified_policy.version}"

        return (
            f"{self.claim_version} [{self.state}] {decided}; current policy {policy.policy_id} v{policy.version} "
            f"({self.current.claim_class}) on recorded evidence: {self.current.status}"
            + (f" — {', '.join(failing)}" if failing else "")
        )


def verified_decision(ledger: ResearchLedger, key: str):
    """The VerificationRecord the latest VERIFIED event for this version cites."""

    verified = [e for e in ledger.history(key) if e.state == "VERIFIED"]

    for ref in reversed(verified[-1].refs if verified else []):
        for record in ledger.verifications_for(key):
            if record.verification_id == ref:
                return record

    return None


def assess_policy(ledger: ResearchLedger, key: str) -> PolicyAssessment:
    claim = ledger.claim(key)
    state = ledger.state(claim.key)
    record = verified_decision(ledger, claim.key) if state.value == "VERIFIED" else None
    supporting = [ledger.evidence(e) for e in claim.supporting_evidence_ids if ledger.has_evidence(e)]
    firmware = supporting[0].firmware_sha256 if supporting else None
    case = supporting[0].case if supporting else None

    if claim.run_id:
        try:
            firmware = ledger.run(claim.run_id).firmware_sha256
        except KeyError:
            pass

    agreements = [a.evidence_id for a in supporting if a.tool == AGREEMENT_TOOL]
    audited = [a.source_agreement_evidence for a in ledger.audits_for(claim.key) if a.source_agreement_evidence]
    gate = PolicyGateEvaluator(ledger, firmware_sha256=firmware, case=case).evaluate(
        claim, corroborating_agreements=agreements, conflict_agreements=audited
    )
    policy = None if record is None else record.policy
    return PolicyAssessment(
        claim_version=claim.key,
        state=state.value,
        verified_by=None if record is None else record.verification_id,
        verified_policy=policy,
        decision_under_current_policy=policy is not None and policy == current_policy() and record.gate is not None and record.gate.status == "PASSED",
        current=gate,
    )
