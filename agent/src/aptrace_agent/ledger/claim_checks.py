"""
Deterministic claim-quality checks shared by claim admission
(research/admission.py) and verification (phase B, verifier.py).

They complement typed semantics (claim_semantics.py), which stay
authoritative for claims that carry them. These checks cover what a prose
claim can get mechanically wrong:

- entity identity: identifiers must be canonical (`FUN_xxxxxxxx`, `0x…`),
  name known functions, and name known peripherals. Nothing is corrected:
  `E0000b4b4` is reported, never read as `FUN_0000b4b4`.
- peripheral access: a claim that a function accesses a peripheral needs
  an access in the structured evidence (a census MMIO site or an effects
  access in the MMIO region). A literal-pool address load is not one.
- absence of access: a claim that a function does not access a peripheral
  needs complete function-effects evidence whose accesses do not depend on
  unresolved inputs. Otherwise the absence holds only for the recorded
  analysis, and the claim must say so.
- call relations (ledger/call_relations.py, codes CALL_*): an asserted call,
  dispatch, reachability or call absence must be supported by the cited
  evidence at its asserted kind and scope.

Which claims the access rules apply to is decided from assertion wording
(function name, peripheral name, access verb, negation, qualification);
those diagnostics are marked `pattern-matched`. Their findings come from
structured evidence fields.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Collection
from typing import Any

from aptrace_agent.ledger.claim_semantics import FunctionRole, extract_facts, to_int
from aptrace_agent.ledger.models import ClaimDiagnostic


REJECT = "reject"
NOTE = "note"

# Stable diagnostic codes.
CLAIM_UNPARSEABLE = "CLAIM_UNPARSEABLE"
EVIDENCE_MISSING = "EVIDENCE_MISSING"
EVIDENCE_REFERENCE_UNKNOWN = "EVIDENCE_REFERENCE_UNKNOWN"
ENTITY_MALFORMED = "ENTITY_MALFORMED"
ENTITY_UNKNOWN = "ENTITY_UNKNOWN"
ENTITY_SESSION_REFERENCE = "ENTITY_SESSION_REFERENCE"
PERIPHERAL_UNKNOWN = "PERIPHERAL_UNKNOWN"
SEMANTICS_INVALID = "SEMANTICS_INVALID"
SEMANTICS_INCONSISTENT = "SEMANTICS_INCONSISTENT"
GRADE_ABOVE_CEILING = "GRADE_ABOVE_CEILING"
UNTYPED_GRADE = "UNTYPED_GRADE"
ACCESS_NOT_ESTABLISHED = "ACCESS_NOT_ESTABLISHED"
ABSENCE_NOT_ESTABLISHED = "ABSENCE_NOT_ESTABLISHED"
ABSENCE_SCOPED = "ABSENCE_SCOPED"
EVIDENCE_OMITTED = "EVIDENCE_OMITTED"
OMISSION_EXPLAINED = "OMISSION_EXPLAINED"
HISTORICAL_REFERENCE = "HISTORICAL_REFERENCE"
# Call relations (ledger/call_relations.py). Reject:
CALL_RELATION_UNSUPPORTED = "CALL_RELATION_UNSUPPORTED"  # no cited edge connects source and target
CALL_SOURCE_MISMATCH = "CALL_SOURCE_MISMATCH"  # cited edges reach the target from other functions only
CALL_TARGET_MISMATCH = "CALL_TARGET_MISMATCH"  # the named site, or the source's enumerated calls, go elsewhere
CALL_SITE_MISMATCH = "CALL_SITE_MISMATCH"  # the edge exists, at another site
CALL_KIND_MISMATCH = "CALL_KIND_MISMATCH"  # the edge exists, as another transfer kind
CALL_TARGET_UNRESOLVED = "CALL_TARGET_UNRESOLVED"  # the relevant indirect site has no derived target
CALL_CONDITION_OMITTED = "CALL_CONDITION_OMITTED"  # only a conditional target; the claim drops the condition
CALL_SCOPE_EXCEEDED = "CALL_SCOPE_EXCEEDED"  # observed in one scenario, or asserted for every execution
CALL_REACHABILITY_UNSUPPORTED = "CALL_REACHABILITY_UNSUPPORTED"  # no cited path from a stated root
CALL_ABSENCE_NOT_ESTABLISHED = "CALL_ABSENCE_NOT_ESTABLISHED"  # a missing edge stated as impossible
# Note:
CALL_RELATION_CHECKED = "CALL_RELATION_CHECKED"  # which evidence and edge kind support the relation
CALL_ABSENCE_SCOPED = "CALL_ABSENCE_SCOPED"  # absence stated for the recorded analysis only
CALL_RELATION_UNCHECKED = "CALL_RELATION_UNCHECKED"  # call wording without identifiable endpoints
# Candidate selection (research/candidates.py).
CANDIDATE_UNKNOWN = "CANDIDATE_UNKNOWN"
CANDIDATE_NOT_OFFERED = "CANDIDATE_NOT_OFFERED"
CLAIM_EQUIVALENT_EXISTS = "CLAIM_EQUIVALENT_EXISTS"

PATTERN = "pattern-matched"

_FUNCTION_RE = re.compile(r"\bFUN_[0-9a-f]{8}\b")
# Identifier-shaped tokens that are not canonical: a letter prefix glued to
# a zero-padded hex address (E0000b4b4, F_0000b4b4), a FUN_ name with the
# wrong width or case, or a bare zero-padded address without 0x.
_MALFORMED_RE = re.compile(
    r"\b(?!FUN_[0-9a-f]{8}\b)(?:[A-Za-z]{1,4}_?)?0{2,}[0-9A-Fa-f]{4,6}\b"
    r"|\bFUN_(?![0-9a-f]{8}\b)[0-9A-Za-z]+\b"
)
# Session-local evidence ids (E1, E12). They are citations, not entities,
# and mean nothing once the session ends: the recorder maps the citation
# list to durable ids, never ids inside the prose.
_SESSION_ID_RE = re.compile(r"\bE\d+\b")
# Numbered peripheral instances (SERCOM0, TCC1, TC3, ADC0).
_PERIPHERAL_RE = re.compile(r"\b[A-Z]{2,6}\d{1,2}\b")
_ACCESS_RE = re.compile(r"\b(access\w*|reads?|reading|writes?|writing|wrote|touch\w*)\b", re.IGNORECASE)
_NEGATION_RE = re.compile(r"\b(not|never|no|neither|nor|without|doesn't|don't|cannot)\b", re.IGNORECASE)
# Wording that limits an absence to the recorded analysis.
_QUALIFIED_RE = re.compile(
    r"\b(observed|recorded|in the (?:recorded |symbolic )?analysis|symbolic|unresolved|not established|undetermined|unknown)\b",
    re.IGNORECASE,
)


def _diag(code: str, severity: str, detail: str, **fields: Any) -> ClaimDiagnostic:
    return ClaimDiagnostic(code=code, severity=severity, detail=detail, **fields)


def entity_diagnostics(
    text: str,
    *,
    function_exists: Callable[[str], bool] | None = None,
    peripherals: Collection[str] | None = None,
) -> list[ClaimDiagnostic]:
    """
    Malformed identifiers always; unknown functions when a resolver is
    given; unknown numbered peripherals when the known set is given.
    """

    out: list[ClaimDiagnostic] = []

    for token in dict.fromkeys(m.group(0) for m in _MALFORMED_RE.finditer(text)):
        out.append(
            _diag(
                ENTITY_MALFORMED, REJECT,
                f"{token!r} is not a canonical firmware identifier (FUN_xxxxxxxx or 0x address); APTrace does not reinterpret it",
                value=token,
            )
        )

    for token in dict.fromkeys(_SESSION_ID_RE.findall(text)):
        out.append(
            _diag(
                ENTITY_SESSION_REFERENCE, REJECT,
                f"{token!r} is a session evidence id used in the assertion; name the firmware entity it concerns "
                "and list evidence only in the citation",
                value=token,
            )
        )

    if function_exists is not None:
        for name in dict.fromkeys(_FUNCTION_RE.findall(text)):
            if not function_exists(name):
                out.append(_diag(ENTITY_UNKNOWN, REJECT, f"{name} is not a known function of this firmware", value=name))

    if peripherals is not None:
        known = {p.upper() for p in peripherals}

        for name in dict.fromkeys(_PERIPHERAL_RE.findall(text)):
            if name not in known:
                out.append(_diag(PERIPHERAL_UNKNOWN, REJECT, f"{name} is not a known peripheral ({', '.join(sorted(known)) or 'none'})", value=name))

    return out


def _clause_negated(text: str) -> bool:
    """A negation shortly before the first access verb ("does not read")."""

    verb = _ACCESS_RE.search(text)
    return bool(verb and _NEGATION_RE.search(text[max(0, verb.start() - 40) : verb.start()]))


def access_diagnostics(assertion: str, evidence: list[tuple[Any, dict[str, Any]]]) -> list[ClaimDiagnostic]:
    """
    Peripheral access or absence asserted in prose, checked against the
    structured roles (claim_semantics.extract_facts) and function-effects
    accesses of the cited evidence.
    """

    if not _ACCESS_RE.search(assertion):
        return []

    functions = list(dict.fromkeys(_FUNCTION_RE.findall(assertion)))
    named = {p for p in _PERIPHERAL_RE.findall(assertion)} | {p for p in ("USB", "EIC") if re.search(rf"\b{p}\b", assertion)}

    if not functions or not named:
        return []

    facts = extract_facts(evidence)
    effects = {
        str(result.get("function") or artifact.arguments.get("function")): (artifact, result)
        for artifact, result in evidence
        if artifact.tool == "function_effects"
    }
    negative = _clause_negated(assertion)
    out: list[ClaimDiagnostic] = []

    for function in functions:
        entry = to_int(function)
        roles = [r for r in facts.roles if r.entry == entry and (r.peripheral in named or r.peripheral is None)]
        access = [r for r in roles if r.role == FunctionRole.MMIO_USER]
        loads = [r for r in roles if r.role == FunctionRole.ADDRESS_CONSTANT_LOADER]
        peripheral = ", ".join(sorted(named))

        if not negative:
            if access:
                continue

            detail = f"no cited evidence shows {function} accessing {peripheral} registers"

            if loads:
                detail += f"; {', '.join(sorted({r.evidence_id for r in loads}))} shows only a literal-pool load of its address (no MMIO site)"

            out.append(_diag(ACCESS_NOT_ESTABLISHED, REJECT, detail, value=function, evidence_ids=sorted({r.evidence_id for r in loads}), basis=PATTERN))
            continue

        if access:
            out.append(
                _diag(
                    ABSENCE_NOT_ESTABLISHED, REJECT,
                    f"cited evidence shows {function} accessing {peripheral} registers, contradicting the stated absence",
                    value=function, evidence_ids=sorted({r.evidence_id for r in access}), basis=PATTERN,
                )
            )
            continue

        pair = effects.get(function)
        gaps: list[str] = []

        if pair is None:
            gaps.append(f"no function_effects evidence for {function} is cited")
        else:
            artifact, result = pair

            if result.get("coverage") != "complete":
                gaps.append(f"{artifact.evidence_id} coverage is {result.get('coverage')!r}, not complete")

            inputs = sorted({i for a in result.get("accesses", []) if a.get("address") == "parametric" for i in a.get("depends_on", [])})

            if inputs:
                gaps.append(
                    f"{artifact.evidence_id} has accesses whose addresses depend on {', '.join(inputs)}; "
                    "their concrete values in reachable callers are not established"
                )

        if not gaps:
            continue

        evidence_ids = [pair[0].evidence_id] if pair else []

        if _QUALIFIED_RE.search(assertion):
            out.append(_diag(ABSENCE_SCOPED, NOTE, "absence stated for the recorded analysis only: " + "; ".join(gaps), value=function, evidence_ids=evidence_ids, basis=PATTERN))
        else:
            out.append(
                _diag(
                    ABSENCE_NOT_ESTABLISHED, REJECT,
                    f"the claim states {function} does not access {peripheral} registers, but " + "; ".join(gaps)
                    + "; scope the claim to the recorded analysis or obtain the missing evidence",
                    value=function, evidence_ids=evidence_ids, basis=PATTERN,
                )
            )

    return out


__all__ = [
    "ABSENCE_NOT_ESTABLISHED",
    "ABSENCE_SCOPED",
    "ACCESS_NOT_ESTABLISHED",
    "CALL_ABSENCE_NOT_ESTABLISHED",
    "CALL_ABSENCE_SCOPED",
    "CALL_CONDITION_OMITTED",
    "CALL_KIND_MISMATCH",
    "CALL_REACHABILITY_UNSUPPORTED",
    "CALL_RELATION_CHECKED",
    "CALL_RELATION_UNCHECKED",
    "CALL_RELATION_UNSUPPORTED",
    "CALL_SCOPE_EXCEEDED",
    "CALL_SITE_MISMATCH",
    "CALL_SOURCE_MISMATCH",
    "CALL_TARGET_MISMATCH",
    "CALL_TARGET_UNRESOLVED",
    "CANDIDATE_NOT_OFFERED",
    "CANDIDATE_UNKNOWN",
    "CLAIM_EQUIVALENT_EXISTS",
    "CLAIM_UNPARSEABLE",
    "ENTITY_MALFORMED",
    "ENTITY_SESSION_REFERENCE",
    "ENTITY_UNKNOWN",
    "EVIDENCE_MISSING",
    "EVIDENCE_OMITTED",
    "EVIDENCE_REFERENCE_UNKNOWN",
    "GRADE_ABOVE_CEILING",
    "HISTORICAL_REFERENCE",
    "NOTE",
    "OMISSION_EXPLAINED",
    "PERIPHERAL_UNKNOWN",
    "REJECT",
    "SEMANTICS_INCONSISTENT",
    "SEMANTICS_INVALID",
    "UNTYPED_GRADE",
    "access_diagnostics",
    "entity_diagnostics",
]
