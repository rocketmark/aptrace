"""
Versioned claim-verification policy (see docs/cross-engine-verification.md).

The policy is data: a claim class per mechanically determined claim shape,
and per class the corroboration it requires and the evidence kinds that can
satisfy it today. Its identity (id, version, digest of the canonical
definition) is recorded on every verification, so decisions made under an
earlier policy, or before any policy, stay distinguishable without
rewriting them.

A class whose evidence_kinds is empty has no evidence contract in the
ledger yet; its corroboration requirement is UNEVALUABLE and a claim in it
cannot reach VERIFIED. That is intentional: missing corroboration is never
treated as success.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from aptrace_agent.ledger.claim_semantics import ClaimSemantics, FunctionRole, Predicate
from aptrace_agent.ledger.hashing import digest
from aptrace_agent.ledger.models import ClaimType, PolicyRef


POLICY_ID = "aptrace-claim-verification"
POLICY_VERSION = "1"


class ClaimClass(StrEnum):
    CODE_EXISTENCE = "CODE_EXISTENCE"
    RESOLVED_INDIRECT_CALL = "RESOLVED_INDIRECT_CALL"
    CONTROL_FLOW = "CONTROL_FLOW"
    BOUNDED_NEGATIVE = "BOUNDED_NEGATIVE"
    MEMORY_ACCESS = "MEMORY_ACCESS"
    # Vector-table slot -> handler mapping (function-entry agreement alone
    # does not corroborate which slot points there).
    VECTOR_MAPPING = "VECTOR_MAPPING"
    UNDETERMINED = "UNDETERMINED"


# Minimum disjoint discovery lineages for independent static corroboration.
MIN_INDEPENDENT_LINEAGES = 2

# Per-source envelope fields a structural-agreement source must carry for
# its observation to count toward independence. Absent fields make the
# requirement UNEVALUABLE, never satisfied.
SOURCE_ENVELOPE_FIELDS = ("lineage", "firmware_sha256", "engine_version")

CLASS_POLICY: dict[ClaimClass, dict[str, Any]] = {
    ClaimClass.CODE_EXISTENCE: {
        "corroboration": "independent static agreement on code at every asserted address, and on the "
        "function entry where the claim asserts it, from >= 2 disjoint discovery lineages",
        "evidence_kinds": ["structural_source_agreement"],
    },
    ClaimClass.RESOLVED_INDIRECT_CALL: {
        "corroboration": "an independent engine resolving the same transfer, or concrete execution "
        "observing it, or a solver result under recorded assumptions",
        "evidence_kinds": [],
    },
    ClaimClass.CONTROL_FLOW: {
        "corroboration": "independent static agreement on the asserted edges or paths within a common scope",
        "evidence_kinds": [],
    },
    ClaimClass.BOUNDED_NEGATIVE: {
        "corroboration": "bounded absences from >= 2 independent engines, each bound recorded "
        "(never unreachability)",
        "evidence_kinds": [],
    },
    ClaimClass.MEMORY_ACCESS: {
        "corroboration": "independent agreement on constant-address accesses",
        "evidence_kinds": [],
    },
    ClaimClass.VECTOR_MAPPING: {
        "corroboration": "independent agreement on the vector-table slot and its handler entry",
        "evidence_kinds": [],
    },
    ClaimClass.UNDETERMINED: {
        "corroboration": "claim class is not mechanically determinable; no cross-engine policy can be satisfied",
        "evidence_kinds": [],
    },
}

# Gate condition status -> verification check severity.
SEVERITY = {
    "CONTRADICTED": "block",
    "UNRESOLVED": "hold",
    "UNMET": "hold",
    "UNEVALUABLE": "hold",
}

_POINTER_ROLES = frozenset(
    {
        FunctionRole.WRITER,
        FunctionRole.CALLBACK_TARGET,
        FunctionRole.FORWARDING_TARGET,
        FunctionRole.REGISTRATION_CALLER,
        FunctionRole.INDIRECT_CALLER,
    }
)


def policy_definition() -> dict[str, Any]:
    return {
        "policy_id": POLICY_ID,
        "version": POLICY_VERSION,
        "min_independent_lineages": MIN_INDEPENDENT_LINEAGES,
        "source_envelope_fields": list(SOURCE_ENVELOPE_FIELDS),
        "classes": {k.value: v for k, v in sorted(CLASS_POLICY.items())},
        "severity": dict(sorted(SEVERITY.items())),
    }


def current_policy() -> PolicyRef:
    return PolicyRef(policy_id=POLICY_ID, version=POLICY_VERSION, digest=digest(policy_definition()))


def claim_class(claim_type: ClaimType | str, semantics: ClaimSemantics | None) -> tuple[ClaimClass, str]:
    """
    Claim class from typed semantics and claim type only. The proposer
    never chooses it; an unmapped shape is UNDETERMINED.
    """

    claim_type = ClaimType(claim_type)

    if semantics is None:
        if claim_type == ClaimType.NO_KNOWN_PATH:
            return ClaimClass.BOUNDED_NEGATIVE, "claim type NO_KNOWN_PATH"

        if claim_type == ClaimType.PATH_EXISTS:
            return ClaimClass.CONTROL_FLOW, "claim type PATH_EXISTS"

        return ClaimClass.UNDETERMINED, f"claim type {claim_type.value} without typed semantics"

    if semantics.predicate == Predicate.CODE_PRESENCE:
        return ClaimClass.CODE_EXISTENCE, "predicate CODE_PRESENCE"

    if semantics.predicate == Predicate.RESOLVED_FUNCTION_POINTER:
        return ClaimClass.RESOLVED_INDIRECT_CALL, "predicate RESOLVED_FUNCTION_POINTER"

    if semantics.predicate == Predicate.PATH_RELATION:
        assert semantics.path is not None

        if semantics.path.status == "NO_KNOWN_PATH":
            return ClaimClass.BOUNDED_NEGATIVE, "PATH_RELATION status NO_KNOWN_PATH"

        return ClaimClass.CONTROL_FLOW, "PATH_RELATION status KNOWN_COMMON_PATH"

    assert semantics.function_role is not None
    role = semantics.function_role.role

    if role in _POINTER_ROLES:
        return ClaimClass.RESOLVED_INDIRECT_CALL, f"FUNCTION_ROLE {role.value} (derived from a resolved pointer)"

    if role == FunctionRole.MMIO_USER:
        return ClaimClass.MEMORY_ACCESS, "FUNCTION_ROLE MMIO_USER"

    if role == FunctionRole.INTERRUPT_VECTOR_HANDLER:
        return ClaimClass.VECTOR_MAPPING, "FUNCTION_ROLE INTERRUPT_VECTOR_HANDLER"

    return ClaimClass.UNDETERMINED, f"FUNCTION_ROLE {role.value} has no policy mapping"
