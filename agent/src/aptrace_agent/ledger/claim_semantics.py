"""
Typed claim semantics and their deterministic verification.

A ClaimVersion may carry a structured predicate next to its prose
assertion. When it does, the predicate is what APTrace verifies: entity
roles, relations, and set scope are checked mechanically against the
structured fields of the supporting evidence. The prose is presentation.

The vocabulary is deliberately small: only predicates, roles, relations
and set kinds that current APTrace evidence establishes mechanically.
No natural-language parsing happens here.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, field_validator, model_validator


class Predicate(StrEnum):
    # A RAM function-pointer slot statically resolved to a code target.
    RESOLVED_FUNCTION_POINTER = "RESOLVED_FUNCTION_POINTER"
    # A function occupies a role that evidence establishes.
    FUNCTION_ROLE = "FUNCTION_ROLE"
    # Two typed function sets have (or have no known) census common path.
    PATH_RELATION = "PATH_RELATION"
    # Executable code exists at an address (optionally: in the function
    # whose entry is stated). Established by structural source agreement.
    CODE_PRESENCE = "CODE_PRESENCE"
    # One control transfer from a source function to a target, of a stated
    # kind and scope (ledger/call_relations.py).
    CALL_RELATION = "CALL_RELATION"


class FunctionRole(StrEnum):
    """Roles APTrace evidence establishes mechanically."""

    WRITER = "WRITER"  # stores the pointer into the slot
    CALLBACK_TARGET = "CALLBACK_TARGET"  # canonical target of a resolved pointer
    FORWARDING_TARGET = "FORWARDING_TARGET"  # body a forwarding stub branches to
    REGISTRATION_CALLER = "REGISTRATION_CALLER"  # contains the call passing the pointer
    INDIRECT_CALLER = "INDIRECT_CALLER"  # contains the indirect transfer consuming the slot
    INTERRUPT_VECTOR_HANDLER = "INTERRUPT_VECTOR_HANDLER"
    # Accesses a peripheral's registers: a census constant-address MMIO
    # site, or a function-effects access in the MMIO region.
    MMIO_USER = "MMIO_USER"
    # Loads a peripheral address constant (literal pool) with no MMIO site.
    # Loading an address is not an access; the census lists such functions
    # as peripheral users, so the two are kept apart here.
    ADDRESS_CONSTANT_LOADER = "ADDRESS_CONSTANT_LOADER"


class SetKind(StrEnum):
    # Census constant-address register/MMIO users of one peripheral.
    PERIPHERAL_MMIO_USAGE = "PERIPHERAL_MMIO_USAGE"
    # An interface inventory set: MMIO register users plus IRQ vector handlers.
    INTERFACE_INVENTORY = "INTERFACE_INVENTORY"
    # Interrupt-vector handlers whose interrupt name has a prefix.
    IRQ_ROOT_SET = "IRQ_ROOT_SET"
    # A peripheral's interrupt-dispatch path (vector stubs plus dispatcher).
    # No current APTrace analysis produces this set.
    INTERRUPT_DISPATCH_SET = "INTERRUPT_DISPATCH_SET"
    # Explicitly named functions.
    FUNCTION_SET = "FUNCTION_SET"
    # A set label APTrace cannot attribute to evidence.
    UNATTRIBUTED = "UNATTRIBUTED"


class CallEdgeKind(StrEnum):
    """
    Kinds of call relation APTrace evidence establishes, strongest scope
    first. They are not interchangeable: a potential target is not a
    dispatch, and an observed dispatch holds for its scenario only.
    """

    # A decoded BL/BLX immediate, or a Ghidra call reference.
    DIRECT_CALL = "DIRECT_CALL"
    # A decoded B/B.W/B<c>.W immediate leaving the source function.
    TAIL_TRANSFER = "TAIL_TRANSFER"
    # An indirect transfer whose target is statically established.
    ESTABLISHED_INDIRECT = "ESTABLISHED_INDIRECT"
    # A target an indirect transfer can take under stated conditions
    # (e.g. the receiver's vptr); not a dispatch.
    POTENTIAL_INDIRECT = "POTENTIAL_INDIRECT"
    # A transfer concretely taken in one scenario's execution.
    OBSERVED_DISPATCH = "OBSERVED_DISPATCH"


class CheckCode(StrEnum):
    CONSISTENT = "CONSISTENT"
    ENTITY_ROLE_MISMATCH = "ENTITY_ROLE_MISMATCH"
    RELATION_MISMATCH = "RELATION_MISMATCH"
    RELATION_UNSUPPORTED = "RELATION_UNSUPPORTED"
    SCOPE_MISMATCH = "SCOPE_MISMATCH"
    PREDICATE_TYPE_MISMATCH = "PREDICATE_TYPE_MISMATCH"


_FUN_RE = re.compile(r"FUN_([0-9a-fA-F]{1,8})")
_HEX_RE = re.compile(r"0x[0-9a-fA-F]{1,8}")


def to_int(value: Any) -> int:
    if isinstance(value, int) and not isinstance(value, bool):
        return value

    text = str(value).strip()
    match = _FUN_RE.fullmatch(text)

    if match:
        return int(match.group(1), 16)

    if _HEX_RE.fullmatch(text):
        return int(text, 16)

    raise ValueError(f"not an address or FUN_ name: {value!r}")


def addr(value: Any) -> str:
    return f"0x{to_int(value):08x}"


def fun(value: Any) -> str:
    return f"FUN_{to_int(value):08x}"


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class SetScope(_Model):
    kind: SetKind
    name: str

    @field_validator("name")
    @classmethod
    def _name(cls, value: str) -> str:
        return value.strip().upper() if not _FUN_RE.fullmatch(value.strip()) else fun(value)

    def __str__(self) -> str:
        return f"{self.kind.value}:{self.name}"

    @classmethod
    def parse(cls, text: str) -> "SetScope":
        kind, _, name = str(text).partition(":")
        return cls(kind=SetKind(kind.strip().upper()), name=name)


_POINTER_FUNCTIONS = ("writer", "registration_caller", "indirect_caller")
_POINTER_ADDRESSES = (
    "slot",
    "writer_instruction",
    "registration_callsite",
    "raw_pointer",
    "canonical_target",
    "forwarding_target",
    "indirect_site",
)


class ResolvedPointer(_Model):
    """A resolved RAM function pointer. Unset fields are not claimed."""

    slot: str
    writer: str | None = None
    writer_instruction: str | None = None
    registration_caller: str | None = None
    registration_callsite: str | None = None
    raw_pointer: str | None = None
    canonical_target: str | None = None
    forwarding_target: str | None = None
    indirect_site: str | None = None
    indirect_caller: str | None = None

    @field_validator(*_POINTER_ADDRESSES)
    @classmethod
    def _address(cls, value: Any) -> str | None:
        return None if value is None else addr(value)

    @field_validator(*_POINTER_FUNCTIONS)
    @classmethod
    def _function(cls, value: Any) -> str | None:
        return None if value is None else fun(value)

    def claimed(self) -> dict[str, str]:
        return {k: v for k, v in self.model_dump().items() if v is not None and k != "slot"}


class FunctionRoleClaim(_Model):
    function: str
    role: FunctionRole
    # Optional context narrowing which evidence establishes the role.
    slot: str | None = None
    peripheral: str | None = None

    @field_validator("function")
    @classmethod
    def _function(cls, value: Any) -> str:
        return fun(value)

    @field_validator("slot")
    @classmethod
    def _slot(cls, value: Any) -> str | None:
        return None if value is None else addr(value)


class PathRelation(_Model):
    status: Literal["KNOWN_COMMON_PATH", "NO_KNOWN_PATH"]
    left: SetScope
    right: SetScope

    @field_validator("left", "right", mode="before")
    @classmethod
    def _scope(cls, value: Any) -> Any:
        return SetScope.parse(value) if isinstance(value, str) else value


class CodePresence(_Model):
    """Code at an address; function_entry, when set, is the containing entry."""

    address: str
    function_entry: str | None = None

    @field_validator("address", "function_entry")
    @classmethod
    def _address(cls, value: Any) -> str | None:
        return None if value is None else addr(value)


class CallRelation(_Model):
    """
    A control transfer from `source` (a function) to `target`. POTENTIAL_INDIRECT
    must state the conditions the cited evidence attaches to the target;
    OBSERVED_DISPATCH must state the scenario it was observed in.
    """

    source: str
    target: str
    kind: CallEdgeKind
    site: str | None = None
    conditions: tuple[str, ...] = ()
    scenario: str | None = None

    @field_validator("source")
    @classmethod
    def _source(cls, value: Any) -> str:
        return fun(value)

    @field_validator("target", "site")
    @classmethod
    def _address(cls, value: Any) -> str | None:
        return None if value is None else addr(value)

    @model_validator(mode="after")
    def _scope(self) -> "CallRelation":
        if self.kind == CallEdgeKind.POTENTIAL_INDIRECT and not any(c.strip() for c in self.conditions):
            raise ValueError("a POTENTIAL_INDIRECT relation needs the conditions its target depends on")

        if self.kind == CallEdgeKind.OBSERVED_DISPATCH and not (self.scenario or "").strip():
            raise ValueError("an OBSERVED_DISPATCH relation needs the scenario it was observed in")

        return self

    def summary(self) -> str:
        site = f" at {self.site}" if self.site else ""
        scope = f" if {'; '.join(self.conditions)}" if self.conditions else ""
        scope += f" in scenario {self.scenario}" if self.scenario else ""
        return f"{self.source} -> {self.target}{site} {self.kind.value}{scope}"


class ClaimSemantics(_Model):
    """Structured predicate of a claim; authoritative for verification."""

    predicate: Predicate
    resolved_pointer: ResolvedPointer | None = None
    function_role: FunctionRoleClaim | None = None
    path: PathRelation | None = None
    code_presence: CodePresence | None = None
    call: CallRelation | None = None

    @model_validator(mode="after")
    def _one_body(self) -> "ClaimSemantics":
        bodies = {
            Predicate.RESOLVED_FUNCTION_POINTER: self.resolved_pointer,
            Predicate.FUNCTION_ROLE: self.function_role,
            Predicate.PATH_RELATION: self.path,
            Predicate.CODE_PRESENCE: self.code_presence,
            Predicate.CALL_RELATION: self.call,
        }

        if bodies[self.predicate] is None or sum(b is not None for b in bodies.values()) != 1:
            raise ValueError(f"{self.predicate.value} semantics need exactly its own body")

        return self

    def summary(self) -> str:
        if self.resolved_pointer:
            fields = ", ".join(f"{k}={v}" for k, v in self.resolved_pointer.model_dump().items() if v is not None)
            return f"{self.predicate.value}({fields})"

        if self.function_role:
            role = self.function_role
            context = "".join(f", {k}={v}" for k, v in (("slot", role.slot), ("peripheral", role.peripheral)) if v)
            return f"{self.predicate.value}({role.function} is {role.role.value}{context})"

        if self.code_presence:
            code = self.code_presence
            entry = f" in function at {code.function_entry}" if code.function_entry else ""
            return f"{self.predicate.value}({code.address}{entry})"

        if self.call:
            return f"{self.predicate.value}({self.call.summary()})"

        assert self.path is not None
        return f"{self.predicate.value}({self.path.left} {self.path.status} {self.path.right})"


# Claim types each predicate may accompany.
COMPATIBLE_CLAIM_TYPES: dict[Predicate, frozenset[str]] = {
    Predicate.RESOLVED_FUNCTION_POINTER: frozenset({"RESOLUTION"}),
    Predicate.FUNCTION_ROLE: frozenset({"RESOLUTION", "STRUCTURE", "BEHAVIOR"}),
    Predicate.PATH_RELATION: frozenset({"PATH_EXISTS", "NO_KNOWN_PATH"}),
    Predicate.CODE_PRESENCE: frozenset({"STRUCTURE"}),
    Predicate.CALL_RELATION: frozenset({"STRUCTURE", "RESOLUTION", "BEHAVIOR"}),
}

PATH_CLAIM_TYPE = {"KNOWN_COMMON_PATH": "PATH_EXISTS", "NO_KNOWN_PATH": "NO_KNOWN_PATH"}


class SemanticCheck(_Model):
    code: CheckCode
    passed: bool
    field: str | None = None
    claimed: str | None = None
    claimed_role: str | None = None
    evidence_value: str | None = None
    evidence_role: str | None = None
    evidence_id: str | None = None
    detail: str = ""
    # Stable admission diagnostic code for this failure, when the predicate
    # has its own (call relations); absent on other checks and older records.
    diagnostic: str | None = None


# -- facts extracted from structured evidence --------------------------------


@dataclass
class PointerFact:
    evidence_id: str
    values: dict[str, int]
    # field -> evidence id establishing it, when not the edge itself
    sources: dict[str, str] = field(default_factory=dict)


@dataclass
class RoleFact:
    entry: int
    role: FunctionRole
    evidence_id: str
    slot: int | None = None
    peripheral: str | None = None


@dataclass
class PathFact:
    evidence_id: str
    status: str
    left: tuple[SetScope, ...]
    right: tuple[SetScope, ...]
    notes: list[str] = field(default_factory=list)


@dataclass
class EvidenceFacts:
    pointers: list[PointerFact] = field(default_factory=list)
    roles: list[RoleFact] = field(default_factory=list)
    paths: list[PathFact] = field(default_factory=list)


_EDGE_FIELDS = {
    "slot": "slot",
    "store": "writer_instruction",
    "callsite": "registration_callsite",
    "raw_value": "raw_pointer",
    "canonical_target": "canonical_target",
    "terminal_target": "forwarding_target",
    "site": "indirect_site",
    "writer": "writer",
    "from_function": "indirect_caller",
}

_ROLE_OF_FIELD = {
    "writer": FunctionRole.WRITER,
    "canonical_target": FunctionRole.CALLBACK_TARGET,
    "forwarding_target": FunctionRole.FORWARDING_TARGET,
    "registration_caller": FunctionRole.REGISTRATION_CALLER,
    "indirect_caller": FunctionRole.INDIRECT_CALLER,
}


def _maybe_int(value: Any) -> int | None:
    try:
        return None if value in (None, "") else to_int(value)
    except ValueError:
        return None


def _census_containing(agreements: list[tuple[str, dict[str, Any]]]) -> dict[int, tuple[int, str]]:
    """address -> (census containing function entry, agreement evidence id)."""

    out: dict[int, tuple[int, str]] = {}

    for evidence_id, result in agreements:
        for entry in result.get("agreements", []):
            for observation in entry.get("observations", []):
                if observation.get("source") == "census" and observation.get("start"):
                    out[to_int(entry["address"])] = (to_int(observation["start"]), evidence_id)

    return out


def _side_scopes(label: Any, members: Any, evidence: list[tuple[Any, dict[str, Any]]]) -> tuple[tuple[SetScope, ...], list[str]]:
    """
    Typed scopes of one common-path side, from its APTrace label convention
    and the supporting evidence that produced the named sets.
    """

    parts = [p for p in str(label or "").split("+") if p]
    scopes: list[SetScope] = []
    produced: set[str] = set()
    notes: list[str] = []
    unverified = False

    for part in parts:
        upper = part.upper()

        if upper.startswith("IRQ:"):
            scopes.append(SetScope(kind=SetKind.IRQ_ROOT_SET, name=upper[4:]))
            unverified = True  # vector-table resolution is not in the evidence
            continue

        if _FUN_RE.fullmatch(part):
            scopes.append(SetScope(kind=SetKind.FUNCTION_SET, name=part))
            produced.add(fun(part))
            continue

        source = None

        for artifact, result in evidence:
            if artifact.tool == "census_peripheral_usage" and str(artifact.arguments.get("peripheral", "")).upper() == upper:
                source = (SetKind.PERIPHERAL_MMIO_USAGE, [f.get("function") for f in result.get("functions", []) if f.get("function")])
                break

            if artifact.tool == "census_usb_inventory" and upper == "USB":
                source = (SetKind.INTERFACE_INVENTORY, list(result.get("functions", [])))

        if source is None:
            scopes.append(SetScope(kind=SetKind.UNATTRIBUTED, name=upper))
            notes.append(f"set {upper!r} is not produced by any supporting evidence")
            continue

        scopes.append(SetScope(kind=source[0], name=upper))
        produced.update(source[1])

    if isinstance(members, list) and not unverified and produced and set(members) != produced:
        notes.append(f"side {label!r} members differ from the sets its evidence produced")
        scopes = [SetScope(kind=SetKind.UNATTRIBUTED, name=str(s)) for s in scopes]

    return tuple(scopes), notes


def extract_facts(evidence: list[tuple[Any, dict[str, Any]]]) -> EvidenceFacts:
    """Mechanical roles, relations and set scopes in supporting evidence."""

    facts = EvidenceFacts()
    agreements = [(a.evidence_id, r) for a, r in evidence if a.tool == "structural_source_agreement"]
    containing = _census_containing(agreements)

    for artifact, result in evidence:
        for edge in result.get("resolved_indirect_edges") or []:
            values = {name: v for key, name in _EDGE_FIELDS.items() if (v := _maybe_int(edge.get(key))) is not None}
            sources: dict[str, str] = {}
            callsite = values.get("registration_callsite")

            if callsite is not None and callsite in containing:
                values["registration_caller"], sources["registration_caller"] = containing[callsite]

            fact = PointerFact(evidence_id=artifact.evidence_id, values=values, sources=sources)
            facts.pointers.append(fact)

            for name, role in _ROLE_OF_FIELD.items():
                if name in values:
                    facts.roles.append(
                        RoleFact(entry=values[name], role=role, evidence_id=sources.get(name, artifact.evidence_id), slot=values.get("slot"))
                    )

        if artifact.tool == "census_usb_inventory":
            for vector in result.get("irq_vectors", []):
                if (entry := _maybe_int(vector.get("handler"))) is not None:
                    facts.roles.append(RoleFact(entry=entry, role=FunctionRole.INTERRUPT_VECTOR_HANDLER, evidence_id=artifact.evidence_id))

            for user in result.get("register_users", []):
                if (entry := _maybe_int(user.get("function"))) is not None:
                    facts.roles.append(RoleFact(entry=entry, role=FunctionRole.MMIO_USER, evidence_id=artifact.evidence_id, peripheral="USB"))

        if artifact.tool == "census_peripheral_usage":
            peripheral = str(artifact.arguments.get("peripheral", "")).upper()

            for item in result.get("functions", []):
                if (entry := _maybe_int(item.get("function"))) is None:
                    continue

                # Only a constant-address MMIO site is an access. A function
                # listed for its address constants alone loads the address.
                if item.get("mmio_site_count", 0) > 0 or item.get("mmio_sites"):
                    role = FunctionRole.MMIO_USER
                elif item.get("constant_load_count", 0) > 0 or item.get("constant_loads"):
                    role = FunctionRole.ADDRESS_CONSTANT_LOADER
                else:
                    continue

                facts.roles.append(RoleFact(entry=entry, role=role, evidence_id=artifact.evidence_id, peripheral=peripheral))

        if artifact.tool == "function_effects":
            entry = _maybe_int(result.get("function") or artifact.arguments.get("function"))

            for access in result.get("accesses", []):
                region = str(access.get("region") or "")
                register = str(access.get("register_name") or "")

                if entry is not None and region.startswith("MMIO"):
                    peripheral = register.split(".", 1)[0].upper() or None
                    facts.roles.append(RoleFact(entry=entry, role=FunctionRole.MMIO_USER, evidence_id=artifact.evidence_id, peripheral=peripheral))

        if artifact.tool == "census_common_paths" and result.get("status") in PATH_CLAIM_TYPE:
            left, left_notes = _side_scopes(artifact.arguments.get("left_label"), artifact.arguments.get("left"), evidence)
            right, right_notes = _side_scopes(artifact.arguments.get("right_label"), artifact.arguments.get("right"), evidence)
            facts.paths.append(PathFact(artifact.evidence_id, str(result["status"]), left, right, left_notes + right_notes))

    return facts


# -- checks -----------------------------------------------------------------


def _show(name: str, value: int) -> str:
    return fun(value) if name in _POINTER_FUNCTIONS else addr(value)


def check_resolved_pointer(claim: ResolvedPointer, facts: EvidenceFacts) -> list[SemanticCheck]:
    slot = to_int(claim.slot)
    candidates = [f for f in facts.pointers if f.values.get("slot") == slot]

    if not candidates:
        return [
            SemanticCheck(
                code=CheckCode.RELATION_UNSUPPORTED,
                passed=False,
                field="slot",
                claimed=claim.slot,
                detail="no supporting evidence resolves a function pointer stored in this slot",
            )
        ]

    claimed = {k: to_int(v) for k, v in claim.claimed().items()}

    for fact in candidates:
        if all(fact.values.get(k) == v for k, v in claimed.items()):
            return [
                SemanticCheck(
                    code=CheckCode.CONSISTENT,
                    passed=True,
                    field=k,
                    claimed=_show(k, v),
                    claimed_role=k,
                    evidence_value=_show(k, v),
                    evidence_role=k,
                    evidence_id=fact.sources.get(k, fact.evidence_id),
                )
                for k, v in claimed.items()
            ] or [SemanticCheck(code=CheckCode.CONSISTENT, passed=True, field="slot", claimed=claim.slot, evidence_id=fact.evidence_id)]

    fact = candidates[0]
    checks: list[SemanticCheck] = []

    for name, value in claimed.items():
        evidence_id = fact.sources.get(name, fact.evidence_id)
        actual = fact.values.get(name)

        if actual == value:
            checks.append(SemanticCheck(code=CheckCode.CONSISTENT, passed=True, field=name, claimed=_show(name, value), claimed_role=name, evidence_value=_show(name, value), evidence_role=name, evidence_id=evidence_id))
            continue

        other_roles = sorted(k for k, v in fact.values.items() if v == value and k != name)
        swapped = [k for k in other_roles if actual is not None and claimed.get(k) == actual]

        if swapped:
            code, detail = CheckCode.RELATION_MISMATCH, f"relation endpoints swapped: evidence has {name}={_show(name, actual)} and {swapped[0]}={_show(swapped[0], value)}"
        elif other_roles:
            code, detail = CheckCode.ENTITY_ROLE_MISMATCH, f"evidence identifies {_show(name, value)} as {', '.join(other_roles)}, not {name}"
        elif actual is not None:
            code, detail = CheckCode.RELATION_MISMATCH, f"evidence has {name}={_show(name, actual)}"
        else:
            code, detail = CheckCode.RELATION_UNSUPPORTED, f"supporting evidence does not establish {name} for this slot"

        checks.append(
            SemanticCheck(
                code=code,
                passed=False,
                field=name,
                claimed=_show(name, value),
                claimed_role=name,
                evidence_value=None if actual is None else _show(name, actual),
                evidence_role=", ".join(other_roles) or None,
                evidence_id=evidence_id,
                detail=detail,
            )
        )

    raw, canonical = claimed.get("raw_pointer"), claimed.get("canonical_target")

    if raw is not None and canonical is not None and raw & ~1 != canonical:
        checks.append(
            SemanticCheck(
                code=CheckCode.RELATION_MISMATCH,
                passed=False,
                field="canonical_target",
                claimed=addr(canonical),
                detail=f"canonical Thumb target of raw pointer {addr(raw)} is {addr(raw & ~1)}",
            )
        )

    return checks


def check_function_role(claim: FunctionRoleClaim, facts: EvidenceFacts) -> list[SemanticCheck]:
    entry = to_int(claim.function)
    slot = None if claim.slot is None else to_int(claim.slot)
    peripheral = claim.peripheral.upper() if claim.peripheral else None
    relevant = [
        r
        for r in facts.roles
        if r.entry == entry and (slot is None or r.slot in (None, slot)) and (peripheral is None or r.peripheral in (None, peripheral))
    ]
    match = next((r for r in relevant if r.role == claim.role and (peripheral is None or r.peripheral == peripheral)), None)

    if match is not None:
        return [SemanticCheck(code=CheckCode.CONSISTENT, passed=True, field="role", claimed=claim.function, claimed_role=claim.role.value, evidence_role=match.role.value, evidence_id=match.evidence_id)]

    if relevant:
        roles = sorted({r.role.value for r in relevant})
        return [
            SemanticCheck(
                code=CheckCode.ENTITY_ROLE_MISMATCH,
                passed=False,
                field="role",
                claimed=claim.function,
                claimed_role=claim.role.value,
                evidence_role=", ".join(roles),
                evidence_id=relevant[0].evidence_id,
                detail=f"supporting evidence identifies {claim.function} as {', '.join(roles)}, not {claim.role.value}",
            )
        ]

    return [
        SemanticCheck(
            code=CheckCode.RELATION_UNSUPPORTED,
            passed=False,
            field="role",
            claimed=claim.function,
            claimed_role=claim.role.value,
            detail=f"no supporting evidence assigns {claim.function} any role",
        )
    ]


def check_path(claim: PathRelation, facts: EvidenceFacts) -> list[SemanticCheck]:
    wanted = {str(claim.left), str(claim.right)}

    if not facts.paths:
        return [SemanticCheck(code=CheckCode.RELATION_UNSUPPORTED, passed=False, field="path", detail="no supporting common-path evidence")]

    for fact in facts.paths:
        sides = [{str(s) for s in fact.left}, {str(s) for s in fact.right}]

        if [{str(claim.left)}, {str(claim.right)}] in (sides, sides[::-1]):
            if fact.status != claim.status:
                return [
                    SemanticCheck(
                        code=CheckCode.RELATION_MISMATCH,
                        passed=False,
                        field="status",
                        claimed=claim.status,
                        evidence_value=fact.status,
                        evidence_id=fact.evidence_id,
                        detail=f"evidence path status for these scopes is {fact.status}",
                    )
                ]

            return [
                SemanticCheck(
                    code=CheckCode.CONSISTENT,
                    passed=True,
                    field="scope",
                    claimed=f"{claim.left} | {claim.right}",
                    evidence_value=fact.status,
                    evidence_id=fact.evidence_id,
                    detail="; ".join(fact.notes),
                )
            ]

    shown = "; ".join(
        f"{f.evidence_id}: {'+'.join(map(str, f.left))} | {'+'.join(map(str, f.right))} = {f.status}" for f in facts.paths
    )
    return [
        SemanticCheck(
            code=CheckCode.SCOPE_MISMATCH,
            passed=False,
            field="scope",
            claimed=" | ".join(sorted(wanted)),
            evidence_value=shown,
            evidence_id=facts.paths[0].evidence_id,
            detail="no supporting common-path evidence was computed over the claimed set scopes; "
            "no APTrace derivation establishes equivalence between different set kinds",
        )
    ]


def check_code_presence(claim: CodePresence, evidence: list[tuple[Any, dict[str, Any]]]) -> list[SemanticCheck]:
    """
    Some source in supporting structural-agreement evidence recognizes code
    at the address (and, if stated, places it in the function at the entry).
    Corroboration by independent sources is the verification policy's
    concern, not this consistency check.
    """

    address = to_int(claim.address)
    entry = None if claim.function_entry is None else to_int(claim.function_entry)
    starts: dict[int, str] = {}
    seen = None

    for artifact, result in evidence:
        if artifact.tool != "structural_source_agreement":
            continue

        for item in result.get("agreements", []):
            if _maybe_int(item.get("address")) != address:
                continue

            for observation in item.get("observations", []):
                if observation.get("available") and observation.get("recognizes_code"):
                    seen = seen or artifact.evidence_id

                    if (start := _maybe_int(observation.get("start"))) is not None:
                        starts.setdefault(start, artifact.evidence_id)

    if seen is None:
        return [
            SemanticCheck(
                code=CheckCode.RELATION_UNSUPPORTED,
                passed=False,
                field="address",
                claimed=claim.address,
                detail="no supporting structural source agreement recognizes code at this address",
            )
        ]

    if entry is None:
        return [SemanticCheck(code=CheckCode.CONSISTENT, passed=True, field="address", claimed=claim.address, evidence_id=seen)]

    if entry in starts:
        return [
            SemanticCheck(
                code=CheckCode.CONSISTENT, passed=True, field="function_entry", claimed=claim.function_entry,
                evidence_value=addr(entry), evidence_id=starts[entry],
            )
        ]

    shown = ", ".join(addr(s) for s in sorted(starts)) or "no function"
    return [
        SemanticCheck(
            code=CheckCode.RELATION_MISMATCH,
            passed=False,
            field="function_entry",
            claimed=claim.function_entry,
            evidence_value=shown,
            evidence_id=seen,
            detail=f"supporting evidence places {claim.address} in {shown}",
        )
    ]


def verify_semantics(semantics: ClaimSemantics, claim_type: str, evidence: list[tuple[Any, dict[str, Any]]]) -> list[SemanticCheck]:
    checks: list[SemanticCheck] = []

    if claim_type not in COMPATIBLE_CLAIM_TYPES[semantics.predicate] or (
        semantics.path is not None and PATH_CLAIM_TYPE[semantics.path.status] != claim_type
    ):
        checks.append(
            SemanticCheck(
                code=CheckCode.PREDICATE_TYPE_MISMATCH,
                passed=False,
                detail=f"claim type {claim_type} does not match predicate {semantics.summary()}",
            )
        )

    facts = extract_facts(evidence)

    if semantics.resolved_pointer is not None:
        checks += check_resolved_pointer(semantics.resolved_pointer, facts)
    elif semantics.function_role is not None:
        checks += check_function_role(semantics.function_role, facts)
    elif semantics.path is not None:
        checks += check_path(semantics.path, facts)
    elif semantics.code_presence is not None:
        checks += check_code_presence(semantics.code_presence, evidence)
    elif semantics.call is not None:
        from aptrace_agent.ledger.call_relations import typed_call_checks

        checks += typed_call_checks(semantics.call, evidence)

    return checks
