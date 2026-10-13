"""
Durable research-ledger records.

Every record here is immutable once written. Current claim status is not a
stored field: it is folded from the append-only lifecycle event log, so the
history of how a claim reached its state is never rewritten.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, SerializerFunctionWrapHandler, model_serializer

from aptrace_agent.ledger.claim_semantics import ClaimSemantics, SemanticCheck


LEDGER_SCHEMA_VERSION = 1


class EvidenceGrade(StrEnum):
    """
    Strength of a derivation, strongest first.

    EXACT and STRONG are the census confidence vocabulary
    (indirect_edge_candidates.confidence). PROBABLE covers documentary or
    pattern-matched support; BOUNDED is a bounded negative result (for
    example NO_KNOWN_PATH) that supports only claims of the same bounded
    scope; UNKNOWN supports nothing.
    """

    EXACT = "EXACT"
    STRONG = "STRONG"
    PROBABLE = "PROBABLE"
    BOUNDED = "BOUNDED"
    UNKNOWN = "UNKNOWN"


GRADE_RANK = {
    EvidenceGrade.EXACT: 4,
    EvidenceGrade.STRONG: 3,
    EvidenceGrade.PROBABLE: 2,
    EvidenceGrade.BOUNDED: 1,
    EvidenceGrade.UNKNOWN: 0,
}


class ClaimType(StrEnum):
    # What an indirect transfer, pointer or identifier resolves to.
    RESOLUTION = "RESOLUTION"
    # Two code regions or subsystems are connected by a known path.
    PATH_EXISTS = "PATH_EXISTS"
    # No path is known within a stated analysis bound (never unreachability).
    NO_KNOWN_PATH = "NO_KNOWN_PATH"
    # An absolute absence claim; no current APTrace analysis establishes one.
    UNREACHABLE = "UNREACHABLE"
    # A function or subsystem performs some behavior or effect.
    BEHAVIOR = "BEHAVIOR"
    # Structural membership or usage (e.g. which functions touch a peripheral).
    STRUCTURE = "STRUCTURE"
    OTHER = "OTHER"


class ClaimState(StrEnum):
    """APTrace-owned lifecycle state; independent of evidence grade."""

    PROPOSED = "PROPOSED"
    VERIFIED = "VERIFIED"
    BLOCKED = "BLOCKED"
    STALE = "STALE"
    SUPERSEDED = "SUPERSEDED"


class AuditVerdict(StrEnum):
    """An auditor's opinion. Never a lifecycle state."""

    SUPPORTED = "SUPPORTED"
    CHALLENGED = "CHALLENGED"
    UNRESOLVED = "UNRESOLVED"


# Actors allowed to append lifecycle events. Models are deliberately absent.
APTRACE_ACTORS = frozenset({"aptrace-ledger", "aptrace-verifier", "aptrace-staleness"})


class _Record(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ExecutionContext(_Record):
    """
    Identity of the inputs under which deterministic evidence is produced.

    artifacts maps an input name (census_db, ghidra_export, firmware_image,
    svd, ghidra_seeds) to its sha256. Generated artifacts such as Ghidra
    seeds are referenced by content hash only; they stay derived artifacts.
    """

    case: str
    firmware_key: str
    firmware_sha256: str
    artifacts: dict[str, str] = Field(default_factory=dict)

    def context_id(self) -> str:
        from aptrace_agent.ledger.hashing import digest

        return "X-" + digest(self.model_dump(mode="json"))[:16]


class SourceRevision(_Record):
    git_commit: str | None = None
    git_branch: str | None = None
    dirty: bool | None = None
    # sha256 over `git diff HEAD` plus untracked file names, when dirty.
    dirty_fingerprint: str | None = None


class InvestigationRun(_Record):
    schema_version: int = LEDGER_SCHEMA_VERSION
    run_id: str
    kind: str = "investigation"  # investigation | audit | benchmark-setup | replay
    case: str
    firmware_key: str
    firmware_sha256: str
    context_id: str
    objective: str
    model: str | None = None
    # Model execution configuration (temperature, token limits, endpoint kind).
    execution_config: dict[str, Any] = Field(default_factory=dict)
    planner_version: str | None = None
    budgets: dict[str, Any] = Field(default_factory=dict)
    started_at: str
    ended_at: str
    termination_reason: str
    parent_run_id: str | None = None
    source: SourceRevision = Field(default_factory=SourceRevision)
    invocation_ids: list[str] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)
    claim_versions: list[str] = Field(default_factory=list)
    # Bounded planner request size history, as recorded by the controller.
    planner_requests: list[dict[str, Any]] = Field(default_factory=list)
    trajectory: list[dict[str, Any]] = Field(default_factory=list)
    # Opaque id of the external work item this run was executed for, fixed
    # when the run is recorded. The ledger does not interpret it; several
    # runs may carry the same id. Absent on standalone runs and older
    # records, and omitted from the serialized record when unset so those
    # records are unchanged.
    work_item_id: str | None = None

    @model_serializer(mode="wrap")
    def _omit_unset_work_item(self, handler: SerializerFunctionWrapHandler) -> dict[str, Any]:
        data = handler(self)

        if data.get("work_item_id") is None:
            data.pop("work_item_id", None)

        return data


class ToolInvocation(_Record):
    """
    One typed APTrace operation execution.

    The replay contract is (tool, arguments) against the recorded context:
    never a shell command line.
    """

    invocation_id: str
    run_id: str
    tool: str
    arguments: dict[str, Any]
    # sha256 of tool + canonical arguments + input-artifact hashes; equal
    # for every execution of the same operation on the same inputs.
    operation_key: str
    context_id: str
    input_artifacts: dict[str, str] = Field(default_factory=dict)
    input_evidence_ids: list[str] = Field(default_factory=list)
    status: str  # ok | error
    evidence_id: str | None = None
    result_sha256: str | None = None
    started_at: str
    ended_at: str
    runtime_ms: float
    error: str | None = None
    replayable: bool = True
    replay_of: str | None = None
    # Session-local evidence id (E3) the producing run used, if any.
    session_evidence_id: str | None = None


class Limitation(_Record):
    text: str
    # Mechanical code when the limitation is inherited from evidence.
    code: str | None = None
    source_evidence_ids: list[str] = Field(default_factory=list)


class EvidenceArtifact(_Record):
    """
    A durable deterministic observation. The structured result is stored
    content-addressed under blobs/; result_sha256 is its identity.
    """

    evidence_id: str
    invocation_id: str
    tool: str
    arguments: dict[str, Any]
    result_sha256: str
    result_bytes: int
    context_id: str
    case: str
    firmware_key: str
    firmware_sha256: str
    grade: EvidenceGrade
    grade_basis: str
    # Limitations the result carries mechanically (see semantics.py).
    limitations: list[Limitation] = Field(default_factory=list)
    path_status: str | None = None
    summary: str = ""


class ClaimVersion(_Record):
    schema_version: int = LEDGER_SCHEMA_VERSION
    claim_id: str
    version: int
    subject: str
    assertion: str
    claim_type: ClaimType
    proposed_grade: EvidenceGrade
    scope: str = ""
    assumptions: list[str] = Field(default_factory=list)
    limitations: list[Limitation] = Field(default_factory=list)
    supporting_evidence_ids: list[str] = Field(default_factory=list)
    contradictory_evidence_ids: list[str] = Field(default_factory=list)
    depends_on: list[str] = Field(default_factory=list)  # claim version keys
    derivation: str = ""
    proposed_by: str  # e.g. "qwen-investigator", "benchmark-fixture"
    run_id: str | None = None
    supersedes: str | None = None
    created_at: str
    # Structured predicate. When present it is authoritative for
    # deterministic verification; the assertion prose is presentation.
    semantics: ClaimSemantics | None = None

    @property
    def key(self) -> str:
        return version_key(self.claim_id, self.version)


def version_key(claim_id: str, version: int) -> str:
    return f"{claim_id}:v{version}"


def parse_version_key(key: str) -> tuple[str, int | None]:
    claim_id, _, version = key.partition(":v")
    return claim_id, (int(version) if version else None)


class LifecycleEvent(_Record):
    seq: int
    at: str
    subject_kind: str  # claim | evidence
    subject: str  # claim version key or evidence id
    state: str  # ClaimState for claims; VALID | INVALIDATED for evidence
    actor: str
    reason: str
    refs: list[str] = Field(default_factory=list)


class AuditStep(_Record):
    number: int
    attempt: int
    request_chars: int
    request_messages: int
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    raw_response: str | None = None
    action: str | None = None  # request | verdict | invalid | error
    tool: str | None = None
    arguments: dict[str, Any] = Field(default_factory=dict)
    rejection: str | None = None
    invocation_id: str | None = None
    evidence_id: str | None = None
    result_summary: str | None = None
    error: str | None = None
    # audit-v0.4+: requested-analysis outcome, one of
    # rejected:{duplicate,invalid_arguments,unavailable_tool,budget},
    # executed:{success,coverage_gap,tool_error}, parse_failure,
    # verdict_rejected. Absent on older records.
    outcome: str | None = None
    # True only for a successful new evidence operation (a structured result
    # or a legitimate coverage-gap result).
    counts_as_falsification: bool | None = None


class FollowUpRequest(_Record):
    question: str
    suggested_tool: str | None = None


class AuditRecord(_Record):
    schema_version: int = LEDGER_SCHEMA_VERSION
    audit_id: str
    claim_version: str
    model: str
    template_version: str
    started_at: str
    ended_at: str
    termination_reason: str
    budgets: dict[str, Any] = Field(default_factory=dict)
    allowed_tools: list[str] = Field(default_factory=list)
    initial_context: str
    steps: list[AuditStep] = Field(default_factory=list)
    verdict: AuditVerdict
    reasoning: str = ""
    scope_check: str = ""
    challenges: list[str] = Field(default_factory=list)
    evidence_inspected: list[str] = Field(default_factory=list)
    contradictory_evidence: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    follow_up_requests: list[FollowUpRequest] = Field(default_factory=list)
    # True when the verdict was synthesized by APTrace because the model
    # never produced a valid one (always UNRESOLVED).
    verdict_synthesized: bool = False
    # audit-v0.4+ fields; absent (defaulted) on older records.
    # Deterministic fingerprint of the exact audit input (claim version,
    # evidence, compact projection, source agreement, template, model,
    # generation parameters, tool surface, budget). No timestamps.
    input_fingerprint: str | None = None
    input_components: dict[str, str] = Field(default_factory=dict)
    # Structural source-agreement evidence APTrace recorded for this audit.
    source_agreement_evidence: str | None = None
    # requested / rejected / executed / successful / coverage_gap counts and
    # whether the falsification requirement was satisfied.
    falsification: dict[str, Any] = Field(default_factory=dict)
    # The model's own verdict when APTrace recorded a different one (e.g. a
    # verdict given without any successful falsification analysis).
    model_verdict: AuditVerdict | None = None
    # Observed serving runtime (served model names, system fingerprints).
    runtime: dict[str, Any] = Field(default_factory=dict)
    # Repeated-audit measurement batch, if this audit belongs to one.
    batch_id: str | None = None
    # A diagnostic audit (e.g. of a claim that failed deterministic
    # verification) is recorded but never used by verification.
    diagnostic: bool = False


class VerificationCheck(_Record):
    name: str
    passed: bool
    # block: fail blocks the claim; stale: fail marks it stale;
    # hold: fail leaves it PROPOSED.
    severity: str
    detail: str = ""
    # Verification phase: A structural, B deterministic semantics,
    # C replay/freshness, P verification policy, D adversarial audit.
    # Absent on older records.
    phase: str | None = None


class PolicyRef(_Record):
    """Identity of the verification policy a verification applied."""

    policy_id: str
    version: str
    # sha256 over the canonical policy definition (see policy.py).
    digest: str


class GateCondition(_Record):
    """
    One condition the deterministic verification-policy gate evaluated.

    status:
      CONTRADICTED  a typed assertion is affirmatively contradicted (blocks)
      UNRESOLVED    a material or potentially material contradiction or
                    discrepancy that cannot be classified or is unresolved
      UNMET         a required kind of support is absent from the evidence
      UNEVALUABLE   the requirement cannot be evaluated: no evidence
                    contract, missing metadata, or incompatible evidence
      NOT_MATERIAL  evaluated and outside the claim's typed assertions
      SATISFIED     evaluated and met
    """

    code: str
    # contradiction | structural | corroboration | class
    kind: str
    status: str
    evidence_ids: list[str] = Field(default_factory=list)
    field: str | None = None
    address: str | None = None
    detail: str = ""


class PolicyGate(_Record):
    """Deterministic verification-policy gate result (phase P)."""

    policy: PolicyRef
    claim_class: str
    class_basis: str = ""
    # PASSED | BLOCKED (contradicted) | HELD (unmet/unresolved) | UNEVALUABLE
    status: str
    conditions: list[GateCondition] = Field(default_factory=list)
    # Structural source-agreement evidence the gate evaluated.
    agreement_evidence_ids: list[str] = Field(default_factory=list)


class VerificationRecord(_Record):
    schema_version: int = LEDGER_SCHEMA_VERSION
    verification_id: str
    claim_version: str
    at: str
    context_id: str
    audit_id: str | None = None
    audit_verdict: AuditVerdict | None = None
    checks: list[VerificationCheck] = Field(default_factory=list)
    replay_invocation_ids: list[str] = Field(default_factory=list)
    outcome: ClaimState
    # precheck (phases A-C and P, before any audit) or full (A-D).
    mode: str = "full"
    # Phase -> passed | failed | skipped. Absent on older records.
    phases: dict[str, str] = Field(default_factory=dict)
    semantic_checks: list[SemanticCheck] = Field(default_factory=list)
    # True when phase D did not consult any audit because A-C or P failed.
    audit_skipped: bool = False
    # Verification policy applied. None on records written before any
    # policy existed, which makes those decisions mechanically identifiable.
    policy: PolicyRef | None = None
    # Phase P result; None when an earlier phase failed or on older records.
    gate: PolicyGate | None = None
    note: str = (
        "Verified means: consistent with the currently recorded evidence and "
        "APTrace's deterministic checks. It is not a proof of semantic truth."
    )
