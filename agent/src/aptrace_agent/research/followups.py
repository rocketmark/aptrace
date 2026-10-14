"""
Investigation continuity: deterministic follow-up candidates for a recorded
investigation run.

Given a run in the research ledger, this module decides which unresolved
questions are worth another bounded investigation, and assembles the
bounded prior context that investigation receives. It reads the ledger and
never writes it; it does not import the work package. Turning a candidate
into a work item is `work/followups.py`; executing it is the ordinary
`research --ledger --work-item` path.

Sources, all read from durable records:

- The open-lead frontier. A run does not record its open leads (only their
  count, in planner_requests). The frontier is re-derived by replaying the
  existing LeadDeriver over the run's durable evidence, in invocation order,
  and only when the run's ExecutionContext equals the current one, so the
  derivation reads the same inputs. The recorded count is a cross-check.
- Evidence gaps in the run's unverified claims (rules below).
- The latest non-diagnostic CHALLENGED/UNRESOLVED audit of each claim.
- Unmet, unevaluable or unresolved conditions in the latest verification.
- STALE lifecycle state.

Every rule reads structured fields; where a rule matches assertion prose
(which claim a peripheral/function gap belongs to) it is disclosed as
pattern-matched in the candidate's priority basis.

Ranking is an ordered category (1 highest), not a confidence score:

  1  an executable evidence gap, CHALLENGED audit, or unmet/unevaluable
     verification condition on an unverified claim proposed by the run
  2  a STALE claim or UNRESOLVED audit; a lead group whose anchor appears in
     firmware-derived evidence supporting one of the run's claims
  3  a lead group linked to a claim only through documentary evidence, or
     not linked to any claim

Ties break on: unresolved relationships addressed (claims + seeded leads),
firmware-derived before documentary, then the candidate key.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from aptrace_agent.ledger.hashing import canonical_json, digest
from aptrace_agent.ledger.models import (
    AuditVerdict,
    ClaimState,
    ClaimVersion,
    EvidenceArtifact,
    ExecutionContext,
    FollowUpProvenance,
    InvestigationRun,
)
from aptrace_agent.ledger.operations import TOOL_INPUTS, input_artifacts
from aptrace_agent.ledger.store import ResearchLedger
from aptrace_agent.research.derivation import LeadDeriver
from aptrace_agent.research.history import ContinuityTracker, HistoricalOperations
from aptrace_agent.research.leads import LeadRegistry
from aptrace_agent.research.projection import ProjectionBudget, clip
from aptrace_agent.research.session import ResearchSession
from aptrace_agent.research.state import Hypothesis, OpenQuestion
from aptrace_agent.schemas import EvidenceObservation


GENERATOR_VERSION = "followups-v1"
DEFAULT_LIMIT = 3
# Seeded leads beyond this stay listed in the candidate but are not seeded;
# the planner sees at most ProjectionBudget-sized state anyway.
MAX_SEED_LEADS = 8
MAX_QUESTIONS = 3
QUESTION_CHARS = 200
OBJECTIVE_CHARS = ProjectionBudget().objective

CLAIM_FOLLOWUP = "claim-followup"
LEAD_GROUP = "lead-group"

PROPOSED = "proposed"
REDUNDANT = "redundant"
BLOCKED = "blocked"

# Analyses APTrace can execute: the typed ledger operations, plus the audit
# tool surface names (ledger/auditor.py) an audit may suggest.
AVAILABLE_TOOLS = frozenset(TOOL_INPUTS) | {
    "inspect_evidence",
    "analyze_peripheral",
    "analyze_usb_interface",
    "find_common_paths",
    "analyze_function_effects",
    "replay_evidence",
}

FOLLOWUP_VERDICTS = (AuditVerdict.CHALLENGED, AuditVerdict.UNRESOLVED)
GATE_FOLLOWUP_STATUSES = ("UNMET", "UNEVALUABLE", "UNRESOLVED")
OPEN_CLAIM_STATES = (ClaimState.PROPOSED, ClaimState.STALE)

DEVICE_IDENTITY_CODE = "STRUCTURAL_USAGE_NOT_DEVICE_IDENTITY"
HARDWARE_BLOCKER = (
    "requires hardware-routing evidence (board netlist, schematic, or a probe of the attached device); "
    "no APTrace operation provides it"
)

_FUNCTION_RE = re.compile(r"\bFUN_[0-9a-f]{8}\b")
_ACCESS_RE = re.compile(r"\b(access\w*|read\w*|writ\w*|configur\w*|program\w*|touch\w*)\b", re.IGNORECASE)
_DEVICE_RE = re.compile(r"\b(connected|attached|wired|routed)\s+to\b|\bcommunicates?\s+with\b|\btalks?\s+to\b", re.IGNORECASE)


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class FrontierLead(_Model):
    kind: str
    description: str
    tool: str
    arguments: dict[str, Any]
    # Durable evidence ids the lead was derived from.
    source_evidence_ids: list[str] = Field(default_factory=list)
    # Subject of the first source evidence: a function, peripheral:X, or query:X.
    anchor: str
    documentary: bool = False

    @property
    def action_key(self) -> str:
        return _action_key(self.tool, self.arguments)

    def line(self) -> str:
        return f"{self.tool}({canonical_json(self.arguments)})"


class Frontier(_Model):
    # re-derived | unavailable
    status: str
    detail: str
    recorded_open_count: int | None = None
    leads: list[FrontierLead] = Field(default_factory=list)
    issues: list[str] = Field(default_factory=list)


class FollowUpCandidate(_Model):
    key: str
    question_key: str
    category: str
    rank: int
    priority_basis: list[str]
    objective: str
    reason: str
    information_gain: str
    source_run_id: str
    claim_versions: list[str] = Field(default_factory=list)
    audit_ids: list[str] = Field(default_factory=list)
    verification_ids: list[str] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)
    seeded_leads: list[FrontierLead] = Field(default_factory=list)
    # Leads consolidated into this candidate (seeded or not).
    lead_count: int = 0
    open_questions: list[str] = Field(default_factory=list)
    prior_hypotheses: list[str] = Field(default_factory=list)
    analyses_performed: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    status: str = PROPOSED
    status_detail: str = ""
    blocker: str | None = None
    firmware_derived: bool = True

    def sort_key(self) -> tuple:
        relationships = len(self.claim_versions) + self.lead_count
        return (self.rank, -relationships, not self.firmware_derived, self.key)

    def provenance(self) -> FollowUpProvenance:
        return FollowUpProvenance(
            followup_key=self.key,
            question_key=self.question_key,
            generator_version=GENERATOR_VERSION,
            category=self.category,
            source_run_id=self.source_run_id,
            claim_versions=list(self.claim_versions),
            audit_ids=list(self.audit_ids),
            verification_ids=list(self.verification_ids),
            prior_evidence_ids=list(self.evidence_ids),
            seeded_leads=[
                {"tool": lead.tool, "arguments": lead.arguments, "description": lead.description, "source_evidence_ids": lead.source_evidence_ids}
                for lead in self.seeded_leads
            ],
            open_questions=list(self.open_questions),
            prior_hypotheses=list(self.prior_hypotheses),
            context_chars=self.context_chars(),
        )

    def context_chars(self) -> int:
        texts = [self.objective, *self.open_questions, *self.prior_hypotheses, *(lead.description for lead in self.seeded_leads)]
        return sum(len(text) for text in texts)


class FollowUpReport(_Model):
    generator_version: str = GENERATOR_VERSION
    run_id: str
    case: str
    firmware_key: str
    run_context_id: str
    current_context_id: str
    limit: int
    frontier: Frontier
    shortlist: list[FollowUpCandidate] = Field(default_factory=list)
    deferred: list[FollowUpCandidate] = Field(default_factory=list)
    suppressed: list[FollowUpCandidate] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)

    def candidates(self) -> list[FollowUpCandidate]:
        return [*self.shortlist, *self.deferred, *self.suppressed]

    def find(self, key: str) -> FollowUpCandidate | None:
        return next((c for c in self.candidates() if c.key == key), None)


DeriverFactory = Callable[[LeadRegistry], LeadDeriver]


# -- helpers ------------------------------------------------------------------


def _action_key(tool: str, arguments: dict[str, Any]) -> str:
    return canonical_json({"tool": tool, "arguments": arguments})


def _anchor(tool: str, arguments: dict[str, Any]) -> str:
    if arguments.get("function"):
        return str(arguments["function"])
    if arguments.get("peripheral"):
        return f"peripheral:{arguments['peripheral']}"
    if arguments.get("query"):
        return f"query:{arguments['query']}"

    return tool


def _short(evidence_id: str) -> str:
    return evidence_id[:7] if evidence_id.startswith("EV-") else evidence_id


def _result(ledger: ResearchLedger, evidence_id: str) -> dict[str, Any] | None:
    try:
        result, _ = ledger.evidence_result(evidence_id)
    except (KeyError, FileNotFoundError, ValueError):
        return None

    return result if isinstance(result, dict) else None


def _evidence(ledger: ResearchLedger, evidence_id: str) -> EvidenceArtifact | None:
    try:
        return ledger.evidence(evidence_id)
    except (KeyError, FileNotFoundError):
        return None


def _functions_in(ledger: ResearchLedger, evidence_id: str) -> set[str]:
    artifact = _evidence(ledger, evidence_id)

    if artifact is None:
        return set()

    text = canonical_json(artifact.arguments) + canonical_json(_result(ledger, evidence_id) or {})
    return set(_FUNCTION_RE.findall(text))


def _recorded_open_count(run: InvestigationRun) -> int | None:
    for request in reversed(run.planner_requests):
        if isinstance(request.get("open_leads"), int):
            return request["open_leads"]

    return None


# -- frontier -----------------------------------------------------------------


def rederive_frontier(
    ledger: ResearchLedger,
    run: InvestigationRun,
    *,
    deriver_for: DeriverFactory | None,
    current_context_id: str,
) -> Frontier:
    """
    Replay the existing LeadDeriver over the run's durable evidence and
    return the leads it derives that the run never executed.

    Refused (status unavailable) when no deriver is supplied or the run's
    input artifacts differ from the current ones: then the replay would not
    read what the run read.
    """

    recorded = _recorded_open_count(run)

    if deriver_for is None:
        return Frontier(status="unavailable", detail="no lead deriver supplied; open leads are not recorded on runs", recorded_open_count=recorded)
    if run.context_id != current_context_id:
        return Frontier(
            status="unavailable",
            detail=f"run context {run.context_id} differs from current {current_context_id}; re-derivation would read different inputs",
            recorded_open_count=recorded,
        )

    registry = LeadRegistry()
    deriver = deriver_for(registry)
    attempted: set[str] = set()
    derived: dict[str, Any] = {}
    to_durable: dict[str, str] = {}
    issues: list[str] = []

    for invocation_id in run.invocation_ids:
        invocation = ledger.invocation(invocation_id)
        attempted.add(_action_key(invocation.tool, invocation.arguments))

        if invocation.status != "ok" or not invocation.evidence_id:
            continue

        result = _result(ledger, invocation.evidence_id)

        if result is None:
            issues.append(f"{invocation.evidence_id}: stored result unavailable")
            continue

        session_id = invocation.session_evidence_id or invocation.evidence_id
        to_durable[session_id] = invocation.evidence_id
        outcome = deriver.derive(EvidenceObservation(id=session_id, tool=invocation.tool, arguments=invocation.arguments, result=result))

        for lead in outcome.leads:
            derived.setdefault(lead.id, lead)

        issues += [f"{issue.kind}: {issue.description}" for issue in outcome.issues]

    leads: list[FrontierLead] = []

    for lead in derived.values():
        action = registry.resolve(lead.id)

        if _action_key(action.tool, action.arguments) in attempted:
            continue

        sources = [to_durable.get(e, e) for e in lead.source_evidence_ids]
        first = _evidence(ledger, sources[0]) if sources else None
        leads.append(
            FrontierLead(
                kind=lead.kind,
                description=lead.description,
                tool=action.tool,
                arguments=dict(action.arguments),
                source_evidence_ids=sources,
                anchor=_anchor(first.tool, first.arguments) if first else action.tool,
                documentary=first is not None and first.tool == "search_case_evidence",
            )
        )

    detail = f"re-derived {len(leads)} open lead(s) from {len(to_durable)} durable observation(s)"

    if recorded is not None:
        detail += f"; run recorded {recorded}" + ("" if recorded == len(leads) else " (MISMATCH: frontier may be incomplete)")

    return Frontier(status="re-derived", detail=detail, recorded_open_count=recorded, leads=leads, issues=issues)


# -- claim gaps ---------------------------------------------------------------


class _Gap(_Model):
    code: str
    rank: int
    detail: str
    question: str
    evidence_ids: list[str] = Field(default_factory=list)
    audit_id: str | None = None
    verification_id: str | None = None
    # Functions the gap is about; seeds lead consolidation.
    functions: list[str] = Field(default_factory=list)
    blocker: str | None = None
    basis: str = ""


def _call_neighbours(ledger: ResearchLedger, evidence_ids: list[str], functions: set[str]) -> set[str]:
    """Direct callers/callees of `functions` from function_facts evidence."""

    neighbours: set[str] = set()

    for evidence_id in evidence_ids:
        artifact = _evidence(ledger, evidence_id)

        if artifact is None or artifact.tool != "function_facts":
            continue

        result = _result(ledger, evidence_id) or {}
        name = result.get("name") or artifact.arguments.get("function")
        edges = {e.get("function") for e in [*result.get("callers", []), *result.get("callees", [])] if e.get("function")}

        if name in functions:
            neighbours |= edges
        elif functions & edges:
            neighbours.add(name)

    return neighbours - functions


def _peripheral_access_gaps(ledger: ResearchLedger, claim: ClaimVersion, run_evidence: list[str]) -> list[_Gap]:
    """
    A claim that a function accesses a peripheral, supported by census usage
    that shows only a literal-pool constant load (no MMIO site) and by no
    function_effects MMIO access, does not establish the access.
    """

    text = f"{claim.subject} {claim.assertion}"

    if not _ACCESS_RE.search(text):
        return []

    functions = sorted(set(_FUNCTION_RE.findall(text)))
    gaps: list[_Gap] = []

    for evidence_id in claim.supporting_evidence_ids:
        artifact = _evidence(ledger, evidence_id)

        if artifact is None or artifact.tool != "census_peripheral_usage":
            continue

        peripheral = str(artifact.arguments.get("peripheral", ""))

        if not peripheral or not re.search(rf"\b{re.escape(peripheral)}\b", text, re.IGNORECASE):
            continue

        census = _result(ledger, evidence_id) or {}
        entries = {f.get("function"): f for f in census.get("functions", [])}

        for function in functions:
            entry = entries.get(function)

            if entry is None or entry.get("mmio_site_count", 0) > 0:
                continue

            loads = entry.get("constant_loads", [])
            effects = [
                e for e in dict.fromkeys([*claim.supporting_evidence_ids, *run_evidence])
                if (a := _evidence(ledger, e)) is not None and a.tool == "function_effects" and a.arguments.get("function") == function
            ]
            mmio = writes = 0
            parametric: set[str] = set()

            for effects_id in effects:
                result = _result(ledger, effects_id) or {}

                for access in result.get("accesses", []):
                    mmio += bool(access.get("region") and str(access["region"]).startswith("MMIO"))
                    writes += access.get("kind") == "write"

                    if access.get("address") == "parametric":
                        parametric |= set(access.get("depends_on", []))

            if mmio:
                continue

            values = ", ".join(sorted({str(load.get("value")) for load in loads})) or "none"
            pools = ", ".join(sorted({str(load.get("pool_address")) for load in loads}))
            detail = (
                f"{claim.key} relates {function} to {peripheral} access, but census {_short(evidence_id)} shows "
                f"{len(loads)} literal-pool constant load(s) of {values}"
                + (f" (pool {pools})" if pools else "")
                + " and mmio_site_count 0"
            )

            if effects:
                detail += (
                    f"; function_effects {', '.join(_short(e) for e in effects)}: 0 MMIO accesses, {writes} write(s)"
                    + (f", address(es) from input(s) {', '.join(sorted(parametric))}" if parametric else "")
                )
            else:
                detail += "; no function_effects evidence for it"

            via = f" via the {'/'.join(sorted(parametric))} address its callers supply" if parametric else ""
            gaps.append(
                _Gap(
                    code="PERIPHERAL_ACCESS_UNESTABLISHED",
                    rank=1,
                    detail=detail,
                    question=f"Does {function} read or write {peripheral} registers{via}, or only use {peripheral}'s address {values} as a value?",
                    evidence_ids=[evidence_id, *effects],
                    functions=[function],
                    basis="pattern-matched: assertion names the function, the peripheral, and an access verb; gap fields are structured census/effects results",
                )
            )

    return gaps


def _device_identity_gaps(claim: ClaimVersion) -> list[_Gap]:
    codes = {limitation.code for limitation in claim.limitations}

    if DEVICE_IDENTITY_CODE not in codes or not _DEVICE_RE.search(claim.assertion):
        return []

    sources = sorted({e for limitation in claim.limitations if limitation.code == DEVICE_IDENTITY_CODE for e in limitation.source_evidence_ids})
    return [
        _Gap(
            code="DEVICE_IDENTITY_REQUIRES_HARDWARE",
            rank=1,
            detail=f"{claim.key} asserts what is attached to a peripheral; its evidence carries {DEVICE_IDENTITY_CODE}",
            question="Which external device is attached?",
            evidence_ids=sources,
            blocker=HARDWARE_BLOCKER,
            basis="pattern-matched: device-identity wording plus a mechanical limitation code",
        )
    ]


def _audit_gaps(ledger: ResearchLedger, claim: ClaimVersion) -> list[_Gap]:
    audit = ledger.latest_audit(claim.key, include_diagnostic=False)

    if audit is None or audit.verdict not in FOLLOWUP_VERDICTS:
        return []

    rank = 1 if audit.verdict == AuditVerdict.CHALLENGED else 2
    evidence = list(dict.fromkeys(audit.evidence_inspected + audit.contradictory_evidence))
    label = f"audit {audit.audit_id} {audit.verdict.value}"
    gaps: list[_Gap] = []

    for request in audit.follow_up_requests:
        tool = request.suggested_tool
        unavailable = tool is not None and tool not in AVAILABLE_TOOLS
        gaps.append(
            _Gap(
                code="AUDIT_REQUEST",
                rank=rank,
                detail=f"{label} requests: {request.question}" + (f" (suggested {tool})" if tool else ""),
                question=request.question,
                evidence_ids=evidence,
                audit_id=audit.audit_id,
                blocker=f"audit suggests {tool!r}, which is not an APTrace operation" if unavailable else None,
                basis="recorded audit follow-up request",
            )
        )

    if not audit.follow_up_requests:
        for challenge in audit.challenges or [audit.reasoning or audit.termination_reason]:
            gaps.append(
                _Gap(
                    code="AUDIT_CHALLENGE",
                    rank=rank,
                    detail=f"{label}: {challenge}",
                    question=f"Obtain evidence that decides: {challenge}",
                    evidence_ids=evidence,
                    audit_id=audit.audit_id,
                    basis="recorded audit challenge (no specific analysis requested)",
                )
            )

    return gaps


def _verification_gaps(ledger: ResearchLedger, claim: ClaimVersion) -> tuple[list[_Gap], list[str]]:
    records = ledger.verifications_for(claim.key)

    if not records or records[-1].outcome == ClaimState.VERIFIED:
        return [], []

    record = records[-1]
    gaps: list[_Gap] = []
    notes: list[str] = []

    for condition in record.gate.conditions if record.gate else []:
        if condition.status == "CONTRADICTED":
            notes.append(f"{claim.key}: gate {condition.code} CONTRADICTED in {record.verification_id}; revising the claim is an operator decision, no follow-up generated")
        elif condition.status in GATE_FOLLOWUP_STATUSES:
            gaps.append(
                _Gap(
                    code=f"GATE_{condition.status}",
                    rank=1,
                    detail=f"verification {record.verification_id} gate {condition.code} {condition.status}: {condition.detail}",
                    question=f"Obtain the {condition.kind} support {condition.code} requires" + (f" for {condition.address}" if condition.address else ""),
                    evidence_ids=list(condition.evidence_ids),
                    verification_id=record.verification_id,
                    basis="recorded verification-policy gate condition",
                )
            )

    for check in record.checks:
        if not check.passed and check.severity == "hold":
            gaps.append(
                _Gap(
                    code=f"CHECK_{check.name.upper()}",
                    rank=1,
                    detail=f"verification {record.verification_id} check {check.name} held: {check.detail}",
                    question=f"Resolve the held check {check.name}: {check.detail}",
                    verification_id=record.verification_id,
                    basis="recorded verification check",
                )
            )

    return gaps, notes


def _stale_gaps(ledger: ResearchLedger, claim: ClaimVersion) -> list[_Gap]:
    if ledger.state(claim.key) != ClaimState.STALE:
        return []

    event = next((e for e in reversed(ledger.events()) if e.subject_kind == "claim" and e.subject == claim.key), None)
    reason = event.reason if event else "stale"
    return [
        _Gap(
            code="STALE_CLAIM",
            rank=2,
            detail=f"{claim.key} is STALE: {reason}",
            question=f"Re-establish or refute {claim.key} under the current inputs",
            evidence_ids=list(claim.supporting_evidence_ids),
            basis="recorded lifecycle event",
        )
    ]


# -- assembly -----------------------------------------------------------------


class FollowUpGenerator:
    def __init__(
        self,
        ledger: ResearchLedger,
        *,
        context: ExecutionContext,
        deriver_for: DeriverFactory | None = None,
        limit: int = DEFAULT_LIMIT,
    ) -> None:
        self.ledger = ledger
        self.context = context
        self.deriver_for = deriver_for
        self.limit = limit
        self._performed: dict[str, tuple[str, str]] | None = None

    # Analyses already recorded under the current inputs: operation_key ->
    # (evidence id, run id). This is the ledger's own operation identity.
    def performed(self) -> dict[str, tuple[str, str]]:
        if self._performed is None:
            self._performed = {
                inv.operation_key: (inv.evidence_id, inv.run_id)
                for inv in sorted(self.ledger.invocations(), key=lambda i: (i.started_at, i.invocation_id))
                if inv.status == "ok" and inv.evidence_id
            }

        return self._performed

    def _operation_key(self, lead: FrontierLead) -> str:
        return ResearchLedger.operation_key(lead.tool, lead.arguments, input_artifacts(self.context, lead.tool), self.context.firmware_sha256)

    def _investigated_by(self, key: str) -> list[str]:
        """Follow-up runs for this key, each with how many of its seeded leads it executed."""

        found = []

        for run in self.ledger.runs():
            if run.followup is None or run.followup.followup_key != key:
                continue

            executed = {_action_key(i.tool, i.arguments) for i in map(self.ledger.invocation, run.invocation_ids)}
            seeded = [_action_key(lead["tool"], lead["arguments"]) for lead in run.followup.seeded_leads]
            found.append(f"{run.run_id} ({sum(k in executed for k in seeded)}/{len(seeded)} seeded leads followed, {run.termination_reason})")

        return found

    def generate(self, run_id: str) -> FollowUpReport:
        run = self.ledger.run(run_id)
        frontier = rederive_frontier(self.ledger, run, deriver_for=self.deriver_for, current_context_id=self.context.context_id())
        limitations: list[str] = []

        if frontier.status != "re-derived":
            limitations.append(f"open-lead frontier unavailable ({frontier.detail}); only claim-based candidates were generated")
        elif frontier.recorded_open_count not in (None, len(frontier.leads)):
            limitations.append(f"re-derived frontier ({len(frontier.leads)}) differs from the recorded open-lead count ({frontier.recorded_open_count})")

        groups = self._group(frontier.leads)
        candidates: list[FollowUpCandidate] = []

        for key in run.claim_versions:
            candidate, notes = self._claim_candidate(run, key, groups)
            limitations += notes
            candidates += candidate

        candidates += [self._lead_candidate(run, anchor, leads) for anchor, leads in groups.items()]
        candidates = [self._finalize(c) for c in candidates]
        active = sorted((c for c in candidates if c.status == PROPOSED), key=FollowUpCandidate.sort_key)
        suppressed = sorted((c for c in candidates if c.status != PROPOSED), key=FollowUpCandidate.sort_key)

        if not active and not suppressed:
            limitations.append("no follow-up source found in the recorded run")

        return FollowUpReport(
            run_id=run.run_id,
            case=run.case,
            firmware_key=run.firmware_key,
            run_context_id=run.context_id,
            current_context_id=self.context.context_id(),
            limit=self.limit,
            frontier=frontier,
            shortlist=active[: self.limit],
            deferred=active[self.limit :],
            suppressed=suppressed,
            limitations=limitations,
        )

    # -- grouping -------------------------------------------------------------

    @staticmethod
    def _group(leads: list[FrontierLead]) -> dict[str, list[FrontierLead]]:
        groups: dict[str, list[FrontierLead]] = {}

        for lead in leads:
            groups.setdefault(lead.anchor, []).append(lead)

        return groups

    # -- claim candidates -----------------------------------------------------

    def _claim_candidate(self, run: InvestigationRun, key: str, groups: dict[str, list[FrontierLead]]) -> tuple[list[FollowUpCandidate], list[str]]:
        try:
            claim = self.ledger.claim(key)
            state = self.ledger.state(key)
        except KeyError:
            return [], [f"{key}: listed on the run but not in the ledger"]

        if state not in OPEN_CLAIM_STATES:
            return [], [f"{key} is {state.value}; no follow-up generated"]

        verification_gaps, notes = _verification_gaps(self.ledger, claim)
        gaps = [
            *_peripheral_access_gaps(self.ledger, claim, run.evidence_ids),
            *_device_identity_gaps(claim),
            *_audit_gaps(self.ledger, claim),
            *verification_gaps,
            *_stale_gaps(self.ledger, claim),
        ]
        executable = [g for g in gaps if g.blocker is None]
        blocked = [g for g in gaps if g.blocker is not None]
        candidates = [self._blocked_candidate(run, claim, state, gap) for gap in blocked]

        if not executable:
            if not gaps:
                notes.append(f"{key} ({state.value}): no recorded audit, verification, or evidence-gap rule applies; nothing to follow up deterministically")

            return candidates, notes

        functions = {f for g in executable for f in g.functions} or set(_FUNCTION_RE.findall(claim.assertion))
        related = functions | _call_neighbours(self.ledger, run.evidence_ids, functions)
        absorbed = [lead for anchor in list(groups) if anchor in related for lead in groups.pop(anchor)]

        # Leads elsewhere that target the gap's own functions.
        for anchor in list(groups):
            absorbed += [lead for lead in groups[anchor] if lead.arguments.get("function") in functions]
            groups[anchor] = [lead for lead in groups[anchor] if lead.arguments.get("function") not in functions]

            if not groups[anchor]:
                del groups[anchor]

        # Leads about the gap's own functions first, then their neighbours.
        absorbed.sort(key=lambda lead: (lead.anchor not in functions and lead.arguments.get("function") not in functions, lead.tool != "callsite_context"))
        about_related = [e for e in run.evidence_ids if (a := _evidence(self.ledger, e)) is not None and a.arguments.get("function") in related]
        evidence = list(dict.fromkeys([e for g in executable for e in g.evidence_ids] + claim.supporting_evidence_ids + about_related))
        rank = min(g.rank for g in executable)
        questions = [g.question for g in executable]
        audit_ids = sorted({g.audit_id for g in executable if g.audit_id})
        verification_ids = sorted({g.verification_id for g in executable if g.verification_id})
        lead_text = ""

        if absorbed:
            anchors = list(dict.fromkeys(lead.anchor for lead in absorbed))
            lead_text = f" Open leads consolidated here: {len(absorbed)} from {', '.join(anchors)}."

        objective = clip(
            f"Follow up {claim.key} ({state.value}, unverified) from run {run.run_id}. "
            + " ".join(questions)
            + lead_text
            + " Confirm or falsify with firmware-derived evidence; do not assume the claim is true.",
            OBJECTIVE_CHARS,
        )
        basis = [f"rank {rank}: {g.code} on {claim.key} ({state.value}) — {g.basis}" for g in executable]
        basis.append(f"consolidates {len(absorbed)} open lead(s) about {', '.join(sorted(functions))} and its direct call neighbours")

        if claim.semantics is None:
            basis.append(f"{claim.key} has no typed semantics: deterministic verification holds it PROPOSED (claim_semantics check not applicable)")

        question_key = digest({"v": 1, "case": run.case, "firmware": run.firmware_sha256, "category": CLAIM_FOLLOWUP, "claim": claim.claim_id})[:16]
        basis_fingerprint = {
            "claim": claim.key,
            "state": state.value,
            "gaps": sorted(g.code + "|" + g.detail for g in executable),
            "evidence": sorted(evidence),
            "audits": audit_ids,
            "verifications": verification_ids,
            "context": self.context.context_id(),
        }
        candidate = FollowUpCandidate(
            key=digest({"q": question_key, "basis": basis_fingerprint})[:24],
            question_key=question_key,
            category=CLAIM_FOLLOWUP,
            rank=rank,
            priority_basis=basis,
            objective=objective,
            reason="; ".join(g.detail for g in executable),
            information_gain=f"decides the unestablished part of {claim.key}: " + " / ".join(questions),
            source_run_id=run.run_id,
            claim_versions=[claim.key],
            audit_ids=audit_ids,
            verification_ids=verification_ids,
            evidence_ids=evidence,
            seeded_leads=absorbed,
            lead_count=len(absorbed),
            open_questions=[clip(g.detail, QUESTION_CHARS) for g in executable][:MAX_QUESTIONS],
            prior_hypotheses=[clip(f"[prior {claim.key} {state.value}, unverified] {claim.assertion}", QUESTION_CHARS)],
            limitations=sorted({l.code or l.text for l in claim.limitations}),
            firmware_derived=True,
        )
        return [candidate, *candidates], notes

    def _blocked_candidate(self, run: InvestigationRun, claim: ClaimVersion, state: ClaimState, gap: _Gap) -> FollowUpCandidate:
        question_key = digest({"v": 1, "case": run.case, "firmware": run.firmware_sha256, "category": CLAIM_FOLLOWUP, "claim": claim.claim_id, "gap": gap.code})[:16]
        return FollowUpCandidate(
            key=digest({"q": question_key, "detail": gap.detail, "context": self.context.context_id()})[:24],
            question_key=question_key,
            category=CLAIM_FOLLOWUP,
            rank=gap.rank,
            priority_basis=[f"{gap.code} on {claim.key} — {gap.basis}"],
            objective=clip(f"{gap.question} ({claim.key})", OBJECTIVE_CHARS),
            reason=gap.detail,
            information_gain="none obtainable with available tools",
            source_run_id=run.run_id,
            claim_versions=[claim.key],
            audit_ids=[gap.audit_id] if gap.audit_id else [],
            evidence_ids=list(gap.evidence_ids),
            status=BLOCKED,
            status_detail=gap.blocker or "",
            blocker=gap.blocker,
        )

    # -- lead-group candidates --------------------------------------------------

    def _claim_links(self, run: InvestigationRun, functions: set[str], sources: set[str]) -> tuple[list[str], bool]:
        """
        Run claims whose supporting evidence mentions these functions or
        produced these leads; is any link through firmware-derived evidence?
        """

        claims: list[str] = []
        firmware = False

        for key in run.claim_versions:
            try:
                claim = self.ledger.claim(key)
            except KeyError:
                continue

            for evidence_id in claim.supporting_evidence_ids:
                if evidence_id in sources or functions & _functions_in(self.ledger, evidence_id):
                    claims.append(key)
                    artifact = _evidence(self.ledger, evidence_id)
                    firmware |= artifact is not None and artifact.tool != "search_case_evidence"

        return list(dict.fromkeys(claims)), firmware

    def _lead_candidate(self, run: InvestigationRun, anchor: str, leads: list[FrontierLead]) -> FollowUpCandidate:
        documentary = all(lead.documentary for lead in leads)
        targets = list(dict.fromkeys(str(lead.arguments.get("function")) for lead in leads if lead.arguments.get("function")))
        anchor_function = anchor if _FUNCTION_RE.fullmatch(anchor) else None
        functions = set(targets) | ({anchor_function} if anchor_function else set())
        sources = list(dict.fromkeys(e for lead in leads for e in lead.source_evidence_ids))
        claims, firmware_link = self._claim_links(run, functions, set(sources))
        rank = 2 if claims and firmware_link and not documentary else 3
        kinds = ", ".join(f"{n} {k}" for k, n in sorted({lead.kind: sum(l.kind == lead.kind for l in leads) for lead in leads}.items()))
        callees = [t for t in targets if t != anchor_function]

        if documentary:
            subject = f"functions {', '.join(targets[:4])} named by case documents ({anchor})"
            question = "Determine from firmware-derived evidence whether these functions belong to the investigated path; the documents are prior human findings."
        elif anchor_function is None:
            subject = f"the remaining leads from {anchor} ({', '.join(targets[:4])})"
            question = f"Determine what {', '.join(targets[:4])} do" + (f", as it bears on {', '.join(claims)}." if claims else ".")
        else:
            subject = f"the unresolved call relationships of {anchor}"
            question = (
                f"Determine what {anchor}'s related functions {', '.join(callees[:4])} do"
                if callees
                else f"Determine how {anchor} is reached and what its call sites pass"
            ) + (f", as it bears on {', '.join(claims)}." if claims else ".")

        basis = [
            f"rank {rank}: "
            + (
                f"anchor appears in firmware-derived evidence supporting {', '.join(claims)}"
                if rank == 2
                else (f"linked to {', '.join(claims)} only through documentary evidence" if claims else "not linked to any claim of the run")
            ),
            f"consolidates {len(leads)} open lead(s) ({kinds}) sharing anchor {anchor}",
        ]
        question_key = digest({"v": 1, "case": run.case, "firmware": run.firmware_sha256, "category": LEAD_GROUP, "anchor": anchor})[:16]
        basis_fingerprint = {"leads": sorted(lead.action_key for lead in leads), "context": self.context.context_id()}

        return FollowUpCandidate(
            key=digest({"q": question_key, "basis": basis_fingerprint})[:24],
            question_key=question_key,
            category=LEAD_GROUP,
            rank=rank,
            priority_basis=basis,
            objective=clip(f"Continue run {run.run_id}: resolve {subject}. {question}", OBJECTIVE_CHARS),
            reason=f"{len(leads)} open lead(s) left by run {run.run_id} share anchor {anchor}",
            information_gain=f"resolves {len(leads)} open relationship(s)" + (f" bearing on {', '.join(claims)}" if claims else ""),
            source_run_id=run.run_id,
            claim_versions=claims,
            evidence_ids=sources,
            seeded_leads=leads,
            lead_count=len(leads),
            open_questions=[clip(question, QUESTION_CHARS)],
            firmware_derived=not documentary,
        )

    # -- redundancy and context bounds ---------------------------------------------

    def _finalize(self, candidate: FollowUpCandidate) -> FollowUpCandidate:
        if candidate.status != PROPOSED:
            return candidate

        performed = self.performed()
        remaining: list[FrontierLead] = []
        done: list[str] = []

        for lead in candidate.seeded_leads:
            hit = performed.get(self._operation_key(lead))

            if hit:
                done.append(f"{lead.line()} -> {hit[0]} (run {hit[1]})")
            else:
                remaining.append(lead)

        analyses = sorted(
            f"{a.tool}({canonical_json(a.arguments)}) -> {a.evidence_id}"
            for e in candidate.evidence_ids
            if (a := _evidence(self.ledger, e)) is not None
        )
        update: dict[str, Any] = {
            "seeded_leads": remaining[:MAX_SEED_LEADS],
            "analyses_performed": analyses + done,
        }

        if done:
            update["open_questions"] = [
                *candidate.open_questions,
                clip(f"Already recorded under current inputs (repeat only with a new reason): {'; '.join(d.split(' -> ')[0] for d in done)}", QUESTION_CHARS),
            ][:MAX_QUESTIONS]
        if len(remaining) > MAX_SEED_LEADS:
            update["limitations"] = [*candidate.limitations, f"{len(remaining) - MAX_SEED_LEADS} further open lead(s) not seeded (bound {MAX_SEED_LEADS})"]

        if investigated := self._investigated_by(candidate.key):
            update |= {
                "status": REDUNDANT,
                "status_detail": (
                    f"already investigated under the same evidence basis by run(s) {', '.join(investigated)}; "
                    "an unanswered question returns when its evidence basis changes, or by an operator --rerun of the item"
                ),
            }
        elif candidate.category == LEAD_GROUP and candidate.seeded_leads and not remaining:
            update |= {"status": REDUNDANT, "status_detail": f"all {len(done)} analyses already recorded under the current inputs"}

        return candidate.model_copy(update=update)


def generate_followups(
    ledger: ResearchLedger,
    run_id: str,
    *,
    context: ExecutionContext,
    deriver_for: DeriverFactory | None = None,
    limit: int = DEFAULT_LIMIT,
) -> FollowUpReport:
    return FollowUpGenerator(ledger, context=context, deriver_for=deriver_for, limit=limit).generate(run_id)


# -- continuity review ------------------------------------------------------------------


def continuity_review(ledger: ResearchLedger, run_id: str) -> dict[str, Any]:
    """
    What a follow-up run produced relative to the run it followed up. Read
    only. The originating question is never marked resolved here: running a
    follow-up changes no claim; resolution is a ledger verification outcome.
    """

    run = ledger.run(run_id)

    if run.followup is None:
        return {"run_id": run_id, "followup": None}

    provenance = run.followup
    source = ledger.run(provenance.source_run_id)
    executed = {_action_key(ledger.invocation(i).tool, ledger.invocation(i).arguments): ledger.invocation(i) for i in run.invocation_ids}
    seeded = [(lead, executed.get(_action_key(lead["tool"], lead["arguments"]))) for lead in provenance.seeded_leads]

    return {
        "run_id": run.run_id,
        "source_run_id": source.run_id,
        "followup_key": provenance.followup_key,
        "termination_reason": run.termination_reason,
        "new_evidence_ids": [e for e in run.evidence_ids if e not in source.evidence_ids],
        "reused_evidence_ids": [e for e in run.evidence_ids if e in source.evidence_ids],
        "proposed_claims": {key: ledger.state(key).value for key in run.claim_versions},
        "originating_claims": {key: ledger.state(key).value for key in provenance.claim_versions},
        "seeded_leads_followed": [
            {"lead": f"{lead['tool']}({canonical_json(lead['arguments'])})", "evidence_id": inv.evidence_id, "input_evidence_ids": inv.input_evidence_ids}
            for lead, inv in seeded
            if inv is not None
        ],
        "seeded_leads_unfollowed": [f"{lead['tool']}({canonical_json(lead['arguments'])})" for lead, inv in seeded if inv is None],
        "question_status": (
            "OPEN: the follow-up ran; whether it answered the question is decided by verifying or auditing the claims, "
            "not by the run finishing"
        ),
    }


# -- follow-up session context --------------------------------------------------------


def seed_session(session: ResearchSession, candidate: FollowUpCandidate, *, history: HistoricalOperations | None = None) -> None:
    """
    Give a new session the candidate's bounded prior context: its seeded
    leads (executed only if followed), its open questions, and the prior
    claim as an unverified hypothesis. Prior evidence is never replayed
    into the session as new observations.

    With `history` (research/history.py) the session also tracks its
    seeded leads, uses compatible historical operations by reference, and
    preloads the candidate's cited prior results that are reusable (facts
    only, no step). Without it, seeding is the spike behaviour.
    """

    source = f"followup:{candidate.key}"
    seeded: list[tuple[str, FrontierLead]] = []

    for lead in candidate.seeded_leads:
        registered = session.registry.register(
            kind=lead.kind,
            description=lead.description,
            tool=lead.tool,
            arguments=dict(lead.arguments),
            source_evidence_ids=list(lead.source_evidence_ids),
        )

        if all(existing.id != registered.id for existing in session.state.leads):
            session.state.add_lead(registered)

        seeded.append((registered.id, lead))

    for number, question in enumerate(candidate.open_questions, start=1):
        session.state.open_questions.append(OpenQuestion(id=f"PQ{number}", question=question, source=source))

    for number, statement in enumerate(candidate.prior_hypotheses, start=1):
        session.state.hypotheses.append(Hypothesis(id=f"PH{number}", statement=statement, source=source))

    if history is None:
        return

    tracker = ContinuityTracker(history=history, origin=source)
    session.continuity = tracker

    for lead_id, lead in seeded:
        session.state.lead(lead_id).origin = source
        tracker.seeded[lead_id] = (lead.tool, dict(lead.arguments), lead.description)
        tracker.anchors[lead_id] = lead.anchor

    for evidence_id in candidate.evidence_ids:
        artifact = _evidence(history.ledger, evidence_id)

        if artifact is not None:
            session.preload(artifact.tool, dict(artifact.arguments))


__all__ = [
    "AVAILABLE_TOOLS",
    "BLOCKED",
    "CLAIM_FOLLOWUP",
    "DEFAULT_LIMIT",
    "FollowUpCandidate",
    "FollowUpGenerator",
    "FollowUpReport",
    "Frontier",
    "FrontierLead",
    "GENERATOR_VERSION",
    "LEAD_GROUP",
    "PROPOSED",
    "REDUNDANT",
    "generate_followups",
    "continuity_review",
    "rederive_frontier",
    "seed_session",
]
