"""
Hand-off between long-horizon work items and the research ledger.

Direction of authority:

- The work store owns whether a unit of work is open, claimed, or done.
- The research ledger owns runs, evidence, claims, audits, and claim
  lifecycle state.

This module reads the ledger and writes only work items. It never appends
lifecycle events, proposes claims, or records audits, so closing work can
never promote, block, or stale a claim. Ledger records are referenced by id
in flat `aptrace_*` metadata keys; nothing from the ledger is copied in.

Correlation is exact in both directions: a work item lists the run ids it
produced (`aptrace_run_ids`), and every run executed for a work item carries
that item's id (`InvestigationRun.work_item_id`) from the moment it is
recorded. Reconciliation follows only those references. Runs that merely
look related (same objective and firmware) are reported for operator
review, never linked.

Ownership while executing: a Beads claim (assignment) plus the host-local
item lock (liveness) plus an attempt marker on the item (identity). A Beads
lease expiry is never treated as evidence that an attempt stopped; APTrace
does not heartbeat, reclaim, or extend leases.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from aptrace_agent.ledger.hashing import digest
from aptrace_agent.ledger.models import AuditVerdict, ExecutionContext, InvestigationRun
from aptrace_agent.ledger.store import LedgerError, ResearchLedger, new_id, now
from aptrace_agent.work.ownership import ItemLock, hostname
from aptrace_agent.work.store import CLOSED, IN_PROGRESS, DuplicateWork, WorkItem, WorkStore, WorkStoreError


KIND = "aptrace_kind"
OBJECTIVE = "aptrace_objective"
CASE = "aptrace_case"
FIRMWARE_KEY = "aptrace_firmware_key"
FIRMWARE_SHA256 = "aptrace_firmware_sha256"
CONTEXT_ID = "aptrace_context_id"
RUN_IDS = "aptrace_run_ids"
RUN_LINKS = "aptrace_run_link_basis"
ATTEMPT_ID = "aptrace_attempt_id"
ATTEMPT_STATE = "aptrace_attempt_state"
ATTEMPT_STARTED = "aptrace_attempt_started_at"
ATTEMPT_ACTOR = "aptrace_attempt_actor"
ATTEMPT_HOST = "aptrace_attempt_host"
ATTEMPT_PID = "aptrace_attempt_pid"
ATTEMPT_DETAIL = "aptrace_attempt_detail"
FOLLOWUP_KEY = "aptrace_followup_key"

REQUIRED = (OBJECTIVE, CASE, FIRMWARE_KEY, FIRMWARE_SHA256)
ATTEMPT_KEYS = (ATTEMPT_ID, ATTEMPT_STATE, ATTEMPT_STARTED, ATTEMPT_ACTOR, ATTEMPT_HOST, ATTEMPT_PID, ATTEMPT_DETAIL)

# Attempt states recorded on the work item.
RUNNING = "running"
RECORDED = "recorded"
FAILED = "failed"

# How a run id came to be on a work item. Both are exact.
LINK_DIRECT = "direct"
LINK_RECONCILED = "reconciled:work_item_id"

# Reconciliation states.
READY = "ready"
ACTIVE = "active"
LINK_RUNS = "link-runs"
AWAITING_COMPLETION = "awaiting-completion"
INTERRUPTED = "interrupted"
CLAIMED_BY_OTHER = "claimed-by-other"
OPERATOR_REVIEW = "operator-review"
CONFLICT = "conflict"
COMPLETED = "completed"

NEXT_STEP = {
    READY: "aptrace-agent research --ledger --work-item {id}",
    ACTIVE: "wait for the running attempt to finish; do not restart it",
    LINK_RUNS: "aptrace-agent work reconcile {id} --apply",
    AWAITING_COMPLETION: (
        "review the linked run(s); then `aptrace-agent work complete {id}`, or run another attempt with "
        "`aptrace-agent research --ledger --work-item {id} --rerun`"
    ),
    INTERRUPTED: (
        "the attempt is not running on this host and recorded no run; restart it with "
        "`aptrace-agent research --ledger --work-item {id} --restart` (may propose duplicate claims)"
    ),
    CLAIMED_BY_OTHER: "coordinate with the assignee; release only after confirming it is not running (`bd unclaim {id} --if-assignee <assignee>`)",
    OPERATOR_REVIEW: "inspect heuristic_candidates; APTrace does not link runs without an explicit work-item reference",
    CONFLICT: "inspect problems; APTrace does not repair conflicting identities",
    COMPLETED: "none",
}

FOLLOWUP_VERDICTS = (AuditVerdict.CHALLENGED, AuditVerdict.UNRESOLVED)


def _at(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


class HandoffError(RuntimeError):
    pass


class InvalidWorkItem(HandoffError):
    """The work item is not a valid APTrace investigation for this case and firmware."""


class WorkRefused(HandoffError):
    """The durable state does not allow the requested action."""

    def __init__(self, reconciliation: Reconciliation, action: str, detail: str | None = None) -> None:
        self.reconciliation = reconciliation
        super().__init__(f"{action} {reconciliation.item.id} refused [{reconciliation.state}]: {detail or reconciliation.detail}")


class WriteBackFailed(HandoffError):
    """The run is recorded in the ledger, but its id could not be written to the work item."""

    def __init__(self, item_id: str, run_id: str, cause: Exception) -> None:
        self.item_id, self.run_id = item_id, run_id
        super().__init__(
            f"run {run_id} is recorded in the ledger, but linking it to {item_id} failed ({cause}); "
            f"the ledger is intact. Repair with `aptrace-agent work reconcile {item_id} --apply`"
        )


# -- investigations ------------------------------------------------------------


def create_investigation(
    store: WorkStore,
    *,
    context: ExecutionContext,
    objective: str,
    title: str | None = None,
    priority: int = 2,
    depends_on: tuple[str, ...] = (),
) -> WorkItem:
    return store.create_work(
        title or f"Investigate: {objective[:80]}",
        description=objective,
        priority=priority,
        depends_on=depends_on,
        metadata={
            KIND: "investigation",
            OBJECTIVE: objective,
            CASE: context.case,
            FIRMWARE_KEY: context.firmware_key,
            FIRMWARE_SHA256: context.firmware_sha256,
            CONTEXT_ID: context.context_id(),
        },
    )


def validate_item(item: WorkItem, context: ExecutionContext, *, objective: str | None = None) -> list[str]:
    """
    Check that the item is an APTrace investigation of this case and
    firmware. Raises InvalidWorkItem; returns non-blocking notes.
    """

    meta = item.metadata

    if meta.get(KIND) != "investigation":
        raise InvalidWorkItem(f"{item.id} is not an APTrace investigation work item ({KIND}={meta.get(KIND)!r})")

    missing = [key for key in REQUIRED if not isinstance(meta.get(key), str) or not meta[key].strip()]

    if missing:
        raise InvalidWorkItem(f"{item.id} lacks required metadata: {', '.join(missing)}")

    expected = {CASE: context.case, FIRMWARE_KEY: context.firmware_key, FIRMWARE_SHA256: context.firmware_sha256}
    wrong = [f"{key}={meta[key]!r} (current {value!r})" for key, value in expected.items() if meta[key] != value]

    if wrong:
        raise InvalidWorkItem(f"{item.id} belongs to a different case or firmware: {'; '.join(wrong)}")

    if objective is not None and objective.strip() != meta[OBJECTIVE].strip():
        raise InvalidWorkItem(f"objective given on the command line differs from {item.id}'s objective {meta[OBJECTIVE]!r}")

    notes = []

    if meta.get(CONTEXT_ID) and meta[CONTEXT_ID] != context.context_id():
        notes.append(
            f"input artifacts changed since {item.id} was created (context {meta[CONTEXT_ID]} -> {context.context_id()}); "
            "same case and firmware, so the run proceeds under the current context"
        )

    return notes


def link_run(store: WorkStore, item_id: str, run_id: str, *, basis: str = LINK_DIRECT) -> WorkItem:
    """Persist a ledger run id on the work item. Idempotent; does not consult the ledger."""

    return _link(store, store.get_work(item_id), [run_id], basis)


def _attempt_state(meta: dict[str, Any]) -> str | None:
    # Items from before attempt states existed carry only a start marker.
    return meta.get(ATTEMPT_STATE) or (RUNNING if meta.get(ATTEMPT_STARTED) else None)


def _link(
    store: WorkStore,
    item: WorkItem,
    run_ids: list[str],
    basis: str,
    *,
    attempt_id: str | None = None,
    current_attempt: bool = False,
) -> WorkItem:
    """
    One metadata write: add run ids and mark the attempt that produced them
    recorded (the named attempt, or with current_attempt the item's
    unfinished attempt, whatever its id).
    """

    meta = item.metadata
    runs = list(meta.get(RUN_IDS) or [])
    new = [run_id for run_id in run_ids if run_id not in runs]
    update: dict[str, Any] = {}

    if new:
        update[RUN_IDS] = runs + new
        update[RUN_LINKS] = {**(meta.get(RUN_LINKS) or {}), **{run_id: basis for run_id in new}}

    named = attempt_id is not None and meta.get(ATTEMPT_ID) == attempt_id
    unfinished = current_attempt and _attempt_state(meta) in (RUNNING, FAILED)

    if (named or unfinished) and meta.get(ATTEMPT_STATE) != RECORDED:
        update[ATTEMPT_STATE] = RECORDED
        update[ATTEMPT_DETAIL] = f"recorded run(s) {', '.join(run_ids)}"

    return store.update_metadata(item.id, update) if update else item


@dataclass
class Outcome:
    item_id: str
    attempt_id: str
    run_id: str
    # False when the item's claim or attempt marker changed hands during the run.
    owned: bool
    reconciliation: Reconciliation
    notes: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "item_id": self.item_id,
            "attempt_id": self.attempt_id,
            "run_id": self.run_id,
            "owned": self.owned,
            "notes": self.notes,
            "reconciliation": self.reconciliation.as_dict(),
        }


def run_investigation(
    store: WorkStore,
    ledger: ResearchLedger,
    item_id: str,
    *,
    actor: str,
    context: ExecutionContext,
    investigate: Callable[[str, str], str],
    lock_dir: Path,
    objective: str | None = None,
    restart: bool = False,
    rerun: bool = False,
) -> Outcome:
    """
    Execute one attempt of an investigation work item through an existing
    APTrace entry point.

    `investigate(objective, work_item_id)` must run the investigation and
    record it in the ledger with that work_item_id, returning the run id.

    Holds the item lock throughout, reconciles before starting, claims the
    item, writes an attempt marker, runs, and links the run. It never closes
    the item: completing investigation work is an explicit operator step
    (`complete_investigation`), because no controller stop reason says the
    objective was answered.
    """

    with ItemLock(lock_dir, item_id) as lock:
        item = store.get_work(item_id)
        notes = validate_item(item, context, objective=objective)
        before = reconcile(store, ledger, item_id, actor=actor, lock=lock, item=item)

        if before.state == INTERRUPTED and not restart:
            raise WorkRefused(before, "start", f"{before.detail}. Pass --restart to start a new attempt")
        if before.state == AWAITING_COMPLETION and not rerun:
            raise WorkRefused(before, "start", f"{before.detail}. Pass --rerun to run another attempt, or complete the item")
        if before.state not in (READY, INTERRUPTED, AWAITING_COMPLETION):
            raise WorkRefused(before, "start")

        blocked = [other for other in item.blockers if store.get_work(other).status != CLOSED]

        if blocked:
            raise WorkRefused(before, "start", f"blocked by unfinished work {', '.join(blocked)}")

        if before.state in (INTERRUPTED, AWAITING_COMPLETION):
            prior = sum(len(ledger.run(r).claim_versions) for r in before.linked_runs)
            notes.append(
                f"new attempt after {before.state}: earlier runs {before.linked_runs or '[]'} proposed {prior} claim version(s); "
                "this attempt may propose equivalent claims under new ids. Nothing is merged or discarded."
            )

        if before.partial_claims:
            notes.append(f"earlier attempt left claim versions whose run was never recorded: {', '.join(before.partial_claims)}")

        store.claim_work(item_id, actor)
        attempt_id = new_id("WA")
        store.update_metadata(
            item_id,
            {
                ATTEMPT_ID: attempt_id,
                ATTEMPT_STATE: RUNNING,
                ATTEMPT_STARTED: now(),
                ATTEMPT_ACTOR: actor,
                ATTEMPT_HOST: hostname(),
                ATTEMPT_PID: os.getpid(),
                ATTEMPT_DETAIL: "",
            },
        )

        try:
            run_id = investigate(item.metadata[OBJECTIVE], item_id)
        except BaseException as exc:
            try:
                store.update_metadata(item_id, {ATTEMPT_STATE: FAILED, ATTEMPT_DETAIL: f"{type(exc).__name__}: {exc}"[:400]})
            except WorkStoreError:
                pass  # reconciliation still sees a running attempt without a run

            raise

        try:
            run = ledger.run(run_id)
        except KeyError:
            raise HandoffError(f"investigation returned run {run_id}, which is not in the ledger") from None

        if run.work_item_id != item_id:
            raise HandoffError(f"run {run_id} was recorded with work_item_id={run.work_item_id!r}, not {item_id!r}; not linking it")

        try:
            current = store.get_work(item_id)
            owned = current.status == IN_PROGRESS and current.assignee == actor and current.metadata.get(ATTEMPT_ID) == attempt_id
            _link(store, current, [run_id], LINK_DIRECT, attempt_id=attempt_id if owned else None)
        except WorkStoreError as exc:
            raise WriteBackFailed(item_id, run_id, exc) from exc

        if not owned:
            notes.append(
                f"ownership of {item_id} changed during the run (now {current.status}, assignee {current.assignee}, "
                f"attempt {current.metadata.get(ATTEMPT_ID)}); the run is linked, the item is left as found"
            )

        return Outcome(item_id, attempt_id, run_id, owned, reconcile(store, ledger, item_id, actor=actor, lock=lock), notes)


def complete_investigation(
    store: WorkStore,
    ledger: ResearchLedger,
    item_id: str,
    *,
    actor: str,
    lock_dir: Path,
    reason: str = "",
) -> Reconciliation:
    """
    Close investigation work once an operator accepts it as done. Requires
    at least one exactly linked run and no running, interrupted, or unlinked
    attempt. Closing says nothing about the claims the runs proposed.
    Idempotent for an already completed item.
    """

    with ItemLock(lock_dir, item_id) as lock:
        rec = reconcile(store, ledger, item_id, actor=actor, lock=lock)

        if rec.state == COMPLETED:
            return rec
        if rec.state != AWAITING_COMPLETION:
            raise WorkRefused(rec, "complete")

        text = (reason.strip() + ". " if reason.strip() else "") + (
            f"Investigation work completed; ledger run(s) {', '.join(rec.linked_runs)}. "
            "Claim state is owned by the APTrace ledger."
        )
        store.complete_work(item_id, text, actor=actor)
        return reconcile(store, ledger, item_id, actor=actor, lock=lock)


# -- reconciliation -----------------------------------------------------------


@dataclass(frozen=True)
class Problem:
    code: str  # missing-run | foreign-run | unreferenced-linked-run | identity-mismatch | invalid-item
    detail: str
    run_id: str | None = None


@dataclass
class Reconciliation:
    item: WorkItem
    state: str
    detail: str
    # Runs listed on the item and present in the ledger.
    linked_runs: list[str] = field(default_factory=list)
    # Runs whose work_item_id names this item but which the item does not list.
    unlinked_runs: list[str] = field(default_factory=list)
    problems: list[Problem] = field(default_factory=list)
    attempt: dict[str, Any] = field(default_factory=dict)
    claim_states: dict[str, str] = field(default_factory=dict)
    # Diagnostics only; never acted on.
    duplicate_claims: list[list[str]] = field(default_factory=list)
    heuristic_candidates: list[str] = field(default_factory=list)
    partial_claims: list[str] = field(default_factory=list)

    @property
    def next_step(self) -> str:
        return NEXT_STEP[self.state].format(id=self.item.id)

    def as_dict(self) -> dict[str, Any]:
        return {
            "item": {"id": self.item.id, "status": self.item.status, "assignee": self.item.assignee, "title": self.item.title},
            "state": self.state,
            "detail": self.detail,
            "next_step": self.next_step,
            "linked_runs": self.linked_runs,
            "unlinked_runs": self.unlinked_runs,
            "problems": [asdict(p) for p in self.problems],
            "attempt": self.attempt,
            "claim_states": self.claim_states,
            "duplicate_claims": self.duplicate_claims,
            "heuristic_candidates": self.heuristic_candidates,
            "partial_claims": self.partial_claims,
        }


def runs_for_item(ledger: ResearchLedger, item_id: str) -> list[InvestigationRun]:
    return sorted((run for run in ledger.runs() if run.work_item_id == item_id), key=lambda run: run.started_at)


def _identity_problems(item: WorkItem, run: InvestigationRun) -> list[Problem]:
    meta = item.metadata
    pairs = ((CASE, run.case), (FIRMWARE_KEY, run.firmware_key), (FIRMWARE_SHA256, run.firmware_sha256))
    wrong = [f"{key.removeprefix('aptrace_')} item={meta[key]!r} run={value!r}" for key, value in pairs if meta.get(key) and meta[key] != value]
    return [Problem("identity-mismatch", f"run {run.run_id}: {'; '.join(wrong)}", run.run_id)] if wrong else []


def _claim_state(ledger: ResearchLedger, key: str) -> str:
    try:
        return ledger.state(key).value
    except (KeyError, LedgerError) as exc:
        return f"unknown ({exc})"


def _duplicates(ledger: ResearchLedger, runs: list[InvestigationRun]) -> list[list[str]]:
    groups: dict[tuple[str, str], list[str]] = {}

    for run in runs:
        for key in run.claim_versions:
            try:
                claim = ledger.claim(key)
            except KeyError:
                continue

            groups.setdefault((claim.claim_type.value, " ".join(claim.assertion.split()).lower()), []).append(key)

    return [keys for keys in groups.values() if len(keys) > 1]


def reconcile(
    store: WorkStore,
    ledger: ResearchLedger,
    item_id: str,
    *,
    actor: str,
    lock: ItemLock,
    item: WorkItem | None = None,
) -> Reconciliation:
    """
    Classify an investigation work item from durable state (work store,
    ledger) and the item lock, without modifying anything.

    An interrupted ResearchController run cannot be resumed: its session and
    planner context are not persisted, and the ledger records a run only
    once it finishes. So the choices are: link an exactly referenced run,
    complete, or deliberately start a new attempt.
    """

    item = item or store.get_work(item_id)
    meta = item.metadata
    problems: list[Problem] = []

    if meta.get(KIND) != "investigation":
        problems.append(Problem("invalid-item", f"{KIND}={meta.get(KIND)!r}, expected 'investigation'"))
    if missing := [key for key in REQUIRED if not meta.get(key)]:
        problems.append(Problem("invalid-item", f"missing metadata {', '.join(missing)}"))

    listed = list(meta.get(RUN_IDS) or [])
    referencing = runs_for_item(ledger, item.id)
    runs: dict[str, InvestigationRun] = {run.run_id: run for run in referencing}
    linked: list[str] = []

    for run_id in listed:
        try:
            run = runs.get(run_id) or ledger.run(run_id)
        except KeyError:
            problems.append(Problem("missing-run", f"{item.id} lists run {run_id}, which is not in the ledger", run_id))
            continue

        if run.work_item_id is None:
            problems.append(Problem("unreferenced-linked-run", f"run {run_id} is listed but carries no work-item reference", run_id))
        elif run.work_item_id != item.id:
            problems.append(Problem("foreign-run", f"run {run_id} references work item {run.work_item_id}", run_id))

        runs[run_id] = run
        linked.append(run_id)

    for run in runs.values():
        problems += _identity_problems(item, run)

    unlinked = [run.run_id for run in referencing if run.run_id not in listed]
    attempt = {key: meta[key] for key in ATTEMPT_KEYS if key in meta}
    attempt_state = _attempt_state(meta)
    uncertain = attempt_state in (RUNNING, FAILED)
    rec = Reconciliation(item=item, state="", detail="", linked_runs=linked, unlinked_runs=unlinked, problems=problems, attempt=attempt)
    rec.claim_states = {key: _claim_state(ledger, key) for run in runs.values() for key in run.claim_versions}
    rec.duplicate_claims = _duplicates(ledger, list(runs.values()))

    if uncertain and not unlinked:
        started = meta.get(ATTEMPT_STARTED)
        since = _at(started) if started else None
        known_runs = {run.run_id for run in ledger.runs()}
        rec.partial_claims = [
            claim.key
            for claim in ledger.all_claim_versions()
            if claim.run_id and claim.run_id not in known_runs and (since is None or _at(claim.created_at) >= since)
        ]

        if not referencing:
            rec.heuristic_candidates = [
                run.run_id
                for run in ledger.runs()
                if run.work_item_id is None
                and run.kind == "investigation"
                and run.objective == meta.get(OBJECTIVE)
                and run.case == meta.get(CASE)
                and run.firmware_sha256 == meta.get(FIRMWARE_SHA256)
                and (since is None or _at(run.started_at) >= since)
            ]

    holder = lock.holder()
    remote = uncertain and attempt_state == RUNNING and meta.get(ATTEMPT_HOST) not in (None, hostname())
    others = item.assignee not in (None, actor)

    if problems:
        rec.state, rec.detail = CONFLICT, "; ".join(p.detail for p in problems)
    elif not lock.held and lock.probe():
        rec.state, rec.detail = ACTIVE, f"another APTrace process holds {item.id} (pid {holder.get('pid', '?')} since {holder.get('at', '?')})"
    elif remote:
        rec.state, rec.detail = ACTIVE, (
            f"attempt {meta.get(ATTEMPT_ID)} is running on host {meta.get(ATTEMPT_HOST)}; its liveness cannot be checked from {hostname()}"
        )
    elif unlinked:
        rec.state, rec.detail = LINK_RUNS, f"run(s) {', '.join(unlinked)} reference {item.id} but are not linked on it"
    elif item.status == CLOSED:
        rec.state, rec.detail = COMPLETED, item.close_reason or "work closed"
    elif uncertain and rec.heuristic_candidates:
        rec.state, rec.detail = OPERATOR_REVIEW, (
            f"attempt {meta.get(ATTEMPT_ID) or '(unnamed)'} recorded no referenced run, but unreferenced run(s) "
            f"{', '.join(rec.heuristic_candidates)} match by objective/case/firmware/time"
        )
    elif others:
        rec.state, rec.detail = CLAIMED_BY_OTHER, f"{item.id} is {item.status} and assigned to {item.assignee}"
    elif uncertain:
        rec.state, rec.detail = INTERRUPTED, (
            f"attempt {meta.get(ATTEMPT_ID) or '(unnamed)'} ({attempt_state}"
            + (f": {meta[ATTEMPT_DETAIL]}" if meta.get(ATTEMPT_DETAIL) else "")
            + ") recorded no run and no process holds the item"
        )
    elif linked:
        rec.state, rec.detail = AWAITING_COMPLETION, f"run(s) {', '.join(linked)} recorded; the item is not closed"
    else:
        rec.state, rec.detail = READY, "no attempt or run recorded"

    return rec


def apply_reconciliation(store: WorkStore, ledger: ResearchLedger, item_id: str, *, actor: str, lock_dir: Path) -> Reconciliation:
    """
    Apply the only automatic repair: link runs whose work_item_id names this
    item and mark the attempt that produced them recorded. Never claims,
    closes, restarts, or touches the ledger. Idempotent.
    """

    lock = ItemLock(lock_dir, item_id)

    if lock.probe():
        return reconcile(store, ledger, item_id, actor=actor, lock=lock)

    with lock:
        rec = reconcile(store, ledger, item_id, actor=actor, lock=lock)

        if rec.state == LINK_RUNS:
            _link(store, rec.item, rec.unlinked_runs, LINK_RECONCILED, current_attempt=True)
            rec = reconcile(store, ledger, item_id, actor=actor, lock=lock)

        return rec


# -- audit follow-ups -----------------------------------------------------------


def followup_id(prefix: str, claim_version: str, audit_id: str) -> str:
    return f"{prefix}-fu{digest({'claim_version': claim_version, 'audit_id': audit_id})[:10]}"


def _followup_reason(ledger: ResearchLedger, audit_id: str) -> str:
    audit = ledger.audit(audit_id)
    parts = list(audit.challenges)
    parts += [r.question for r in audit.follow_up_requests]

    if audit.verdict_synthesized:
        parts.append("verdict synthesized by APTrace: no successful falsification analysis")
    if not parts:
        parts.append(audit.reasoning or audit.termination_reason)

    return "; ".join(p.strip() for p in parts if p and p.strip())[:600]


def followup_for_audit(
    store: WorkStore,
    ledger: ResearchLedger,
    audit_id: str,
    *,
    prefix: str,
    source_item: str | None = None,
) -> tuple[WorkItem | None, bool]:
    """
    Open follow-up work for a CHALLENGED or UNRESOLVED audit.

    Returns (item, created). The item id is derived from the claim version
    and audit id, so a repeat (including a concurrent one) finds the existing
    item instead of creating another. SUPPORTED and diagnostic audits get no
    follow-up. The audit and the claim's lifecycle are left untouched.
    """

    audit = ledger.audit(audit_id)

    if audit.verdict not in FOLLOWUP_VERDICTS or audit.diagnostic:
        return None, False

    item_id = followup_id(prefix, audit.claim_version, audit_id)
    reason = _followup_reason(ledger, audit_id)
    claim = ledger.claim(audit.claim_version)
    metadata = {
        KIND: "audit-followup",
        FOLLOWUP_KEY: item_id,
        "aptrace_claim_version": audit.claim_version,
        "aptrace_audit_id": audit_id,
        "aptrace_audit_verdict": audit.verdict.value,
        "aptrace_followup_reason": reason,
        "aptrace_claim_run_id": claim.run_id,
    }

    if source_item:
        metadata["aptrace_source_work"] = source_item

    try:
        item = store.create_work(
            f"Follow up {audit.verdict.value} audit of {audit.claim_version}",
            description=f"Audit {audit_id} returned {audit.verdict.value} for {audit.claim_version}: {reason}",
            priority=1 if audit.verdict == AuditVerdict.CHALLENGED else 2,
            metadata=metadata,
            discovered_from=source_item,
            item_id=item_id,
        )
    except DuplicateWork:
        return store.get_work(item_id), False

    return item, True

