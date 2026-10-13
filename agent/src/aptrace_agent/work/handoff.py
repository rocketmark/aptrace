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
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone

from aptrace_agent.ledger.hashing import digest
from aptrace_agent.ledger.models import AuditVerdict, ExecutionContext, InvestigationRun
from aptrace_agent.ledger.store import ResearchLedger
from aptrace_agent.work.store import CLOSED, IN_PROGRESS, DuplicateWork, WorkItem, WorkStore


KIND = "aptrace_kind"
OBJECTIVE = "aptrace_objective"
RUN_IDS = "aptrace_run_ids"
RUN_LINKS = "aptrace_run_link_basis"
ATTEMPT_STARTED = "aptrace_attempt_started_at"
ATTEMPT_ACTOR = "aptrace_attempt_actor"
FOLLOWUP_KEY = "aptrace_followup_key"

# How a run id came to be on a work item.
LINK_DIRECT = "direct"
LINK_RECOVERED = "recovered:objective+case+firmware+attempt-window"

FOLLOWUP_VERDICTS = (AuditVerdict.CHALLENGED, AuditVerdict.UNRESOLVED)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def _at(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


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
            "aptrace_case": context.case,
            "aptrace_firmware_key": context.firmware_key,
            "aptrace_firmware_sha256": context.firmware_sha256,
            "aptrace_context_id": context.context_id(),
        },
    )


def link_run(store: WorkStore, item_id: str, run_id: str, *, basis: str = LINK_DIRECT) -> WorkItem:
    """Persist a ledger run id on the work item. Idempotent."""

    item = store.get_work(item_id)
    runs = list(item.metadata.get(RUN_IDS) or [])

    if run_id in runs:
        return item

    links = dict(item.metadata.get(RUN_LINKS) or {})
    links[run_id] = basis
    return store.update_metadata(item_id, {RUN_IDS: [*runs, run_id], RUN_LINKS: links})


def run_investigation(store: WorkStore, item_id: str, *, actor: str, investigate: Callable[[str], str]) -> str:
    """
    Claim a work item and hand its objective to an existing APTrace
    investigation entry point, which records the run in the ledger and
    returns its run id. The run id is written back and the work closed.

    Closing records that the investigation ran. Claims the run proposed stay
    in whatever state the ledger gives them.
    """

    item = store.claim_work(item_id, actor)
    objective = item.metadata[OBJECTIVE]
    store.update_metadata(item_id, {ATTEMPT_STARTED: _now(), ATTEMPT_ACTOR: actor})

    try:
        run_id = investigate(objective)
    except Exception as exc:
        store.release_work(item_id, actor, f"investigation raised {type(exc).__name__}; no run linked")
        raise

    link_run(store, item_id, run_id)
    store.complete_work(item_id, f"work completed: ledger run {run_id} recorded. Claim state is owned by the APTrace ledger.", actor=actor)
    return run_id


# -- recovery -----------------------------------------------------------------


@dataclass
class Recovery:
    item: WorkItem
    linked_runs: list[str]
    missing_runs: list[str]
    orphan_runs: list[str]
    claim_states: dict[str, str] = field(default_factory=dict)
    next_action: str = ""
    detail: str = ""


def _orphans(ledger: ResearchLedger, item: WorkItem, linked: set[str]) -> list[InvestigationRun]:
    started = item.metadata.get(ATTEMPT_STARTED)

    if not started:
        return []

    since = _at(started)
    return [
        run
        for run in ledger.runs()
        if run.kind == "investigation"
        and run.run_id not in linked
        and run.objective == item.metadata.get(OBJECTIVE)
        and run.case == item.metadata.get("aptrace_case")
        and run.firmware_sha256 == item.metadata.get("aptrace_firmware_sha256")
        and _at(run.started_at) >= since
    ]


def recover(store: WorkStore, ledger: ResearchLedger, item_id: str) -> Recovery:
    """
    Reconstruct an investigation work item's position from durable state
    only (work store + ledger), without modifying either.

    An interrupted ResearchController run cannot be resumed: its session
    and planner context are not persisted, and the ledger records a run only
    once it finishes. So the choices are: link a finished-but-unlinked run,
    or restart the investigation from its objective.
    """

    item = store.get_work(item_id)
    linked = list(item.metadata.get(RUN_IDS) or [])
    present = [r for r in linked if _has_run(ledger, r)]
    missing = [r for r in linked if r not in present]
    orphans = [run.run_id for run in _orphans(ledger, item, set(linked))]
    states: dict[str, str] = {}

    for run_id in present:
        for key in ledger.run(run_id).claim_versions:
            states[key] = ledger.state(key).value

    recovery = Recovery(item=item, linked_runs=present, missing_runs=missing, orphan_runs=orphans, claim_states=states)

    if missing:
        recovery.next_action, recovery.detail = "investigate-ledger", f"linked run(s) absent from ledger: {', '.join(missing)}"
    elif item.status == CLOSED:
        recovery.next_action, recovery.detail = "none", "work completed"
    elif len(orphans) == 1:
        recovery.next_action, recovery.detail = "link-orphan-run", f"run {orphans[0]} finished but was never linked"
    elif len(orphans) > 1:
        recovery.next_action, recovery.detail = "operator-review", f"several unlinked runs match: {', '.join(orphans)}"
    elif present:
        recovery.next_action, recovery.detail = "complete", "a linked run exists; close the work item"
    elif item.status == IN_PROGRESS:
        recovery.next_action, recovery.detail = "restart", (
            f"claimed by {item.assignee} with no recorded run; restart from the objective "
            "(same actor may re-claim; others wait for lease expiry and `bd reclaim`)"
        )
    else:
        recovery.next_action, recovery.detail = "start", "no attempt recorded"

    return recovery


def apply_recovery(store: WorkStore, ledger: ResearchLedger, item_id: str, *, actor: str) -> Recovery:
    """
    Apply only the unambiguous step: link a single orphan run and close.
    The actor must hold (or be able to take) the claim; another worker's
    live claim raises ClaimConflict until its lease is reclaimed.
    """

    recovery = recover(store, ledger, item_id)

    if recovery.next_action in ("link-orphan-run", "complete"):
        store.claim_work(item_id, actor)

    if recovery.next_action == "link-orphan-run":
        link_run(store, item_id, recovery.orphan_runs[0], basis=LINK_RECOVERED)
        recovery = recover(store, ledger, item_id)

    if recovery.next_action == "complete":
        store.complete_work(item_id, f"work completed: ledger run(s) {', '.join(recovery.linked_runs)} recorded (recovered).", actor=actor)
        recovery = recover(store, ledger, item_id)

    return recovery


def _has_run(ledger: ResearchLedger, run_id: str) -> bool:
    try:
        ledger.run(run_id)
    except KeyError:
        return False

    return True


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

