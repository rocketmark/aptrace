"""
Materialize APTrace follow-up candidates (research/followups.py) as Beads
investigation work items.

A follow-up item is an ordinary `investigation` item, so the existing
`research --ledger --work-item` path runs it. It carries ledger ids only:
the candidate key, its question key, the source run and the claim, audit,
and evidence ids the candidate cites. The objective is the candidate's
specific objective; the bounded context is re-assembled from the ledger
when the item runs, never copied into Beads.

Deduplication: the item id is derived from the candidate key, which covers
the question and its evidence basis. Creating the same candidate again
(also concurrently, or after reopening the store) hits DuplicateWork and
returns the existing item, open or closed; a closed item is never reopened
or recreated. A changed evidence basis yields a new key and a new item that
lists earlier items for the same question (`aptrace_prior_followups`).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from aptrace_agent.ledger.models import ExecutionContext
from aptrace_agent.research.followups import CLAIM_FOLLOWUP, GENERATOR_VERSION, PROPOSED, FollowUpCandidate
from aptrace_agent.work.handoff import CASE, CONTEXT_ID, FIRMWARE_KEY, FIRMWARE_SHA256, FOLLOWUP_KEY, KIND, OBJECTIVE
from aptrace_agent.work.store import CLOSED, DuplicateWork, WorkItem, WorkNotFound, WorkStore


QUESTION_KEY = "aptrace_followup_question"
SOURCE_RUN = "aptrace_source_run"
CATEGORY = "aptrace_followup_category"
GENERATOR = "aptrace_followup_generator"
CLAIM_VERSIONS = "aptrace_claim_versions"
AUDIT_IDS = "aptrace_audit_ids"
VERIFICATION_IDS = "aptrace_verification_ids"
EVIDENCE_IDS = "aptrace_evidence_ids"
PRIOR_FOLLOWUPS = "aptrace_prior_followups"
RELATED_WORK = "aptrace_related_work"

# Candidate rank (1..3) is the Beads priority.
MAX_EVIDENCE_REFS = 24


class FollowUpRefused(RuntimeError):
    pass


def followup_item_id(prefix: str, candidate_key: str) -> str:
    return f"{prefix}-fq{candidate_key[:10]}"


@dataclass
class Materialized:
    item: WorkItem
    created: bool
    detail: str
    notes: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {"item_id": self.item.id, "status": self.item.status, "created": self.created, "detail": self.detail, "notes": self.notes}


def existing_followups(store: WorkStore, candidate: FollowUpCandidate, *, prefix: str) -> dict[str, Any]:
    """Read-only: the item for this exact candidate and items for the same question."""

    item_id = followup_item_id(prefix, candidate.key)

    try:
        exact = store.get_work(item_id)
    except WorkNotFound:
        exact = None

    prior = [item for item in store.find_work(QUESTION_KEY, candidate.question_key) if item.id != item_id]
    related = [item for audit_id in candidate.audit_ids for item in store.find_work("aptrace_audit_id", audit_id)]
    return {"item_id": item_id, "exact": exact, "prior": prior, "related": related}


def _description(candidate: FollowUpCandidate) -> str:
    lines = [
        candidate.objective,
        "",
        f"Why: {candidate.reason}",
        f"Expected information gain: {candidate.information_gain}",
        f"Priority basis: {'; '.join(candidate.priority_basis)}",
        f"Source run: {candidate.source_run_id}",
    ]

    if candidate.claim_versions:
        lines.append(f"Claims (unverified; closing this item never changes them): {', '.join(candidate.claim_versions)}")
    if candidate.audit_ids:
        lines.append(f"Audits: {', '.join(candidate.audit_ids)}")

    lines.append(f"Context is re-assembled from the APTrace ledger when run (followups {GENERATOR_VERSION}, key {candidate.key}).")
    return "\n".join(lines)


def materialize(
    store: WorkStore,
    candidate: FollowUpCandidate,
    *,
    context: ExecutionContext,
    prefix: str,
    source_item: str | None = None,
) -> Materialized:
    """
    Create the investigation work item for one candidate, or return the
    existing one. Never modifies an existing item and never touches the ledger.
    """

    if candidate.status != PROPOSED:
        raise FollowUpRefused(f"candidate {candidate.key} is {candidate.status}: {candidate.status_detail}")
    if candidate.blocker:
        raise FollowUpRefused(f"candidate {candidate.key} is blocked: {candidate.blocker}")

    found = existing_followups(store, candidate, prefix=prefix)
    item_id = found["item_id"]

    if found["exact"] is not None:
        item = found["exact"]
        state = "completed; not recreated" if item.status == CLOSED else f"already {item.status}"
        return Materialized(item, False, f"{item_id} {state}")

    notes: list[str] = []
    discovered_from = None

    if source_item:
        try:
            store.get_work(source_item)
            discovered_from = source_item
        except WorkNotFound:
            notes.append(f"source work item {source_item} not in this store; no discovered-from link")

    metadata: dict[str, Any] = {
        KIND: "investigation",
        OBJECTIVE: candidate.objective,
        CASE: context.case,
        FIRMWARE_KEY: context.firmware_key,
        FIRMWARE_SHA256: context.firmware_sha256,
        CONTEXT_ID: context.context_id(),
        FOLLOWUP_KEY: candidate.key,
        QUESTION_KEY: candidate.question_key,
        SOURCE_RUN: candidate.source_run_id,
        CATEGORY: candidate.category,
        GENERATOR: GENERATOR_VERSION,
        CLAIM_VERSIONS: list(candidate.claim_versions),
        EVIDENCE_IDS: list(candidate.evidence_ids[:MAX_EVIDENCE_REFS]),
    }

    if candidate.audit_ids:
        metadata[AUDIT_IDS] = list(candidate.audit_ids)
    if candidate.verification_ids:
        metadata[VERIFICATION_IDS] = list(candidate.verification_ids)
    if found["prior"]:
        metadata[PRIOR_FOLLOWUPS] = sorted(item.id for item in found["prior"])
        notes.append(f"earlier follow-up(s) for the same question under a different evidence basis: {', '.join(metadata[PRIOR_FOLLOWUPS])}")
    if found["related"]:
        metadata[RELATED_WORK] = sorted({item.id for item in found["related"]})
        notes.append(f"audit follow-up item(s) for the same audit: {', '.join(metadata[RELATED_WORK])}")

    noun = candidate.claim_versions[0] if candidate.category == CLAIM_FOLLOWUP and candidate.claim_versions else candidate.source_run_id
    title = f"Follow up {noun}: {candidate.objective.split('. ', 1)[-1][:90]}"

    try:
        item = store.create_work(
            title,
            description=_description(candidate),
            priority=candidate.rank,
            metadata=metadata,
            discovered_from=discovered_from,
            item_id=item_id,
        )
    except DuplicateWork:
        # A concurrent creator won; its item is the follow-up.
        item = store.get_work(item_id)
        return Materialized(item, False, f"{item_id} created concurrently; not duplicated", notes)

    return Materialized(item, True, f"created {item_id}", notes)


def followup_reference(item: WorkItem) -> tuple[str, str] | None:
    """(source run id, candidate key) when the item is a materialized follow-up."""

    meta = item.metadata

    if meta.get(KIND) == "investigation" and meta.get(FOLLOWUP_KEY) and meta.get(SOURCE_RUN):
        return str(meta[SOURCE_RUN]), str(meta[FOLLOWUP_KEY])

    return None


__all__ = ["FollowUpRefused", "Materialized", "existing_followups", "followup_item_id", "followup_reference", "materialize"]
