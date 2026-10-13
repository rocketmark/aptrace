"""
Long-horizon work tracking, kept separate from research knowledge.

`store` defines the work-item boundary; `beads` implements it with the Beads
CLI; `ownership` holds the host-local lock that marks a work item as being
executed; `handoff` connects work items to ledger runs and audits without
writing to the ledger. The research ledger does not import this package.
"""

from aptrace_agent.work.store import (
    ClaimConflict,
    DuplicateWork,
    WorkActive,
    WorkItem,
    WorkNotFound,
    WorkStore,
    WorkStoreError,
    WorkStoreUnavailable,
)

__all__ = [
    "ClaimConflict",
    "DuplicateWork",
    "WorkActive",
    "WorkItem",
    "WorkNotFound",
    "WorkStore",
    "WorkStoreError",
    "WorkStoreUnavailable",
]
