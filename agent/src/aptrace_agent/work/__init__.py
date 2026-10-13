"""
Long-horizon work tracking, kept separate from research knowledge.

`store` defines the work-item boundary; `beads` implements it with the Beads
CLI; `handoff` connects work items to ledger runs and audits without writing
to the ledger. The research ledger does not import this package.
"""

from aptrace_agent.work.store import (
    ClaimConflict,
    DuplicateWork,
    WorkItem,
    WorkNotFound,
    WorkStore,
    WorkStoreError,
    WorkStoreUnavailable,
)

__all__ = [
    "ClaimConflict",
    "DuplicateWork",
    "WorkItem",
    "WorkNotFound",
    "WorkStore",
    "WorkStoreError",
    "WorkStoreUnavailable",
]
