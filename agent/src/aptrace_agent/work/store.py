"""
Long-horizon work items: the boundary APTrace uses to track investigation
work, independent of how that work is stored.

A work item is a unit of work (investigate, audit, follow up). Its status
says whether the work was done, never whether a claim is valid: claim
lifecycle state belongs to the research ledger alone. A work dependency
orders work; it is not an evidentiary dependency between claim versions.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol


OPEN = "open"
IN_PROGRESS = "in_progress"
CLOSED = "closed"


class WorkStoreError(RuntimeError):
    pass


class WorkStoreUnavailable(WorkStoreError):
    """The backing store cannot be reached (missing tool, timeout, bad store)."""


class WorkNotFound(WorkStoreError, KeyError):
    pass


class ClaimConflict(WorkStoreError):
    """Another actor holds the work item."""


class DuplicateWork(WorkStoreError):
    """A work item with this explicit id already exists."""


class WorkActive(WorkStoreError):
    """Another local process is executing (or reconciling) this work item."""


@dataclass(frozen=True)
class WorkItem:
    id: str
    title: str
    status: str
    priority: int
    assignee: str | None = None
    description: str = ""
    close_reason: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    # (other item id, relation), e.g. ("apt-1x2", "blocks").
    dependencies: tuple[tuple[str, str], ...] = ()

    @property
    def blockers(self) -> list[str]:
        return [other for other, kind in self.dependencies if kind == "blocks"]


class WorkStore(Protocol):
    def create_work(
        self,
        title: str,
        *,
        description: str = "",
        priority: int = 2,
        metadata: dict[str, Any] | None = None,
        depends_on: tuple[str, ...] = (),
        discovered_from: str | None = None,
        item_id: str | None = None,
    ) -> WorkItem: ...

    def get_work(self, item_id: str) -> WorkItem: ...

    def find_work(self, key: str, value: str) -> list[WorkItem]: ...

    def ready_work(self) -> list[WorkItem]: ...

    def add_dependency(self, item_id: str, depends_on: str) -> None: ...

    def claim_work(self, item_id: str, actor: str) -> WorkItem: ...

    def claim_next(self, actor: str) -> WorkItem | None: ...

    def release_work(self, item_id: str, actor: str, reason: str) -> WorkItem: ...

    def update_metadata(self, item_id: str, metadata: dict[str, Any]) -> WorkItem: ...

    def complete_work(self, item_id: str, reason: str, *, actor: str | None = None) -> WorkItem: ...
