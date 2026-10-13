"""
Shared fixtures for work-item tests: an in-memory WorkStore with the claim
semantics observed in bd 1.3.1, and the `research --ledger` investigation
path driven by a scripted planner.

FakeWorkStore mirrors, concretely observed against bd 1.3.1:
- claim: idempotent for the holder; "already claimed by X" for others, also
  after the lease has expired (only `bd reclaim` releases a claim);
  "issue not claimable: status closed" for closed items;
- release: compare-and-swap on the assignee;
- close: refused for another actor's in_progress claim;
- metadata update: top-level merge, no assignee guard.
"""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from aptrace_agent.investigator import AutonomousInvestigationRun
from aptrace_agent.ledger.models import SourceRevision
from aptrace_agent.ledger.recorder import RecordingExecutor, record_investigation
from aptrace_agent.ledger.store import now
from aptrace_agent.research import LeadFollower, LeadRegistry, ResearchController, ResearchSession
from aptrace_agent.work.store import (
    CLOSED,
    IN_PROGRESS,
    OPEN,
    ClaimConflict,
    DuplicateWork,
    WorkItem,
    WorkNotFound,
    WorkStoreError,
    WorkStoreUnavailable,
)

from ledger_support import FakeExecutor


OBJECTIVE = "Determine which handler services USB_OTHER and what it dispatches."
CLAIMS = "PROBABLE STRUCTURE E1 FUN_0000cc14 is the USB_OTHER interrupt handler."


class FakeWorkStore:
    def __init__(self, prefix: str = "apt") -> None:
        self.prefix = prefix
        self.items: dict[str, dict[str, Any]] = {}
        self.writes = 0
        # Metadata writes allowed before the store "dies" (None: never).
        self.fail_metadata_after: int | None = None

    def _item(self, item_id: str) -> WorkItem:
        raw = self.items.get(item_id)

        if raw is None:
            raise WorkNotFound(f"no issue found matching {item_id}")

        return WorkItem(**copy.deepcopy(raw))

    def snapshot(self) -> dict[str, Any]:
        return copy.deepcopy(self.items)

    def create_work(self, title, *, description="", priority=2, metadata=None, depends_on=(), discovered_from=None, item_id=None):
        item_id = item_id or f"{self.prefix}-{len(self.items) + 1:03d}"

        if item_id in self.items:
            raise DuplicateWork(f"issue {item_id} already exists")

        deps = tuple((other, "blocks") for other in depends_on)

        if discovered_from:
            deps += ((discovered_from, "discovered-from"),)

        self.items[item_id] = dict(
            id=item_id, title=title, status=OPEN, priority=priority, assignee=None, description=description,
            close_reason=None, metadata=dict(metadata or {}), dependencies=deps,
        )
        return self._item(item_id)

    def get_work(self, item_id):
        return self._item(item_id)

    def find_work(self, key, value):
        return [self._item(i) for i, raw in self.items.items() if raw["metadata"].get(key) == value]

    def ready_work(self):
        return [
            self._item(i)
            for i, raw in self.items.items()
            if raw["status"] == OPEN and all(self.items[o]["status"] == CLOSED for o, k in raw["dependencies"] if k == "blocks")
        ]

    def add_dependency(self, item_id, depends_on):
        self.items[item_id]["dependencies"] += ((depends_on, "blocks"),)

    def claim_work(self, item_id, actor):
        self._item(item_id)
        raw = self.items[item_id]

        if raw["status"] == CLOSED:
            raise WorkStoreError("bd update failed (1): issue not claimable: status closed")
        if raw["status"] == IN_PROGRESS and raw["assignee"] not in (None, actor):
            raise ClaimConflict(f"issue already claimed by {raw['assignee']}")

        raw.update(status=IN_PROGRESS, assignee=actor)
        return self._item(item_id)

    def claim_next(self, actor):
        ready = self.ready_work()
        return self.claim_work(ready[0].id, actor) if ready else None

    def release_work(self, item_id, actor, reason):
        raw = self.items[item_id]

        if raw["assignee"] != actor:
            raise WorkStoreError("bd unclaim failed (13): precondition no longer held")

        raw.update(status=OPEN, assignee=None)
        return self._item(item_id)

    def update_metadata(self, item_id, metadata):
        self._item(item_id)
        self.writes += 1

        if self.fail_metadata_after is not None and self.writes > self.fail_metadata_after:
            raise WorkStoreUnavailable("simulated: bd unavailable during metadata write")

        self.items[item_id]["metadata"].update(copy.deepcopy(metadata))
        return self._item(item_id)

    def complete_work(self, item_id, reason, *, actor=None):
        raw = self.items[item_id]

        if raw["status"] == IN_PROGRESS and raw["assignee"] not in (None, actor):
            raise ClaimConflict(f"cannot close {item_id}: assignee is {raw['assignee']}")

        raw.update(status=CLOSED, close_reason=reason)
        return self._item(item_id)

    def reclaim(self, item_id):
        """What `bd reclaim` does once a lease has expired: clear the claim."""

        self.items[item_id].update(status=OPEN, assignee=None)


class Planner:
    """Follows the first lead, then answers the finish-only claim request."""

    def __init__(self, claims: str = CLAIMS):
        self.claims = claims
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))

    def _create(self, **kwargs):
        names = [t["function"]["name"] for t in kwargs["tools"]]

        if names == ["finish"]:
            name, arguments = "finish", {"reason": "budget", "claims": self.claims}
        else:
            lead = kwargs["tools"][0]["function"]["parameters"]["properties"]["lead_id"]["enum"][0]
            name, arguments = "follow_lead", {"lead_id": lead}

        call = SimpleNamespace(function=SimpleNamespace(name=name, arguments=json.dumps(arguments)))
        return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=None, tool_calls=[call]))])


def investigator(ledger, context, claims: str = CLAIMS, calls: list | None = None):
    """The `research --ledger` path: controller run, then record_investigation."""

    def investigate(objective: str, work_item_id: str | None = None) -> str:
        if calls is not None:
            calls.append((objective, work_item_id))

        registry = LeadRegistry()
        executor = RecordingExecutor(FakeExecutor())
        session = ResearchSession(objective=objective, registry=registry, follower=LeadFollower(registry=registry, executor=executor))
        session.state.add_lead(registry.register(kind="function", description="USB handler", tool="function_facts", arguments={"function": "FUN_0000cc14"}))
        started = now()
        result = ResearchController(planner_client=Planner(claims), planner_model="scripted", reconciler=object(), max_steps=1, claim_contract=True).run(session)
        run = AutonomousInvestigationRun(objective=objective, seed_function=None, result=result, state=session.state.model_copy(deep=True), evidence=tuple(session.ledger.all()))
        recorded = record_investigation(
            ledger, run, context=context(), recorder=executor, model="scripted", execution_config={}, planner_version="test",
            budgets={"max_steps": 1}, started_at=started, ended_at=now(), source=SourceRevision(), work_item_id=work_item_id,
        )
        return recorded.run_id

    return investigate


def snapshot(root: Path) -> dict[str, str]:
    return {
        str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in sorted(root.rglob("*"))
        if p.is_file()
    }
