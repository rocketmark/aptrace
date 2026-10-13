"""
WorkStore backed by the Beads `bd` CLI (embedded Dolt mode).

Every call is one `bd ... --json` subprocess against an explicit BEADS_DIR,
run from that directory's parent so `bd` never discovers, writes to, or
commits into an enclosing repository. Usage metrics are disabled per call
with DO_NOT_TRACK. Beads failures surface as WorkStoreError subclasses and
never reach the research ledger.

Tested against bd 1.3.1 (c1c4b642a). The JSON shapes parsed here are that
version's; other minors are refused rather than guessed at.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from aptrace_agent.work.store import (
    ClaimConflict,
    DuplicateWork,
    WorkItem,
    WorkNotFound,
    WorkStoreError,
    WorkStoreUnavailable,
)


PINNED_BEADS_VERSION = "1.3.1"
SUPPORTED_SERIES = "1.3."
DEFAULT_TIMEOUT_S = 60.0


def find_bd() -> str | None:
    return os.environ.get("APTRACE_BD") or shutil.which("bd")


def _inside_git(path: Path) -> bool:
    existing = next((p for p in (path, *path.parents) if p.is_dir()), None)

    if existing is None:
        return False

    inside = subprocess.run(["git", "-C", str(existing), "rev-parse", "--is-inside-work-tree"], capture_output=True, text=True)
    return inside.returncode == 0 and inside.stdout.strip() == "true"


def _edge(raw: dict[str, Any]) -> tuple[str, str]:
    # `show` embeds the other issue (id, dependency_type); `list`/`ready`
    # return edge rows (issue_id, depends_on_id, type).
    if "depends_on_id" in raw:
        return raw["depends_on_id"], raw.get("type", "")

    return raw["id"], raw.get("dependency_type", "")


def _item(raw: dict[str, Any]) -> WorkItem:
    return WorkItem(
        id=raw["id"],
        title=raw.get("title", ""),
        status=raw.get("status", ""),
        priority=int(raw.get("priority", 2)),
        assignee=raw.get("assignee") or None,
        description=raw.get("description", ""),
        close_reason=raw.get("close_reason") or None,
        metadata=dict(raw.get("metadata") or {}),
        dependencies=tuple(_edge(d) for d in raw.get("dependencies") or ()),
    )


def _one(payload: Any) -> dict[str, Any]:
    return payload[0] if isinstance(payload, list) else payload


class BeadsWorkStore:
    def __init__(
        self,
        beads_dir: Path,
        *,
        bd: str | None = None,
        actor: str = "aptrace",
        env: Mapping[str, str] | None = None,
        timeout: float = DEFAULT_TIMEOUT_S,
    ) -> None:
        self.beads_dir = Path(beads_dir).resolve()
        self.bd = bd or find_bd()
        self.actor = actor
        self.timeout = timeout
        self._env = dict(env or {})

    # -- process boundary -----------------------------------------------------

    def _environment(self) -> dict[str, str]:
        env = dict(os.environ)
        env.update(self._env)
        env.update(
            BEADS_DIR=str(self.beads_dir),
            DO_NOT_TRACK="1",
            BD_NON_INTERACTIVE="1",
            BD_NO_INSTALL_HOOKS="1",
            BD_NO_DEP_TYPE_WARNING="1",
            BD_NO_PAGER="1",
        )
        return env

    def _exec(self, args: list[str], *, actor: str | None = None) -> subprocess.CompletedProcess[str]:
        if not self.bd:
            raise WorkStoreUnavailable(f"Beads CLI not found: install bd {PINNED_BEADS_VERSION} and set APTRACE_BD or put bd on PATH")

        command = [self.bd, *args, "--actor", actor or self.actor]
        # Only initialize() creates the store root; `bd version` may run before it exists.
        cwd = self.beads_dir.parent if self.beads_dir.parent.is_dir() else None

        try:
            return subprocess.run(
                command,
                cwd=cwd,
                env=self._environment(),
                capture_output=True,
                text=True,
                timeout=self.timeout,
                stdin=subprocess.DEVNULL,
            )
        except FileNotFoundError as exc:
            raise WorkStoreUnavailable(f"Beads CLI not runnable ({exc}): install bd {PINNED_BEADS_VERSION} and set APTRACE_BD or put bd on PATH") from exc
        except subprocess.TimeoutExpired as exc:
            raise WorkStoreUnavailable(f"bd {args[0]} timed out after {self.timeout}s") from exc

    def _json(self, args: list[str], *, actor: str | None = None) -> Any:
        if not (self.beads_dir / "metadata.json").is_file():
            raise WorkStoreUnavailable(f"no Beads store at {self.beads_dir}")

        done = self._exec([*args, "--json"], actor=actor)

        if done.returncode != 0:
            message = (done.stderr.strip() + "\n" + done.stdout.strip()).strip()
            lowered = message.lower()

            if "already claimed by" in lowered or ("cannot close" in lowered and "assignee is" in lowered):
                raise ClaimConflict(message)
            if "already exists" in lowered:
                raise DuplicateWork(message)
            if "not found" in lowered or "no issues found" in lowered:
                raise WorkNotFound(message)
            if "database is locked" in lowered or "timeout" in lowered:
                raise WorkStoreUnavailable(message)

            raise WorkStoreError(f"bd {args[0]} failed ({done.returncode}): {message[:800]}")

        try:
            return json.loads(done.stdout) if done.stdout.strip() else None
        except json.JSONDecodeError as exc:
            raise WorkStoreError(f"bd {args[0]} returned non-JSON output: {done.stdout[:400]!r}") from exc

    # -- lifecycle ------------------------------------------------------------

    def version(self) -> str:
        done = self._exec(["version"])
        text = done.stdout.strip()

        if done.returncode != 0 or not text.startswith("bd version "):
            raise WorkStoreUnavailable(f"cannot determine bd version: {text or done.stderr.strip()}")

        return text.split()[2]

    def check_version(self) -> str:
        version = self.version()

        if not version.startswith(SUPPORTED_SERIES):
            raise WorkStoreUnavailable(f"bd {version} is untested; this adapter is pinned to {PINNED_BEADS_VERSION} (set APTRACE_BD to a 1.3.x binary)")

        return version

    def open_checked(self) -> BeadsWorkStore:
        """
        Production entry: a supported bd, an existing store, and a store
        outside any git work tree. Never creates or initializes anything.
        """

        self.check_version()

        if _inside_git(self.beads_dir.parent):
            raise WorkStoreError(f"refusing to use a Beads store inside git work tree {self.beads_dir.parent}; keep it outside the checkout")
        if not (self.beads_dir / "metadata.json").is_file():
            raise WorkStoreUnavailable(f"no Beads store at {self.beads_dir}; create one with `aptrace-agent work init`")

        return self

    def initialize(self, *, prefix: str = "apt", allow_inside_git: bool = False) -> None:
        """
        Create the store if missing. `bd init` writes a .gitignore into its
        working directory (and, without BEADS_DIR, runs `git init` and
        commits), so by default it refuses to initialize inside a git work
        tree such as the APTrace checkout.
        """

        if (self.beads_dir / "metadata.json").is_file():
            return

        self.check_version()
        parent = self.beads_dir.parent
        parent.mkdir(parents=True, exist_ok=True)

        if not allow_inside_git and _inside_git(parent):
            raise WorkStoreError(f"refusing to initialize Beads inside git work tree {parent}")

        self.beads_dir.mkdir(parents=True, exist_ok=True)
        done = self._exec(["init", "--non-interactive", "--skip-agents", "--skip-hooks", "--quiet", "-p", prefix])

        if done.returncode != 0:
            raise WorkStoreError(f"bd init failed: {done.stderr.strip()[:800]}")

    # -- work items -----------------------------------------------------------

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
    ) -> WorkItem:
        args = ["create", title, "-t", "task", "-p", str(priority)]

        if description:
            args += ["-d", description]
        if metadata:
            args += ["--metadata", json.dumps(metadata, sort_keys=True)]
        if item_id:
            args += ["--id", item_id]

        deps = [f"blocked-by:{other}" for other in depends_on]

        if discovered_from:
            deps.append(f"discovered-from:{discovered_from}")
        if deps:
            args += ["--deps", ",".join(deps)]

        created = _one(self._json(args))
        return self.get_work(created["id"])

    def get_work(self, item_id: str) -> WorkItem:
        return _item(_one(self._json(["show", item_id])))

    def find_work(self, key: str, value: str) -> list[WorkItem]:
        rows = self._json(["list", "--all", "--limit", "0", "--flat", "--metadata-field", f"{key}={value}"]) or []
        return [self.get_work(row["id"]) for row in rows]

    def ready_work(self) -> list[WorkItem]:
        return [_item(row) for row in self._json(["ready", "--limit", "0"]) or []]

    def add_dependency(self, item_id: str, depends_on: str) -> None:
        # `bd dep add A B`: A depends on (is blocked by) B.
        self._json(["dep", "add", item_id, depends_on])

    def claim_work(self, item_id: str, actor: str) -> WorkItem:
        return _item(_one(self._json(["update", item_id, "--claim"], actor=actor)))

    def claim_next(self, actor: str) -> WorkItem | None:
        rows = self._json(["ready", "--claim"], actor=actor) or []
        return _item(rows[0]) if rows else None

    # Leases: claims carry a 5-minute lease in bd 1.3.1 (not configurable from
    # the CLI). A lease only matters to `bd reclaim`. APTrace's production path
    # never heartbeats or reclaims; these two exist for experiments and for a
    # future supervisor (see docs/work-store.md).

    def heartbeat(self, item_id: str, actor: str) -> None:
        self._json(["heartbeat", item_id], actor=actor)

    def reclaim_stale(self, *, older_than: str = "10m") -> Any:
        """Revert in_progress items whose lease expired at least `older_than` ago."""

        return self._json(["reclaim", "--older-than", older_than])

    def release_work(self, item_id: str, actor: str, reason: str) -> WorkItem:
        return _item(_one(self._json(["unclaim", item_id, "--if-assignee", actor, "--reason", reason], actor=actor)))

    def update_metadata(self, item_id: str, metadata: dict[str, Any]) -> WorkItem:
        # bd 1.3.1 merges --metadata into the existing object (top-level keys).
        self._json(["update", item_id, "--metadata", json.dumps(metadata, sort_keys=True)])
        return self.get_work(item_id)

    def complete_work(self, item_id: str, reason: str, *, actor: str | None = None) -> WorkItem:
        # bd refuses to close another actor's in_progress claim.
        return _item(_one(self._json(["close", item_id, "--reason", reason], actor=actor)))

    # -- history and portability ---------------------------------------------

    def history(self, item_id: str) -> list[dict[str, Any]]:
        return self._json(["history", item_id, "--events"]) or []

    def export_jsonl(self, path: Path) -> Path:
        self._json(["export", "-o", str(path)])
        return path

    def import_jsonl(self, path: Path) -> Any:
        return self._json(["import", str(path)])
