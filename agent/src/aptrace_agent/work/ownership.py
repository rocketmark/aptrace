"""
Host-local ownership of a work item while APTrace executes it.

A Beads claim records who is assigned the work, but it cannot say whether
that work is still executing: the same actor may re-claim idempotently, and
a claim's lease only matters to `bd reclaim`. So every APTrace process that
executes, reconciles, or completes a work item holds an exclusive advisory
lock (flock) on a per-item file for the whole operation. The kernel drops
the lock when the process exits for any reason, so "the lock is free" is an
exact statement that no process on this host is executing the item.

The lock is host-local. It says nothing about processes on other hosts,
which is why an attempt recorded by another host is treated as possibly
active (see handoff.reconcile).
"""

from __future__ import annotations

import fcntl
import json
import os
import re
import socket
from datetime import datetime, timezone
from pathlib import Path
from typing import IO, Any

from aptrace_agent.work.store import WorkActive


_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


def hostname() -> str:
    return socket.gethostname()


class ItemLock:
    def __init__(self, directory: Path, item_id: str) -> None:
        if not _SAFE_ID.match(item_id):
            raise ValueError(f"unsupported work item id {item_id!r}")

        self.path = Path(directory) / f"{item_id}.lock"
        self._file: IO[str] | None = None

    @property
    def held(self) -> bool:
        return self._file is not None

    def holder(self) -> dict[str, Any]:
        """Diagnostic: who last wrote the lock file (pid, host, time)."""

        try:
            return json.loads(self.path.read_text() or "{}")
        except (OSError, ValueError):
            return {}

    def acquire(self) -> ItemLock:
        if self._file is not None:
            return self

        self.path.parent.mkdir(parents=True, exist_ok=True)
        handle = self.path.open("a+", encoding="utf-8")

        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            handle.close()
            holder = self.holder()
            raise WorkActive(
                f"work item {self.path.stem} is held by another APTrace process "
                f"(pid {holder.get('pid', '?')} on {holder.get('host', '?')} since {holder.get('at', '?')})"
            ) from None

        handle.seek(0)
        handle.truncate()
        handle.write(json.dumps({"pid": os.getpid(), "host": hostname(), "at": datetime.now(timezone.utc).isoformat(timespec="seconds")}))
        handle.flush()
        self._file = handle
        return self

    def release(self) -> None:
        if self._file is None:
            return

        try:
            fcntl.flock(self._file, fcntl.LOCK_UN)
        finally:
            self._file.close()
            self._file = None

    def probe(self) -> bool:
        """True if another process holds the lock. Never keeps it."""

        if self._file is not None:
            return False

        try:
            self.acquire()
        except WorkActive:
            return True

        self.release()
        return False

    def __enter__(self) -> ItemLock:
        return self.acquire()

    def __exit__(self, *_exc: object) -> None:
        self.release()
