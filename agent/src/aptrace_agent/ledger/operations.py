"""
Typed APTrace operation execution with durable recording and replay.

The replay contract is a typed operation identity (tool + validated
arguments) executed against the current ExecutionContext through the same
EvidenceExecutor the investigator uses. No shell command is persisted.
"""

from __future__ import annotations

import subprocess
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from aptrace_agent.ledger.hashing import digest
from aptrace_agent.ledger.models import (
    EvidenceArtifact,
    ExecutionContext,
    SourceRevision,
    ToolInvocation,
)
from aptrace_agent.ledger.store import ResearchLedger, now
from aptrace_agent.schemas import EvidenceObservation


# Input artifacts each typed operation reads, by context artifact name.
# The firmware image itself is covered by the context firmware_sha256.
TOOL_INPUTS: dict[str, tuple[str, ...]] = {
    "census_peripheral_usage": ("census_db", "svd"),
    "census_common_paths": ("census_db", "svd"),
    "census_usb_inventory": ("census_db", "svd"),
    "function_effects": ("census_db", "svd"),
    "function_facts": ("ghidra_export",),
    "function_disassembly": ("ghidra_export",),
    "callsite_context": ("ghidra_export",),
    "structural_source_agreement": ("census_db", "ghidra_export", "macaw_census"),
    "pin_table_entry": (),
    "search_case_evidence": (),
}

# Operations whose output is a deterministic function of the recorded inputs.
# Case-document search reads mutable prose, so it is recorded but never
# treated as replay-verifiable evidence.
DETERMINISTIC_TOOLS = frozenset(TOOL_INPUTS) - {"search_case_evidence"}

# Results above this size are compared by hash only when a replay differs.
DIFF_LIMIT_BYTES = 16 * 1024 * 1024


class OperationExecutor(Protocol):
    def execute_operation(self, tool: str, arguments: dict, *, evidence_id: str) -> EvidenceObservation: ...


def input_artifacts(context: ExecutionContext, tool: str) -> dict[str, str]:
    return {name: context.artifacts[name] for name in TOOL_INPUTS.get(tool, ()) if name in context.artifacts}


def source_revision(repo: Path) -> SourceRevision:
    def git(*args: str) -> str | None:
        try:
            out = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, timeout=20, check=True)
        except (OSError, subprocess.SubprocessError):
            return None

        return out.stdout

    commit = git("rev-parse", "HEAD")

    if commit is None:
        return SourceRevision()

    status = git("status", "--porcelain") or ""
    dirty = bool(status.strip())
    fingerprint = None

    if dirty:
        untracked = sorted(line[3:] for line in status.splitlines() if line.startswith("??"))
        fingerprint = digest({"diff": git("diff", "HEAD") or "", "untracked": untracked})[:16]

    return SourceRevision(
        git_commit=commit.strip(),
        git_branch=(git("rev-parse", "--abbrev-ref", "HEAD") or "").strip() or None,
        dirty=dirty,
        dirty_fingerprint=fingerprint,
    )


@dataclass
class ReplayResult:
    original: ToolInvocation
    replay: ToolInvocation
    matches: bool
    original_sha256: str | None
    replay_sha256: str | None
    input_drift: dict[str, tuple[str | None, str | None]] = field(default_factory=dict)
    differences: list[str] = field(default_factory=list)


def _differences(old: Any, new: Any, path: str = "", limit: int = 8) -> list[str]:
    """Bounded structural diff of two JSON values, for surfacing changes."""

    out: list[str] = []

    def walk(a: Any, b: Any, p: str) -> None:
        if len(out) >= limit or a == b:
            return

        if isinstance(a, dict) and isinstance(b, dict):
            for key in sorted(set(a) | set(b)):
                walk(a.get(key), b.get(key), f"{p}.{key}" if p else str(key))
            return

        if isinstance(a, list) and isinstance(b, list) and len(a) == len(b):
            for i, (x, y) in enumerate(zip(a, b)):
                walk(x, y, f"{p}[{i}]")
            return

        out.append(f"{p or '<root>'}: {str(a)[:80]!r} -> {str(b)[:80]!r}")

    walk(old, new, path)
    return out


class LedgerOperationRunner:
    """Execute typed operations, recording invocation + evidence durably."""

    def __init__(
        self,
        ledger: ResearchLedger,
        executor: OperationExecutor,
        context: Callable[[], ExecutionContext],
    ) -> None:
        self.ledger = ledger
        self.executor = executor
        self._context = context
        self._seq: dict[str, int] = {}

    def context(self) -> ExecutionContext:
        return self._context()

    def run(
        self,
        run_id: str,
        tool: str,
        arguments: dict[str, Any],
        *,
        input_evidence_ids: Iterable[str] = (),
        replay_of: str | None = None,
    ) -> tuple[ToolInvocation, EvidenceArtifact | None]:
        context = self.context()
        seq = self._seq.get(run_id, 0) + 1
        self._seq[run_id] = seq
        started = now()
        clock = time.perf_counter()
        result: dict[str, Any] | None = None
        error: str | None = None

        try:
            observation = self.executor.execute_operation(tool, dict(arguments), evidence_id=f"E{seq}")
            result = observation.result
        except Exception as exc:  # recorded, not swallowed silently
            error = f"{type(exc).__name__}: {exc}"[:500]

        return self.ledger.record_invocation(
            run_id=run_id,
            seq=seq,
            tool=tool,
            arguments=dict(arguments),
            context=context,
            input_artifacts=input_artifacts(context, tool),
            started_at=started,
            ended_at=now(),
            runtime_ms=round((time.perf_counter() - clock) * 1000, 3),
            result=result,
            error=error,
            input_evidence_ids=input_evidence_ids,
            replayable=tool in DETERMINISTIC_TOOLS,
            replay_of=replay_of,
        )

    def replay(self, invocation_id: str, *, run_id: str) -> ReplayResult:
        """
        Re-execute a recorded invocation's typed operation and compare the
        result hash. Differences are surfaced, never silently accepted.
        """

        original = self.ledger.invocation(invocation_id)

        if not original.replayable:
            raise ValueError(f"{invocation_id} ({original.tool}) is not a deterministic replayable operation")

        context = self.context()
        current_inputs = input_artifacts(context, original.tool)
        drift = {
            name: (original.input_artifacts.get(name), current_inputs.get(name))
            for name in sorted(set(original.input_artifacts) | set(current_inputs))
            if original.input_artifacts.get(name) != current_inputs.get(name)
        }

        if self._firmware_of(original) not in (None, context.firmware_sha256):
            raise ValueError(f"{invocation_id} was produced for a different firmware; refusing cross-firmware replay")

        replay, _artifact = self.run(run_id, original.tool, original.arguments, replay_of=invocation_id)
        differences: list[str] = []

        if replay.status != "ok":
            differences.append(f"replay failed: {replay.error}")
        elif original.result_sha256 and replay.result_sha256 != original.result_sha256:
            if not self.ledger.has_blob(original.result_sha256):
                differences = ["recorded result blob unavailable locally; result hash differs"]
            elif max(self.ledger.blob_size(original.result_sha256), self.ledger.blob_size(replay.result_sha256)) > DIFF_LIMIT_BYTES:
                differences = [
                    f"result hash differs ({original.result_sha256[:12]} -> {replay.result_sha256[:12]}); "
                    "structural diff skipped for a large result"
                ]
            else:
                old, _ok = self.ledger.load_blob(original.result_sha256)
                new, _ok = self.ledger.load_blob(replay.result_sha256)
                differences = _differences(old, new)

        return ReplayResult(
            original=original,
            replay=replay,
            matches=replay.status == "ok" and replay.result_sha256 == original.result_sha256,
            original_sha256=original.result_sha256,
            replay_sha256=replay.result_sha256,
            input_drift=drift,
            differences=differences,
        )

    def _firmware_of(self, invocation: ToolInvocation) -> str | None:
        if invocation.evidence_id and self.ledger.has_evidence(invocation.evidence_id):
            return self.ledger.evidence(invocation.evidence_id).firmware_sha256

        return None
