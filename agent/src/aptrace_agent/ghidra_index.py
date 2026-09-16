from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from aptrace_agent.schemas import CallSite, FunctionFacts


DEFAULT_MAX_EDGES = 25


class GhidraIndex:
    def __init__(self, artifact: Path):
        self.artifact = artifact
        self._functions: dict[str, dict[str, Any]] = {}
        self._callers: dict[str, list[CallSite]] = {}
        self._callees: dict[str, list[CallSite]] = {}

        with artifact.open("r", encoding="utf-8") as f:
            data = json.load(f)

        self._index(data)

    def _walk(self, value: Any):
        if isinstance(value, dict):
            yield value
            for child in value.values():
                yield from self._walk(child)
        elif isinstance(value, list):
            for child in value:
                yield from self._walk(child)

    def _index(self, data: Any) -> None:
        seen_edges: set[tuple[str, str, str]] = set()

        for record in self._walk(data):
            name = record.get("name")
            entry = record.get("entry")

            if (
                isinstance(name, str)
                and isinstance(entry, str)
                and name.startswith("FUN_")
            ):
                self._functions.setdefault(name, record)

            from_fn = record.get("fromFunction")
            to_fn = record.get("toFunction")
            from_addr = record.get("from")

            if (
                isinstance(from_fn, str)
                and isinstance(to_fn, str)
                and isinstance(from_addr, str)
            ):
                edge = (from_fn, to_fn, from_addr)
                if edge in seen_edges:
                    continue
                seen_edges.add(edge)

                self._callers.setdefault(to_fn, []).append(
                    CallSite(
                        function=from_fn,
                        address=from_addr,
                    )
                )

                self._callees.setdefault(from_fn, []).append(
                    CallSite(
                        function=to_fn,
                        address=from_addr,
                    )
                )

    def function_facts(
        self,
        name: str,
        max_edges: int = DEFAULT_MAX_EDGES,
    ) -> FunctionFacts:
        record = self._functions.get(name)

        if record is None:
            raise KeyError(f"Function not found: {name}")

        callers = sorted(
            self._callers.get(name, []),
            key=lambda x: x.address,
        )
        callees = sorted(
            self._callees.get(name, []),
            key=lambda x: x.address,
        )

        return FunctionFacts(
            name=name,
            entry=record["entry"],
            size=record.get("size"),
            callers=callers[:max_edges],
            callees=callees[:max_edges],
            unique_caller_count=len({x.function for x in callers}),
            callsite_count=len(callers),
            unique_callee_count=len({x.function for x in callees}),
            outgoing_callsite_count=len(callees),
            callers_truncated=len(callers) > max_edges,
            callees_truncated=len(callees) > max_edges,
        )


def autopilot_ghidra_index() -> GhidraIndex:
    repo_root = Path(__file__).resolve().parents[3]

    artifact = (
        repo_root
        / "cases"
        / "performing-rigs"
        / "research"
        / "runs"
        / "ghidra"
        / "firmware_autopilot868.json"
    )

    if not artifact.is_file():
        raise FileNotFoundError(artifact)

    return GhidraIndex(artifact)
