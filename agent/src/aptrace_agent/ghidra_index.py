from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from aptrace_agent.schemas import CallSite, FunctionFacts


DEFAULT_MAX_EDGES = 25


@dataclass(frozen=True)
class RejectedCallEdge:
    from_function: str
    to_function: str
    address: str
    reason: str


class GhidraIndex:
    def __init__(self, artifact: Path):
        self.artifact = artifact
        self._functions: dict[str, dict[str, Any]] = {}
        self._callers: dict[str, list[CallSite]] = {}
        self._callees: dict[str, list[CallSite]] = {}
        self._rejected_edges: list[RejectedCallEdge] = []

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
        records = list(self._walk(data))

        for record in records:
            name = record.get("name")
            entry = record.get("entry")

            if (
                isinstance(name, str)
                and isinstance(entry, str)
                and name.startswith("FUN_")
            ):
                self._functions.setdefault(name, record)

        seen_edges: set[tuple[str, str, str]] = set()

        for record in records:
            from_fn = record.get("fromFunction")
            to_fn = record.get("toFunction")
            from_addr = record.get("from")

            if not (
                isinstance(from_fn, str)
                and isinstance(to_fn, str)
                and isinstance(from_addr, str)
            ):
                continue

            edge = (
                from_fn,
                to_fn,
                from_addr,
            )

            if edge in seen_edges:
                continue

            seen_edges.add(edge)

            reason = self._caller_range_problem(
                from_fn,
                from_addr,
            )

            if reason is not None:
                self._rejected_edges.append(
                    RejectedCallEdge(
                        from_function=from_fn,
                        to_function=to_fn,
                        address=from_addr,
                        reason=reason,
                    )
                )
                continue

            self._callers.setdefault(
                to_fn,
                [],
            ).append(
                CallSite(
                    function=from_fn,
                    address=from_addr,
                )
            )

            self._callees.setdefault(
                from_fn,
                [],
            ).append(
                CallSite(
                    function=to_fn,
                    address=from_addr,
                )
            )

    def _caller_range_problem(
        self,
        function: str,
        address: str,
    ) -> str | None:
        record = self._functions.get(function)

        if record is None:
            return None

        entry_raw = record.get("entry")
        size_raw = record.get("size")

        if not isinstance(entry_raw, str):
            return None

        if not isinstance(size_raw, int):
            return None

        try:
            entry = int(entry_raw, 16)
            callsite = int(address, 16)
        except ValueError:
            return None

        end = entry + size_raw

        if entry <= callsite < end:
            return None

        return (
            f"callsite {address} lies outside "
            f"{function} range "
            f"0x{entry:08x}..0x{end:08x}"
        )

    def rejected_edges(
        self,
        *,
        to_function: str | None = None,
    ) -> list[RejectedCallEdge]:
        if to_function is None:
            return list(self._rejected_edges)

        return [
            edge
            for edge in self._rejected_edges
            if edge.to_function == to_function
        ]

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
            unique_caller_count=len(
                {x.function for x in callers}
            ),
            callsite_count=len(callers),
            unique_callee_count=len(
                {x.function for x in callees}
            ),
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
