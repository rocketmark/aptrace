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
        # Export name -> canonical FUN_<entry> identity. A seeded project
        # export may carry provenance labels; APTrace evidence names
        # functions by entry (the census convention), so labels are mapped.
        self._canonical: dict[str, str] = {}

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
            elif (
                isinstance(name, str)
                and isinstance(entry, str)
                and "size" in record
                and "thunk" in record
            ):
                canonical = f"FUN_{int(entry, 16):08x}"
                self._canonical.setdefault(name, canonical)
                self._functions.setdefault(canonical, {**record, "name": canonical, "label": name})

        seen_edges: set[tuple[str, str, str]] = set()

        for record in records:
            from_fn = self._canonical.get(record.get("fromFunction"), record.get("fromFunction"))
            to_fn = self._canonical.get(record.get("toFunction"), record.get("toFunction"))
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


AUTOPILOT_GHIDRA_KEY = "autopilot868"


class GhidraCacheStale(RuntimeError):
    pass


def _aptrace_ghidra():
    import sys

    tools = Path(__file__).resolve().parents[3] / "tools" / "ghidra"

    if str(tools) not in sys.path:
        sys.path.insert(0, str(tools))

    import aptrace_ghidra

    return aptrace_ghidra


def ghidra_cache_identity(key: str = AUTOPILOT_GHIDRA_KEY) -> dict[str, Any]:
    """
    The persistent Ghidra project's recorded identity (meta.json), after
    checking it against the current firmware, build scripts and generated
    seeds. A stale cache is refused, never silently used.

    When analyzeHeadless is not installed the installed Ghidra version
    cannot be compared; every other identity field still is.
    """

    ag = _aptrace_ghidra()

    try:
        state, meta, expected = ag.cache_status(key)
    except SystemExit:
        meta = ag.read_meta(key)

        if meta is None:
            raise GhidraCacheStale(f"Ghidra cache for {key} has not been built")

        path, _base, _labels = ag.firmware_info(key)
        expected = dict(meta, firmware_sha256=ag.sha256_of(path))

        for script in ag.BUILD_SCRIPTS:
            expected[f"script_sha256:{script}"] = ag._file_identity_hash(ag.SCRIPTS_DIR / script)

        if ag.seed_file(key).exists():
            expected["derived_seeds_sha256"] = ag.sha256_of(ag.seed_file(key))

        state = "fresh" if meta == expected else "stale"

    if state != "fresh":
        changed = sorted(k for k in expected if (meta or {}).get(k) != expected[k])
        raise GhidraCacheStale(
            f"Ghidra cache for {key} is {state} ({', '.join(changed) or 'not built'}); "
            f"run tools/ghidra/aptrace_ghidra.py rebuild {key}"
        )

    return dict(meta)


def ghidra_cache_paths(key: str = AUTOPILOT_GHIDRA_KEY) -> dict[str, Path]:
    cache = _aptrace_ghidra().cache_dir(key)
    return {
        "static_export": cache / "static_export.json",
        "census_export": cache / "census_export.json",
        "meta": cache / "meta.json",
    }


def autopilot_ghidra_index() -> GhidraIndex:
    """
    Ghidra index over the persistent, seeded Ghidra project export: the
    same Ghidra analysis the census is built from (vector table plus the
    generated function-pointer seeds), checked fresh before use.

    The legacy one-shot export under research/runs/ghidra/ was produced
    without the generated seeds and is no longer read here.
    """

    ghidra_cache_identity()
    artifact = ghidra_cache_paths()["static_export"]

    if not artifact.is_file():
        raise FileNotFoundError(artifact)

    return GhidraIndex(artifact)
