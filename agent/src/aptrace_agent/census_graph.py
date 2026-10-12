from __future__ import annotations

import collections
import re
import sqlite3
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field


ANALYSIS_NAME = "census_common_paths"
ANALYSIS_VERSION = 1

# APTrace-owned bounds. Callers never choose these.
MAX_SET_SIZE = 16
MAX_HOPS = 8
MAX_COMMON = 8
MAX_SHARED_STATE = 6
MAX_FRONTIER = 6
MAX_PATH = 6
# A common descendant called from at least this many distinct functions
# firmware-wide is flagged as a shared utility rather than a convergence
# point specific to the two sets.
SHARED_UTILITY_FAN_IN = 8

_FUNCTION_RE = re.compile(r"FUN_([0-9a-f]{8})")


class PathStatus(StrEnum):
    KNOWN_COMMON_PATH = "KNOWN_COMMON_PATH"
    # Every known common descendant is a widely shared utility.
    SHARED_UTILITIES_ONLY = "SHARED_UTILITIES_ONLY"
    NO_KNOWN_PATH = "NO_KNOWN_PATH"
    CENSUS_UNAVAILABLE = "CENSUS_UNAVAILABLE"
    NO_RESOLVABLE_INPUT = "NO_RESOLVABLE_INPUT"


class SetMember(BaseModel):
    function: str
    census_name: str
    reachability: str | None = None
    roots: list[str] = Field(default_factory=list)


class Convergence(BaseModel):
    function: str
    census_name: str
    hops_left: int
    hops_right: int
    path_left: list[str]
    path_right: list[str]
    fan_in: int
    shared_utility: bool


class SharedState(BaseModel):
    address: str
    left: str  # READ / WRITE / READ+WRITE
    right: str
    left_functions: list[str]
    right_functions: list[str]


class UnresolvedSite(BaseModel):
    site: str
    function: str | None
    side: str  # left / right / both
    kind: str


class ResolvedIndirectEdge(BaseModel):
    """
    A graph edge recovered from a statically initialized RAM function
    pointer (census `resolved_function_pointers`), never a direct call:
    the consumer site loads its target from `slot`, whose known store(s)
    hold the constant `raw_value`.
    """

    edge_kind: str = "resolved_indirect"
    site: str
    from_function: str
    to_function: str
    slot: str
    raw_value: str
    canonical_target: str
    terminal_target: str | None = None
    store: str
    writer: str | None = None
    derivation: str | None = None
    callsite: str | None = None
    arg_reg: str | None = None
    confidence: str


class CommonPathResult(BaseModel):
    """
    Bounded convergence analysis of two function sets over the census
    call graph.

    Edges are the census "strong" graph: resolved direct control transfers
    between functions plus indirect targets the census resolved statically
    or observed dynamically. Absence of a common path is reported as
    NO_KNOWN_PATH, never as unreachability; unresolved indirect transfers
    inside the explored region are listed as the frontier where a path
    could still exist.
    """

    status: PathStatus
    left_label: str
    right_label: str
    left: list[SetMember] = Field(default_factory=list)
    right: list[SetMember] = Field(default_factory=list)
    unknown_inputs: list[str] = Field(default_factory=list)
    explored_left: int = 0
    explored_right: int = 0
    max_hops: int = MAX_HOPS
    hop_limited: bool = False
    common_total: int = 0
    common: list[Convergence] = Field(default_factory=list)
    shared_state_total: int = 0
    shared_state: list[SharedState] = Field(default_factory=list)
    frontier_total: int = 0
    frontier: list[UnresolvedSite] = Field(default_factory=list)
    resolved_indirect_edges: list[ResolvedIndirectEdge] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    provenance: dict[str, Any] = Field(default_factory=dict)
    planner_summary: str = ""


_LIMITATIONS = [
    "Graph edges are the census strong graph (resolved direct transfers plus "
    "statically resolved or dynamically observed indirect targets); "
    "unresolved indirect transfers are frontier, not edges.",
    "resolved_indirect edges come from statically initialized RAM function "
    "pointers whose every known store is one constant code pointer; stores "
    "through computed pointers are not excluded.",
    "NO_KNOWN_PATH means no path this census can construct within the hop "
    "bound; it is not a proof of unreachability.",
    "Shared RAM state is from constant-address accesses only; "
    "pointer-based accesses are not attributed.",
]


@dataclass
class _Graph:
    names: dict[int, str]  # function id -> census name
    entries: dict[int, int]  # function id -> entry
    sizes: dict[int, int]
    by_entry: dict[int, int]  # entry -> function id
    adjacency: dict[int, set[int]]
    fan_in: dict[int, int]
    unresolved: dict[int, list[tuple[int, str]]]  # function id -> [(site, kind)]
    reachability: dict[int, str]
    root_reach: dict[int, list[str]]  # function id -> vector-root labels
    ram_access: dict[int, dict[int, set[str]]]  # function id -> addr -> {READ, WRITE}
    dispatch: dict[int, list[int]] = field(default_factory=dict)  # function id -> table-branch sites
    resolved_indirect: dict[int, list[ResolvedIndirectEdge]] = field(default_factory=dict)  # source fid -> edges
    vector_root_count: int = 0
    sources: list[str] = field(default_factory=list)


def _fn(entry: int) -> str:
    return f"FUN_{entry:08x}"


class CensusGraph:
    """
    Read-only, bounded call-graph questions over an existing census.

    APTrace binds the firmware identity and database at construction.
    Callers name functions only; hop limits, result sizes and edge
    semantics are fixed here. The graph is loaded once per process.
    """

    def __init__(
        self,
        *,
        firmware_key: str,
        db_path: Path,
        expected_sha256: str,
        irq_label: Callable[[int], str | None] = lambda _irq: None,
    ) -> None:
        self.firmware_key = firmware_key
        self.db_path = Path(db_path)
        self.expected_sha256 = expected_sha256.lower()
        self.irq_label = irq_label
        self._graph: _Graph | None = None
        self._unavailable: str | None = None

    # -- loading ------------------------------------------------------------

    def _load(self) -> _Graph | None:
        if self._graph is not None or self._unavailable is not None:
            return self._graph

        if not self.db_path.is_file():
            self._unavailable = "no census database has been prepared"
            return None

        conn = sqlite3.connect(f"{self.db_path.resolve().as_uri()}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row

        try:
            firmware = conn.execute(
                "SELECT id, sha256, ram_base, ram_size FROM firmware WHERE key=?",
                (self.firmware_key,),
            ).fetchone()

            if firmware is None or str(firmware["sha256"]).lower() != self.expected_sha256:
                self._unavailable = "census missing or built from a different firmware image"
                return None

            self._graph = self._build(conn, int(firmware["id"]), int(firmware["ram_base"]), int(firmware["ram_size"]))
            return self._graph
        finally:
            conn.close()

    def _build(self, conn: sqlite3.Connection, fw: int, ram_base: int, ram_size: int) -> _Graph:
        names: dict[int, str] = {}
        entries: dict[int, int] = {}
        sizes: dict[int, int] = {}
        spans: list[tuple[int, int, int]] = []

        for row in conn.execute("SELECT id, entry, name, size FROM functions WHERE firmware_id=?", (fw,)):
            names[row["id"]] = row["name"]
            entries[row["id"]] = row["entry"]
            sizes[row["id"]] = row["size"]
            spans.append((row["entry"], row["entry"] + max(row["size"], 1), row["id"]))

        spans.sort()
        block_owner = {
            row["start_addr"]: row["function_id"]
            for row in conn.execute(
                "SELECT start_addr, function_id FROM basic_blocks WHERE firmware_id=? AND function_id IS NOT NULL",
                (fw,),
            )
        }

        def owner(addr: int) -> int | None:
            row = conn.execute(
                "SELECT function_id FROM basic_blocks WHERE firmware_id=? AND ? BETWEEN start_addr AND end_addr "
                "AND function_id IS NOT NULL ORDER BY start_addr LIMIT 1",
                (fw, addr),
            ).fetchone()

            if row is not None:
                return row["function_id"]

            for start, end, fid in spans:
                if start <= addr < end:
                    return fid

            return block_owner.get(addr)

        adjacency: dict[int, set[int]] = collections.defaultdict(set)

        # Same edge semantics as tools/census/reachability.py's strong graph.
        for row in conn.execute(
            "SELECT from_function_id, to_function_id FROM edges WHERE firmware_id=? AND resolved=1 "
            "AND source LIKE 'ghidra%' AND from_function_id IS NOT NULL AND to_function_id IS NOT NULL",
            (fw,),
        ):
            if row["from_function_id"] != row["to_function_id"]:
                adjacency[row["from_function_id"]].add(row["to_function_id"])

        for row in conn.execute(
            "SELECT from_addr, candidate_function_id FROM indirect_edge_candidates WHERE firmware_id=? "
            "AND confidence IN ('EXACT','STRONG') AND candidate_function_id IS NOT NULL",
            (fw,),
        ):
            source = owner(row["from_addr"])

            if source is not None and source != row["candidate_function_id"]:
                adjacency[source].add(row["candidate_function_id"])

        resolved_indirect, resolved_sites = self._resolved_indirect(conn, fw, entries, owner)

        fan_in: dict[int, int] = collections.Counter()

        for source, targets in adjacency.items():
            for target in targets:
                fan_in[target] += 1

        unresolved: dict[int, list[tuple[int, str]]] = collections.defaultdict(list)
        seen_sites: set[int] = set()

        for row in conn.execute(
            "SELECT from_addr, from_function_id, instr_shape FROM indirect_edge_resolutions "
            "WHERE firmware_id=? AND classification='UNRESOLVED' ORDER BY from_addr",
            (fw,),
        ):
            fid = row["from_function_id"] or owner(row["from_addr"])

            if fid is not None:
                unresolved[fid].append((row["from_addr"], f"unresolved {row['instr_shape']}"))
                seen_sites.add(row["from_addr"])

        for row in conn.execute(
            "SELECT from_addr, from_function_id, kind FROM edges WHERE firmware_id=? AND resolved=0 ORDER BY from_addr",
            (fw,),
        ):
            if row["from_addr"] in seen_sites or row["from_addr"] in resolved_sites:
                continue

            fid = row["from_function_id"] or owner(row["from_addr"])

            if fid is not None:
                unresolved[fid].append((row["from_addr"], row["kind"]))
                seen_sites.add(row["from_addr"])

        dispatch: dict[int, list[int]] = collections.defaultdict(list)

        for row in conn.execute(
            "SELECT from_addr, from_function_id FROM indirect_edge_resolutions "
            "WHERE firmware_id=? AND instr_shape='table-branch' ORDER BY from_addr",
            (fw,),
        ):
            fid = row["from_function_id"] or owner(row["from_addr"])

            if fid is not None:
                dispatch[fid].append(row["from_addr"])

        reachability = {
            row["function_id"]: row["status"]
            for row in conn.execute(
                "SELECT function_id, status FROM function_reachability WHERE firmware_id=?", (fw,)
            )
        }

        vector_roots: list[tuple[int, str]] = []

        for row in conn.execute(
            "SELECT r.function_id, r.root_kind, v.vector_index FROM reachability_roots r "
            "LEFT JOIN vectors v ON v.firmware_id=r.firmware_id AND v.target_addr=r.addr "
            "WHERE r.firmware_id=? AND r.root_kind IN ('reset-vector','system-vector','irq-vector') "
            "AND r.function_id IS NOT NULL ORDER BY r.addr, v.vector_index",
            (fw,),
        ):
            if row["root_kind"] == "reset-vector":
                label = "reset"
            elif row["root_kind"] == "irq-vector" and row["vector_index"] is not None:
                irq = row["vector_index"] - 16
                label = self.irq_label(irq) or f"IRQ{irq}"
            else:
                label = "system-exception"

            vector_roots.append((row["function_id"], label))

        root_reach: dict[int, list[str]] = collections.defaultdict(list)

        for root, label in vector_roots:
            for fid in _bfs(adjacency, {root}, limit=None):
                if label not in root_reach[fid]:
                    root_reach[fid].append(label)

        ram_access: dict[int, dict[int, set[str]]] = collections.defaultdict(lambda: collections.defaultdict(set))

        for row in conn.execute(
            "SELECT from_function_id, to_addr, direction FROM memory_accesses WHERE firmware_id=? "
            "AND from_function_id IS NOT NULL AND direction IN ('READ','WRITE') AND to_addr >= ? AND to_addr < ?",
            (fw, ram_base, ram_base + ram_size),
        ):
            ram_access[row["from_function_id"]][row["to_addr"]].add(row["direction"])

        return _Graph(
            names=names,
            entries=entries,
            sizes=sizes,
            by_entry={entry: fid for fid, entry in entries.items()},
            adjacency=dict(adjacency),
            fan_in=dict(fan_in),
            unresolved=dict(unresolved),
            reachability=reachability,
            root_reach=dict(root_reach),
            ram_access={fid: dict(acc) for fid, acc in ram_access.items()},
            dispatch=dict(dispatch),
            resolved_indirect=resolved_indirect,
            vector_root_count=len(vector_roots),
            sources=["census-edges", "census-indirect-candidates", "census-reachability", "census-memory-accesses"]
            + (["census-resolved-function-pointers"] if resolved_indirect else []),
        )

    @staticmethod
    def _resolved_indirect(
        conn: sqlite3.Connection,
        fw: int,
        entries: dict[int, int],
        owner: Callable[[int], int | None],
    ) -> tuple[dict[int, list[ResolvedIndirectEdge]], set[int]]:
        """STRONG RAM function-pointer candidates, with their store provenance."""

        out: dict[int, list[ResolvedIndirectEdge]] = collections.defaultdict(list)
        sites: set[int] = set()

        try:
            rows = conn.execute(
                "SELECT c.from_addr, c.candidate_function_id, c.confidence, r.slot_addr, r.raw_value, "
                "r.canonical_target, r.terminal_target, r.store_addr, r.writer_function_id, r.derivation, "
                "r.callsite_addr, r.arg_reg FROM indirect_edge_candidates c JOIN resolved_function_pointers r "
                "ON r.firmware_id=c.firmware_id AND r.consumer_site=c.from_addr AND r.canonical_target=c.candidate_addr "
                "WHERE c.firmware_id=? AND c.source='ram-fnptr-constant-store' AND c.confidence='STRONG' "
                "AND c.candidate_function_id IS NOT NULL AND r.value_kind='constant' ORDER BY c.from_addr, r.store_addr",
                (fw,),
            ).fetchall()
        except sqlite3.OperationalError:  # census predating resolved_function_pointers
            return {}, set()

        hx = lambda v: None if v is None else f"0x{v:08x}"  # noqa: E731

        for row in rows:
            source = owner(row["from_addr"])

            if source is None:
                continue

            sites.add(row["from_addr"])
            writer = entries.get(row["writer_function_id"])
            out[source].append(
                ResolvedIndirectEdge(
                    site=hx(row["from_addr"]),
                    from_function=_fn(entries[source]),
                    to_function=_fn(entries[row["candidate_function_id"]]),
                    slot=hx(row["slot_addr"]),
                    raw_value=hx(row["raw_value"]),
                    canonical_target=hx(row["canonical_target"]),
                    terminal_target=hx(row["terminal_target"]),
                    store=hx(row["store_addr"]),
                    writer=None if writer is None else _fn(writer),
                    derivation=row["derivation"],
                    callsite=hx(row["callsite_addr"]),
                    arg_reg=row["arg_reg"],
                    confidence=row["confidence"],
                )
            )

        return dict(out), sites

    # -- public API ---------------------------------------------------------

    def function_entry(self, name: str) -> int | None:
        graph = self._load()
        match = _FUNCTION_RE.fullmatch(str(name))

        if graph is None or match is None:
            return None

        entry = int(match.group(1), 16)
        return entry if entry in graph.by_entry else None

    def common_paths(
        self,
        left: Sequence[str],
        right: Sequence[str],
        *,
        left_label: str = "left",
        right_label: str = "right",
    ) -> CommonPathResult:
        graph = self._load()
        base = dict(left_label=str(left_label)[:40], right_label=str(right_label)[:40], max_hops=MAX_HOPS)

        if graph is None:
            result = CommonPathResult(status=PathStatus.CENSUS_UNAVAILABLE, **base)
            result.planner_summary = f"common paths {result.left_label}|{result.right_label}: census unavailable ({self._unavailable})"
            return result

        unknown: list[str] = []

        def resolve(names: Iterable[str]) -> list[int]:
            ids: list[int] = []

            for name in list(dict.fromkeys(str(n) for n in names))[:MAX_SET_SIZE]:
                match = _FUNCTION_RE.fullmatch(name)
                fid = graph.by_entry.get(int(match.group(1), 16)) if match else None

                if fid is None:
                    unknown.append(name[:40])
                elif fid not in ids:
                    ids.append(fid)

            return ids

        left_ids = resolve(left)
        right_ids = resolve(right)
        members = lambda ids: [self._member(graph, fid) for fid in ids]  # noqa: E731

        result = CommonPathResult(
            status=PathStatus.NO_KNOWN_PATH,
            left=members(left_ids),
            right=members(right_ids),
            unknown_inputs=unknown,
            limitations=list(_LIMITATIONS),
            provenance={
                "analysis": ANALYSIS_NAME,
                "analysis_version": ANALYSIS_VERSION,
                "firmware_key": self.firmware_key,
                "firmware_sha256": self.expected_sha256,
                "sources": graph.sources,
                "edge_semantics": "strong (ghidra resolved + EXACT/STRONG indirect)",
                "vector_roots": graph.vector_root_count,
            },
            **base,
        )

        if not left_ids or not right_ids:
            result.status = PathStatus.NO_RESOLVABLE_INPUT
            result.planner_summary = (
                f"common paths {result.left_label}|{result.right_label}: no census function in "
                f"{'left' if not left_ids else 'right'} set (unknown: {', '.join(unknown[:4])})"
            )
            return result

        dist_left, parent_left, limited_left = _bfs_tree(graph.adjacency, left_ids, MAX_HOPS)
        dist_right, parent_right, limited_right = _bfs_tree(graph.adjacency, right_ids, MAX_HOPS)
        result.explored_left = len(dist_left)
        result.explored_right = len(dist_right)
        result.hop_limited = limited_left or limited_right

        common_ids = set(dist_left) & set(dist_right)
        ranked = sorted(
            common_ids,
            key=lambda fid: (
                graph.fan_in.get(fid, 0) >= SHARED_UTILITY_FAN_IN,
                max(dist_left[fid], dist_right[fid]),
                dist_left[fid] + dist_right[fid],
                graph.entries[fid],
            ),
        )
        result.common_total = len(ranked)
        result.common = [
            Convergence(
                function=_fn(graph.entries[fid]),
                census_name=graph.names[fid],
                hops_left=dist_left[fid],
                hops_right=dist_right[fid],
                path_left=_path(graph, parent_left, fid),
                path_right=_path(graph, parent_right, fid),
                fan_in=graph.fan_in.get(fid, 0),
                shared_utility=graph.fan_in.get(fid, 0) >= SHARED_UTILITY_FAN_IN,
            )
            for fid in ranked[:MAX_COMMON]
        ]

        if any(not item.shared_utility for item in result.common):
            result.status = PathStatus.KNOWN_COMMON_PATH
        elif ranked:
            result.status = PathStatus.SHARED_UTILITIES_ONLY

        # Shared RAM state between the two sides' exclusive regions: the
        # usual ISR-to-main-loop channel, invisible to call-graph paths.
        only_left = set(dist_left) - common_ids
        only_right = set(dist_right) - common_ids
        shared = _shared_state(graph, only_left, only_right)
        result.shared_state_total = len(shared)
        result.shared_state = shared[:MAX_SHARED_STATE]

        frontier: list[UnresolvedSite] = []

        for fid in sorted(set(dist_left) | set(dist_right), key=lambda f: graph.entries[f]):
            side = "both" if fid in common_ids else ("left" if fid in dist_left else "right")

            for site, kind in graph.unresolved.get(fid, []):
                frontier.append(
                    UnresolvedSite(site=f"0x{site:08x}", function=_fn(graph.entries[fid]), side=side, kind=kind)
                )

        result.frontier_total = len(frontier)
        result.frontier = frontier[:MAX_FRONTIER]
        result.resolved_indirect_edges = [
            edge
            for fid in sorted(set(dist_left) | set(dist_right), key=lambda f: graph.entries[f])
            for edge in graph.resolved_indirect.get(fid, [])
        ]
        result.planner_summary = _summary(result)
        return result

    def downstream(self, names: Sequence[str], max_hops: int = MAX_HOPS) -> dict[str, int]:
        """Functions reachable from the named set: name -> hops."""

        graph = self._load()

        if graph is None:
            return {}

        ids = [
            graph.by_entry[int(m.group(1), 16)]
            for name in names
            if (m := _FUNCTION_RE.fullmatch(str(name))) and int(m.group(1), 16) in graph.by_entry
        ]
        dist, _parent, _limited = _bfs_tree(graph.adjacency, ids, max_hops)
        return {_fn(graph.entries[fid]): hops for fid, hops in dist.items()}

    def resolved_indirect_edges(self, names: Iterable[str]) -> list[ResolvedIndirectEdge]:
        """Pointer-derived (resolved_indirect) edges leaving the named functions."""

        graph = self._load()

        if graph is None:
            return []

        out: list[ResolvedIndirectEdge] = []

        for name in dict.fromkeys(names):
            entry = self.function_entry(name)

            if entry is not None:
                out.extend(graph.resolved_indirect.get(graph.by_entry[entry], []))

        return out

    def dispatch_sites(self, name: str) -> list[str]:
        """Table-branch (switch) dispatch sites inside a function."""

        graph = self._load()
        entry = self.function_entry(name)

        if graph is None or entry is None:
            return []

        return [f"0x{site:08x}" for site in graph.dispatch.get(graph.by_entry[entry], [])]

    def containing_function(self, address: int) -> str | None:
        """Census function whose [entry, entry+size) contains an address."""

        graph = self._load()

        if graph is None:
            return None

        for fid, entry in graph.entries.items():
            if entry <= address < entry + max(graph.sizes.get(fid, 1), 1):
                return f"{graph.names[fid]}@{_fn(entry)}"

        return None

    def unresolved_sites(self, name: str) -> list[tuple[str, str]]:
        graph = self._load()
        entry = self.function_entry(name)

        if graph is None or entry is None:
            return []

        return [(f"0x{site:08x}", kind) for site, kind in graph.unresolved.get(graph.by_entry[entry], [])]

    def member(self, name: str) -> SetMember | None:
        graph = self._load()
        entry = self.function_entry(name)

        if graph is None or entry is None:
            return None

        return self._member(graph, graph.by_entry[entry])

    def census_name(self, name: str) -> str | None:
        graph = self._load()
        entry = self.function_entry(name)
        return None if graph is None or entry is None else graph.names[graph.by_entry[entry]]

    @staticmethod
    def _member(graph: _Graph, fid: int) -> SetMember:
        return SetMember(
            function=_fn(graph.entries[fid]),
            census_name=graph.names[fid],
            reachability=graph.reachability.get(fid),
            roots=_compact_roots(graph.root_reach.get(fid, [])),
        )


def _bfs(adjacency: dict[int, set[int]], start: set[int], limit: int | None) -> dict[int, int]:
    dist, _parent, _limited = _bfs_tree(adjacency, start, limit)
    return dist


def _bfs_tree(
    adjacency: dict[int, set[int]],
    start: Iterable[int],
    limit: int | None,
) -> tuple[dict[int, int], dict[int, int | None], bool]:
    dist: dict[int, int] = {}
    parent: dict[int, int | None] = {}
    queue: collections.deque[int] = collections.deque()

    for fid in sorted(set(start)):
        dist[fid] = 0
        parent[fid] = None
        queue.append(fid)

    limited = False

    while queue:
        node = queue.popleft()

        for nxt in sorted(adjacency.get(node, ())):
            if nxt in dist:
                continue

            if limit is not None and dist[node] + 1 > limit:
                limited = True
                continue

            dist[nxt] = dist[node] + 1
            parent[nxt] = node
            queue.append(nxt)

    return dist, parent, limited


def _path(graph: _Graph, parent: dict[int, int | None], fid: int) -> list[str]:
    chain: list[str] = []
    node: int | None = fid

    while node is not None:
        chain.append(_fn(graph.entries[node]))
        node = parent.get(node)

    chain.reverse()

    if len(chain) > MAX_PATH:
        chain = chain[:2] + ["..."] + chain[-(MAX_PATH - 3):]

    return chain


def _shared_state(graph: _Graph, left: set[int], right: set[int]) -> list[SharedState]:
    def side(ids: set[int]) -> dict[int, tuple[set[str], set[int]]]:
        out: dict[int, tuple[set[str], set[int]]] = {}

        for fid in ids:
            for addr, directions in graph.ram_access.get(fid, {}).items():
                dirs, fns = out.setdefault(addr, (set(), set()))
                dirs.update(directions)
                fns.add(fid)

        return out

    left_side = side(left)
    right_side = side(right)
    shared: list[SharedState] = []

    for addr in sorted(set(left_side) & set(right_side)):
        ldirs, lfns = left_side[addr]
        rdirs, rfns = right_side[addr]

        # Only a write on one side and any access on the other is a channel.
        if "WRITE" not in ldirs and "WRITE" not in rdirs:
            continue

        shared.append(
            SharedState(
                address=f"0x{addr:08x}",
                left="+".join(sorted(ldirs)),
                right="+".join(sorted(rdirs)),
                left_functions=[_fn(graph.entries[f]) for f in sorted(lfns, key=graph.entries.get)][:3],
                right_functions=[_fn(graph.entries[f]) for f in sorted(rfns, key=graph.entries.get)][:3],
            )
        )

    # Cross-direction channels (one side writes, the other reads) first.
    shared.sort(key=lambda s: (not (("WRITE" in s.left) != ("WRITE" in s.right)), s.address))
    return shared


_NUMBERED = re.compile(r"^(.*?)(\d+)$")


def _compact_roots(labels: list[str]) -> list[str]:
    """Collapse numbered root labels into ranges: EIC_EXTINT_0..15."""

    groups: dict[str, list[int]] = {}
    plain: list[str] = []

    for label in labels:
        match = _NUMBERED.match(label)

        if match:
            groups.setdefault(match.group(1), []).append(int(match.group(2)))
        elif label not in plain:
            plain.append(label)

    out = list(plain)

    for prefix, numbers in groups.items():
        numbers = sorted(set(numbers))
        start = prev = numbers[0]

        for number in numbers[1:] + [None]:
            if number is not None and number == prev + 1:
                prev = number
                continue

            out.append(f"{prefix}{start}" if start == prev else f"{prefix}{start}..{prev}")

            if number is not None:
                start = prev = number

    if len(out) > 5:
        out = out[:4] + [f"+{len(out) - 4} more"]

    return out


def _summary(result: CommonPathResult) -> str:
    left_names = ",".join(m.function for m in result.left[:4]) + ("..." if len(result.left) > 4 else "")
    right_names = ",".join(m.function for m in result.right[:4]) + ("..." if len(result.right) > 4 else "")
    lines = [
        f"common paths {result.left_label}[{left_names}] | {result.right_label}[{right_names}] "
        f"(census strong graph, <= {result.max_hops} hops): {result.status.value}; "
        f"explored {result.explored_left}/{result.explored_right} functions"
        + ("; hop bound reached" if result.hop_limited else "")
    ]

    roots = lambda members: ",".join(sorted({r for m in members for r in m.roots})) or "none known"  # noqa: E731
    lines.append(f"  roots reaching left: {roots(result.left)}; right: {roots(result.right)}")

    specific = [c for c in result.common if not c.shared_utility]
    utility = [c for c in result.common if c.shared_utility]

    for item in specific[:3]:
        lines.append(
            f"  converge at {item.function} ({item.census_name}) hops {item.hops_left}/{item.hops_right} "
            f"via {'>'.join(item.path_left[-3:])} and {'>'.join(item.path_right[-3:])}"
        )

    if utility:
        lines.append(
            f"  shared utilities (fan-in >= {SHARED_UTILITY_FAN_IN}): "
            + ", ".join(f"{c.function}(fan-in {c.fan_in})" for c in utility[:3])
        )

    if result.common_total > len(result.common):
        lines.append(f"  +{result.common_total - len(result.common)} more common descendants retained")

    if result.shared_state:
        lines.append(
            f"  shared RAM ({result.shared_state_total}): "
            + "; ".join(f"{s.address} L:{s.left} R:{s.right}" for s in result.shared_state[:3])
        )

    if result.resolved_indirect_edges:
        lines.append(
            "  resolved_indirect edges (RAM function pointer, not direct calls): "
            + "; ".join(
                f"{e.site} {e.from_function}=>{e.to_function} via RAM {e.slot}={e.raw_value} "
                f"(store {e.store}{f' arg {e.arg_reg}@{e.callsite}' if e.callsite else ''}, {e.confidence})"
                for e in result.resolved_indirect_edges[:2]
            )
        )

    if result.frontier_total:
        lines.append(
            f"  unresolved indirect sites in explored region: {result.frontier_total} "
            f"(e.g. {', '.join(f'{u.site} in {u.function}' for u in result.frontier[:3])}); "
            "paths through them are unknown"
        )

    if result.status in (PathStatus.NO_KNOWN_PATH, PathStatus.SHARED_UTILITIES_ONLY):
        lines.append("  no specific convergence known; this is not proof of unreachability")

    if result.unknown_inputs:
        lines.append(f"  not census functions: {', '.join(result.unknown_inputs[:4])}")

    return "\n".join(lines)
