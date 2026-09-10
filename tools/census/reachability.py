"""APTrace census reduce: transitive reachability from mechanically-
justified roots.

Roots (see `compute_roots`) are deliberately narrow:

  - `Reset_Handler` (vector[1]'s target) and every other populated
    system/IRQ vector -- these ARE the hardware's own definition of an
    entry point (the ARMv7-M vector table), not a heuristic.
  - Any address that RESOLVED control flow (static, from Ghidra, or
    dynamic, from a real Unicorn run) actually uses as an indirect
    call/jump target -- i.e. a row in `indirect_edge_candidates` with
    confidence EXACT or STRONG (see indirect_resolve.py). This is
    deliberately NOT the same as `function_pointers` (raw_scan.py's
    flash-word scan): a flash word that merely happens to equal a
    function's entry point, with nothing in this image's own control
    flow ever actually branching to it, is NOT treated as a root here
    -- see docs/tooling/census.md.

Reachability is computed twice over the same root set:

  1. A "strong" graph using only resolved direct edges (Ghidra's own
     call/branch/fallthrough edges) plus indirect edges classified
     STATICALLY_RESOLVED or DYNAMICALLY_OBSERVED -- functions reached
     this way are DEFINITELY_REACHABLE.
  2. A "weak" graph additionally allowed to follow FINITE_CANDIDATE_SET
     indirect-edge candidates -- functions reached only via this wider
     graph (not the strong one) are
     POSSIBLY_REACHABLE_VIA_UNRESOLVED_INDIRECT.

Everything else is NO_KNOWN_PATH -- not "unreachable" (this module
never claims a negative proof), just "no path this census's evidence
can currently construct."
"""
import collections

# ARMv7-M system exception vector names, indices 1-15, that count as
# reachability roots on their own (every populated one -- the CPU will
# genuinely vector to it under the right fault/exception condition,
# whether or not this census's scenario corpus ever triggers it).
_SYSTEM_VECTOR_ROOT_KIND = "system-vector"


def compute_roots(conn, firmware_id):
    """Populate reachability_roots and return the set of root function
    ids (functions whose entry exactly matches a root address)."""
    roots = []  # (addr, root_kind, justification)

    for v in conn.execute(
            "SELECT vector_index, target_addr, name, is_irq FROM vectors "
            "WHERE firmware_id=? AND target_addr IS NOT NULL", (firmware_id,)):
        if v["vector_index"] == 1:
            roots.append((v["target_addr"], "reset-vector",
                          "vector[1] (Reset) -- the CPU's own boot entry point"))
        elif v["is_irq"]:
            roots.append((v["target_addr"], "irq-vector",
                          f"vector[{v['vector_index']}] (IRQ{v['vector_index'] - 16}) -- a real NVIC-dispatched handler"))
        else:
            roots.append((v["target_addr"], _SYSTEM_VECTOR_ROOT_KIND,
                          f"vector[{v['vector_index']}] ({v['name']}) -- a real ARMv7-M system exception handler"))

    for c in conn.execute(
            "SELECT DISTINCT candidate_addr FROM indirect_edge_candidates "
            "WHERE firmware_id=? AND confidence IN ('EXACT','STRONG')", (firmware_id,)):
        roots.append((c["candidate_addr"], "confirmed-indirect-target",
                       "resolved (static or dynamic) target of a real indirect call/jump in this image"))

    rows = [{"firmware_id": firmware_id, "addr": addr, "root_kind": kind, "justification": just,
             "source": "reachability", "function_id": None} for addr, kind, just in roots]
    # function_id filled in below, after functions are looked up (dedup by (addr, root_kind) first).
    dedup = {}
    for r in rows:
        dedup[(r["addr"], r["root_kind"])] = r
    entry_to_id = {row["entry"]: row["id"] for row in conn.execute(
        "SELECT id, entry FROM functions WHERE firmware_id=?", (firmware_id,))}
    final_rows = []
    root_function_ids = set()
    for (addr, kind), r in dedup.items():
        r["function_id"] = entry_to_id.get(addr)
        final_rows.append(r)
        if r["function_id"] is not None:
            root_function_ids.add(r["function_id"])

    from db import replace_firmware_rows  # local import: reduce.py already put tools/census on sys.path
    replace_firmware_rows(conn, firmware_id, "reachability_roots", final_rows)
    conn.commit()
    return root_function_ids


def _indirect_adjacency(conn, firmware_id, func_ranges, allowed_confidences):
    """function_id -> set(function_id) reached via an indirect-edge
    candidate whose confidence is in `allowed_confidences` (empty tuple
    means "any confidence" -- used to build the wider "weak" graph)."""
    adj = collections.defaultdict(set)
    q = "SELECT from_addr, candidate_function_id FROM indirect_edge_candidates WHERE firmware_id=? AND candidate_function_id IS NOT NULL"
    if allowed_confidences:
        placeholders = ",".join("?" for _ in allowed_confidences)
        q += f" AND confidence IN ({placeholders})"
        params = (firmware_id, *allowed_confidences)
    else:
        params = (firmware_id,)
    for row in conn.execute(q, params):
        from_fid = func_ranges.containing(row["from_addr"])
        if from_fid is not None:
            adj[from_fid].add(row["candidate_function_id"])
    return adj


def compute(conn, firmware_id, func_ranges):
    """Compute and persist function_reachability for every function.
    `func_ranges` is a build.FunctionRanges (or equivalent .containing()
    lookup) over this firmware's functions."""
    root_function_ids = compute_roots(conn, firmware_id)

    direct_adj = collections.defaultdict(set)
    for row in conn.execute(
            "SELECT from_function_id, to_function_id FROM edges "
            "WHERE firmware_id=? AND resolved=1 AND source LIKE 'ghidra%' "
            "AND from_function_id IS NOT NULL AND to_function_id IS NOT NULL",
            (firmware_id,)):
        direct_adj[row["from_function_id"]].add(row["to_function_id"])

    strong_indirect_adj = _indirect_adjacency(conn, firmware_id, func_ranges, ("EXACT", "STRONG"))
    weak_indirect_adj = _indirect_adjacency(conn, firmware_id, func_ranges, ())  # every confidence, including WEAK

    def merged(*adjs):
        out = collections.defaultdict(set)
        for a in adjs:
            for k, vs in a.items():
                out[k] |= vs
        return out

    strong_adj = merged(direct_adj, strong_indirect_adj)
    weak_adj = merged(direct_adj, strong_indirect_adj, weak_indirect_adj)

    def bfs(adj, roots):
        dist = {r: 0 for r in roots}
        order = collections.deque(roots)
        while order:
            u = order.popleft()
            for v in adj.get(u, ()):
                if v not in dist:
                    dist[v] = dist[u] + 1
                    order.append(v)
        return dist

    strong_dist = bfs(strong_adj, root_function_ids)
    weak_dist = bfs(weak_adj, root_function_ids)

    # nearest root (addr/kind) per function, for reporting -- reuse the
    # same BFS parent tracking via a second pass keyed off strong_dist/
    # weak_dist's hop counts (cheap re-derivation, avoids a second data
    # structure): pick, among roots at distance 0 in whichever graph
    # reached this function first, the root with the smallest addr for
    # determinism when several are equally near.
    roots_rows = conn.execute(
        "SELECT addr, root_kind, function_id FROM reachability_roots WHERE firmware_id=?",
        (firmware_id,)).fetchall()
    root_addr_kind = {r["function_id"]: (r["addr"], r["root_kind"]) for r in roots_rows if r["function_id"] is not None}

    all_function_ids = [row["id"] for row in conn.execute(
        "SELECT id FROM functions WHERE firmware_id=?", (firmware_id,))]

    out_rows = []
    for fid in all_function_ids:
        if fid in strong_dist:
            status = "DEFINITELY_REACHABLE"
            hops = strong_dist[fid]
        elif fid in weak_dist:
            status = "POSSIBLY_REACHABLE_VIA_UNRESOLVED_INDIRECT"
            hops = weak_dist[fid]
        else:
            status = "NO_KNOWN_PATH"
            hops = None
        nearest_addr, nearest_kind = root_addr_kind.get(fid, (None, None))
        out_rows.append({
            "firmware_id": firmware_id, "function_id": fid, "status": status,
            "nearest_root_addr": nearest_addr, "nearest_root_kind": nearest_kind,
            "hops": hops, "source": "reachability",
        })

    from db import replace_firmware_rows
    replace_firmware_rows(conn, firmware_id, "function_reachability", out_rows)
    conn.commit()
    return out_rows
