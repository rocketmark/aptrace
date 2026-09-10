"""APTrace census reduce: deterministic component grouping over
REACHABLE functions (DEFINITELY_REACHABLE or
POSSIBLY_REACHABLE_VIA_UNRESOLVED_INDIRECT -- grouping NO_KNOWN_PATH
dead code isn't useful for the residual-reduction goal this layer
exists for).

A union-find over resource/graph relationships, deliberately NOT
"union on any shared call edge" (that collapses almost the whole binary
into one component through common utility functions like memcpy/delay
-- not a useful grouping). Union rules, all mechanical:

  1. Strongly-connected call-graph components (Tarjan's algorithm over
     resolved direct call edges) -- mutual recursion is rare and strong
     evidence two functions belong together.
  2. A direct call edge to a LOW-FAN-IN callee (in-degree <=
     CALL_UNION_MAX_CALLERS) -- a "private-ish" helper relationship,
     not a shared utility hub.
  3. Sharing at least one resolved MMIO peripheral access, LOW-FAN-IN
     only (<= RESOURCE_UNION_MAX_OWNERS distinct owning functions).
  4. Sharing at least one exact RAM address access, LOW-FAN-IN only
     (same bound). Empirically necessary: an UNBOUNDED version of this
     rule (the original implementation) was found this pass to collapse
     nearly an entire firmware's reachable set into ONE component
     through a handful of pervasively-shared global-state addresses
     (mando868: one RAM address alone is touched by 46 distinct
     reachable functions) -- exactly the "shared utility hub" failure
     mode rules 1/2 already guard against for the call graph, just not
     previously guarded for resource-sharing. See RESOURCE_UNION_MAX_OWNERS.
  5. Sharing at least one pin (from the `pins` table), LOW-FAN-IN only
     (same bound).
  6. Co-occurring in at least one same dynamic_run (real co-execution
     during the same scenario leg).
  7. Two DISTINCT callees of the SAME LOW-FAN-OUT caller (out-degree <=
     CALL_UNION_MAX_CALLEES) -- the "common caller" case: a small
     setup/dispatch function that calls only a tight few siblings is
     real evidence those siblings belong together, symmetric to rule 2
     (which unions on the common-CALLEE side); bounded the same way so
     a high-fan-out dispatcher (e.g. a big switch/vtable caller) does
     not collapse unrelated callees into one component.
  8. Sharing at least one string/constant reference (a `literal_refs`
     row whose `to_addr` is a real `strings` row), LOW-FAN-IN only
     (same bound) -- two functions that both format/compare against the
     SAME string literal are real, mechanical evidence of a shared
     purpose, the same category of signal as sharing a peripheral or
     RAM address (and the same hub risk, e.g. a generic shared format
     string referenced from many unrelated call sites).

Component IDs (`component_index`) are small integers, stable for a
GIVEN evidence state: assigned by sorting each component's members by
entry address and ordering components by their own minimum member's
entry address. Re-running `census reduce` with unchanged evidence
reproduces identical IDs; changed evidence (a rebuild, new dynamic
coverage) can change them -- that's inherent to any evidence-derived
grouping, not a bug.
"""
import json

CALL_UNION_MAX_CALLERS = 3
CALL_UNION_MAX_CALLEES = 3
# Same "private-ish, not a shared hub" discipline as the call-graph
# rules above, applied to resource-sharing rules 3/4/5/8. Chosen against
# mando868's own real distribution of RAM-address owner counts (a
# natural break: 1-9 owners is a smooth, dense distribution of real
# small clusters; 10+ owners jumps straight to isolated outliers at
# 11/14/15/16/19/36/46 -- pervasive global-state addresses, not a
# meaningful grouping signal) -- see components.py's module docstring.
RESOURCE_UNION_MAX_OWNERS = 8


class DSU:
    def __init__(self, items):
        self.parent = {i: i for i in items}

    def find(self, x):
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a, b):
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[max(ra, rb)] = min(ra, rb)


def _union_low_fan_in_owners(dsu, owners_by_resource, max_owners):
    """Union every pair of owners of a shared resource (peripheral/RAM
    address/pin/string), UNLESS that resource has more than
    `max_owners` distinct owners -- see RESOURCE_UNION_MAX_OWNERS."""
    for owners in owners_by_resource.values():
        if len(owners) > max_owners:
            continue
        for o in owners[1:]:
            dsu.union(owners[0], o)


def _sccs(adjacency, nodes):
    """Tarjan's SCC over `adjacency` (dict node -> iterable(node)),
    restricted to `nodes`. Returns a list of sets, each a strongly-
    connected component (including trivial singletons, which callers
    should ignore)."""
    index_counter = [0]
    stack, lowlink, index, on_stack = [], {}, {}, {}
    result = []

    def strongconnect(v):
        work = [(v, iter(adjacency.get(v, ())))]
        index[v] = index_counter[0]
        lowlink[v] = index_counter[0]
        index_counter[0] += 1
        stack.append(v)
        on_stack[v] = True
        while work:
            node, it = work[-1]
            advanced = False
            for w in it:
                if w not in nodes:
                    continue
                if w not in index:
                    index[w] = index_counter[0]
                    lowlink[w] = index_counter[0]
                    index_counter[0] += 1
                    stack.append(w)
                    on_stack[w] = True
                    work.append((w, iter(adjacency.get(w, ()))))
                    advanced = True
                    break
                elif on_stack.get(w):
                    lowlink[node] = min(lowlink[node], index[w])
            if not advanced:
                work.pop()
                if work:
                    parent = work[-1][0]
                    lowlink[parent] = min(lowlink[parent], lowlink[node])
                if lowlink[node] == index[node]:
                    comp = set()
                    while True:
                        w = stack.pop()
                        on_stack[w] = False
                        comp.add(w)
                        if w == node:
                            break
                    result.append(comp)

    for n in nodes:
        if n not in index:
            strongconnect(n)
    return result


def compute(conn, firmware_id):
    reachable = [r["function_id"] for r in conn.execute(
        "SELECT function_id FROM function_reachability WHERE firmware_id=? "
        "AND status IN ('DEFINITELY_REACHABLE','POSSIBLY_REACHABLE_VIA_UNRESOLVED_INDIRECT')",
        (firmware_id,))]
    node_set = set(reachable)
    if not node_set:
        from db import replace_firmware_rows
        replace_firmware_rows(conn, firmware_id, "components", [])
        replace_firmware_rows(conn, firmware_id, "component_members", [])
        conn.commit()
        return []

    dsu = DSU(node_set)

    call_adj = {}
    in_degree = {}
    for row in conn.execute(
            "SELECT from_function_id, to_function_id FROM edges WHERE firmware_id=? AND resolved=1 "
            "AND source LIKE 'ghidra%' AND kind LIKE '%call%' AND from_function_id IS NOT NULL "
            "AND to_function_id IS NOT NULL", (firmware_id,)):
        f, t = row["from_function_id"], row["to_function_id"]
        call_adj.setdefault(f, set()).add(t)
        in_degree[t] = in_degree.get(t, 0) + 1

    # Rule 1: SCC membership.
    for comp in _sccs(call_adj, node_set):
        if len(comp) > 1:
            members = list(comp)
            for m in members[1:]:
                dsu.union(members[0], m)

    # Rule 2: direct call to a low-fan-in callee.
    for f, callees in call_adj.items():
        if f not in node_set:
            continue
        for t in callees:
            if t in node_set and in_degree.get(t, 0) <= CALL_UNION_MAX_CALLERS:
                dsu.union(f, t)

    # Rule 3: shared MMIO peripheral.
    peripheral_owners = {}
    for row in conn.execute(
            "SELECT DISTINCT from_function_id, peripheral FROM mmio_accesses "
            "WHERE firmware_id=? AND peripheral IS NOT NULL AND from_function_id IS NOT NULL",
            (firmware_id,)):
        if row["from_function_id"] in node_set:
            peripheral_owners.setdefault(row["peripheral"], []).append(row["from_function_id"])
    _union_low_fan_in_owners(dsu, peripheral_owners, RESOURCE_UNION_MAX_OWNERS)

    # Rule 4: shared exact RAM address.
    ram_owners = {}
    for row in conn.execute(
            "SELECT DISTINCT from_function_id, to_addr FROM memory_accesses "
            "WHERE firmware_id=? AND from_function_id IS NOT NULL", (firmware_id,)):
        if row["from_function_id"] in node_set:
            ram_owners.setdefault(row["to_addr"], []).append(row["from_function_id"])
    _union_low_fan_in_owners(dsu, ram_owners, RESOURCE_UNION_MAX_OWNERS)

    # Rule 5: shared pin.
    pin_owners = {}
    for row in conn.execute(
            "SELECT DISTINCT from_function_id, pin_name FROM pins WHERE firmware_id=? "
            "AND from_function_id IS NOT NULL", (firmware_id,)):
        if row["from_function_id"] in node_set:
            pin_owners.setdefault(row["pin_name"], []).append(row["from_function_id"])
    _union_low_fan_in_owners(dsu, pin_owners, RESOURCE_UNION_MAX_OWNERS)

    # Rule 6: dynamic co-execution (same dynamic_run).
    run_owners = {}
    for row in conn.execute(
            "SELECT DISTINCT function_id, dynamic_run_id FROM dynamic_coverage "
            "WHERE firmware_id=? AND function_id IS NOT NULL", (firmware_id,)):
        if row["function_id"] in node_set:
            run_owners.setdefault(row["dynamic_run_id"], []).append(row["function_id"])
    for owners in run_owners.values():
        for o in owners[1:]:
            dsu.union(owners[0], o)

    # Rule 7: two callees of the SAME low-fan-out caller (the "common
    # caller" case -- symmetric to rule 2's "common callee"). Fan-out is
    # measured over ALL resolved callees (not just those in node_set),
    # same conservative convention rule 2 uses for fan-in.
    out_degree = {f: len(callees) for f, callees in call_adj.items()}
    for f, callees in call_adj.items():
        if out_degree.get(f, 0) > CALL_UNION_MAX_CALLEES:
            continue
        siblings = [t for t in callees if t in node_set]
        for o in siblings[1:]:
            dsu.union(siblings[0], o)

    # Rule 8: shared string/constant reference.
    string_owners = {}
    for row in conn.execute(
            "SELECT DISTINCT l.from_function_id, l.to_addr FROM literal_refs l JOIN strings s "
            "ON s.firmware_id=l.firmware_id AND s.addr=l.to_addr "
            "WHERE l.firmware_id=? AND l.from_function_id IS NOT NULL", (firmware_id,)):
        if row["from_function_id"] in node_set:
            string_owners.setdefault(row["to_addr"], []).append(row["from_function_id"])
    _union_low_fan_in_owners(dsu, string_owners, RESOURCE_UNION_MAX_OWNERS)

    groups = {}
    for fid in node_set:
        groups.setdefault(dsu.find(fid), []).append(fid)

    entry_by_fid = {row["id"]: row["entry"] for row in conn.execute(
        "SELECT id, entry FROM functions WHERE firmware_id=?", (firmware_id,))}
    ordered = sorted(groups.values(), key=lambda members: min(entry_by_fid[m] for m in members))

    component_rows, member_rows = [], []
    for idx, members in enumerate(ordered):
        members_sorted = sorted(members, key=lambda m: entry_by_fid[m])
        placeholders = ",".join("?" for _ in members)
        peripherals = sorted({r[0] for r in conn.execute(
            f"SELECT DISTINCT peripheral FROM mmio_accesses WHERE firmware_id=? AND from_function_id IN ({placeholders}) "
            f"AND peripheral IS NOT NULL", (firmware_id, *members))})
        pins = sorted({r[0] for r in conn.execute(
            f"SELECT DISTINCT pin_name FROM pins WHERE firmware_id=? AND from_function_id IN ({placeholders})",
            (firmware_id, *members))})
        ram_addrs = sorted({r[0] for r in conn.execute(
            f"SELECT DISTINCT to_addr FROM memory_accesses WHERE firmware_id=? AND from_function_id IN ({placeholders})",
            (firmware_id, *members))})
        scenarios = sorted({r[0] for r in conn.execute(
            f"SELECT DISTINCT dr.scenario FROM dynamic_coverage dc JOIN dynamic_runs dr ON dr.id=dc.dynamic_run_id "
            f"WHERE dc.firmware_id=? AND dc.function_id IN ({placeholders})", (firmware_id, *members))})
        strings = sorted({r[0] for r in conn.execute(
            f"SELECT DISTINCT s.value FROM literal_refs l JOIN strings s ON s.firmware_id=l.firmware_id "
            f"AND s.addr=l.to_addr WHERE l.firmware_id=? AND l.from_function_id IN ({placeholders})",
            (firmware_id, *members))})

        component_rows.append({
            "firmware_id": firmware_id, "component_index": idx, "n_functions": len(members),
            "peripherals_json": json.dumps(peripherals), "pins_json": json.dumps(pins),
            "ram_addrs_json": json.dumps([f"0x{a:08x}" for a in ram_addrs]),
            "scenarios_json": json.dumps(scenarios), "strings_json": json.dumps(strings),
            "source": "components",
        })
        for m in members_sorted:
            member_rows.append({"firmware_id": firmware_id, "component_index": idx, "function_id": m})

    from db import replace_firmware_rows
    replace_firmware_rows(conn, firmware_id, "components", component_rows)
    conn.commit()
    # component_members references components.id, which only exists
    # after the insert above -- resolve component_index -> id now.
    idx_to_id = {row["component_index"]: row["id"] for row in conn.execute(
        "SELECT id, component_index FROM components WHERE firmware_id=?", (firmware_id,))}
    for m in member_rows:
        m["component_id"] = idx_to_id[m.pop("component_index")]
    replace_firmware_rows(conn, firmware_id, "component_members", member_rows)
    conn.commit()
    return component_rows
