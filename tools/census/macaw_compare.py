#!/usr/bin/env python3
"""Read-only, standalone comparison between the existing Ghidra-based
census (census.sqlite3) and the standalone `aptrace macaw-census` JSON
evidence producer (src/APTrace/MacawCensus.hs).

This is evidence comparison only -- it never decides which tool is
"correct", never writes to the database, never ingests Macaw rows into
SQLite, and never modifies either analysis producer. It answers three
mechanical questions:

  * What does Macaw discover that Ghidra does not?
  * What does Ghidra discover that Macaw does not?
  * Where do they disagree on calls (and functions)?

## The fairness rule this tool exists to respect

Macaw's census (`aptrace macaw-census`) is seeded ONLY from the
firmware's own vector-table handlers (`APTrace.MacawCensus.normalizeRoots`)
-- it never sees Ghidra's function list, Capstone, or any heuristic
whole-image scan. Ghidra's static analysis, by contrast, does broad
whole-image heuristic discovery (prologue matching, etc.) on top of the
same vector table. A function Ghidra found that Macaw didn't is
therefore NOT evidence Macaw "missed reachable code" -- Macaw was never
asked to look there. This tool always reports two separate views:

  A. Whole inventory -- raw Ghidra-vs-Macaw function sets, with that
     caveat printed every time "ghidra-only" is shown.
  B. Same-root static comparison -- Ghidra's OWN static reachability,
     computed fresh by THIS tool from the identical vector-table roots
     Macaw used, using only Ghidra's own resolved base-evidence edges.
     This is the fair, apples-to-apples comparison.

## What "same-root Ghidra reachability" deliberately excludes

Per the task this tool was built for, Part B never touches:

  * Unicorn/dynamic evidence (`dynamic_*` tables)
  * `function_reachability` (the existing closure-reduction table --
    that graph additionally follows FINITE_CANDIDATE_SET indirect
    edges, a strictly WIDER graph than "Ghidra's own resolved static
    evidence")
  * `indirect_edge_candidates`/`indirect_edge_resolutions`
  * Capstone edges (`edges.source = 'capstone-sweep'`)
  * reference-source/library-match tables

Only `functions`, `basic_blocks`, `edges` (filtered to
`source LIKE 'ghidra%'`), and `vectors` -- the base-evidence tables --
are read. The function-level reachability graph itself mirrors
`tools/census/reachability.py`'s own `direct_adj` query exactly
(`resolved=1 AND source LIKE 'ghidra%'`, every edge kind, not just
calls -- the project's own existing definition of "Ghidra's resolved
static call/control-flow graph"), so this tool computes the same kind
of graph that module does, just seeded from Macaw's specific root set
instead of `reachability_roots` and without the indirect-edge widening.

## Call-site addressing granularity

Ghidra's `edges.from_addr` for a call is the exact instruction address
of the `BL`/`BLX`. Macaw's `calls[].call_site` (APTrace.MacawCensus)
is the owning BLOCK's start address, which can be earlier than the
call instruction itself if the block has leading straight-line code.
Comparing by exact address equality would therefore spuriously call
identical call sites "different" whenever a Macaw block has more than
one instruction. This tool instead matches a Ghidra call edge to a
Macaw call by *containment*: does the edge's `from_addr` fall inside
`[call_site, call_site + block_size)` for that Macaw call, using
Macaw's own `basic_blocks[].size`? This is a real, disclosed
representational difference between the two tools -- not a bug in
either.

Usage:
    macaw_compare.py autopilot868 /path/to/macaw_census.json [--db PATH] [--json]
"""
import argparse
import collections
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import db as census_db  # noqa: E402


def hx(n):
    return f"0x{n:08x}" if n is not None else None


def maddr(s):
    """Parse one of Macaw census JSON's own hex-string addresses
    ("0xcc24") -- None passes through unchanged (JSON null)."""
    return None if s is None else int(s, 16)


def load_macaw_census(path):
    with open(path) as f:
        doc = json.load(f)
    if doc.get("discovery_error"):
        print(f"WARNING: this Macaw census run itself reported a discovery_error: "
              f"{doc['discovery_error']!r} -- its functions/calls lists will be empty.",
              file=sys.stderr)
    return doc


def check_firmware_match(conn, fw_id, macaw):
    """Cross-check the DB's own firmware row against the Macaw JSON's
    self-reported flash/RAM parameters -- purely a sanity warning
    (printed, never fatal): comparing evidence built from two different
    firmware images/load addresses would be silently meaningless."""
    row = conn.execute(
        "SELECT flash_base, ram_base, ram_size FROM firmware WHERE id=?", (fw_id,)).fetchone()
    fm = macaw["firmware"]
    mismatches = []
    for field, db_val, macaw_field in (
            ("flash_base", row["flash_base"], "flash_base"),
            ("ram_base", row["ram_base"], "ram_base"),
            ("ram_size", row["ram_size"], "ram_size")):
        macaw_val = maddr(fm[macaw_field])
        if macaw_val != db_val:
            mismatches.append(f"{field}: db={hx(db_val)} macaw={hx(macaw_val)}")
    if mismatches:
        print("WARNING: firmware parameter mismatch between the census DB and the Macaw "
              "JSON -- comparison may not be apples-to-apples:", file=sys.stderr)
        for m in mismatches:
            print(f"  {m}", file=sys.stderr)


# ---------------------------------------------------------------------
# Part A: whole inventory (no root restriction, no fairness claim)
# ---------------------------------------------------------------------

def whole_inventory(conn, fw_id, macaw):
    ghidra_funcs = {row["entry"]: row["name"] for row in conn.execute(
        "SELECT entry, name FROM functions WHERE firmware_id=?", (fw_id,))}
    macaw_funcs = {maddr(f["entry"]) for f in macaw["functions"]}
    ghidra_set = set(ghidra_funcs)
    return {
        "ghidra_funcs": ghidra_funcs,
        "ghidra_set": ghidra_set,
        "macaw_set": macaw_funcs,
        "intersection": sorted(ghidra_set & macaw_funcs),
        "ghidra_only": sorted(ghidra_set - macaw_funcs),
        "macaw_only": sorted(macaw_funcs - ghidra_set),
    }


# ---------------------------------------------------------------------
# Part B: same-root static comparison
# ---------------------------------------------------------------------

def macaw_root_addrs(macaw):
    """The exact canonical vector-table target addresses Macaw seeded
    discovery from (APTrace.MacawCensus.normalizeRoots + macawCortexMEntry
    -- already Thumb-bit-stripped in the JSON's own `canonical_addr`)."""
    return sorted({maddr(r["canonical_addr"]) for r in macaw["roots"]
                   if r.get("resolved") and r.get("canonical_addr") is not None})


def ghidra_vector_target_addrs(conn, fw_id):
    """Every populated vector-table target Ghidra's own independent raw
    flash scan found (tools/census/raw_scan.py) -- used only for the
    disclosed fairness check below, never as the Part B seed set itself."""
    return sorted({row["target_addr"] for row in conn.execute(
        "SELECT DISTINCT target_addr FROM vectors WHERE firmware_id=? AND target_addr IS NOT NULL",
        (fw_id,))})


def report_root_fairness(conn, fw_id, macaw):
    """A real, mechanically-detectable asymmetry: if Ghidra's own raw
    vector-table scan found MORE (or different) populated targets than
    Macaw's own root set, Part B's "same-root" comparison is only as
    fair as Macaw's root set actually being complete. Disclosed, not
    silently absorbed into a wider seed set -- Part B still seeds from
    exactly Macaw's roots, per the task."""
    macaw_roots = set(macaw_root_addrs(macaw))
    ghidra_vectors = set(ghidra_vector_target_addrs(conn, fw_id))
    only_in_ghidra_vectors = sorted(ghidra_vectors - macaw_roots)
    only_in_macaw_roots = sorted(macaw_roots - ghidra_vectors)
    return {
        "macaw_root_count": len(macaw_roots),
        "ghidra_vector_target_count": len(ghidra_vectors),
        "only_in_ghidra_vectors": only_in_ghidra_vectors,
        "only_in_macaw_roots": only_in_macaw_roots,
    }


def ghidra_function_id_by_entry(conn, fw_id):
    return {row["entry"]: row["id"] for row in conn.execute(
        "SELECT id, entry FROM functions WHERE firmware_id=?", (fw_id,))}


def ghidra_resolved_static_adjacency(conn, fw_id):
    """function_id -> set(function_id): Ghidra's own resolved static
    edges only. Deliberately mirrors reachability.py's own `direct_adj`
    query verbatim (every edge kind, not just calls -- that module's own
    established definition of "Ghidra's resolved static graph"),
    excluding Capstone (source LIKE 'ghidra%') and every closure-
    reduction table."""
    adj = collections.defaultdict(set)
    for row in conn.execute(
            "SELECT from_function_id, to_function_id FROM edges "
            "WHERE firmware_id=? AND resolved=1 AND source LIKE 'ghidra%' "
            "AND from_function_id IS NOT NULL AND to_function_id IS NOT NULL",
            (fw_id,)):
        adj[row["from_function_id"]].add(row["to_function_id"])
    return adj


def bfs(adj, roots):
    seen = set(roots)
    order = collections.deque(roots)
    while order:
        u = order.popleft()
        for v in adj.get(u, ()):
            if v not in seen:
                seen.add(v)
                order.append(v)
    return seen


def ghidra_same_root_functions(conn, fw_id, macaw):
    """BFS Ghidra's own resolved static call/control-flow graph starting
    from exactly the vector-table addresses Macaw's own root set used.
    Returns (reachable_function_ids, {entry: function_id}, unmatched_root_addrs)."""
    func_id_by_entry = ghidra_function_id_by_entry(conn, fw_id)
    root_addrs = macaw_root_addrs(macaw)
    root_ids = []
    unmatched_roots = []
    for addr in root_addrs:
        fid = func_id_by_entry.get(addr)
        if fid is None:
            unmatched_roots.append(addr)
        else:
            root_ids.append(fid)
    adj = ghidra_resolved_static_adjacency(conn, fw_id)
    reachable_ids = bfs(adj, root_ids)
    return reachable_ids, func_id_by_entry, unmatched_roots


def compare_functions_same_root(conn, fw_id, macaw, ghidra_reachable_ids, func_id_by_entry, ghidra_names):
    id_to_entry = {fid: entry for entry, fid in func_id_by_entry.items()}
    ghidra_reachable_entries = {id_to_entry[fid] for fid in ghidra_reachable_ids if fid in id_to_entry}
    macaw_entries = {maddr(f["entry"]) for f in macaw["functions"]}
    shared = sorted(ghidra_reachable_entries & macaw_entries)
    ghidra_only = sorted(ghidra_reachable_entries - macaw_entries)
    macaw_only = sorted(macaw_entries - ghidra_reachable_entries)
    return {
        "ghidra_reachable_count": len(ghidra_reachable_entries),
        "macaw_count": len(macaw_entries),
        "shared": shared,
        "ghidra_only": [(a, ghidra_names.get(a)) for a in ghidra_only],
        "macaw_only": macaw_only,
    }


# ---------------------------------------------------------------------
# Calls comparison (same-root subgraph only)
# ---------------------------------------------------------------------

def macaw_calls_by_caller(macaw):
    """caller_entry -> [(call_site, call_site+size, call_dict)], where
    call_dict has parsed-int caller/call_site/callee/raw_target and the
    original kind string. Block size comes from Macaw's own basic_blocks
    list (see module docstring's "call-site addressing granularity")."""
    block_size = {}
    for b in macaw["basic_blocks"]:
        block_size[(maddr(b["function_entry"]), maddr(b["block_start"]))] = b["size"]
    by_caller = collections.defaultdict(list)
    for c in macaw["calls"]:
        caller = maddr(c["caller"])
        site = maddr(c["call_site"])
        size = block_size.get((caller, site), 1)
        call = {
            "caller": caller,
            "call_site": site,
            "callee": maddr(c["callee"]),
            "raw_target": maddr(c.get("raw_target")),
            "kind": c["kind"],
        }
        by_caller[caller].append((site, site + max(size, 1), call))
    return by_caller


def find_macaw_call(by_caller, caller_entry, addr):
    for start, end, call in by_caller.get(caller_entry, ()):
        if start <= addr < end:
            return call
    return None


def ghidra_calls_in_reachable_set(conn, fw_id, reachable_ids):
    if not reachable_ids:
        return [], 0
    placeholders = ",".join("?" for _ in reachable_ids)
    rows = conn.execute(
        f"SELECT e.from_addr, e.to_addr, e.resolved, ff.entry AS caller_entry "
        f"FROM edges e JOIN functions ff ON ff.id = e.from_function_id "
        f"WHERE e.firmware_id=? AND e.kind LIKE '%call%' AND e.source LIKE 'ghidra%' "
        f"AND e.from_function_id IN ({placeholders}) "
        f"ORDER BY ff.entry, e.from_addr",
        (fw_id, *reachable_ids))
    calls = [dict(r) for r in rows]
    unattributed = conn.execute(
        "SELECT COUNT(*) FROM edges WHERE firmware_id=? AND kind LIKE '%call%' "
        "AND source LIKE 'ghidra%' AND from_function_id IS NULL", (fw_id,)).fetchone()[0]
    return calls, unattributed


def group_ghidra_calls_by_macaw_call(ghidra_calls, macaw_by_caller):
    """Group every Ghidra call-edge row landing in the same Macaw
    call-site range under that one Macaw call, and separately group
    unmatched Ghidra rows by their own (caller, from_addr).

    This grouping matters: Ghidra's own basic-block model can (and does,
    on this firmware -- e.g. a real resolved switch/vtable-style
    dispatch at flash 0x635e) record SEVERAL distinct 'call' edge rows
    from the very same instruction address, one per concrete target its
    own analysis resolved. Comparing those one-by-one against Macaw's
    single resolved value would misreport an N-target Ghidra dispatch as
    N-1 spurious "different target" disagreements. Grouped first, the
    comparison is: does Macaw's one answer fall within Ghidra's full
    resolved target SET for that call site?
    """
    grouped = {}
    unmatched = collections.OrderedDict()
    for g in ghidra_calls:
        mc = find_macaw_call(macaw_by_caller, g["caller_entry"], g["from_addr"])
        if mc is None:
            key = (g["caller_entry"], g["from_addr"])
            unmatched.setdefault(key, []).append(g)
            continue
        key = id(mc)
        if key not in grouped:
            grouped[key] = {"macaw": mc, "targets": set(), "rows": []}
        if g["resolved"] and g["to_addr"] is not None:
            grouped[key]["targets"].add(g["to_addr"])
        grouped[key]["rows"].append(g)
    return grouped, unmatched


def compare_calls(ghidra_calls, macaw_by_caller):
    """Categorizes every call this tool can attribute to the same-root
    subgraph on either side. `both_unresolved` is reported as a
    sub-detail of `exact_agreement` (both tools agreeing the target is
    unknown IS a form of agreement), never silently merged with a
    concrete-address match. A Ghidra call site with more than one
    resolved concrete target (see `group_ghidra_calls_by_macaw_call`) is
    still `exact_agreement` if Macaw's single value is one of them."""
    cats = {
        "exact_agreement": [],
        "macaw_resolved_ghidra_unresolved": [],
        "ghidra_resolved_macaw_indirect": [],
        "different_targets": [],
        "macaw_only": [],
        "ghidra_only": [],
    }
    grouped, ghidra_only = group_ghidra_calls_by_macaw_call(ghidra_calls, macaw_by_caller)
    for g in grouped.values():
        mc = g["macaw"]
        m_resolved = mc["kind"] == "direct"
        g_resolved = bool(g["targets"])
        entry = {"macaw": mc, "ghidra_targets": sorted(g["targets"]), "ghidra_row_count": len(g["rows"])}
        if m_resolved and g_resolved:
            if mc["callee"] in g["targets"]:
                cats["exact_agreement"].append({**entry, "both_unresolved": False})
            else:
                cats["different_targets"].append(entry)
        elif m_resolved and not g_resolved:
            cats["macaw_resolved_ghidra_unresolved"].append(entry)
        elif not m_resolved and g_resolved:
            cats["ghidra_resolved_macaw_indirect"].append(entry)
        else:
            cats["exact_agreement"].append({**entry, "both_unresolved": True})
    matched = set(grouped)
    for caller, entries in macaw_by_caller.items():
        for _start, _end, mc in entries:
            if id(mc) not in matched:
                cats["macaw_only"].append(mc)
    for (caller_entry, from_addr), rows in ghidra_only.items():
        targets = sorted({r["to_addr"] for r in rows if r["resolved"] and r["to_addr"] is not None})
        cats["ghidra_only"].append({"caller_entry": caller_entry, "from_addr": from_addr,
                                     "targets": targets, "row_count": len(rows)})
    return cats


# ---------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------

def build_report(conn, fw_id, macaw):
    inv = whole_inventory(conn, fw_id, macaw)
    fairness = report_root_fairness(conn, fw_id, macaw)
    reachable_ids, func_id_by_entry, unmatched_roots = ghidra_same_root_functions(conn, fw_id, macaw)
    fn_cmp = compare_functions_same_root(conn, fw_id, macaw, reachable_ids, func_id_by_entry, inv["ghidra_funcs"])
    ghidra_calls, unattributed_ghidra_calls = ghidra_calls_in_reachable_set(conn, fw_id, reachable_ids)
    by_caller = macaw_calls_by_caller(macaw)
    call_cmp = compare_calls(ghidra_calls, by_caller)
    return {
        "whole_inventory": inv,
        "root_fairness": fairness,
        "same_root_unmatched_roots": unmatched_roots,
        "same_root_functions": fn_cmp,
        "same_root_calls": call_cmp,
        "unattributed_ghidra_call_edges_total": unattributed_ghidra_calls,
    }


def print_report(report, ghidra_names):
    inv = report["whole_inventory"]
    fairness = report["root_fairness"]
    fn = report["same_root_functions"]
    calls = report["same_root_calls"]

    print("=" * 78)
    print("PART A -- WHOLE INVENTORY (raw sets, no root restriction)")
    print("=" * 78)
    print(f"Ghidra function entries : {len(inv['ghidra_set'])}")
    print(f"Macaw function entries  : {len(inv['macaw_set'])}")
    print(f"Intersection            : {len(inv['intersection'])}")
    print(f"Ghidra-only             : {len(inv['ghidra_only'])}")
    print(f"Macaw-only              : {len(inv['macaw_only'])}")
    print()
    print("*** Ghidra-only here does NOT mean Macaw missed reachable code. ***")
    print("*** Macaw is seeded ONLY from vector-table roots; Ghidra runs a  ***")
    print("*** broader whole-image heuristic scan. See Part B for the fair ***")
    print("*** same-root comparison.                                      ***")
    if inv["macaw_only"]:
        print(f"\nMacaw-only entries ({len(inv['macaw_only'])}):")
        for a in inv["macaw_only"]:
            print(f"  {hx(a)}")

    print()
    print("=" * 78)
    print("Root fairness check (Macaw's own roots vs. Ghidra/raw_scan's vector table)")
    print("=" * 78)
    print(f"Macaw root count            : {fairness['macaw_root_count']}")
    print(f"Ghidra vector target count  : {fairness['ghidra_vector_target_count']}")
    if fairness["only_in_ghidra_vectors"]:
        print(f"Populated in Ghidra's vector table but NOT among Macaw's roots "
              f"({len(fairness['only_in_ghidra_vectors'])}):")
        for a in fairness["only_in_ghidra_vectors"]:
            print(f"  {hx(a)}")
        print("  -> Part B below still seeds from exactly Macaw's own root set,")
        print("     per the task; this gap is disclosed, not silently widened.")
    if fairness["only_in_macaw_roots"]:
        print(f"In Macaw's roots but not in Ghidra's own vector scan "
              f"({len(fairness['only_in_macaw_roots'])}):")
        for a in fairness["only_in_macaw_roots"]:
            print(f"  {hx(a)}")
    if not fairness["only_in_ghidra_vectors"] and not fairness["only_in_macaw_roots"]:
        print("Identical root sets.")

    if report["same_root_unmatched_roots"]:
        print(f"\nMacaw roots with no exact Ghidra function entry at that address "
              f"({len(report['same_root_unmatched_roots'])}):")
        for a in report["same_root_unmatched_roots"]:
            print(f"  {hx(a)}  (excluded from the Ghidra BFS seed set below)")

    print()
    print("=" * 78)
    print("PART B -- SAME-ROOT STATIC COMPARISON")
    print("(Ghidra reachability computed fresh by this tool, from Macaw's own")
    print(" root set, using only resolved Ghidra base-evidence edges)")
    print("=" * 78)
    print()
    print("--- Functions ---")
    print(f"Ghidra same-root reachable : {fn['ghidra_reachable_count']}")
    print(f"Macaw functions            : {fn['macaw_count']}")
    print(f"Shared                     : {len(fn['shared'])}")
    print(f"Ghidra-only (same-root)    : {len(fn['ghidra_only'])}")
    print(f"Macaw-only (same-root)     : {len(fn['macaw_only'])}")
    if fn["ghidra_only"]:
        print("\nGhidra-only (same-root) entries:")
        for addr, name in fn["ghidra_only"]:
            print(f"  {hx(addr)}  {name or ''}")
    if fn["macaw_only"]:
        print("\nMacaw-only (same-root) entries:")
        for addr in fn["macaw_only"]:
            print(f"  {hx(addr)}")

    print()
    print("--- Calls (same-root subgraph; call-site matched by Macaw block range) ---")
    for label, key in (
            ("Exact agreement (concrete or both-unresolved)", "exact_agreement"),
            ("Macaw resolved / Ghidra unresolved", "macaw_resolved_ghidra_unresolved"),
            ("Ghidra resolved / Macaw indirect", "ghidra_resolved_macaw_indirect"),
            ("Different concrete targets", "different_targets"),
            ("Macaw-only call sites", "macaw_only"),
            ("Ghidra-only call sites", "ghidra_only")):
        print(f"{label:48s}: {len(calls[key])}")
    if report["unattributed_ghidra_call_edges_total"]:
        print(f"(Ghidra call edges with no owning function at all, repo-wide, "
              f"not included above: {report['unattributed_ghidra_call_edges_total']})")

    def fmt_targets(ts):
        if not ts:
            return "(none)"
        if len(ts) == 1:
            return hx(ts[0])
        return "{" + ", ".join(hx(t) for t in ts) + "}"

    if calls["different_targets"]:
        print("\nDifferent concrete targets:")
        for row in calls["different_targets"]:
            m = row["macaw"]
            multi = f" [{row['ghidra_row_count']} ghidra row(s)]" if row["ghidra_row_count"] > 1 else ""
            print(f"  caller={hx(m['caller'])} call_site={hx(m['call_site'])}: "
                  f"ghidra->{fmt_targets(row['ghidra_targets'])}  macaw->{hx(m['callee'])}{multi}")
    if calls["macaw_resolved_ghidra_unresolved"]:
        print("\nMacaw resolved / Ghidra unresolved:")
        for row in calls["macaw_resolved_ghidra_unresolved"]:
            m = row["macaw"]
            print(f"  caller={hx(m['caller'])} call_site={hx(m['call_site'])}: macaw->{hx(m['callee'])}")
    if calls["ghidra_resolved_macaw_indirect"]:
        print("\nGhidra resolved / Macaw indirect:")
        for row in calls["ghidra_resolved_macaw_indirect"]:
            m = row["macaw"]
            extra = f" (macaw raw_target={hx(m['raw_target'])})" if m["raw_target"] else ""
            multi = f" [{row['ghidra_row_count']} ghidra row(s)]" if row["ghidra_row_count"] > 1 else ""
            print(f"  caller={hx(m['caller'])} call_site={hx(m['call_site'])}: "
                  f"ghidra->{fmt_targets(row['ghidra_targets'])}, macaw kind={m['kind']}{extra}{multi}")
    if calls["macaw_only"]:
        print(f"\nMacaw-only call sites ({len(calls['macaw_only'])}):")
        for m in calls["macaw_only"]:
            print(f"  caller={hx(m['caller'])} call_site={hx(m['call_site'])} "
                  f"kind={m['kind']} callee={hx(m['callee'])}")
    if calls["ghidra_only"]:
        print(f"\nGhidra-only call sites ({len(calls['ghidra_only'])}):")
        for g in calls["ghidra_only"]:
            multi = f" [{g['row_count']} row(s)]" if g["row_count"] > 1 else ""
            print(f"  caller={hx(g['caller_entry'])} call_site={hx(g['from_addr'])} "
                  f"target={fmt_targets(g['targets'])}{multi}")


def report_to_jsonable(report):
    def fmt_addr_list(xs):
        return [hx(x) for x in xs]

    inv = report["whole_inventory"]
    fn = report["same_root_functions"]
    calls = report["same_root_calls"]

    def fmt_call(c):
        return {"caller": hx(c["caller"]), "call_site": hx(c["call_site"]),
                "callee": hx(c["callee"]), "raw_target": hx(c["raw_target"]), "kind": c["kind"]}

    def fmt_pair(row):
        out = {"ghidra_targets": fmt_addr_list(row["ghidra_targets"]),
               "ghidra_row_count": row["ghidra_row_count"],
               "macaw": fmt_call(row["macaw"])}
        if "both_unresolved" in row:
            out["both_unresolved"] = row["both_unresolved"]
        return out

    return {
        "whole_inventory": {
            "ghidra_count": len(inv["ghidra_set"]),
            "macaw_count": len(inv["macaw_set"]),
            "intersection_count": len(inv["intersection"]),
            "ghidra_only_count": len(inv["ghidra_only"]),
            "macaw_only_count": len(inv["macaw_only"]),
            "macaw_only": fmt_addr_list(inv["macaw_only"]),
        },
        "root_fairness": {
            "macaw_root_count": report["root_fairness"]["macaw_root_count"],
            "ghidra_vector_target_count": report["root_fairness"]["ghidra_vector_target_count"],
            "only_in_ghidra_vectors": fmt_addr_list(report["root_fairness"]["only_in_ghidra_vectors"]),
            "only_in_macaw_roots": fmt_addr_list(report["root_fairness"]["only_in_macaw_roots"]),
        },
        "same_root_unmatched_roots": fmt_addr_list(report["same_root_unmatched_roots"]),
        "same_root_functions": {
            "ghidra_reachable_count": fn["ghidra_reachable_count"],
            "macaw_count": fn["macaw_count"],
            "shared_count": len(fn["shared"]),
            "ghidra_only": [{"addr": hx(a), "name": n} for a, n in fn["ghidra_only"]],
            "macaw_only": fmt_addr_list(fn["macaw_only"]),
        },
        "same_root_calls": {
            "exact_agreement_count": len(calls["exact_agreement"]),
            "macaw_resolved_ghidra_unresolved": [fmt_pair(r) for r in calls["macaw_resolved_ghidra_unresolved"]],
            "ghidra_resolved_macaw_indirect": [fmt_pair(r) for r in calls["ghidra_resolved_macaw_indirect"]],
            "different_targets": [fmt_pair(r) for r in calls["different_targets"]],
            "macaw_only": [fmt_call(c) for c in calls["macaw_only"]],
            "ghidra_only": [{"caller": hx(g["caller_entry"]), "call_site": hx(g["from_addr"]),
                              "targets": fmt_addr_list(g["targets"]), "row_count": g["row_count"]}
                             for g in calls["ghidra_only"]],
        },
        "unattributed_ghidra_call_edges_total": report["unattributed_ghidra_call_edges_total"],
    }


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("firmware", help="firmware key, e.g. autopilot868 (must already have a census build)")
    ap.add_argument("macaw_json", help="path to an `aptrace macaw-census` JSON output file")
    ap.add_argument("--db", default=None, help="census.sqlite3 path (default: research/runs/census/census.sqlite3)")
    ap.add_argument("--json", action="store_true", help="print the machine-readable comparison as JSON instead")
    args = ap.parse_args(argv)

    conn = census_db.connect(args.db, create=False)
    fw_id = census_db.get_firmware_id(conn, args.firmware)
    macaw = load_macaw_census(args.macaw_json)
    check_firmware_match(conn, fw_id, macaw)

    report = build_report(conn, fw_id, macaw)
    if args.json:
        print(json.dumps(report_to_jsonable(report), indent=2))
    else:
        print_report(report, report["whole_inventory"]["ghidra_funcs"])
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
