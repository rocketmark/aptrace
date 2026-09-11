#!/usr/bin/env python3
"""APTrace census: a deterministic, mechanical firmware evidence database
and query CLI.

`build` runs the full pipeline (Ghidra static export + basic-block/CFG
export, a raw vector/function-pointer scan, an independent Capstone
cross-check, SVD/pin resolution, disagreement detection) and populates
research/runs/census/census.sqlite3 (or --db). Every other subcommand is
a read-only query against that database -- no tool invocation, no LLM
interpretation, just SQL. See docs/tooling/census.md for the full design
writeup, what each table means, and current limitations.

`reduce` runs the closure-reduction layer on top of an existing `build`
(reachability, indirect-edge resolution, library/platform
fingerprinting, function feature records, component grouping, a
hardware-init snapshot) -- see docs/tooling/census.md's "Closure
reduction" section.

Usage:
    aptrace_census.py build autopilot868
    aptrace_census.py reduce autopilot868
    aptrace_census.py summary autopilot868
    aptrace_census.py function autopilot868 0x8258
    aptrace_census.py callers autopilot868 0x8258
    aptrace_census.py callees autopilot868 0x8258
    aptrace_census.py readers autopilot868 0x20001b14
    aptrace_census.py writers autopilot868 0x20001b14
    aptrace_census.py peripheral autopilot868 TC1
    aptrace_census.py pin autopilot868 PB05
    aptrace_census.py uncovered autopilot868
    aptrace_census.py indirect-edges autopilot868 [--classification C]
    aptrace_census.py warnings autopilot868 [--category CATEGORY]
    aptrace_census.py ingest-dynamic <export.json-or-dir> [--firmware KEY]
    aptrace_census.py reachable autopilot868 [--status S]
    aptrace_census.py residual autopilot868
    aptrace_census.py components autopilot868 [--id N]
    aptrace_census.py library-matches autopilot868 [--confidence C]
    aptrace_census.py hardware-snapshot autopilot868 [--peripheral P]
    aptrace_census.py residual-ranked autopilot868 [--tier HIGH|MEDIUM|LOW]
    aptrace_census.py residual-components autopilot868
    aptrace_census.py hardware-contract autopilot868 [--out FILE.json]
    aptrace_census.py diff autopilot868 autopilot915 [--json]
    aptrace_census.py reference-corpus fetch
    aptrace_census.py reference-corpus build
    aptrace_census.py reference-match autopilot868
    aptrace_census.py reference-matches autopilot868 [--package P] [--tier T]
    aptrace_census.py reference-unmatched autopilot868
    aptrace_census.py state-map autopilot868 --base 0x200025bc --count 18 --width 1 \\
        [--label NAME] [--dispatcher-entry ADDR] [--tx-wrapper ADDR ...] \\
        [--extra-seed ADDR=HEXBYTES ...] [--index-addr ADDR] [--index-width N]
"""
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import db as census_db  # noqa: E402


def hexaddr(s):
    return int(s, 16)


def hx(n):
    return f"0x{n:08x}" if n is not None else None


# --- build ------------------------------------------------------------

def cmd_build(args):
    import build as build_mod
    build_mod.build(args.firmware, db_path=args.db, ghidra_build=not args.no_ghidra_build)


def cmd_reduce(args):
    import reduce as reduce_mod
    reduce_mod.reduce_firmware(args.firmware, db_path=args.db)


# --- summary / closure report ------------------------------------------

def cmd_summary(args):
    conn = census_db.connect(args.db, create=False)
    fw = census_db.get_firmware_id(conn, args.firmware)
    c = conn.cursor()

    def count(sql, *params):
        return c.execute(sql, params).fetchone()[0]

    n_functions = count("SELECT COUNT(*) FROM functions WHERE firmware_id=?", fw)
    n_blocks = count("SELECT COUNT(*) FROM basic_blocks WHERE firmware_id=?", fw)
    n_unattributed_blocks = count(
        "SELECT COUNT(*) FROM basic_blocks WHERE firmware_id=? AND function_id IS NULL", fw)
    n_resolved_edges = count(
        "SELECT COUNT(*) FROM edges WHERE firmware_id=? AND resolved=1 AND source LIKE 'ghidra%'", fw)
    n_unresolved_edges = count(
        "SELECT COUNT(*) FROM edges WHERE firmware_id=? AND resolved=0", fw)
    n_capstone_edges = count(
        "SELECT COUNT(*) FROM edges WHERE firmware_id=? AND source='capstone-sweep'", fw)
    n_vectors = count("SELECT COUNT(*) FROM vectors WHERE firmware_id=?", fw)
    n_irq = count("SELECT COUNT(*) FROM vectors WHERE firmware_id=? AND is_irq=1 AND target_addr IS NOT NULL", fw)
    n_funcptrs = count("SELECT COUNT(*) FROM function_pointers WHERE firmware_id=?", fw)
    n_ram_locs = count("SELECT COUNT(DISTINCT to_addr) FROM memory_accesses WHERE firmware_id=?", fw)
    n_mmio_sites = count("SELECT COUNT(DISTINCT to_addr) FROM mmio_accesses WHERE firmware_id=?", fw)
    n_peripherals = count("SELECT COUNT(*) FROM peripherals WHERE firmware_id=?", fw)
    n_pins = count("SELECT COUNT(DISTINCT pin_name) FROM pins WHERE firmware_id=?", fw)
    n_strings = count("SELECT COUNT(*) FROM strings WHERE firmware_id=?", fw)

    n_dyn_runs = count("SELECT COUNT(*) FROM dynamic_runs WHERE firmware_id=?", fw)
    n_dyn_scenarios = count("SELECT COUNT(DISTINCT scenario) FROM dynamic_runs WHERE firmware_id=?", fw)
    n_covered_functions = count(
        "SELECT COUNT(DISTINCT function_id) FROM dynamic_coverage "
        "WHERE firmware_id=? AND function_id IS NOT NULL", fw)
    n_uncovered_functions = n_functions - n_covered_functions

    warn_rows = c.execute(
        "SELECT category, COUNT(*) FROM scan_warnings WHERE firmware_id=? GROUP BY category ORDER BY category",
        (fw,)).fetchall()

    print(f"=== Census summary: {args.firmware} ===")
    print(f"Executable/function regions discovered: {n_functions} functions, {n_blocks} basic blocks "
          f"({n_unattributed_blocks} not attributed to a known function)")
    print(f"Vectors: {n_vectors} total, {n_irq} IRQ vectors populated")
    print(f"CFG edges: {n_resolved_edges} resolved (Ghidra), {n_unresolved_edges} unresolved indirect, "
          f"{n_capstone_edges} from the independent Capstone sweep")
    print(f"Function-pointer candidates (raw flash scan): {n_funcptrs}")
    print(f"RAM locations referenced (statically): {n_ram_locs}")
    print(f"MMIO sites referenced (statically): {n_mmio_sites}, across {n_peripherals} resolved peripherals")
    print(f"Pins referenced (PINCFG/PMUX evidence): {n_pins}")
    print(f"Strings: {n_strings}")
    print()
    print(f"Dynamic coverage: {n_dyn_runs} ingested run(s) across {n_dyn_scenarios} scenario(s)")
    print(f"  functions dynamically exercised: {n_covered_functions}")
    print(f"  functions never exercised in any known scenario: {n_uncovered_functions}")
    print()
    print(f"Scan warnings/disagreements: {sum(n for _c, n in warn_rows)} total")
    for category, n in warn_rows:
        print(f"  {category}: {n}")

    has_reduction = count("SELECT COUNT(*) FROM function_reachability WHERE firmware_id=?", fw) > 0
    if not has_reduction:
        print(f"\n(no closure-reduction data yet -- run 'census reduce {args.firmware}')")
        return

    print("\n=== Closure reduction ===")
    reach_rows = c.execute(
        "SELECT status, COUNT(*) FROM function_reachability WHERE firmware_id=? GROUP BY status", (fw,)).fetchall()
    reach = {s: n for s, n in reach_rows}
    print(f"Reachability: DEFINITELY_REACHABLE={reach.get('DEFINITELY_REACHABLE', 0)}  "
          f"POSSIBLY_REACHABLE_VIA_UNRESOLVED_INDIRECT={reach.get('POSSIBLY_REACHABLE_VIA_UNRESOLVED_INDIRECT', 0)}  "
          f"NO_KNOWN_PATH={reach.get('NO_KNOWN_PATH', 0)}")

    ind_rows = c.execute(
        "SELECT classification, COUNT(*) FROM indirect_edge_resolutions WHERE firmware_id=? "
        "GROUP BY classification", (fw,)).fetchall()
    ind = {s: n for s, n in ind_rows}
    print(f"Indirect edges: STATICALLY_RESOLVED={ind.get('STATICALLY_RESOLVED', 0)}  "
          f"DYNAMICALLY_OBSERVED={ind.get('DYNAMICALLY_OBSERVED', 0)}  "
          f"FINITE_CANDIDATE_SET={ind.get('FINITE_CANDIDATE_SET', 0)}  UNRESOLVED={ind.get('UNRESOLVED', 0)}")

    lib_rows = c.execute(
        "SELECT confidence, COUNT(*) FROM library_matches WHERE firmware_id=? GROUP BY confidence", (fw,)).fetchall()
    lib = {s: n for s, n in lib_rows}
    n_ref_confirmed = count(
        "SELECT COUNT(*) FROM library_matches WHERE firmware_id=? AND reference_source_confirmed=1", fw)
    print(f"Cross-image fingerprint matches (shared/platform-code EVIDENCE ONLY -- see below): "
          f"EXACT={lib.get('EXACT', 0)}  STRONG_MATCH={lib.get('STRONG_MATCH', 0)}  "
          f"POSSIBLE_MATCH={lib.get('POSSIBLE_MATCH', 0)}  NO_MATCH={lib.get('NO_MATCH', 0)}")
    print(f"Reference-source-confirmed (TRUE library, matched against real fetched upstream source): "
          f"{n_ref_confirmed}")

    # IMPORTANT EVIDENCE RULE: a cross-image fingerprint match (however
    # strong, however cross-product) is NEVER converted into "library
    # truth" here -- it is kept as shared/platform-code evidence only
    # (queryable via `library-matches`). Only reference_source_confirmed
    # (matched against REAL, FETCHED upstream source -- see
    # reference_library.py) counts toward the residual-exclusion split
    # below. See docs/tooling/census.md.
    n_reachable = reach.get("DEFINITELY_REACHABLE", 0) + reach.get("POSSIBLY_REACHABLE_VIA_UNRESOLVED_INDIRECT", 0)
    n_reachable_ref_confirmed = count(
        "SELECT COUNT(*) FROM function_reachability r JOIN library_matches l "
        "ON l.firmware_id=r.firmware_id AND l.function_id=r.function_id "
        "WHERE r.firmware_id=? AND r.status != 'NO_KNOWN_PATH' AND l.reference_source_confirmed=1", fw)
    n_reachable_covered = count(
        "SELECT COUNT(DISTINCT r.function_id) FROM function_reachability r "
        "JOIN dynamic_coverage dc ON dc.firmware_id=r.firmware_id AND dc.function_id=r.function_id "
        "WHERE r.firmware_id=? AND r.status != 'NO_KNOWN_PATH'", fw)
    import residual_priority
    n_residual = len(residual_priority.residual_function_ids(conn, fw))
    print(f"Reachable functions: {n_reachable}  (of which {n_reachable_ref_confirmed} are reference-source-"
          f"confirmed TRUE library code, {n_reachable_covered} are dynamically exercised)")
    print(f">>> Residual reachable, non-reference-confirmed, dynamically-unexercised functions: {n_residual} <<<")
    print("    (cross-image shared-code evidence is NOT subtracted here -- see 'library-matches' to inspect it)")

    n_components = count("SELECT COUNT(*) FROM components WHERE firmware_id=?", fw)
    print(f"Components: {n_components}")

    tier_rows = c.execute(
        "SELECT tier, COUNT(*) FROM residual_priority WHERE firmware_id=? GROUP BY tier", (fw,)).fetchall()
    if tier_rows:
        tiers = {t: n for t, n in tier_rows}
        n_residual_components = count(
            "SELECT COUNT(DISTINCT c.component_index) FROM residual_priority rp "
            "JOIN component_members cm ON cm.firmware_id=rp.firmware_id AND cm.function_id=rp.function_id "
            "JOIN components c ON c.id=cm.component_id WHERE rp.firmware_id=?", fw)
        print(f"Residual priority: HIGH={tiers.get('HIGH', 0)}  MEDIUM={tiers.get('MEDIUM', 0)}  "
              f"LOW={tiers.get('LOW', 0)}  ({n_residual_components} component(s) contain >=1 residual function "
              f"-- see 'residual-ranked'/'residual-components')")

    hw = c.execute("SELECT * FROM hardware_snapshot_runs WHERE firmware_id=?", (fw,)).fetchone()
    if hw:
        n_hw_peripherals = count(
            "SELECT COUNT(DISTINCT peripheral) FROM hardware_snapshot WHERE firmware_id=?", fw)
        n_hw_regs = count("SELECT COUNT(*) FROM hardware_snapshot WHERE firmware_id=?", fw)
        n_pins_out = count("SELECT COUNT(*) FROM pin_snapshot WHERE firmware_id=? AND direction='OUT'", fw)
        n_pins_in = count("SELECT COUNT(*) FROM pin_snapshot WHERE firmware_id=? AND direction='IN'", fw)
        n_pins_muxed = count("SELECT COUNT(*) FROM pin_snapshot WHERE firmware_id=? AND pmuxen=1", fw)
        print(f"Hardware snapshot: init_status={hw['init_status']}  boot_method={hw['boot_method']}  "
              f"{n_hw_regs} register(s) across {n_hw_peripherals} peripheral(s)")
        print(f"  pins: {n_pins_out} configured OUT, {n_pins_in} configured IN, {n_pins_muxed} PMUX-enabled")
    else:
        print("Hardware snapshot: not taken")

    contract_row = c.execute("SELECT * FROM hardware_contract_runs WHERE firmware_id=?", (fw,)).fetchone()
    if contract_row:
        print(f"Hardware contract: generated {contract_row['generated_at']}  "
              f"({len(contract_row['contract_json'])} bytes JSON -- see 'hardware-contract')")
    else:
        print("Hardware contract: not generated")


# --- function / callers / callees --------------------------------------

def cmd_function(args):
    conn = census_db.connect(args.db, create=False)
    fw = census_db.get_firmware_id(conn, args.firmware)
    addr = hexaddr(args.addr)
    f = conn.execute(
        "SELECT * FROM functions WHERE firmware_id=? AND entry=?", (fw, addr)).fetchone()
    if f is None:
        print(f"No function with entry {hx(addr)} in '{args.firmware}'.")
        return
    n_blocks = conn.execute(
        "SELECT COUNT(*) FROM basic_blocks WHERE firmware_id=? AND function_id=?", (fw, f["id"])).fetchone()[0]
    n_callers = conn.execute(
        "SELECT COUNT(*) FROM edges WHERE firmware_id=? AND to_function_id=? AND kind LIKE '%call%'",
        (fw, f["id"])).fetchone()[0]
    n_callees = conn.execute(
        "SELECT COUNT(DISTINCT to_function_id) FROM edges WHERE firmware_id=? AND from_function_id=? "
        "AND kind LIKE '%call%' AND to_function_id IS NOT NULL", (fw, f["id"])).fetchone()[0]
    n_covered_pcs = conn.execute(
        "SELECT COUNT(DISTINCT pc) FROM dynamic_coverage WHERE firmware_id=? AND function_id=?",
        (fw, f["id"])).fetchone()[0]
    scenarios = [r[0] for r in conn.execute(
        "SELECT DISTINCT dr.scenario FROM dynamic_coverage dc JOIN dynamic_runs dr ON dr.id=dc.dynamic_run_id "
        "WHERE dc.firmware_id=? AND dc.function_id=?", (fw, f["id"]))]

    print(f"{f['name']}  entry={hx(f['entry'])}  size={f['size']}  thunk={bool(f['thunk'])}  "
          f"external={bool(f['external'])}  source={f['source']}")
    print(f"  basic blocks: {n_blocks}")
    print(f"  callers (resolved): {n_callers}   distinct callees (resolved): {n_callees}")
    if n_covered_pcs:
        print(f"  dynamically exercised: {n_covered_pcs} unique PC(s) hit, in scenario(s): {', '.join(scenarios)}")
    else:
        print("  dynamically exercised: NEVER (no ingested scenario reached this function)")


def cmd_callers(args):
    conn = census_db.connect(args.db, create=False)
    fw = census_db.get_firmware_id(conn, args.firmware)
    addr = hexaddr(args.addr)
    rows = conn.execute(
        "SELECT e.from_addr, e.kind, e.resolved, e.source, ff.name AS from_name "
        "FROM edges e LEFT JOIN functions ff ON ff.id = e.from_function_id "
        "WHERE e.firmware_id=? AND e.to_addr=? AND e.kind LIKE '%call%' "
        "ORDER BY e.from_addr", (fw, addr))
    n = 0
    for r in rows:
        n += 1
        print(f"{hx(r['from_addr'])}  {r['from_name'] or '(unattributed)'}  [{r['kind']}, {r['source']}]")
    if n == 0:
        print(f"No callers of {hx(addr)} found.")


def cmd_callees(args):
    conn = census_db.connect(args.db, create=False)
    fw = census_db.get_firmware_id(conn, args.firmware)
    addr = hexaddr(args.addr)
    f = conn.execute("SELECT id FROM functions WHERE firmware_id=? AND entry=?", (fw, addr)).fetchone()
    if f is None:
        print(f"No function with entry {hx(addr)}.")
        return
    rows = conn.execute(
        "SELECT DISTINCT e.to_addr, tf.name AS to_name, e.kind, e.source "
        "FROM edges e LEFT JOIN functions tf ON tf.id = e.to_function_id "
        "WHERE e.firmware_id=? AND e.from_function_id=? AND e.kind LIKE '%call%' "
        "ORDER BY e.to_addr", (fw, f["id"]))
    n = 0
    for r in rows:
        n += 1
        target = hx(r["to_addr"]) if r["to_addr"] is not None else "(unresolved)"
        print(f"{target}  {r['to_name'] or ''}  [{r['kind']}, {r['source']}]")
    if n == 0:
        print(f"No callees found from {hx(addr)}.")


# --- readers / writers ---------------------------------------------------

def _mem_access_rows(conn, fw, addr, direction):
    return conn.execute(
        "SELECT m.from_addr, m.width, m.direction, m.source, f.name AS from_name "
        "FROM memory_accesses m LEFT JOIN functions f ON f.id = m.from_function_id "
        "WHERE m.firmware_id=? AND m.to_addr=? AND m.direction=? ORDER BY m.from_addr",
        (fw, addr, direction))


def cmd_readers(args):
    conn = census_db.connect(args.db, create=False)
    fw = census_db.get_firmware_id(conn, args.firmware)
    addr = hexaddr(args.addr)
    n = 0
    for r in _mem_access_rows(conn, fw, addr, "READ"):
        n += 1
        print(f"{hx(r['from_addr'])}  {r['from_name'] or '(unattributed)'}  width={r['width']}  [{r['source']}]")
    dyn = conn.execute(
        "SELECT COUNT(*) FROM dynamic_memory WHERE firmware_id=? AND addr=? AND direction='read'",
        (fw, addr)).fetchone()[0]
    print(f"({n} static reader(s); {dyn} dynamic read access(es) logged)")


def cmd_writers(args):
    conn = census_db.connect(args.db, create=False)
    fw = census_db.get_firmware_id(conn, args.firmware)
    addr = hexaddr(args.addr)
    n = 0
    for r in _mem_access_rows(conn, fw, addr, "WRITE"):
        n += 1
        print(f"{hx(r['from_addr'])}  {r['from_name'] or '(unattributed)'}  width={r['width']}  [{r['source']}]")
    dyn = conn.execute(
        "SELECT COUNT(*) FROM dynamic_memory WHERE firmware_id=? AND addr=? AND direction='write'",
        (fw, addr)).fetchone()[0]
    print(f"({n} static writer(s); {dyn} dynamic write access(es) logged)")


# --- peripheral / pin ----------------------------------------------------

def cmd_peripheral(args):
    conn = census_db.connect(args.db, create=False)
    fw = census_db.get_firmware_id(conn, args.firmware)
    name = args.name.upper()
    p = conn.execute("SELECT * FROM peripherals WHERE firmware_id=? AND name=?", (fw, name)).fetchone()
    if p is None:
        print(f"'{name}' is not referenced by '{args.firmware}' (no resolved MMIO access).")
        return
    print(f"{p['name']}  base={hx(p['base_addr'])}  size=0x{p['size']:x}  "
          f"static access_count={p['access_count']}")
    rows = conn.execute(
        "SELECT DISTINCT m.from_addr, f.name AS from_name, m.register_name, m.direction "
        "FROM mmio_accesses m LEFT JOIN functions f ON f.id = m.from_function_id "
        "WHERE m.firmware_id=? AND m.peripheral=? ORDER BY m.from_addr", (fw, name))
    for r in rows:
        print(f"  {hx(r['from_addr'])}  {r['from_name'] or '(unattributed)'}  "
              f"{r['register_name'] or ''}  [{r['direction']}]")
    dyn_scenarios = [r[0] for r in conn.execute(
        "SELECT DISTINCT dr.scenario FROM dynamic_mmio dm JOIN dynamic_runs dr ON dr.id=dm.dynamic_run_id "
        "WHERE dm.firmware_id=? AND dm.peripheral=?", (fw, name))]
    if dyn_scenarios:
        print(f"  dynamically touched in scenario(s): {', '.join(dyn_scenarios)}")


def cmd_pin(args):
    conn = census_db.connect(args.db, create=False)
    fw = census_db.get_firmware_id(conn, args.firmware)
    pin_name = args.name.upper()
    rows = conn.execute(
        "SELECT p.*, f.name AS from_name FROM pins p LEFT JOIN functions f ON f.id = p.from_function_id "
        "WHERE p.firmware_id=? AND p.pin_name=? ORDER BY p.evidence_kind, p.from_addr", (fw, pin_name))
    n = 0
    for r in rows:
        n += 1
        print(f"{r['evidence_kind']:8}  {hx(r['from_addr'])}  {r['from_name'] or '(unattributed)'}  "
              f"mmio={hx(r['mmio_addr'])} ({r['register_name']})  confidence={r['confidence']}")
    if n == 0:
        print(f"No PINCFG/PMUX evidence for {pin_name} in '{args.firmware}' "
              "(note: PORT bitmask registers (DIR/OUT/IN/...) are not attributed to a single pin -- "
              "see 'peripheral PORT' for all raw PORT accesses).")


# --- uncovered / indirect-edges / warnings --------------------------------

def cmd_uncovered(args):
    conn = census_db.connect(args.db, create=False)
    fw = census_db.get_firmware_id(conn, args.firmware)
    rows = conn.execute(
        "SELECT f.entry, f.name, f.size FROM functions f WHERE f.firmware_id=? AND f.id NOT IN "
        "(SELECT DISTINCT function_id FROM dynamic_coverage WHERE firmware_id=? AND function_id IS NOT NULL) "
        "ORDER BY f.entry", (fw, fw))
    n = 0
    for r in rows:
        n += 1
        print(f"{hx(r['entry'])}  {r['name']}  size={r['size']}")
    print(f"({n} function(s) discovered but never dynamically exercised in any ingested scenario)")


def cmd_indirect_edges(args):
    conn = census_db.connect(args.db, create=False)
    fw = census_db.get_firmware_id(conn, args.firmware)
    has_reduction = conn.execute(
        "SELECT COUNT(*) FROM indirect_edge_resolutions WHERE firmware_id=?", (fw,)).fetchone()[0] > 0
    if not has_reduction:
        rows = conn.execute(
            "SELECT e.from_addr, e.kind, e.source, f.name AS from_name FROM edges e "
            "LEFT JOIN functions f ON f.id = e.from_function_id "
            "WHERE e.firmware_id=? AND e.resolved=0 ORDER BY e.from_addr", (fw,))
        n = 0
        for r in rows:
            n += 1
            print(f"{hx(r['from_addr'])}  {r['from_name'] or '(unattributed)'}  [{r['kind']}, {r['source']}]")
        print(f"({n} unresolved indirect edge(s) -- run 'census reduce {args.firmware}' for full "
              f"STATICALLY_RESOLVED/DYNAMICALLY_OBSERVED/FINITE_CANDIDATE_SET/UNRESOLVED classification)")
        return

    q = ("SELECT r.from_addr, r.instr_mnemonic, r.instr_shape, r.classification, r.note, "
         "f.name AS from_name FROM indirect_edge_resolutions r "
         "LEFT JOIN functions f ON f.id = r.from_function_id WHERE r.firmware_id=?")
    params = [fw]
    if args.classification:
        q += " AND r.classification=?"
        params.append(args.classification.upper())
    q += " ORDER BY r.from_addr"
    n = 0
    counts = {}
    for r in conn.execute(q, params):
        n += 1
        counts[r["classification"]] = counts.get(r["classification"], 0) + 1
        cands = conn.execute(
            "SELECT candidate_addr, confidence, source FROM indirect_edge_candidates "
            "WHERE firmware_id=? AND from_addr=? ORDER BY confidence, candidate_addr",
            (fw, r["from_addr"])).fetchall()
        cand_str = "; ".join(f"{hx(c['candidate_addr'])}[{c['confidence']}/{c['source']}]" for c in cands[:6])
        if len(cands) > 6:
            cand_str += f"; +{len(cands) - 6} more"
        print(f"{hx(r['from_addr'])}  {r['from_name'] or '(unattributed)'}  {r['instr_mnemonic']} "
              f"({r['instr_shape']})  [{r['classification']}]" + (f"  candidates: {cand_str}" if cand_str else "")
              + (f"  -- {r['note']}" if r["note"] else ""))
    print(f"({n} indirect edge(s): {counts})")


def cmd_warnings(args):
    conn = census_db.connect(args.db, create=False)
    fw = census_db.get_firmware_id(conn, args.firmware)
    if args.category:
        rows = conn.execute(
            "SELECT * FROM scan_warnings WHERE firmware_id=? AND category=? ORDER BY addr",
            (fw, args.category))
    else:
        rows = conn.execute(
            "SELECT * FROM scan_warnings WHERE firmware_id=? ORDER BY category, addr", (fw,))
    n = 0
    for r in rows:
        n += 1
        print(f"[{r['category']}] {hx(r['addr']) if r['addr'] is not None else ''}  {r['detail']}")
    print(f"({n} warning(s))")


# --- ingest-dynamic --------------------------------------------------------

def cmd_ingest_dynamic(args):
    import dynamic_ingest
    conn = census_db.connect(args.db)
    path = Path(args.path)
    if path.is_dir():
        nfiles, nruns = dynamic_ingest.ingest_dir(conn, path, firmware_key_filter=args.firmware)
        print(f"Ingested {nfiles} file(s), {nruns} dynamic run(s).")
    else:
        nruns = dynamic_ingest.ingest_file(conn, path, firmware_key_filter=args.firmware)
        print(f"Ingested {nruns} dynamic run(s).")


# --- reachable / residual / components / library-matches / hardware-snapshot --

def cmd_reachable(args):
    conn = census_db.connect(args.db, create=False)
    fw = census_db.get_firmware_id(conn, args.firmware)
    q = ("SELECT f.entry, f.name, r.status, r.nearest_root_addr, r.nearest_root_kind, r.hops "
         "FROM function_reachability r JOIN functions f ON f.id=r.function_id WHERE r.firmware_id=?")
    params = [fw]
    if args.status:
        q += " AND r.status=?"
        params.append(args.status.upper())
    q += " ORDER BY f.entry"
    n = 0
    for r in conn.execute(q, params):
        n += 1
        root = f"{hx(r['nearest_root_addr'])} ({r['nearest_root_kind']})" if r["nearest_root_addr"] is not None else "-"
        print(f"{hx(r['entry'])}  {r['name']}  [{r['status']}]  hops={r['hops']}  nearest_root={root}")
    print(f"({n} function(s))")


def cmd_residual(args):
    """The residual queue: reachable, not reference-source-confirmed
    library code, dynamically-unexercised functions -- the small set
    later semantic analysis should actually look at. A cross-image
    fingerprint match (shown here for context) is NOT, by itself,
    grounds for exclusion -- see docs/tooling/census.md's evidence rule.
    Uses residual_priority.residual_function_ids -- the ONE place this
    definition lives, so this command and `residual-ranked`/
    `residual-components` can never silently drift apart."""
    import residual_priority
    conn = census_db.connect(args.db, create=False)
    fw = census_db.get_firmware_id(conn, args.firmware)
    ids = residual_priority.residual_function_ids(conn, fw)
    if not ids:
        print("(0 residual function(s) -- reachable, not reference-source-confirmed library code, "
              "never dynamically exercised)")
        return
    placeholders = ",".join("?" for _ in ids)
    rows = conn.execute(
        "SELECT f.entry, f.name, f.size, r.status, l.confidence AS lib_confidence, "
        "l.reference_source_confirmed, ff.n_callers, ff.n_callees, ff.peripherals_json, ff.pins_json "
        "FROM function_reachability r "
        "JOIN functions f ON f.id = r.function_id "
        "LEFT JOIN library_matches l ON l.firmware_id=r.firmware_id AND l.function_id=r.function_id "
        "LEFT JOIN function_features ff ON ff.firmware_id=r.firmware_id AND ff.function_id=r.function_id "
        f"WHERE r.firmware_id=? AND r.function_id IN ({placeholders}) ORDER BY f.entry", (fw, *ids))
    n = 0
    for r in rows:
        n += 1
        print(f"{hx(r['entry'])}  {r['name']}  size={r['size']}  [{r['status']}]  "
              f"shared-code-evidence={r['lib_confidence'] or 'NO_MATCH'}  callers={r['n_callers']} "
              f"callees={r['n_callees']}  peripherals={r['peripherals_json']}  pins={r['pins_json']}")
    print(f"({n} residual function(s) -- reachable, not reference-source-confirmed library code, "
          f"never dynamically exercised)")


def cmd_components(args):
    conn = census_db.connect(args.db, create=False)
    fw = census_db.get_firmware_id(conn, args.firmware)
    if args.id is not None:
        comps = conn.execute(
            "SELECT * FROM components WHERE firmware_id=? AND component_index=?", (fw, args.id)).fetchall()
    else:
        comps = conn.execute(
            "SELECT * FROM components WHERE firmware_id=? ORDER BY component_index", (fw,)).fetchall()
    for comp in comps:
        members = conn.execute(
            "SELECT f.entry, f.name FROM component_members cm JOIN functions f ON f.id=cm.function_id "
            "WHERE cm.component_id=? ORDER BY f.entry", (comp["id"],)).fetchall()
        print(f"component {comp['component_index']}  ({comp['n_functions']} functions)")
        print(f"  functions: {', '.join(f'{hx(m[0])}:{m[1]}' for m in members[:12])}"
              + (f"  (+{len(members) - 12} more)" if len(members) > 12 else ""))
        print(f"  peripherals: {comp['peripherals_json']}")
        print(f"  pins: {comp['pins_json']}")
        print(f"  RAM addrs: {comp['ram_addrs_json']}")
        print(f"  scenarios: {comp['scenarios_json']}")
    print(f"({len(comps)} component(s))")


def cmd_library_matches(args):
    conn = census_db.connect(args.db, create=False)
    fw = census_db.get_firmware_id(conn, args.firmware)
    q = ("SELECT f.entry, f.name, l.confidence, l.method, l.matched_firmware_key, l.matched_function_name "
         "FROM library_matches l JOIN functions f ON f.id=l.function_id WHERE l.firmware_id=?")
    params = [fw]
    if args.confidence:
        q += " AND l.confidence=?"
        params.append(args.confidence.upper())
    q += " ORDER BY f.entry"
    n = 0
    counts = {}
    for r in conn.execute(q, params):
        n += 1
        counts[r["confidence"]] = counts.get(r["confidence"], 0) + 1
        match = f"{r['matched_firmware_key']}:{r['matched_function_name']}" if r["matched_firmware_key"] else "-"
        print(f"{hx(r['entry'])}  {r['name']}  [{r['confidence']}/{r['method']}]  matched={match}")
    print(f"({n} function(s): {counts})")


def cmd_hardware_snapshot(args):
    conn = census_db.connect(args.db, create=False)
    fw = census_db.get_firmware_id(conn, args.firmware)
    run = conn.execute("SELECT * FROM hardware_snapshot_runs WHERE firmware_id=?", (fw,)).fetchone()
    if run is None:
        print(f"No hardware snapshot for '{args.firmware}' -- run 'census reduce {args.firmware}'.")
        return
    print(f"init_status={run['init_status']}  boot_method={run['boot_method']}  "
          f"instructions_executed={run['instructions_executed']}  stop_reason={run['stop_reason']}")
    print(f"notes: {run['notes']}")
    if run["assumptions_json"]:
        import json as _json
        assumptions = _json.loads(run["assumptions_json"])
        print(f"disclosed assumptions ({len(assumptions)}):")
        for a in assumptions:
            addr_s = hx(a["addr"]) if a.get("addr") is not None else "-"
            print(f"  [{a['kind']}] {addr_s}  {a['detail']}")
            print(f"      citation: {a['citation']}")
    print()
    q = "SELECT * FROM hardware_snapshot WHERE firmware_id=?"
    params = [fw]
    if args.peripheral:
        q += " AND peripheral=?"
        params.append(args.peripheral.upper())
    q += " ORDER BY addr"
    n = 0
    for r in conn.execute(q, params):
        n += 1
        print(f"{hx(r['addr'])}  {r['peripheral']}.{r['register_name']}  = 0x{r['raw_value']}  "
              f"(width={r['width']})")
    print(f"({n} register(s))")
    if not args.peripheral:
        print()
        pin_rows = conn.execute(
            "SELECT * FROM pin_snapshot WHERE firmware_id=? AND (direction IS NOT NULL OR pmuxen=1) "
            "ORDER BY group_index, pin_index", (fw,)).fetchall()
        for r in pin_rows:
            pincfg_s = f"0x{r['pincfg_raw']:02x}" if r["pincfg_raw"] is not None else "-"
            print(f"{r['pin_name']}  dir={r['direction']}  out={r['output_value']}  in={r['input_value']}  "
                  f"pincfg={pincfg_s}  pmuxen={r['pmuxen']}  pmux_nibble={r['pmux_nibble']}")
        print(f"({len(pin_rows)} configured pin(s) shown -- pass a pin name to 'pin' for full evidence detail)")


# --- residual-ranked / residual-components / hardware-contract / diff ------

def cmd_residual_ranked(args):
    """The residual queue, RANKED: every residual function's deterministic
    priority score plus the individual signals that produced it -- never
    just the number. Grouped into the three disclosed tiers."""
    import json as _json
    import residual_priority
    conn = census_db.connect(args.db, create=False)
    fw = census_db.get_firmware_id(conn, args.firmware)
    q = ("SELECT rp.*, f.entry, f.name FROM residual_priority rp "
         "JOIN functions f ON f.id = rp.function_id WHERE rp.firmware_id=?")
    params = [fw]
    if args.tier:
        q += " AND rp.tier=?"
        params.append(args.tier.upper())
    q += " ORDER BY rp.score DESC, f.entry"
    rows = conn.execute(q, params).fetchall()
    if not rows:
        has_any = conn.execute("SELECT COUNT(*) FROM residual_priority WHERE firmware_id=?", (fw,)).fetchone()[0]
        if has_any == 0:
            print(f"No residual-priority data for '{args.firmware}' -- run 'census reduce {args.firmware}'.")
        else:
            print(f"(0 function(s) in tier {args.tier!r})")
        return

    by_tier = {}
    for r in rows:
        by_tier.setdefault(r["tier"], []).append(r)
    for tier in ("HIGH", "MEDIUM", "LOW"):
        if tier not in by_tier:
            continue
        print(f"=== {residual_priority.TIER_LABELS[tier]} ({len(by_tier[tier])}) ===")
        for r in by_tier[tier]:
            print(f"{hx(r['entry'])}  {r['name']}  score={r['score']}")
            for reason in _json.loads(r["reasons_json"]):
                sign = "+" if reason["points"] >= 0 else ""
                print(f"    {sign}{reason['points']}  [{reason['signal']}] {reason['description']}"
                      f" -- {reason['evidence']}")
        print()
    print(f"({len(rows)} residual function(s) scored -- see docs/tooling/census.md's "
          f"'Residual prioritization' section for the fixed signal table)")


def cmd_residual_components(args):
    """Residual functions collapsed into components (tools/census/
    components.py's existing deterministic grouping, restricted to
    components with >=1 residual member) -- the actual small,
    evidence-rich unit a later semantic phase should look at instead of
    hundreds of individual functions."""
    import json as _json
    import residual_priority
    conn = census_db.connect(args.db, create=False)
    fw = census_db.get_firmware_id(conn, args.firmware)

    residual_rows = conn.execute(
        "SELECT rp.function_id, rp.score, rp.tier FROM residual_priority rp WHERE rp.firmware_id=?", (fw,)).fetchall()
    if not residual_rows:
        print(f"No residual-priority data for '{args.firmware}' -- run 'census reduce {args.firmware}'.")
        return
    residual_by_fid = {r["function_id"]: r for r in residual_rows}

    comp_of_fid = {}
    for r in conn.execute(
            "SELECT cm.function_id, c.id AS component_id, c.component_index FROM component_members cm "
            "JOIN components c ON c.id = cm.component_id WHERE cm.firmware_id=?", (fw,)):
        comp_of_fid[r["function_id"]] = (r["component_id"], r["component_index"])

    residual_component_ids = sorted({comp_of_fid[fid][1] for fid in residual_by_fid if fid in comp_of_fid})

    summaries = []
    for comp_idx in residual_component_ids:
        comp = conn.execute(
            "SELECT * FROM components WHERE firmware_id=? AND component_index=?", (fw, comp_idx)).fetchone()
        members = conn.execute(
            "SELECT f.id, f.entry, f.name FROM component_members cm JOIN functions f ON f.id=cm.function_id "
            "WHERE cm.component_id=? ORDER BY f.entry", (comp["id"],)).fetchall()
        member_ids = [m["id"] for m in members]
        placeholders = ",".join("?" for _ in member_ids)

        roots = sorted({r[0] for r in conn.execute(
            f"SELECT DISTINCT nearest_root_kind FROM function_reachability WHERE firmware_id=? "
            f"AND function_id IN ({placeholders}) AND nearest_root_kind IS NOT NULL", (fw, *member_ids))})
        tier_dist = {}
        for m in members:
            rp = residual_by_fid.get(m["id"])
            if rp:
                tier_dist[rp["tier"]] = tier_dist.get(rp["tier"], 0) + 1
        n_unresolved_indirect = conn.execute(
            f"SELECT COUNT(*) FROM indirect_edge_resolutions WHERE firmware_id=? AND from_function_id IN "
            f"({placeholders}) AND classification IN ('UNRESOLVED','FINITE_CANDIDATE_SET')",
            (fw, *member_ids)).fetchone()[0]
        lib_rows = conn.execute(
            f"SELECT confidence, reference_source_confirmed FROM library_matches WHERE firmware_id=? "
            f"AND function_id IN ({placeholders})", (fw, *member_ids)).fetchall()
        lib_counts = {}
        n_ref_confirmed = 0
        for lr in lib_rows:
            lib_counts[lr["confidence"]] = lib_counts.get(lr["confidence"], 0) + 1
            n_ref_confirmed += lr["reference_source_confirmed"]

        max_score = max((residual_by_fid[m["id"]]["score"] for m in members if m["id"] in residual_by_fid),
                         default=None)
        comp_tier = residual_priority.tier_for(max_score) if max_score is not None else "LOW"

        summaries.append({
            "component_index": comp_idx, "comp": comp, "members": members, "roots": roots,
            "tier_dist": tier_dist, "n_unresolved_indirect": n_unresolved_indirect, "lib_counts": lib_counts,
            "n_ref_confirmed": n_ref_confirmed, "max_score": max_score, "comp_tier": comp_tier,
        })

    summaries.sort(key=lambda s: (-(s["max_score"] if s["max_score"] is not None else -999), s["component_index"]))

    by_tier = {}
    for s in summaries:
        by_tier.setdefault(s["comp_tier"], []).append(s)
    for tier in ("HIGH", "MEDIUM", "LOW"):
        if tier not in by_tier:
            continue
        print(f"=== {residual_priority.TIER_LABELS[tier]} COMPONENTS ({len(by_tier[tier])}) ===")
        for s in by_tier[tier]:
            comp = s["comp"]
            n_residual_members = sum(s["tier_dist"].values())
            print(f"component {s['component_index']}  ({comp['n_functions']} function(s), "
                  f"{n_residual_members} residual)  max_score={s['max_score']}")
            print(f"  functions: " + ", ".join(f"{hx(m['entry'])}:{m['name']}" for m in s["members"][:12])
                  + (f"  (+{len(s['members']) - 12} more)" if len(s["members"]) > 12 else ""))
            print(f"  reachability roots: {s['roots']}")
            print(f"  priority distribution (residual members only): {s['tier_dist']}")
            print(f"  peripherals: {comp['peripherals_json']}")
            print(f"  pins: {comp['pins_json']}")
            print(f"  RAM addrs: {comp['ram_addrs_json']}")
            print(f"  strings/constants: {comp['strings_json']}")
            print(f"  dynamic scenarios: {comp['scenarios_json']}")
            print(f"  unresolved/finite-candidate-set indirect edges from members: {s['n_unresolved_indirect']}")
            print(f"  cross-image fingerprint matches: {s['lib_counts']}  "
                  f"(reference-source-confirmed: {s['n_ref_confirmed']})")
        print()
    print(f"({sum(len(s) for s in by_tier.values())} component(s) contain >=1 residual function, out of "
          f"{len(residual_by_fid)} residual function(s) total -- see 'components' for the full, "
          f"non-residual-filtered grouping)")


def cmd_hardware_contract(args):
    conn = census_db.connect(args.db, create=False)
    fw = census_db.get_firmware_id(conn, args.firmware)
    row = conn.execute("SELECT * FROM hardware_contract_runs WHERE firmware_id=?", (fw,)).fetchone()
    if row is None:
        print(f"No hardware contract for '{args.firmware}' -- run 'census reduce {args.firmware}'.")
        return
    import json as _json
    contract = _json.loads(row["contract_json"])
    text = _json.dumps(contract, indent=2, sort_keys=False)
    if args.out:
        Path(args.out).write_text(text)
        print(f"Wrote hardware contract ({len(text)} bytes, generated_at={row['generated_at']}) to {args.out}")
    else:
        print(text)


def cmd_diff(args):
    import firmware_diff
    conn = census_db.connect(args.db, create=False)
    result = firmware_diff.diff_firmwares(conn, args.firmware_a, args.firmware_b)
    if args.json:
        import json as _json
        print(_json.dumps(result, indent=2, sort_keys=False))
        return

    print(f"=== census diff: {args.firmware_a} vs {args.firmware_b} ===")
    c = result["counts"]
    print(f"Hardware register diffs: {c['hardware_register_diffs']}")
    for d in result["hardware_register_diffs"][:30]:
        print(f"  {d['peripheral']}.{d['register']} @{d['addr']}: A=0x{d['value_a']} B=0x{d['value_b']}")
    if c["hardware_register_diffs"] > 30:
        print(f"  (+{c['hardware_register_diffs'] - 30} more)")

    print(f"\nMMIO sites only in A: {c['mmio_sites_only_in_a']}   only in B: {c['mmio_sites_only_in_b']}")
    for d in result["mmio_site_diffs"]["only_in_a"][:15]:
        print(f"  A only: {d['peripheral']}.{d['register']}")
    for d in result["mmio_site_diffs"]["only_in_b"][:15]:
        print(f"  B only: {d['peripheral']}.{d['register']}")

    print(f"\nPin config diffs: {c['pin_config_diffs']}")
    for d in result["pin_config_diffs"][:30]:
        if "only_in" in d:
            print(f"  {d['pin_name']}: only configured in {d['only_in'].upper()}")
        else:
            print(f"  {d['pin_name']}: {d['changed_fields']}")

    rd = result["residual_diffs"]
    print(f"\nResidual/function diffs (paired by EXACT byte-identical fingerprint):")
    print(f"  byte-identical function pairs: {rd['byte_identical_function_count']}")
    print(f"  functions only in A: {c['functions_only_in_a']}   only in B: {c['functions_only_in_b']}")
    print(f"  residual priority diffs (same code, different residual score/tier): {c['residual_priority_diffs']}")
    for d in rd["residual_priority_diffs"][:15]:
        print(f"    {d['name_a']} ({d['entry_a']}/{d['entry_b']}): A={d['priority_a']} B={d['priority_b']}")

    print(f"\nString/constant diffs: only in A: {c['strings_only_in_a']}   only in B: {c['strings_only_in_b']}")
    print(f"Hardware-relevant constant diffs (MMIO-touching, byte-identical functions with differing "
          f"literal-ref counts): {c['hardware_relevant_constant_diffs']}")
    for d in result["hardware_relevant_constant_diffs"][:15]:
        print(f"  {d['name_a']} ({d['entry_a']}/{d['entry_b']}): "
              f"n_literal_refs A={d['n_literal_refs_a']} B={d['n_literal_refs_b']}")
    print(f"\n({result['note']})")


# --- reference-corpus / reference-match / reference-matches / reference-unmatched --

def cmd_reference_corpus(args):
    import reference_corpus
    conn = census_db.connect(args.db)
    if args.subcommand == "fetch":
        reference_corpus.fetch(conn=conn)
    elif args.subcommand == "build":
        reference_corpus.build(conn)
    else:
        raise SystemExit(f"unknown reference-corpus subcommand {args.subcommand!r} (fetch/build)")


def cmd_reference_match(args):
    import reference_match
    sys.path.insert(0, str(HERE.parent / "ghidra"))
    import aptrace_ghidra as ghidra
    conn = census_db.connect(args.db, create=False)
    fw = census_db.get_firmware_id(conn, args.firmware)
    fw_row = conn.execute("SELECT * FROM firmware WHERE id=?", (fw,)).fetchone()
    fw_path, _flash_base_s, _labels = ghidra.firmware_info(args.firmware)
    firmware_bytes = fw_path.read_bytes()
    reference_match.compute(conn, fw, firmware_bytes, fw_row["flash_base"])


def cmd_reference_matches(args):
    conn = census_db.connect(args.db, create=False)
    fw = census_db.get_firmware_id(conn, args.firmware)
    q = ("SELECT rm.*, f.entry, f.name FROM reference_matches rm JOIN functions f ON f.id=rm.function_id "
         "WHERE rm.firmware_id=?")
    params = [fw]
    if args.tier:
        q += " AND rm.tier=?"
        params.append(args.tier.upper())
    q += " ORDER BY f.entry"
    rows = conn.execute(q, params).fetchall()
    if args.package:
        pkg_rows = conn.execute(
            "SELECT rm.function_id FROM reference_matches rm "
            "JOIN reference_symbols rs ON rs.id = rm.reference_symbol_id "
            "JOIN reference_packages rp ON rp.id = rs.package_id "
            "WHERE rm.firmware_id=? AND rp.pkg_key=?", (fw, args.package)).fetchall()
        keep = {r["function_id"] for r in pkg_rows}
        rows = [r for r in rows if r["function_id"] in keep]

    n = 0
    counts = {}
    for r in rows:
        n += 1
        counts[r["tier"]] = counts.get(r["tier"], 0) + 1
        print(f"firmware: {args.firmware}")
        print(f"function: {hx(r['entry'])}  {r['name']}")
        print(f"match: {r['tier']}")
        if r["reference_symbol_id"]:
            sym = conn.execute(
                "SELECT rs.source_file, rs.symbol, rp.name AS pkg_name, rp.version AS pkg_version "
                "FROM reference_symbols rs JOIN reference_packages rp ON rp.id = rs.package_id "
                "WHERE rs.id=?", (r["reference_symbol_id"],)).fetchone()
            print(f"package: {sym['pkg_name']}")
            print(f"version: {sym['pkg_version']}")
            print(f"source: {sym['source_file']}")
            print(f"symbol: {sym['symbol']}")
        print(f"is_ambiguous: {bool(r['is_ambiguous'])}")
        print(f"reference_source_confirmed: {bool(r['reference_source_confirmed'])}")
        print(f"provenance: {r['detail']}")
        print()
    print(f"({n} match(es): {counts})")


def cmd_state_map(args):
    """Generic indexed state/event array mapper -- see state_map.py's
    module docstring for the evidence model. Prints a deterministic
    slot-by-slot summary and stores the full result in SQLite
    (state_map_runs/state_map_slots/state_map_dispatcher_probes)."""
    import state_map
    conn = census_db.connect(args.db, create=False)
    base = hexaddr(args.base)
    dispatcher_entry = hexaddr(args.dispatcher_entry) if args.dispatcher_entry else None
    tx_wrappers = [hexaddr(a) for a in args.tx_wrapper]
    index_addr = hexaddr(args.index_addr) if args.index_addr else None

    run_id = state_map.build_state_map(
        conn, args.firmware, base, args.count, args.width,
        label=args.label, dispatcher_entry=dispatcher_entry)

    if dispatcher_entry is not None:
        state_map.probe_dispatcher(
            conn, run_id, args.firmware, base, args.width, args.count, dispatcher_entry,
            tx_wrappers=tx_wrappers, extra_seed=args.extra_seed, index_addr=index_addr,
            index_width=args.index_width, max_instructions=args.max_instructions)

    print(f"state-map run {run_id}: '{args.firmware}' base={hx(base)} count={args.count} "
          f"width={args.width}" + (f" label={args.label!r}" if args.label else ""))
    print(f"{'slot':>4}  {'addr':>10}  {'static_w':>8}  {'reachable_w':>11}  {'dyn_w':>5}  "
          f"{'dispatcher':>13}  unresolved")
    for row in state_map.summary_rows(conn, run_id):
        s, probe = row["slot"], row["probe"]
        writers = json.loads(s["static_writers_json"])
        reach = sorted({w["reachability"] for w in writers if w["reachability"]})
        disp = "-"
        if probe:
            disp = probe["outcome"]
            if probe["output_depends_on_unresolved_source"]:
                disp += "*"
        unresolved = "UNRESOLVED_PRODUCER" if s["unresolved_producer"] else ""
        print(f"{s['slot_index']:>4}  {hx(s['addr']):>10}  {len(writers):>8}  "
              f"{','.join(reach) or '-':>11}  {s['has_dynamic_writer']:>5}  {disp:>13}  {unresolved}")
    print(f"\n(run_id={run_id}; * = dispatcher reached a real TX call but this probe supplied no "
          f"source value, so the captured output is empty/all-zero -- "
          f"output_depends_on_unresolved_source)")


def cmd_reference_unmatched(args):
    conn = census_db.connect(args.db, create=False)
    fw = census_db.get_firmware_id(conn, args.firmware)
    rows = conn.execute(
        "SELECT f.entry, f.name, f.size FROM reference_matches rm JOIN functions f ON f.id=rm.function_id "
        "WHERE rm.firmware_id=? AND rm.tier='NO_MATCH' ORDER BY f.entry", (fw,)).fetchall()
    n_total = conn.execute("SELECT COUNT(*) FROM reference_matches WHERE firmware_id=?", (fw,)).fetchone()[0]
    if n_total == 0:
        print(f"No reference-match data for '{args.firmware}' -- run 'reference-match {args.firmware}'.")
        return
    for r in rows:
        print(f"{hx(r['entry'])}  {r['name']}  size={r['size']}")
    print(f"({len(rows)} unmatched function(s) of {n_total} total)")


def main(argv):
    import argparse
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--db", default=None, help="census database path (default: research/runs/census/census.sqlite3)")
    sub = p.add_subparsers(dest="command", required=True)

    b = sub.add_parser("build", help="run the full census pipeline for one firmware image")
    b.add_argument("firmware")
    b.add_argument("--no-ghidra-build", action="store_true")

    rd_cmd = sub.add_parser("reduce", help="run the closure-reduction layer on top of an existing build")
    rd_cmd.add_argument("firmware")

    s = sub.add_parser("summary", help="mechanical closure-report counts")
    s.add_argument("firmware")

    fn = sub.add_parser("function", help="details for one function")
    fn.add_argument("firmware")
    fn.add_argument("addr")

    cl = sub.add_parser("callers", help="every resolved caller of an address")
    cl.add_argument("firmware")
    cl.add_argument("addr")

    ce = sub.add_parser("callees", help="every resolved callee of a function")
    ce.add_argument("firmware")
    ce.add_argument("addr")

    rd = sub.add_parser("readers", help="static + dynamic readers of a RAM address")
    rd.add_argument("firmware")
    rd.add_argument("addr")

    wr = sub.add_parser("writers", help="static + dynamic writers of a RAM address")
    wr.add_argument("firmware")
    wr.add_argument("addr")

    pe = sub.add_parser("peripheral", help="every access to a named SAMD51 peripheral")
    pe.add_argument("firmware")
    pe.add_argument("name")

    pn = sub.add_parser("pin", help="PINCFG/PMUX evidence for one pin (e.g. PB05)")
    pn.add_argument("firmware")
    pn.add_argument("name")

    un = sub.add_parser("uncovered", help="functions discovered but never dynamically exercised")
    un.add_argument("firmware")

    ie = sub.add_parser("indirect-edges", help="every indirect call/jump, classified if 'reduce' has run")
    ie.add_argument("firmware")
    ie.add_argument("--classification", default=None,
                     help="STATICALLY_RESOLVED / DYNAMICALLY_OBSERVED / FINITE_CANDIDATE_SET / UNRESOLVED")

    wa = sub.add_parser("warnings", help="every scan disagreement/anomaly")
    wa.add_argument("firmware")
    wa.add_argument("--category", default=None)

    ig = sub.add_parser("ingest-dynamic", help="ingest a dynamic_export.py JSON file or directory")
    ig.add_argument("path")
    ig.add_argument("--firmware", default=None)

    rc = sub.add_parser("reachable", help="every function's reachability status")
    rc.add_argument("firmware")
    rc.add_argument("--status", default=None,
                     help="DEFINITELY_REACHABLE / POSSIBLY_REACHABLE_VIA_UNRESOLVED_INDIRECT / NO_KNOWN_PATH")

    res = sub.add_parser("residual", help="the residual queue for later semantic analysis")
    res.add_argument("firmware")

    cm = sub.add_parser("components", help="deterministic function groupings")
    cm.add_argument("firmware")
    cm.add_argument("--id", type=int, default=None, dest="id")

    lm = sub.add_parser("library-matches", help="library/platform fingerprint matches")
    lm.add_argument("firmware")
    lm.add_argument("--confidence", default=None,
                     help="EXACT / STRONG_MATCH / POSSIBLE_MATCH / NO_MATCH")

    hw = sub.add_parser("hardware-snapshot", help="MCU register/pin state snapshot")
    hw.add_argument("firmware")
    hw.add_argument("--peripheral", default=None)

    rr = sub.add_parser("residual-ranked", help="the residual queue, ranked by deterministic priority score")
    rr.add_argument("firmware")
    rr.add_argument("--tier", default=None, help="HIGH / MEDIUM / LOW")

    rcomp = sub.add_parser("residual-components", help="residual functions collapsed into components")
    rcomp.add_argument("firmware")

    hc = sub.add_parser("hardware-contract", help="machine-readable hardware contract (JSON)")
    hc.add_argument("firmware")
    hc.add_argument("--out", default=None, help="write JSON to this file instead of stdout")

    df = sub.add_parser("diff", help="structured mechanical diff between two firmware images (e.g. 868 vs 915)")
    df.add_argument("firmware_a")
    df.add_argument("firmware_b")
    df.add_argument("--json", action="store_true", help="print the full structured diff as JSON")

    rcorp = sub.add_parser("reference-corpus", help="fetch/build the mechanical reference-source corpus")
    rcorp.add_argument("subcommand", choices=["fetch", "build"])

    rm = sub.add_parser("reference-match", help="match one firmware's functions against the reference corpus")
    rm.add_argument("firmware")

    rms = sub.add_parser("reference-matches", help="list reference-source match results")
    rms.add_argument("firmware")
    rms.add_argument("--package", default=None, help="filter to one reference_packages.pkg_key")
    rms.add_argument("--tier", default=None,
                     help="EXACT_BYTES/EXACT_INSTRUCTIONS/RELOCATION_NORMALIZED/PC_RELATIVE_NORMALIZED/"
                          "STRONG_STRUCTURAL/NO_MATCH")

    run = sub.add_parser("reference-unmatched", help="functions with NO_MATCH against the reference corpus")
    run.add_argument("firmware")

    sm = sub.add_parser("state-map", help="generic indexed state/event array mapper (see state_map.py)")
    sm.add_argument("firmware")
    sm.add_argument("--base", required=True, help="array base address, e.g. 0x200025bc")
    sm.add_argument("--count", type=int, required=True, help="number of slots")
    sm.add_argument("--width", type=int, default=1, help="bytes per slot (default 1)")
    sm.add_argument("--label", default=None, help="human-readable name for this array, purely descriptive")
    sm.add_argument("--dispatcher-entry", default=None,
                     help="optional: also run the generic dispatcher probe from this real entry point")
    sm.add_argument("--tx-wrapper", action="append", default=[],
                     help="a real TX-wrapper address the probe should stop at and capture (repeatable)")
    sm.add_argument("--extra-seed", action="append", default=[],
                     help="ADDR=HEXBYTES, applied identically before every probed slot (repeatable) -- "
                          "mechanical wiring (e.g. a queue-length constant), never a semantic source value")
    sm.add_argument("--index-addr", default=None,
                     help="optional: also write the slot index N here each iteration (e.g. a scan-table slot)")
    sm.add_argument("--index-width", type=int, default=1)
    sm.add_argument("--max-instructions", type=int, default=5000)

    args = p.parse_args(argv)
    {
        "build": cmd_build, "reduce": cmd_reduce, "summary": cmd_summary, "function": cmd_function,
        "callers": cmd_callers, "callees": cmd_callees, "readers": cmd_readers,
        "writers": cmd_writers, "peripheral": cmd_peripheral, "pin": cmd_pin,
        "uncovered": cmd_uncovered, "indirect-edges": cmd_indirect_edges,
        "warnings": cmd_warnings, "ingest-dynamic": cmd_ingest_dynamic,
        "reachable": cmd_reachable, "residual": cmd_residual, "components": cmd_components,
        "library-matches": cmd_library_matches, "hardware-snapshot": cmd_hardware_snapshot,
        "residual-ranked": cmd_residual_ranked, "residual-components": cmd_residual_components,
        "hardware-contract": cmd_hardware_contract, "diff": cmd_diff,
        "reference-corpus": cmd_reference_corpus, "reference-match": cmd_reference_match,
        "reference-matches": cmd_reference_matches, "reference-unmatched": cmd_reference_unmatched,
        "state-map": cmd_state_map,
    }[args.command](args)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
