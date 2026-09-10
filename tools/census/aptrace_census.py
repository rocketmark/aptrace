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

Usage:
    aptrace_census.py build autopilot868
    aptrace_census.py summary autopilot868
    aptrace_census.py function autopilot868 0x8258
    aptrace_census.py callers autopilot868 0x8258
    aptrace_census.py callees autopilot868 0x8258
    aptrace_census.py readers autopilot868 0x20001b14
    aptrace_census.py writers autopilot868 0x20001b14
    aptrace_census.py peripheral autopilot868 TC1
    aptrace_census.py pin autopilot868 PB05
    aptrace_census.py uncovered autopilot868
    aptrace_census.py indirect-edges autopilot868
    aptrace_census.py warnings autopilot868 [--category CATEGORY]
    aptrace_census.py ingest-dynamic <export.json-or-dir> [--firmware KEY]
"""
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
    rows = conn.execute(
        "SELECT e.from_addr, e.kind, e.source, f.name AS from_name FROM edges e "
        "LEFT JOIN functions f ON f.id = e.from_function_id "
        "WHERE e.firmware_id=? AND e.resolved=0 ORDER BY e.from_addr", (fw,))
    n = 0
    for r in rows:
        n += 1
        print(f"{hx(r['from_addr'])}  {r['from_name'] or '(unattributed)'}  [{r['kind']}, {r['source']}]")
    print(f"({n} unresolved indirect edge(s))")


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


def main(argv):
    import argparse
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--db", default=None, help="census database path (default: research/runs/census/census.sqlite3)")
    sub = p.add_subparsers(dest="command", required=True)

    b = sub.add_parser("build", help="run the full census pipeline for one firmware image")
    b.add_argument("firmware")
    b.add_argument("--no-ghidra-build", action="store_true")

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

    ie = sub.add_parser("indirect-edges", help="every unresolved indirect call/jump")
    ie.add_argument("firmware")

    wa = sub.add_parser("warnings", help="every scan disagreement/anomaly")
    wa.add_argument("firmware")
    wa.add_argument("--category", default=None)

    ig = sub.add_parser("ingest-dynamic", help="ingest a dynamic_export.py JSON file or directory")
    ig.add_argument("path")
    ig.add_argument("--firmware", default=None)

    args = p.parse_args(argv)
    {
        "build": cmd_build, "summary": cmd_summary, "function": cmd_function,
        "callers": cmd_callers, "callees": cmd_callees, "readers": cmd_readers,
        "writers": cmd_writers, "peripheral": cmd_peripheral, "pin": cmd_pin,
        "uncovered": cmd_uncovered, "indirect-edges": cmd_indirect_edges,
        "warnings": cmd_warnings, "ingest-dynamic": cmd_ingest_dynamic,
    }[args.command](args)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
