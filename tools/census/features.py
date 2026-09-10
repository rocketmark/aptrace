"""APTrace census reduce: one materialized function_features row per
function -- purely structural counts and small evidence lists (never a
semantic field), aggregated from tables build.py and this reduce layer
already populated. Convenience/performance only: every count here is
independently re-derivable from the base tables (functions, edges,
memory_accesses, mmio_accesses, pins, strings, literal_refs,
dynamic_coverage, function_reachability, library_matches) by direct
SQL -- this table just saves re-joining them for a single-function
lookup.
"""
import json


def compute(conn, firmware_id):
    functions = conn.execute("SELECT id FROM functions WHERE firmware_id=?", (firmware_id,)).fetchall()
    irq_by_function = {}
    for v in conn.execute(
            "SELECT vector_index, target_addr FROM vectors WHERE firmware_id=? AND is_irq=1 "
            "AND target_addr IS NOT NULL", (firmware_id,)):
        f = conn.execute("SELECT id FROM functions WHERE firmware_id=? AND entry=?",
                          (firmware_id, v["target_addr"])).fetchone()
        if f is not None:
            irq_by_function[f["id"]] = v["vector_index"]

    reach = {r["function_id"]: r["status"] for r in conn.execute(
        "SELECT function_id, status FROM function_reachability WHERE firmware_id=?", (firmware_id,))}
    lib = {r["function_id"]: r["confidence"] for r in conn.execute(
        "SELECT function_id, confidence FROM library_matches WHERE firmware_id=?", (firmware_id,))}

    out = []
    for row in functions:
        fid = row["id"]

        n_callers = conn.execute(
            "SELECT COUNT(*) FROM edges WHERE firmware_id=? AND to_function_id=? AND kind LIKE '%call%'",
            (firmware_id, fid)).fetchone()[0]
        n_callees = conn.execute(
            "SELECT COUNT(DISTINCT to_function_id) FROM edges WHERE firmware_id=? AND from_function_id=? "
            "AND kind LIKE '%call%' AND to_function_id IS NOT NULL", (firmware_id, fid)).fetchone()[0]
        n_blocks = conn.execute(
            "SELECT COUNT(*) FROM basic_blocks WHERE firmware_id=? AND function_id=?",
            (firmware_id, fid)).fetchone()[0]
        n_ram_reads = conn.execute(
            "SELECT COUNT(*) FROM memory_accesses WHERE firmware_id=? AND from_function_id=? AND direction='READ'",
            (firmware_id, fid)).fetchone()[0]
        n_ram_writes = conn.execute(
            "SELECT COUNT(*) FROM memory_accesses WHERE firmware_id=? AND from_function_id=? AND direction='WRITE'",
            (firmware_id, fid)).fetchone()[0]
        n_mmio_reads = conn.execute(
            "SELECT COUNT(*) FROM mmio_accesses WHERE firmware_id=? AND from_function_id=? AND direction='READ'",
            (firmware_id, fid)).fetchone()[0]
        n_mmio_writes = conn.execute(
            "SELECT COUNT(*) FROM mmio_accesses WHERE firmware_id=? AND from_function_id=? AND direction='WRITE'",
            (firmware_id, fid)).fetchone()[0]
        n_literal_refs = conn.execute(
            "SELECT COUNT(*) FROM literal_refs WHERE firmware_id=? AND from_function_id=?",
            (firmware_id, fid)).fetchone()[0]
        n_strings = conn.execute(
            "SELECT COUNT(DISTINCT l.to_addr) FROM literal_refs l JOIN strings s "
            "ON s.firmware_id=l.firmware_id AND s.addr=l.to_addr "
            "WHERE l.firmware_id=? AND l.from_function_id=?", (firmware_id, fid)).fetchone()[0]
        pins = [r[0] for r in conn.execute(
            "SELECT DISTINCT pin_name FROM pins WHERE firmware_id=? AND from_function_id=?",
            (firmware_id, fid))]
        n_indirect_from = conn.execute(
            "SELECT COUNT(*) FROM indirect_edge_resolutions WHERE firmware_id=? AND from_function_id=?",
            (firmware_id, fid)).fetchone()[0]
        peripherals = [r[0] for r in conn.execute(
            "SELECT DISTINCT peripheral FROM mmio_accesses WHERE firmware_id=? AND from_function_id=? "
            "AND peripheral IS NOT NULL", (firmware_id, fid))]
        scenarios = [r[0] for r in conn.execute(
            "SELECT DISTINCT dr.scenario FROM dynamic_coverage dc JOIN dynamic_runs dr ON dr.id=dc.dynamic_run_id "
            "WHERE dc.firmware_id=? AND dc.function_id=?", (firmware_id, fid))]
        n_dynamic_runs = conn.execute(
            "SELECT COUNT(DISTINCT dynamic_run_id) FROM dynamic_coverage WHERE firmware_id=? AND function_id=?",
            (firmware_id, fid)).fetchone()[0]

        out.append({
            "firmware_id": firmware_id, "function_id": fid, "n_callers": n_callers, "n_callees": n_callees,
            "n_basic_blocks": n_blocks, "n_ram_reads": n_ram_reads, "n_ram_writes": n_ram_writes,
            "n_mmio_reads": n_mmio_reads, "n_mmio_writes": n_mmio_writes, "n_literal_refs": n_literal_refs,
            "n_strings": n_strings, "n_pins": len(pins), "n_indirect_edges_from": n_indirect_from,
            "is_irq_handler": int(fid in irq_by_function), "irq_vector_index": irq_by_function.get(fid),
            "n_dynamic_runs": n_dynamic_runs, "n_dynamic_scenarios": len(scenarios),
            "peripherals_json": json.dumps(sorted(peripherals)), "pins_json": json.dumps(sorted(pins)),
            "scenarios_json": json.dumps(sorted(scenarios)), "reachability_status": reach.get(fid),
            "library_confidence": lib.get(fid), "source": "features",
        })

    from db import replace_firmware_rows
    replace_firmware_rows(conn, firmware_id, "function_features", out)
    conn.commit()
    return out
