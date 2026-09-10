#!/usr/bin/env python3
"""APTrace census: regression coverage for tools/census/. Same convention
as tools/unicorn/test_concrete.py and tools/ghidra/test_aptrace_ghidra.py
(plain assertions, not pytest). Run with the Unicorn venv, which is the
only Python environment in this repo with both sqlite3 and capstone
available:

    tools/unicorn/.venv/bin/python3 tools/census/test_census.py

Covers: address normalization/parsing helpers, SQLite schema creation +
idempotent replace, SVD/pin resolution, the raw vector-table scan against
a synthetic image, and a handful of known AutoPilot868 facts against a
REAL built census database (building one if not already present -- same
"pay the cost once" convention as test_aptrace_ghidra.py) so a real
regression in the Ghidra/Capstone/SVD pipeline is caught, not just the
helper functions in isolation.
"""
import struct
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "ghidra"))

import db as census_db  # noqa: E402
import raw_scan  # noqa: E402
import pins  # noqa: E402
import aptrace_census as cli  # noqa: E402
import aptrace_ghidra as ghidra  # noqa: E402

FAILURES = []


def check(name, condition, detail=""):
    status = "ok" if condition else "FAIL"
    print(f"  [{status}] {name}" + (f" -- {detail}" if detail and not condition else ""))
    if not condition:
        FAILURES.append(name)


def test_address_helpers():
    print("test_address_helpers")
    check("hexaddr('0x8258') == 0x8258", cli.hexaddr("0x8258") == 0x8258)
    check("hexaddr('8258') == 0x8258 (no 0x prefix required)", cli.hexaddr("8258") == 0x8258)
    check("hx(0x8258) == '0x00008258'", cli.hx(0x8258) == "0x00008258")
    check("hx(None) is None", cli.hx(None) is None)


def test_svd_pin_resolution():
    print("test_svd_pin_resolution")
    m = pins._samd51_map()
    port_base = next(base for base, size, name, regs in m.peripherals if name == "PORT")
    pincfg0_addr = None
    pmux3_addr = None
    for base, size, name, regs in m.peripherals:
        if name != "PORT":
            continue
        for regname, off, _sz in regs:
            if regname == "GROUP0.PINCFG0":
                pincfg0_addr = base + off
            if regname == "GROUP1.PMUX3":
                pmux3_addr = base + off

    per, reg, note = pins.resolve_mmio_addr(pincfg0_addr)
    check("PORT.GROUP0.PINCFG0 resolves to peripheral PORT", per == "PORT", per)
    check("PORT.GROUP0.PINCFG0 resolves to register GROUP0.PINCFG0", reg == "GROUP0.PINCFG0", reg)
    ev = pins.port_pin_evidence(per, reg, 0, pincfg0_addr)
    check("PINCFG0 -> exactly one pin, PA00, exact confidence",
          ev == [{"pin_name": "PA00", "group_index": 0, "pin_index": 0,
                   "evidence_kind": "pincfg", "confidence": "exact"}], ev)

    per2, reg2, _note2 = pins.resolve_mmio_addr(pmux3_addr)
    ev2 = pins.port_pin_evidence(per2, reg2, 0, pmux3_addr)
    check("PMUX3 (GROUP1) -> two heuristic candidate pins, PB06/PB07",
          {e["pin_name"] for e in ev2} == {"PB06", "PB07"} and
          all(e["confidence"] == "heuristic" for e in ev2), ev2)

    per3, reg3, note3 = pins.resolve_mmio_addr(port_base + 0x08)  # OUT register: bitmask, not pin-indexed
    check("PORT.GROUP0.OUT resolves to a register but no per-pin evidence",
          per3 == "PORT" and pins.port_pin_evidence(per3, reg3, 0, port_base + 0x08) == [])

    check("an address with no SAMD51 peripheral resolves to None",
          pins.resolve_mmio_addr(0x12345678) == (None, None, None))


def test_raw_vector_scan():
    print("test_raw_vector_scan (synthetic image, no Ghidra)")
    flash_base = 0x4000
    # initial SP, Reset (index1, thumb bit set), NMI (index2, empty),
    # one IRQ slot populated (index16), rest left as 0xFFFFFFFF (empty).
    num_vectors = 39
    words = [0xFFFFFFFF] * (num_vectors + 1)
    words[0] = 0x20030000       # initial SP
    words[1] = flash_base | 1   # Reset
    words[2] = 0                # NMI, empty (0 also means "empty")
    words[16] = flash_base | 1  # first IRQ slot
    data = b"".join(struct.pack("<I", w) for w in words)
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
        f.write(data)
        tmp_path = Path(f.name)
    try:
        vectors = raw_scan.read_vectors(tmp_path, flash_base, num_vectors=num_vectors,
                                          known_function_entries={flash_base})
        check("vector 0 is the initial SP, no target/name/is_irq semantics",
              vectors[0]["target_addr"] is None and vectors[0]["is_irq"] == 0)
        check("vector 1 (Reset) targets flash_base, landed_in_known_function=1",
              vectors[1]["target_addr"] == flash_base and vectors[1]["landed_in_known_function"] == 1
              and vectors[1]["name"] == "Reset")
        check("vector 2 (NMI, empty slot) has target_addr None",
              vectors[2]["target_addr"] is None and vectors[2]["landed_in_known_function"] is None)
        check("vector 16 (first IRQ) is flagged is_irq=1, name=None",
              vectors[16]["is_irq"] == 1 and vectors[16]["name"] is None
              and vectors[16]["target_addr"] == flash_base)
        check("vector 17 (empty IRQ slot) has target_addr None",
              vectors[17]["target_addr"] is None)
    finally:
        tmp_path.unlink()


def test_function_pointer_candidate_scan():
    print("test_function_pointer_candidate_scan (synthetic image, no Ghidra)")
    flash_base = 0x4000
    # A tiny "function" at 0x4000 (4 bytes, outside the scan since it's
    # inside a known function body), then a data word at 0x4004 that IS
    # a real function-pointer candidate (points at 0x4000 | 1), then a
    # data word at 0x4008 that looks like a pointer but doesn't match any
    # known function (should NOT be reported).
    data = b"\x00\xbf\x00\xbf" + struct.pack("<I", flash_base | 1) + struct.pack("<I", 0xdeadbeef | 1)
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
        f.write(data)
        tmp_path = Path(f.name)
    try:
        candidates = raw_scan.scan_function_pointer_candidates(
            tmp_path, flash_base, function_ranges=[(flash_base, 4)], known_function_entries={flash_base})
        check("exactly one real candidate found (the one pointing at a known function)",
              len(candidates) == 1, candidates)
        check("the candidate is at 0x4004 and targets 0x4000",
              candidates[0]["location_addr"] == flash_base + 4 and candidates[0]["target_addr"] == flash_base)
    finally:
        tmp_path.unlink()


def test_db_schema_and_idempotent_replace():
    print("test_db_schema_and_idempotent_replace (scratch database)")
    with tempfile.TemporaryDirectory() as d:
        db_path = Path(d) / "scratch.sqlite3"
        conn = census_db.connect(db_path)
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        for expected in ("firmware", "functions", "basic_blocks", "edges", "vectors",
                          "function_pointers", "memory_accesses", "mmio_accesses", "strings",
                          "pins", "peripherals", "dynamic_runs", "dynamic_coverage",
                          "dynamic_memory", "dynamic_mmio", "scan_warnings"):
            check(f"schema creates table '{expected}'", expected in tables)

        conn.execute("INSERT INTO firmware (key, path, sha256, flash_base, size_bytes, ram_base, "
                     "ram_size, mmio_base, mmio_size, built_at) VALUES "
                     "('scratch','x','y',0x4000,100,0x20000000,0x1000,0x40000000,0x1000,'now')")
        conn.commit()
        fw_id = census_db.get_firmware_id(conn, "scratch")

        census_db.replace_firmware_rows(conn, fw_id, "functions", [
            {"firmware_id": fw_id, "entry": 0x4000, "name": "f1", "size": 10, "thunk": 0,
             "external": 0, "source": "test"}])
        conn.commit()
        n = conn.execute("SELECT COUNT(*) FROM functions WHERE firmware_id=?", (fw_id,)).fetchone()[0]
        check("first replace_firmware_rows inserts exactly 1 row", n == 1, n)

        census_db.replace_firmware_rows(conn, fw_id, "functions", [
            {"firmware_id": fw_id, "entry": 0x4010, "name": "f2", "size": 20, "thunk": 0,
             "external": 0, "source": "test"}])
        conn.commit()
        rows = conn.execute("SELECT entry FROM functions WHERE firmware_id=?", (fw_id,)).fetchall()
        check("second replace_firmware_rows REPLACES (not unions) -- exactly 1 row, the new one",
              [r[0] for r in rows] == [0x4010], rows)

        try:
            census_db.get_firmware_id(conn, "does-not-exist")
            check("get_firmware_id raises for an unknown key", False)
        except ValueError:
            check("get_firmware_id raises for an unknown key", True)


def test_known_autopilot868_facts():
    print("test_known_autopilot868_facts (real Ghidra/Capstone/SVD pipeline, builds if needed)")
    state, _meta, _expected = ghidra.cache_status("autopilot868")
    if state != "fresh":
        print("  (autopilot868 Ghidra cache not fresh -- run "
              "'tools/ghidra/aptrace_ghidra.py build autopilot868' first; skipping)")
        return
    import build as build_mod
    with tempfile.TemporaryDirectory() as d:
        db_path = Path(d) / "autopilot868_test.sqlite3"
        build_mod.build("autopilot868", db_path=db_path, verbose=False, ghidra_build=False)
        conn = census_db.connect(db_path, create=False)
        fw = census_db.get_firmware_id(conn, "autopilot868")

        n_functions = conn.execute("SELECT COUNT(*) FROM functions WHERE firmware_id=?", (fw,)).fetchone()[0]
        check("autopilot868 has a substantial function count (known: several hundred)",
              n_functions > 300, n_functions)

        # ascii_dispatcher__CUSTOM @ 0x8258 is an established, previously
        # human-confirmed function in this project (see
        # research/provenance/ghidra_labels.tsv / docs/investigations) --
        # a real regression in the Ghidra pipeline or provenance labels
        # would silently rename or drop it.
        f = conn.execute("SELECT * FROM functions WHERE firmware_id=? AND entry=?",
                          (fw, 0x8258)).fetchone()
        check("0x8258 is a known function (ascii_dispatcher__CUSTOM)",
              f is not None and f["name"] == "ascii_dispatcher__CUSTOM",
              f["name"] if f else None)

        n_vectors = conn.execute("SELECT COUNT(*) FROM vectors WHERE firmware_id=?", (fw,)).fetchone()[0]
        check("57 vectors recorded (vector 0 + 56 handler slots, per APTraceSeedVectorTable.java)",
              n_vectors == 57, n_vectors)
        reset_vec = conn.execute(
            "SELECT * FROM vectors WHERE firmware_id=? AND vector_index=1", (fw,)).fetchone()
        check("Reset vector (index 1) landed in a known function",
              reset_vec["landed_in_known_function"] == 1)

        n_port = conn.execute(
            "SELECT COUNT(*) FROM peripherals WHERE firmware_id=? AND name='PORT'", (fw,)).fetchone()[0]
        check("PORT is a referenced peripheral (the firmware drives GPIO)", n_port == 1)

        n_resolved_mmio = conn.execute(
            "SELECT COUNT(*) FROM mmio_accesses WHERE firmware_id=? AND peripheral IS NOT NULL", (fw,)
        ).fetchone()[0]
        n_total_mmio = conn.execute(
            "SELECT COUNT(*) FROM mmio_accesses WHERE firmware_id=?", (fw,)).fetchone()[0]
        check("most MMIO accesses resolve to a named peripheral",
              n_total_mmio > 0 and n_resolved_mmio / n_total_mmio > 0.8,
              f"{n_resolved_mmio}/{n_total_mmio}")

        n_unresolved_edges = conn.execute(
            "SELECT COUNT(*) FROM edges WHERE firmware_id=? AND resolved=0", (fw,)).fetchone()[0]
        check("some unresolved indirect edges exist (known: this firmware has computed calls)",
              n_unresolved_edges > 0, n_unresolved_edges)


if __name__ == "__main__":
    test_address_helpers()
    test_svd_pin_resolution()
    test_raw_vector_scan()
    test_function_pointer_candidate_scan()
    test_db_schema_and_idempotent_replace()
    test_known_autopilot868_facts()

    print()
    if FAILURES:
        print(f"{len(FAILURES)} check(s) FAILED: {FAILURES}")
        sys.exit(1)
    print("All checks passed.")
    sys.exit(0)
