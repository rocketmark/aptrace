#!/usr/bin/env python3
"""APTrace census reduce: regression coverage for the closure-reduction
layer (reachability, indirect-edge resolution, fingerprinting,
component grouping, hardware-snapshot pin decoding). Same convention as
tools/census/test_census.py -- plain assertions, not pytest. Run with
the Unicorn venv:

    tools/unicorn/.venv/bin/python3 tools/census/test_reduce.py

Covers isolated logic against small synthetic databases/byte buffers
(no Ghidra/Unicorn needed for most checks) plus a handful of real-data
sanity checks against the actual built census database, if present.
"""
import json
import struct
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import db as census_db  # noqa: E402
import reachability  # noqa: E402
import indirect_resolve  # noqa: E402
import fingerprint  # noqa: E402
import components  # noqa: E402
import hardware_snapshot  # noqa: E402
import boot_recipes  # noqa: E402
import reference_library  # noqa: E402

FAILURES = []


def check(name, condition, detail=""):
    status = "ok" if condition else "FAIL"
    print(f"  [{status}] {name}" + (f" -- {detail}" if detail and not condition else ""))
    if not condition:
        FAILURES.append(name)


def _scratch_db():
    d = tempfile.TemporaryDirectory()
    conn = census_db.connect(Path(d.name) / "scratch.sqlite3")
    return d, conn


def _make_firmware(conn, key="scratch"):
    conn.execute(
        "INSERT INTO firmware (key, path, sha256, flash_base, size_bytes, ram_base, ram_size, "
        "mmio_base, mmio_size, built_at) VALUES (?,'x','y',0x4000,1000,0x20000000,0x1000,0x40000000,0x1000,'now')",
        (key,))
    conn.commit()
    return census_db.get_firmware_id(conn, key)


def _make_function(conn, fw, entry, name, size=16):
    conn.execute(
        "INSERT INTO functions (firmware_id, entry, name, size, thunk, external, source) "
        "VALUES (?,?,?,?,0,0,'test')", (fw, entry, name, size))
    conn.commit()
    return conn.execute("SELECT id FROM functions WHERE firmware_id=? AND entry=?", (fw, entry)).fetchone()["id"]


class FakeFuncRanges:
    def __init__(self, entry_to_id_size):
        self.rows = sorted(entry_to_id_size)  # list of (entry, size, id)

    def containing(self, addr):
        for entry, size, fid in self.rows:
            if entry <= addr < entry + max(size, 1):
                return fid
        return None


# --- reachability ----------------------------------------------------------

def test_reachability():
    print("test_reachability (synthetic call graph)")
    d, conn = _scratch_db()
    try:
        fw = _make_firmware(conn)
        # root (Reset) -> A -> B ; C is only reachable via an
        # indirect_edge_candidates row with confidence WEAK (a finite
        # candidate set) ; D has no path at all.
        root = _make_function(conn, fw, 0x4000, "Reset_Handler")
        a = _make_function(conn, fw, 0x4100, "A")
        b = _make_function(conn, fw, 0x4200, "B")
        c = _make_function(conn, fw, 0x4300, "C")
        _make_function(conn, fw, 0x4400, "D")

        conn.execute("INSERT INTO vectors (firmware_id, vector_index, raw_value, target_addr, name, is_irq, "
                     "landed_in_known_function, source) VALUES (?,1,0x4001,0x4000,'Reset',0,1,'test')", (fw,))
        conn.execute("INSERT INTO edges (firmware_id, from_addr, to_addr, kind, resolved, from_function_id, "
                     "to_function_id, source) VALUES (?,0x4010,0x4100,'call',1,?,?,'ghidra-basicblockmodel')",
                     (fw, root, a))
        conn.execute("INSERT INTO edges (firmware_id, from_addr, to_addr, kind, resolved, from_function_id, "
                     "to_function_id, source) VALUES (?,0x4110,0x4200,'call',1,?,?,'ghidra-basicblockmodel')",
                     (fw, a, b))
        # A finite-candidate-set edge from B to C (WEAK confidence).
        # 0x4204 is strictly inside B's [0x4200, 0x4210) range (size=16
        # from _make_function's default) -- func_ranges.containing()
        # attributes it to B, unlike the exclusive-upper-bound 0x4210.
        conn.execute("INSERT INTO indirect_edge_candidates (firmware_id, from_addr, candidate_addr, "
                     "candidate_function_id, confidence, source) VALUES (?,0x4204,0x4300,?,'WEAK','flash-table-scan')",
                     (fw, c))
        conn.commit()

        func_ranges = FakeFuncRanges([(0x4000, 16, root), (0x4100, 16, a), (0x4200, 16, b),
                                        (0x4300, 16, c), (0x4400, 16, conn.execute(
                                            "SELECT id FROM functions WHERE entry=0x4400").fetchone()["id"])])
        rows = reachability.compute(conn, fw, func_ranges)
        status = {r["function_id"]: r["status"] for r in rows}

        check("Reset_Handler itself is DEFINITELY_REACHABLE (a root)", status[root] == "DEFINITELY_REACHABLE")
        check("A is DEFINITELY_REACHABLE (direct call from root)", status[a] == "DEFINITELY_REACHABLE")
        check("B is DEFINITELY_REACHABLE (direct call from A)", status[b] == "DEFINITELY_REACHABLE")
        check("C is POSSIBLY_REACHABLE_VIA_UNRESOLVED_INDIRECT (only reachable via a WEAK finite-candidate edge)",
              status[c] == "POSSIBLY_REACHABLE_VIA_UNRESOLVED_INDIRECT")
        d_id = conn.execute("SELECT id FROM functions WHERE entry=0x4400").fetchone()["id"]
        check("D is NO_KNOWN_PATH (nothing points at it)", status[d_id] == "NO_KNOWN_PATH")

        roots = conn.execute("SELECT * FROM reachability_roots WHERE firmware_id=?", (fw,)).fetchall()
        check("exactly one root recorded (the Reset vector)", len(roots) == 1, roots)
        check("root is tagged 'reset-vector'", roots[0]["root_kind"] == "reset-vector")
    finally:
        conn.close()
        d.cleanup()


def test_reachability_does_not_trust_raw_function_pointer_candidates():
    print("test_reachability_does_not_trust_raw_function_pointer_candidates "
          "(a function_pointers row alone must NOT become a root)")
    d, conn = _scratch_db()
    try:
        fw = _make_firmware(conn)
        target = _make_function(conn, fw, 0x4500, "NeverCalled")
        # A function_pointers CANDIDATE row (raw flash-word scan) --
        # deliberately NOT an indirect_edge_candidates row, since no
        # real control flow actually uses it.
        conn.execute("INSERT INTO function_pointers (firmware_id, location_addr, raw_value, target_addr, "
                     "matches_known_function, source) VALUES (?,0x4600,0x4501,0x4500,1,'raw-flashword-scan')", (fw,))
        conn.commit()
        func_ranges = FakeFuncRanges([(0x4500, 16, target)])
        rows = reachability.compute(conn, fw, func_ranges)
        status = {r["function_id"]: r["status"] for r in rows}
        check("a raw function_pointers candidate with no real control-flow use stays NO_KNOWN_PATH",
              status[target] == "NO_KNOWN_PATH")
        n_roots = conn.execute("SELECT COUNT(*) FROM reachability_roots WHERE firmware_id=?", (fw,)).fetchone()[0]
        check("no root was created from it", n_roots == 0)
    finally:
        conn.close()
        d.cleanup()


# --- indirect edge resolution -----------------------------------------------

def test_decode_instruction_shapes():
    print("test_decode_instruction_shapes (known Thumb byte patterns)")
    flash_base = 0x4000
    data = bytearray(64)
    # bx r3 (register-indirect)
    data[0:2] = b"\x18\x47"
    # blx r3 (register-indirect)
    data[2:4] = b"\x98\x47"
    mnem, shape, reg = indirect_resolve.decode_instruction(bytes(data), flash_base, flash_base)
    check("bx r3 decodes as reg-indirect targeting r3", shape == "reg-indirect" and reg == "r3", (mnem, shape, reg))
    mnem, shape, reg = indirect_resolve.decode_instruction(bytes(data), flash_base, flash_base + 2)
    check("blx r3 decodes as reg-indirect targeting r3", shape == "reg-indirect" and reg == "r3", (mnem, shape, reg))

    # bx sl (r10) -- hardening: Capstone's ARM EABI register ALIAS text
    # ("sl") must be normalized to the canonical "r10" concrete.py's
    # registers dict actually keys on, or a real downstream lookup
    # (extract_indirect_hits) raises KeyError -- confirmed this pass on
    # a real Mando868 indirect-call site.
    data[4:6] = b"\x50\x47"
    mnem, shape, reg = indirect_resolve.decode_instruction(bytes(data), flash_base, flash_base + 4)
    check("bx sl normalizes to reg-indirect targeting r10 (not the Capstone alias 'sl')",
          shape == "reg-indirect" and reg == "r10", (mnem, shape, reg))


def test_scan_pointer_table():
    print("test_scan_pointer_table (bounded flash-word pointer scan)")
    flash_base = 0x4000
    data = bytearray(64)
    # Two plausible Thumb pointers (odd, in-range), then a non-pointer
    # (even) word that should stop the scan.
    struct.pack_into("<I", data, 0, flash_base | 1)
    struct.pack_into("<I", data, 4, (flash_base + 0x10) | 1)
    struct.pack_into("<I", data, 8, 0xDEAD0000)  # even -- not a plausible pointer, stops the scan
    struct.pack_into("<I", data, 12, (flash_base + 0x20) | 1)  # must NOT be reached
    found = indirect_resolve.scan_pointer_table(bytes(data), flash_base, flash_base)
    check("scan finds exactly 2 entries before stopping at the non-pointer word",
          [t for _i, t in found] == [flash_base, flash_base + 0x10], found)


def test_scan_halfword_table_tbh():
    print("test_scan_halfword_table (TBH-style halfword offset table)")
    flash_base = 0x4000
    data = bytearray(32)
    base_for_offset = flash_base + 8
    # TBH entries are HALFWORD offsets from base_for_offset: entry 0 -> +0*2, entry 1 -> +4*2=+8.
    struct.pack_into("<H", data, 8, 0)
    struct.pack_into("<H", data, 10, 4)
    found = indirect_resolve.scan_halfword_table(bytes(data), flash_base, base_for_offset, 2, base_for_offset,
                                                    max_entries=2)
    check("TBH entry 0 -> base_for_offset itself", found[0] == (0, base_for_offset), found)
    check("TBH entry 1 -> base_for_offset + 2*4", found[1] == (1, base_for_offset + 8), found)


def test_dynamic_candidates_smoke():
    print("test_dynamic_candidates_smoke (real replay, watches a known-reached address)")
    # 0x8258 is ascii_dispatcher__CUSTOM's entry -- every scenario in the
    # corpus reaches it early (see docs/investigations/protocol-pipeline.md).
    # This is a real integration check, not a synthetic one -- skipped
    # quietly if the firmware isn't present (e.g. a checkout without the
    # proprietary .bin files).
    fw_path = HERE.parent.parent / "research" / "firmware" / "originals" / "firmware_autopilot868.bin"
    if not fw_path.exists():
        print("  (firmware not present -- skipping)")
        return
    found = indirect_resolve.dynamic_candidates("autopilot868", {0x8258: "r0"}, verbose=False)
    check("watching a known-reached address across the real scenario corpus finds at least one hit",
          len(found.get(0x8258, [])) > 0, found)


# --- fingerprinting ----------------------------------------------------------

def test_family_helper():
    print("test_family_helper")
    check("autopilot868 -> autopilot", fingerprint._family("autopilot868") == "autopilot")
    check("autopilot915 -> autopilot", fingerprint._family("autopilot915") == "autopilot")
    check("mando868 -> mando", fingerprint._family("mando868") == "mando")
    check("a key with no trailing digits is unchanged", fingerprint._family("scratch") == "scratch")


def test_fingerprint_exact_and_cross_family_preference():
    print("test_fingerprint_exact_and_cross_family_preference")
    d, conn = _scratch_db()
    try:
        fw_a = _make_firmware(conn, "autopilot868")
        fw_a2 = _make_firmware(conn, "autopilot915")
        fw_m = _make_firmware(conn, "mando868")
        fa = _make_function(conn, fw_a, 0x4000, "F", size=4)
        fa2 = _make_function(conn, fw_a2, 0x4000, "F", size=4)
        fm = _make_function(conn, fw_m, 0x4000, "F", size=4)

        same_bytes = b"\x00\xbf\x00\xbf"  # nop; nop
        fingerprint.compute_fingerprints(conn, fw_a, same_bytes, 0x4000)
        fingerprint.compute_fingerprints(conn, fw_a2, same_bytes, 0x4000)
        fingerprint.compute_fingerprints(conn, fw_m, same_bytes, 0x4000)
        fingerprint.recompute_all_matches(conn)

        m_a = conn.execute("SELECT * FROM library_matches WHERE firmware_id=? AND function_id=?",
                            (fw_a, fa)).fetchone()
        check("byte-identical function across images -> EXACT", m_a["confidence"] == "EXACT")
        check("EXACT match prefers the CROSS-family image (mando) over the same-family sibling (autopilot915)",
              m_a["matched_firmware_key"] == "mando868", m_a["matched_firmware_key"])
        check("cross-family match's method has no '-same-product' suffix",
              not m_a["method"].endswith("-same-product"), m_a["method"])

        # Now remove the cross-family option and confirm it falls back
        # to the same-product sibling, correctly tagged.
        conn.execute("DELETE FROM function_fingerprints WHERE firmware_id=?", (fw_m,))
        conn.commit()
        fingerprint.compute_matches(conn, fw_a, "autopilot868")
        m_a2 = conn.execute("SELECT * FROM library_matches WHERE firmware_id=? AND function_id=?",
                             (fw_a, fa)).fetchone()
        check("falls back to the same-product sibling once no cross-family match exists",
              m_a2["matched_firmware_key"] == "autopilot915")
        check("same-product fallback match IS tagged '-same-product'",
              m_a2["method"].endswith("-same-product"), m_a2["method"])
    finally:
        conn.close()
        d.cleanup()


def test_fingerprint_no_match():
    print("test_fingerprint_no_match (unique function, nothing to compare against)")
    d, conn = _scratch_db()
    try:
        fw = _make_firmware(conn, "onlyone")
        f = _make_function(conn, fw, 0x4000, "Solo", size=4)
        fingerprint.compute_fingerprints(conn, fw, b"\x00\xbf\x00\xbf", 0x4000)
        fingerprint.recompute_all_matches(conn)
        m = conn.execute("SELECT * FROM library_matches WHERE firmware_id=? AND function_id=?", (fw, f)).fetchone()
        check("no other firmware in the DB -> NO_MATCH", m["confidence"] == "NO_MATCH")
    finally:
        conn.close()
        d.cleanup()


# --- components --------------------------------------------------------------

def test_components_resource_sharing():
    print("test_components_resource_sharing (shared peripheral unions two otherwise-unrelated functions)")
    d, conn = _scratch_db()
    try:
        fw = _make_firmware(conn)
        a = _make_function(conn, fw, 0x4000, "A")
        b = _make_function(conn, fw, 0x4100, "B")
        isolated = _make_function(conn, fw, 0x4200, "Isolated")
        for fid in (a, b, isolated):
            conn.execute("INSERT INTO function_reachability (firmware_id, function_id, status, source) "
                         "VALUES (?,?,'DEFINITELY_REACHABLE','test')", (fw, fid))
        # A and B share peripheral 'TC1'; Isolated shares nothing.
        conn.execute("INSERT INTO mmio_accesses (firmware_id, from_addr, from_function_id, to_addr, width, "
                     "direction, peripheral, source) VALUES (?,0x4010,?,0x40003c00,4,'WRITE','TC1','test')", (fw, a))
        conn.execute("INSERT INTO mmio_accesses (firmware_id, from_addr, from_function_id, to_addr, width, "
                     "direction, peripheral, source) VALUES (?,0x4110,?,0x40003c04,4,'WRITE','TC1','test')", (fw, b))
        conn.commit()

        rows = components.compute(conn, fw)
        member_component = {}
        for comp in rows:
            members = [m["function_id"] for m in conn.execute(
                "SELECT function_id FROM component_members WHERE component_id=(SELECT id FROM components "
                "WHERE firmware_id=? AND component_index=?)", (fw, comp["component_index"]))]
            for m in members:
                member_component[m] = comp["component_index"]

        check("A and B end up in the same component (shared TC1 access)",
              member_component[a] == member_component[b], member_component)
        check("Isolated is in its own, different component",
              member_component[isolated] != member_component[a], member_component)
    finally:
        conn.close()
        d.cleanup()


def test_components_call_union_respects_fan_in_threshold():
    print("test_components_call_union_respects_fan_in_threshold "
          "(a high-fan-in shared callee must NOT collapse unrelated callers into one component)")
    d, conn = _scratch_db()
    try:
        fw = _make_firmware(conn)
        hub = _make_function(conn, fw, 0x4000, "Hub")
        callers = [_make_function(conn, fw, 0x4100 + i * 0x10, f"Caller{i}")
                    for i in range(components.CALL_UNION_MAX_CALLERS + 2)]
        for fid in [hub] + callers:
            conn.execute("INSERT INTO function_reachability (firmware_id, function_id, status, source) "
                         "VALUES (?,?,'DEFINITELY_REACHABLE','test')", (fw, fid))
        for i, caller in enumerate(callers):
            conn.execute("INSERT INTO edges (firmware_id, from_addr, to_addr, kind, resolved, from_function_id, "
                         "to_function_id, source) VALUES (?,?,0x4000,'call',1,?,?,'ghidra-basicblockmodel')",
                         (fw, 0x4100 + i * 0x10 + 2, caller, hub))
        conn.commit()

        rows = components.compute(conn, fw)
        member_component = {}
        for comp in rows:
            members = [m["function_id"] for m in conn.execute(
                "SELECT function_id FROM component_members WHERE component_id=(SELECT id FROM components "
                "WHERE firmware_id=? AND component_index=?)", (fw, comp["component_index"]))]
            for m in members:
                member_component[m] = comp["component_index"]

        distinct_caller_components = {member_component[c] for c in callers}
        check(f"callers of a high-fan-in hub ({len(callers)} > {components.CALL_UNION_MAX_CALLERS}) "
              f"are NOT all unioned together through it",
              len(distinct_caller_components) > 1, distinct_caller_components)
    finally:
        conn.close()
        d.cleanup()


# --- hardware snapshot pin decoding -------------------------------------------

class FakeUc:
    def __init__(self, memory):
        self.memory = memory  # dict addr -> bytes

    def mem_read(self, addr, length):
        out = bytearray()
        for i in range(length):
            out.append(self.memory.get(addr + i, 0))
        return bytes(out)


def test_decode_pins():
    print("test_decode_pins (mechanical bit extraction, no real Unicorn/Ghidra needed)")
    d, conn = _scratch_db()
    try:
        fw = _make_firmware(conn)
        base = 0x41008000
        mem = {}

        def write32(off, val):
            for i, b in enumerate(val.to_bytes(4, "little")):
                mem[base + off + i] = b

        # GROUP0.DIR: pin 3 = OUT, everything else IN.
        write32(0x00, 1 << 3)
        # GROUP0.OUT: pin 3 driven high.
        write32(0x10, 1 << 3)
        # GROUP0.IN: pin 5 reads high.
        write32(0x20, 1 << 5)
        # GROUP0.PINCFG3 (offset 0x40+3): PMUXEN (bit1) set -> raw 0x02.
        mem[base + 0x40 + 3] = 0x02
        # GROUP0.PMUX1 (offset 0x30+1, covers pins 2/3): low nibble=pin2, high nibble=pin3.
        mem[base + 0x30 + 1] = 0xA5  # pin2 (low nibble) = 5, pin3 (high nibble) = 0xA

        uc = FakeUc(mem)
        machine = SimpleNamespace(uc=uc)
        regs = [("GROUP0.DIR", 0x00, 4), ("GROUP0.OUT", 0x10, 4), ("GROUP0.IN", 0x20, 4)]
        for i in range(32):
            regs.append((f"GROUP0.PINCFG{i}", 0x40 + i, 1))
        for i in range(16):
            regs.append((f"GROUP0.PMUX{i}", 0x30 + i, 1))
        svd_map = SimpleNamespace(peripherals=[(base, 0x80, "PORT", regs)])

        rows = hardware_snapshot.decode_pins(conn, fw, machine, svd_map)
        by_pin = {r["pin_name"]: r for r in rows}

        check("PA03 direction is OUT (DIR bit 3 set)", by_pin["PA03"]["direction"] == "OUT")
        check("PA05 direction is IN (DIR bit 5 clear)", by_pin["PA05"]["direction"] == "IN")
        check("PA03 output_value is 1 (OUT bit 3 set)", by_pin["PA03"]["output_value"] == 1)
        check("PA05 input_value is 1 (IN bit 5 set)", by_pin["PA05"]["input_value"] == 1)
        check("PA00 input_value is 0 (IN bit 0 clear)", by_pin["PA00"]["input_value"] == 0)
        check("PA03 pincfg_raw is 0x02", by_pin["PA03"]["pincfg_raw"] == 0x02)
        check("PA03 pmuxen is 1 (PINCFG bit1 set)", by_pin["PA03"]["pmuxen"] == 1)
        check("PA02 (even, low nibble of PMUX1) pmux_nibble is 5", by_pin["PA02"]["pmux_nibble"] == 5)
        check("PA03 (odd, high nibble of PMUX1) pmux_nibble is 0xA", by_pin["PA03"]["pmux_nibble"] == 0xA)

        db_rows = conn.execute("SELECT COUNT(*) FROM pin_snapshot WHERE firmware_id=?", (fw,)).fetchone()[0]
        check("all 32 GROUP0 pins persisted", db_rows == 32, db_rows)
    finally:
        conn.close()
        d.cleanup()


# --- boot recipes -------------------------------------------------------

def test_boot_recipe_reference_lookup():
    print("test_boot_recipe_reference_lookup (reference images return their own recipe verbatim)")
    d, conn = _scratch_db()
    try:
        recipe, gaps = boot_recipes.resolve_for_firmware(conn, "autopilot868")
        check("autopilot868 gets its own reference recipe, no gaps", recipe is boot_recipes.AUTOPILOT_RECIPE and gaps == [])
        recipe, gaps = boot_recipes.resolve_for_firmware(conn, "mando868")
        check("mando868 gets its own reference recipe, no gaps", recipe is boot_recipes.MANDO_RECIPE and gaps == [])
        recipe, gaps = boot_recipes.resolve_for_firmware(conn, "unknown-product123")
        check("an unknown product family returns no recipe, with a gap explaining why",
              recipe is None and len(gaps) == 1, gaps)
    finally:
        conn.close()
        d.cleanup()


def test_init_status_classification():
    print("test_init_status_classification (complete / partial-justified / blocked)")

    def fake_result(watch_hits, instructions):
        return SimpleNamespace(watch_hits=watch_hits, instructions_executed=instructions)

    steady_recipe = {"steady_state_addr": 0x8960, "steady_state_hits": 5}
    hits = [{"address": "0x00008960"}] * 5
    check("5 hits at the steady-state address -> complete",
          boot_recipes.init_status_for(steady_recipe, fake_result(hits, 400000)) == "complete")

    hits_short = [{"address": "0x00008960"}] * 3
    check("fewer hits than required -> not complete (falls to partial-justified, real progress made)",
          boot_recipes.init_status_for(steady_recipe, fake_result(hits_short, 400000)) == "partial-justified")

    no_milestone_recipe = {"steady_state_addr": None, "steady_state_hits": None}
    check("no watch hits, but real instruction progress -> partial-justified",
          boot_recipes.init_status_for(no_milestone_recipe, fake_result([], 50000)) == "partial-justified")
    check("no watch hits, negligible instruction progress -> blocked",
          boot_recipes.init_status_for(no_milestone_recipe, fake_result([], 5)) == "blocked")
    check("no recipe at all -> blocked", boot_recipes.init_status_for(None, fake_result([], 400000)) == "blocked")


def test_remap_code_and_ram_addr():
    print("test_remap_code_and_ram_addr (EXACT-fingerprint-based sibling address remapping)")
    d, conn = _scratch_db()
    try:
        fw_ref = _make_firmware(conn, "refimg")
        fw_sib = _make_firmware(conn, "sibimg")
        # Reference: a code function at 0x1000 (16 bytes) and a tiny
        # "tick reader" function at 0x2000 that touches RAM 0x20000100.
        ref_code = _make_function(conn, fw_ref, 0x1000, "CodeFn", size=16)
        ref_tick = _make_function(conn, fw_ref, 0x2000, "TickFn", size=8)
        # Sibling: the SAME functions, shifted by +0x10 (simulating a
        # real cross-build layout shift), touching a DIFFERENT RAM
        # address for its own tick counter.
        sib_code = _make_function(conn, fw_sib, 0x1010, "CodeFn", size=16)
        sib_tick = _make_function(conn, fw_sib, 0x2010, "TickFn", size=8)

        for fw, fid, entry in ((fw_ref, ref_code, 0x1000), (fw_sib, sib_code, 0x1010),
                                 (fw_ref, ref_tick, 0x2000), (fw_sib, sib_tick, 0x2010)):
            same_hash = "codehash" if fid in (ref_code, sib_code) else "tickhash"
            conn.execute("INSERT INTO function_fingerprints (firmware_id, function_id, exact_hash, "
                         "normalized_hash, byte_size, block_count, edge_count, callee_count, source) "
                         "VALUES (?,?,?,?,4,1,0,0,'test')", (fw, fid, same_hash, same_hash))
        conn.execute("INSERT INTO memory_accesses (firmware_id, from_addr, from_function_id, to_addr, "
                     "width, direction, source) VALUES (?,0x2002,?,0x20000100,4,'READ','test')",
                     (fw_ref, ref_tick))
        conn.execute("INSERT INTO memory_accesses (firmware_id, from_addr, from_function_id, to_addr, "
                     "width, direction, source) VALUES (?,0x2012,?,0x20000200,4,'READ','test')",
                     (fw_sib, sib_tick))
        conn.commit()

        gaps = []
        code_result = boot_recipes._remap_code_addr(conn, fw_sib, "refimg", 0x1004, gaps)
        check("code address remaps via EXACT match + offset (0x1004 -> 0x1014)", code_result == 0x1014, code_result)
        check("no gaps for a clean remap", gaps == [], gaps)

        gaps2 = []
        ram_result = boot_recipes._remap_ram_addr(conn, fw_sib, "refimg", 0x20000100, gaps2)
        check("RAM address remaps via the matched function's OWN target, not offset arithmetic",
              ram_result == 0x20000200, ram_result)
        check("no gaps for a clean RAM remap", gaps2 == [], gaps2)

        gaps3 = []
        missing = boot_recipes._remap_code_addr(conn, fw_sib, "refimg", 0x9999, gaps3)
        check("an address with no containing reference function fails closed (None + a gap note)",
              missing is None and len(gaps3) == 1, gaps3)
    finally:
        conn.close()
        d.cleanup()


def test_reference_library_confirms_autopilot868_and_propagates():
    print("test_reference_library_confirms_autopilot868_and_propagates "
          "(curated CONFIRMED-tier tagging, mechanically propagated via EXACT fingerprint match)")
    d, conn = _scratch_db()
    try:
        fw_a = _make_firmware(conn, "autopilot868")
        fw_other = _make_firmware(conn, "otherimg")
        reset_a = _make_function(conn, fw_a, 0xcc24, "Reset_Handler", size=4)
        reset_o = _make_function(conn, fw_other, 0x5000, "FUN_00005000", size=4)
        conn.execute("INSERT INTO function_fingerprints (firmware_id, function_id, exact_hash, "
                     "normalized_hash, byte_size, block_count, edge_count, callee_count, source) "
                     "VALUES (?,?,?,?,4,1,0,0,'test')", (fw_a, reset_a, "resethash", "resethash"))
        conn.execute("INSERT INTO function_fingerprints (firmware_id, function_id, exact_hash, "
                     "normalized_hash, byte_size, block_count, edge_count, callee_count, source) "
                     "VALUES (?,?,?,?,4,1,0,0,'test')", (fw_other, reset_o, "resethash", "resethash"))
        conn.commit()

        n = reference_library.apply_reference_confirmations(conn, fw_a, "autopilot868")
        # This scratch DB only created ONE of AUTOPILOT868_CONFIRMED's
        # functions (Reset_Handler) -- apply_reference_confirmations
        # correctly tags only what actually exists, not a fixed count.
        check("apply_reference_confirmations tags exactly the CONFIRMED function that exists in this DB",
              n == 1, n)
        row = conn.execute("SELECT * FROM library_matches WHERE firmware_id=? AND function_id=?",
                            (fw_a, reset_a)).fetchone()
        check("Reset_Handler is reference_source_confirmed=1", row["reference_source_confirmed"] == 1)
        check("its citation names the real upstream source", "ArduinoCore-samd" in row["reference_source_citation"])

        reference_library.apply_reference_confirmations(conn, fw_other, "otherimg")
        row2 = conn.execute("SELECT * FROM library_matches WHERE firmware_id=? AND function_id=?",
                             (fw_other, reset_o)).fetchone()
        check("the confirmation propagates to another image's EXACT-matched counterpart",
              row2 is not None and row2["reference_source_confirmed"] == 1)
        check("the propagated citation records it was mechanically derived, not independently confirmed",
              "propagated via EXACT fingerprint match" in row2["reference_source_citation"])
    finally:
        conn.close()
        d.cleanup()


def test_recompute_all_matches_preserves_reference_confirmation():
    print("test_recompute_all_matches_preserves_reference_confirmation "
          "(hardening: fingerprinting a LATER firmware must not wipe an EARLIER one's confirmed=1 flag)")
    d, conn = _scratch_db()
    try:
        fw_a = _make_firmware(conn, "autopilot868")
        fw_m = _make_firmware(conn, "mando868")
        fa = _make_function(conn, fw_a, 0xcc24, "Reset_Handler", size=4)
        fm = _make_function(conn, fw_m, 0x9000, "F", size=4)
        conn.execute("INSERT INTO function_fingerprints (firmware_id, function_id, exact_hash, "
                     "normalized_hash, byte_size, block_count, edge_count, callee_count, source) "
                     "VALUES (?,?,?,?,4,1,0,0,'test')", (fw_a, fa, "resethash", "resethash"))
        conn.commit()
        fingerprint.recompute_all_matches(conn)
        reference_library.apply_reference_confirmations(conn, fw_a, "autopilot868")
        before = conn.execute("SELECT reference_source_confirmed FROM library_matches WHERE firmware_id=? "
                              "AND function_id=?", (fw_a, fa)).fetchone()
        check("confirmed right after tagging", before["reference_source_confirmed"] == 1)

        # Now fingerprint a SECOND, unrelated firmware -- this triggers
        # recompute_all_matches, which rebuilds AUTOPILOT868's own
        # library_matches rows too (it iterates every fingerprinted
        # image). Before the fix, this silently reset the flag to 0.
        conn.execute("INSERT INTO function_fingerprints (firmware_id, function_id, exact_hash, "
                     "normalized_hash, byte_size, block_count, edge_count, callee_count, source) "
                     "VALUES (?,?,?,?,4,1,0,0,'test')", (fw_m, fm, "unrelatedhash", "unrelatedhash"))
        conn.commit()
        fingerprint.recompute_all_matches(conn)

        after = conn.execute("SELECT reference_source_confirmed, reference_source_citation FROM library_matches "
                             "WHERE firmware_id=? AND function_id=?", (fw_a, fa)).fetchone()
        check("still confirmed after a LATER firmware's fingerprinting rebuilds library_matches",
              after["reference_source_confirmed"] == 1)
        check("citation text also survives the rebuild", after["reference_source_citation"] is not None)
    finally:
        conn.close()
        d.cleanup()


def test_cross_image_match_alone_is_not_reference_confirmed():
    print("test_cross_image_match_alone_is_not_reference_confirmed "
          "(the important evidence rule: a plain fingerprint match must never set reference_source_confirmed)")
    d, conn = _scratch_db()
    try:
        fw_a = _make_firmware(conn, "autopilot868")
        fw_m = _make_firmware(conn, "mando868")
        fa = _make_function(conn, fw_a, 0x9000, "F", size=4)
        fm = _make_function(conn, fw_m, 0x9000, "F", size=4)
        for fw, fid in ((fw_a, fa), (fw_m, fm)):
            conn.execute("INSERT INTO function_fingerprints (firmware_id, function_id, exact_hash, "
                         "normalized_hash, byte_size, block_count, edge_count, callee_count, source) "
                         "VALUES (?,?,?,?,4,1,0,0,'test')", (fw, fid, "sharedhash", "sharedhash"))
        conn.commit()
        fingerprint.recompute_all_matches(conn)

        row = conn.execute("SELECT * FROM library_matches WHERE firmware_id=? AND function_id=?",
                            (fw_a, fa)).fetchone()
        check("a plain cross-image EXACT match is recorded", row["confidence"] == "EXACT")
        check("but reference_source_confirmed defaults to 0 -- NOT converted into library truth",
              row["reference_source_confirmed"] == 0)
    finally:
        conn.close()
        d.cleanup()


# --- real-data sanity checks (skip quietly if the DB/firmware isn't built yet) --

def test_real_reduce_data():
    print("test_real_reduce_data (against the actual built census database, if present)")
    db_path = census_db.DEFAULT_DB_PATH
    if not db_path.exists():
        print("  (no census database built yet -- skipping)")
        return
    conn = census_db.connect(db_path, create=False)
    try:
        fw = census_db.get_firmware_id(conn, "autopilot868")
    except ValueError:
        print("  (autopilot868 not yet reduced -- skipping)")
        return
    n_reach = conn.execute("SELECT COUNT(*) FROM function_reachability WHERE firmware_id=?", (fw,)).fetchone()[0]
    if n_reach == 0:
        print("  (autopilot868 has no reduce data yet -- run 'census reduce autopilot868' -- skipping)")
        return

    n_functions = conn.execute("SELECT COUNT(*) FROM functions WHERE firmware_id=?", (fw,)).fetchone()[0]
    n_definitely = conn.execute(
        "SELECT COUNT(*) FROM function_reachability WHERE firmware_id=? AND status='DEFINITELY_REACHABLE'",
        (fw,)).fetchone()[0]
    check("at least one function is DEFINITELY_REACHABLE", n_definitely > 0)
    check("reachable functions are a real subset of discovered functions (not all of them)",
          0 < n_definitely < n_functions, (n_definitely, n_functions))

    reset_root = conn.execute(
        "SELECT * FROM reachability_roots WHERE firmware_id=? AND root_kind='reset-vector'", (fw,)).fetchone()
    check("a reset-vector root was recorded", reset_root is not None)

    n_statically_resolved = conn.execute(
        "SELECT COUNT(*) FROM indirect_edge_resolutions WHERE firmware_id=? AND classification='STATICALLY_RESOLVED'",
        (fw,)).fetchone()[0]
    check("at least one indirect edge is STATICALLY_RESOLVED (known TBB jump tables in this image)",
          n_statically_resolved > 0)

    n_components = conn.execute("SELECT COUNT(*) FROM components WHERE firmware_id=?", (fw,)).fetchone()[0]
    check("at least one component was generated", n_components > 0)

    n_mismatched_thunks = conn.execute(
        "SELECT COUNT(*) FROM library_matches WHERE firmware_id=? AND method='ghidra-thunk' "
        "AND confidence != 'EXACT'", (fw,)).fetchone()[0]
    check("thunks (a Ghidra-native fact) are always classified EXACT", n_mismatched_thunks == 0)

    hw_run = conn.execute("SELECT * FROM hardware_snapshot_runs WHERE firmware_id=?", (fw,)).fetchone()
    check("a hardware_snapshot_runs row exists", hw_run is not None)
    if hw_run:
        check("init_status is honestly one of the three documented states", hw_run["init_status"] in
              ("complete", "partial-justified", "blocked"), hw_run["init_status"])
        check("boot_method names a reference recipe", hw_run["boot_method"] in
              ("autopilot868", "mando868"), hw_run["boot_method"])
        check("assumptions_json is a non-empty disclosed list", hw_run["assumptions_json"] and
              len(json.loads(hw_run["assumptions_json"])) > 0)
        n_hw_regs = conn.execute("SELECT COUNT(*) FROM hardware_snapshot WHERE firmware_id=?", (fw,)).fetchone()[0]
        check("hardware register rows were captured", n_hw_regs > 0, n_hw_regs)
    conn.close()


if __name__ == "__main__":
    test_reachability()
    test_reachability_does_not_trust_raw_function_pointer_candidates()
    test_decode_instruction_shapes()
    test_scan_pointer_table()
    test_scan_halfword_table_tbh()
    test_dynamic_candidates_smoke()
    test_family_helper()
    test_fingerprint_exact_and_cross_family_preference()
    test_fingerprint_no_match()
    test_components_resource_sharing()
    test_components_call_union_respects_fan_in_threshold()
    test_decode_pins()
    test_boot_recipe_reference_lookup()
    test_init_status_classification()
    test_remap_code_and_ram_addr()
    test_reference_library_confirms_autopilot868_and_propagates()
    test_recompute_all_matches_preserves_reference_confirmation()
    test_cross_image_match_alone_is_not_reference_confirmed()
    test_real_reduce_data()

    print()
    if FAILURES:
        print(f"{len(FAILURES)} check(s) FAILED: {FAILURES}")
        sys.exit(1)
    print("All checks passed.")
    sys.exit(0)
