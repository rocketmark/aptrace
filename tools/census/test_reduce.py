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
import residual_priority  # noqa: E402
import hardware_contract  # noqa: E402
import firmware_diff  # noqa: E402

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


def test_components_shared_ram_respects_owner_threshold():
    print("test_components_shared_ram_respects_owner_threshold "
          "(a pervasively-shared RAM address -- e.g. a global-state struct field -- must NOT collapse "
          "the whole reachable set into one component; hardening for a real mando868 finding)")
    d, conn = _scratch_db()
    try:
        fw = _make_firmware(conn)
        owners = [_make_function(conn, fw, 0x4000 + i * 0x10, f"Owner{i}")
                   for i in range(components.RESOURCE_UNION_MAX_OWNERS + 3)]
        for fid in owners:
            conn.execute("INSERT INTO function_reachability (firmware_id, function_id, status, source) "
                         "VALUES (?,?,'DEFINITELY_REACHABLE','test')", (fw, fid))
            conn.execute("INSERT INTO memory_accesses (firmware_id, from_addr, from_function_id, to_addr, "
                         "width, direction, source) VALUES (?,?,?,0x20000500,4,'WRITE','test')",
                         (fw, 0x4000 + owners.index(fid) * 0x10 + 2, fid))
        conn.commit()

        rows = components.compute(conn, fw)
        member_component = {}
        for comp in rows:
            members = [m["function_id"] for m in conn.execute(
                "SELECT function_id FROM component_members WHERE component_id=(SELECT id FROM components "
                "WHERE firmware_id=? AND component_index=?)", (fw, comp["component_index"]))]
            for m in members:
                member_component[m] = comp["component_index"]

        distinct_components = {member_component[o] for o in owners}
        check(f"owners of a widely-shared RAM address ({len(owners)} > "
              f"{components.RESOURCE_UNION_MAX_OWNERS}) are NOT all unioned together through it",
              len(distinct_components) > 1, distinct_components)
    finally:
        conn.close()
        d.cleanup()


def test_components_shared_low_fan_out_caller():
    print("test_components_shared_low_fan_out_caller "
          "(rule 7: two callees of the SAME low-fan-out caller are unioned -- the 'common caller' case)")
    d, conn = _scratch_db()
    try:
        fw = _make_firmware(conn)
        setup = _make_function(conn, fw, 0x4000, "Setup")
        sib1 = _make_function(conn, fw, 0x4100, "Sibling1")
        sib2 = _make_function(conn, fw, 0x4200, "Sibling2")
        isolated = _make_function(conn, fw, 0x4300, "Isolated")
        for fid in (setup, sib1, sib2, isolated):
            conn.execute("INSERT INTO function_reachability (firmware_id, function_id, status, source) "
                         "VALUES (?,?,'DEFINITELY_REACHABLE','test')", (fw, fid))
        # Setup (low fan-out: exactly 2 callees, <= CALL_UNION_MAX_CALLEES) calls both siblings.
        conn.execute("INSERT INTO edges (firmware_id, from_addr, to_addr, kind, resolved, from_function_id, "
                     "to_function_id, source) VALUES (?,0x4010,0x4100,'call',1,?,?,'ghidra-basicblockmodel')",
                     (fw, setup, sib1))
        conn.execute("INSERT INTO edges (firmware_id, from_addr, to_addr, kind, resolved, from_function_id, "
                     "to_function_id, source) VALUES (?,0x4014,0x4200,'call',1,?,?,'ghidra-basicblockmodel')",
                     (fw, setup, sib2))
        conn.commit()

        rows = components.compute(conn, fw)
        member_component = {}
        for comp in rows:
            members = [m["function_id"] for m in conn.execute(
                "SELECT function_id FROM component_members WHERE component_id=(SELECT id FROM components "
                "WHERE firmware_id=? AND component_index=?)", (fw, comp["component_index"]))]
            for m in members:
                member_component[m] = comp["component_index"]

        check("Sibling1 and Sibling2 end up in the same component (common low-fan-out caller)",
              member_component[sib1] == member_component[sib2], member_component)
        check("Isolated is in its own, different component",
              member_component[isolated] != member_component[sib1], member_component)
    finally:
        conn.close()
        d.cleanup()


def test_components_shared_low_fan_out_caller_respects_threshold():
    print("test_components_shared_low_fan_out_caller_respects_threshold "
          "(a HIGH-fan-out caller must NOT collapse all its callees into one component)")
    d, conn = _scratch_db()
    try:
        fw = _make_firmware(conn)
        hub = _make_function(conn, fw, 0x4000, "Hub")
        callees = [_make_function(conn, fw, 0x4100 + i * 0x10, f"Callee{i}")
                    for i in range(components.CALL_UNION_MAX_CALLEES + 2)]
        for fid in [hub] + callees:
            conn.execute("INSERT INTO function_reachability (firmware_id, function_id, status, source) "
                         "VALUES (?,?,'DEFINITELY_REACHABLE','test')", (fw, fid))
        for i, callee in enumerate(callees):
            conn.execute("INSERT INTO edges (firmware_id, from_addr, to_addr, kind, resolved, from_function_id, "
                         "to_function_id, source) VALUES (?,?,?,'call',1,?,?,'ghidra-basicblockmodel')",
                         (fw, 0x4000 + i * 4, 0x4100 + i * 0x10, hub, callee))
            # Pad each callee's fan-IN above CALL_UNION_MAX_CALLERS with
            # unrelated (non-reachable, not part of node_set) dummy
            # callers, so rule 2 (low-fan-in callee) can never explain an
            # observed union here -- isolates THIS test to rule 7 alone.
            for j in range(components.CALL_UNION_MAX_CALLERS + 2):
                dummy = _make_function(conn, fw, 0x6000 + i * 0x100 + j * 0x10, f"Dummy{i}_{j}")
                conn.execute("INSERT INTO edges (firmware_id, from_addr, to_addr, kind, resolved, "
                             "from_function_id, to_function_id, source) VALUES (?,?,?,'call',1,?,?,"
                             "'ghidra-basicblockmodel')", (fw, 0x6000 + i * 0x100 + j * 0x10 + 2,
                             0x4100 + i * 0x10, dummy, callee))
        conn.commit()

        rows = components.compute(conn, fw)
        member_component = {}
        for comp in rows:
            members = [m["function_id"] for m in conn.execute(
                "SELECT function_id FROM component_members WHERE component_id=(SELECT id FROM components "
                "WHERE firmware_id=? AND component_index=?)", (fw, comp["component_index"]))]
            for m in members:
                member_component[m] = comp["component_index"]

        distinct_callee_components = {member_component[c] for c in callees}
        check(f"callees of a high-fan-out hub ({len(callees)} > {components.CALL_UNION_MAX_CALLEES}) "
              f"are NOT all unioned together through it",
              len(distinct_callee_components) > 1, distinct_callee_components)
    finally:
        conn.close()
        d.cleanup()


def test_components_shared_string_reference():
    print("test_components_shared_string_reference "
          "(rule 8: two functions referencing the SAME string literal are unioned)")
    d, conn = _scratch_db()
    try:
        fw = _make_firmware(conn)
        a = _make_function(conn, fw, 0x4000, "A")
        b = _make_function(conn, fw, 0x4100, "B")
        isolated = _make_function(conn, fw, 0x4200, "Isolated")
        for fid in (a, b, isolated):
            conn.execute("INSERT INTO function_reachability (firmware_id, function_id, status, source) "
                         "VALUES (?,?,'DEFINITELY_REACHABLE','test')", (fw, fid))
        conn.execute("INSERT INTO strings (firmware_id, addr, length, data_type, value, source) "
                     "VALUES (?,0x5000,4,'string','ERR!','test')", (fw,))
        conn.execute("INSERT INTO literal_refs (firmware_id, from_addr, from_function_id, to_addr, "
                     "to_label, ref_type, source) VALUES (?,0x4010,?,0x5000,NULL,'data','test')", (fw, a))
        conn.execute("INSERT INTO literal_refs (firmware_id, from_addr, from_function_id, to_addr, "
                     "to_label, ref_type, source) VALUES (?,0x4110,?,0x5000,NULL,'data','test')", (fw, b))
        conn.commit()

        rows = components.compute(conn, fw)
        member_component = {}
        strings_by_component = {}
        for comp in rows:
            members = [m["function_id"] for m in conn.execute(
                "SELECT function_id FROM component_members WHERE component_id=(SELECT id FROM components "
                "WHERE firmware_id=? AND component_index=?)", (fw, comp["component_index"]))]
            for m in members:
                member_component[m] = comp["component_index"]
            strings_by_component[comp["component_index"]] = json.loads(comp["strings_json"])

        check("A and B end up in the same component (shared string literal)",
              member_component[a] == member_component[b], member_component)
        check("Isolated is in its own, different component",
              member_component[isolated] != member_component[a], member_component)
        check("the shared component's strings_json includes the literal value",
              "ERR!" in strings_by_component[member_component[a]], strings_by_component)
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


def test_remap_code_addr_nearby_gap_fallback_is_tagged():
    print("test_remap_code_addr_nearby_gap_fallback_is_tagged "
          "(NEARBY_GAP_WINDOW=0x400 fallback must remain visibly tagged wherever used -- provenance rule)")
    d, conn = _scratch_db()
    try:
        fw_ref = _make_firmware(conn, "refimg")
        fw_sib = _make_firmware(conn, "sibimg")
        # Reference function only declares 4 bytes; the address requested
        # (0x1008) falls 4 bytes past its own end -- inside the
        # NEARBY_GAP_WINDOW (0x400) but NOT strictly contained.
        ref_code = _make_function(conn, fw_ref, 0x1000, "CodeFn", size=4)
        sib_code = _make_function(conn, fw_sib, 0x1010, "CodeFn", size=4)
        for fw, fid in ((fw_ref, ref_code), (fw_sib, sib_code)):
            conn.execute("INSERT INTO function_fingerprints (firmware_id, function_id, exact_hash, "
                         "normalized_hash, byte_size, block_count, edge_count, callee_count, source) "
                         "VALUES (?,?,'codehash','codehash',4,1,0,0,'test')", (fw, fid))
        conn.commit()

        gaps = []
        result = boot_recipes._remap_code_addr(conn, fw_sib, "refimg", 0x1008, gaps)
        check("still remaps via the enclosing function's offset (0x1008 -> 0x1018)", result == 0x1018, result)
        check("exactly one gap note recorded (the fallback IS a disclosed gap, not a silent success)",
              len(gaps) == 1, gaps)
        check("the gap note visibly says 'best-effort, not a guaranteed-exact remap'",
              gaps and "best-effort, not a guaranteed-exact remap" in gaps[0], gaps)

        # Far outside the window (well past 0x400 bytes past the
        # function's own end) must still fail closed, exactly as before.
        gaps2 = []
        far = boot_recipes._remap_code_addr(conn, fw_sib, "refimg", 0x1000 + 0x500, gaps2)
        check("an address beyond NEARBY_GAP_WINDOW still fails closed (never silently guessed)",
              far is None, (far, gaps2))
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

# --- residual priority scoring -------------------------------------------

def _make_features(conn, fw, fid, **overrides):
    row = {
        "firmware_id": fw, "function_id": fid, "n_callers": 0, "n_callees": 0, "n_basic_blocks": 1,
        "n_ram_reads": 0, "n_ram_writes": 0, "n_mmio_reads": 0, "n_mmio_writes": 0, "n_literal_refs": 0,
        "n_strings": 0, "n_pins": 0, "n_indirect_edges_from": 0, "is_irq_handler": 0, "irq_vector_index": None,
        "n_dynamic_runs": 0, "n_dynamic_scenarios": 0, "peripherals_json": "[]", "pins_json": "[]",
        "scenarios_json": "[]", "reachability_status": "DEFINITELY_REACHABLE", "library_confidence": None,
        "source": "test",
    }
    row.update(overrides)
    cols = list(row.keys())
    conn.execute(f"INSERT INTO function_features ({', '.join(cols)}) VALUES ({', '.join('?' for _ in cols)})",
                 [row[c] for c in cols])


def _make_residual(conn, fw, fid):
    conn.execute("INSERT INTO function_reachability (firmware_id, function_id, status, source) "
                 "VALUES (?,?,'DEFINITELY_REACHABLE','test')", (fw, fid))


def test_residual_priority_tier_boundaries():
    print("test_residual_priority_tier_boundaries (pure tier_for() boundary checks, no DB needed)")
    check("score below MEDIUM_THRESHOLD is LOW", residual_priority.tier_for(0) == "LOW")
    check("score at MEDIUM_THRESHOLD is MEDIUM",
          residual_priority.tier_for(residual_priority.MEDIUM_THRESHOLD) == "MEDIUM")
    check("score at HIGH_THRESHOLD is HIGH",
          residual_priority.tier_for(residual_priority.HIGH_THRESHOLD) == "HIGH")
    check("a large negative score is LOW", residual_priority.tier_for(-10) == "LOW")


def test_residual_priority_signals():
    print("test_residual_priority_signals (every positive/negative signal fires on the evidence that "
          "should trigger it, and ONLY that evidence -- reasons_json discloses each one individually)")
    d, conn = _scratch_db()
    try:
        fw = _make_firmware(conn)

        # 1. MMIO + pin access -> HIGH tier (3 + 3 = 6 >= HIGH_THRESHOLD=5).
        mmio_pin_fn = _make_function(conn, fw, 0x5000, "MmioPinFn")
        _make_residual(conn, fw, mmio_pin_fn)
        _make_features(conn, fw, mmio_pin_fn, n_mmio_reads=1, n_pins=1,
                       peripherals_json='["TC1"]', pins_json='["PA08"]')

        # 2. Isolated leaf utility -> LOW tier (both negative signals fire, no positives).
        isolated_fn = _make_function(conn, fw, 0x5100, "IsolatedFn")
        _make_residual(conn, fw, isolated_fn)
        _make_features(conn, fw, isolated_fn, n_basic_blocks=1)

        # 3. IRQ relationship via a resolved call edge to a real IRQ handler.
        irq_handler_fn = _make_function(conn, fw, 0x5200, "IrqHandlerFn")
        _make_features(conn, fw, irq_handler_fn, is_irq_handler=1)
        irq_related_fn = _make_function(conn, fw, 0x5300, "IrqRelatedFn")
        _make_residual(conn, fw, irq_related_fn)
        _make_features(conn, fw, irq_related_fn)
        conn.execute("INSERT INTO edges (firmware_id, from_addr, to_addr, kind, resolved, from_function_id, "
                     "to_function_id, source) VALUES (?,0x5304,0x5200,'call',1,?,?,'ghidra-basicblockmodel')",
                     (fw, irq_related_fn, irq_handler_fn))

        # 4. NVM access.
        nvm_fn = _make_function(conn, fw, 0x5400, "NvmFn")
        _make_residual(conn, fw, nvm_fn)
        _make_features(conn, fw, nvm_fn, n_mmio_writes=1, peripherals_json='["NVMCTRL"]')

        # 5. called_from_covered_code: a resolved caller that IS dynamically exercised.
        covered_caller = _make_function(conn, fw, 0x5500, "CoveredCaller")
        _make_features(conn, fw, covered_caller, n_dynamic_runs=3)
        called_fn = _make_function(conn, fw, 0x5600, "CalledFn")
        _make_residual(conn, fw, called_fn)
        _make_features(conn, fw, called_fn)
        conn.execute("INSERT INTO edges (firmware_id, from_addr, to_addr, kind, resolved, from_function_id, "
                     "to_function_id, source) VALUES (?,0x5504,0x5600,'call',1,?,?,'ghidra-basicblockmodel')",
                     (fw, covered_caller, called_fn))

        # 6. shared_ram_with_covered_code: same static RAM address as a dynamically-covered function.
        covered_fn2 = _make_function(conn, fw, 0x5700, "CoveredFn2")
        _make_features(conn, fw, covered_fn2, n_dynamic_runs=2)
        conn.execute("INSERT INTO memory_accesses (firmware_id, from_addr, from_function_id, to_addr, "
                     "width, direction, source) VALUES (?,0x5704,?,0x20000600,4,'WRITE','test')",
                     (fw, covered_fn2))
        shared_ram_fn = _make_function(conn, fw, 0x5800, "SharedRamFn")
        _make_residual(conn, fw, shared_ram_fn)
        _make_features(conn, fw, shared_ram_fn)
        conn.execute("INSERT INTO memory_accesses (firmware_id, from_addr, from_function_id, to_addr, "
                     "width, direction, source) VALUES (?,0x5804,?,0x20000600,4,'READ','test')",
                     (fw, shared_ram_fn))

        # 7. protocol_data_path: shares RAM with a dynamic run that captured real TX/RX bytes.
        conn.execute("INSERT INTO dynamic_runs (firmware_id, scenario, leg_index, ran_at, source_file) "
                     "VALUES (?,'g',0,'now','test.json')", (fw,))
        run_id = conn.execute("SELECT id FROM dynamic_runs WHERE firmware_id=?", (fw,)).fetchone()["id"]
        conn.execute("INSERT INTO dynamic_tx_rx (dynamic_run_id, firmware_id, direction, data_hex, note) "
                     "VALUES (?,?,'TX','ab','test')", (run_id, fw))
        conn.execute("INSERT INTO dynamic_memory (dynamic_run_id, firmware_id, addr, width, direction, pc, value) "
                     "VALUES (?,?,0x20000900,4,'write',0x5904,'01')", (run_id, fw))
        protocol_fn = _make_function(conn, fw, 0x5900, "ProtocolFn")
        _make_residual(conn, fw, protocol_fn)
        _make_features(conn, fw, protocol_fn)
        conn.execute("INSERT INTO memory_accesses (firmware_id, from_addr, from_function_id, to_addr, "
                     "width, direction, source) VALUES (?,0x5904,?,0x20000900,4,'WRITE','test')",
                     (fw, protocol_fn))

        # 8. unresolved_indirect_involvement: the SITE of an UNRESOLVED indirect instruction.
        indirect_site_fn = _make_function(conn, fw, 0x5a00, "IndirectSiteFn")
        _make_residual(conn, fw, indirect_site_fn)
        _make_features(conn, fw, indirect_site_fn)
        conn.execute("INSERT INTO indirect_edge_resolutions (firmware_id, from_addr, from_function_id, "
                     "instr_mnemonic, instr_shape, classification, note, source) "
                     "VALUES (?,0x5a04,?,'bx','reg-indirect','UNRESOLVED',NULL,'test')",
                     (fw, indirect_site_fn))

        # 9. component_partial_dynamic_coverage: shares a component with a dynamically-covered function.
        conn.execute("INSERT INTO components (firmware_id, component_index, n_functions, source) "
                     "VALUES (?,0,2,'test')", (fw,))
        comp_id = conn.execute("SELECT id FROM components WHERE firmware_id=?", (fw,)).fetchone()["id"]
        covered_fn3 = _make_function(conn, fw, 0x5b00, "CoveredFn3")
        _make_features(conn, fw, covered_fn3, n_dynamic_runs=1)
        comp_partial_fn = _make_function(conn, fw, 0x5c00, "CompPartialFn")
        _make_residual(conn, fw, comp_partial_fn)
        _make_features(conn, fw, comp_partial_fn)
        for fid in (covered_fn3, comp_partial_fn):
            conn.execute("INSERT INTO component_members (firmware_id, component_id, function_id) "
                         "VALUES (?,?,?)", (fw, comp_id, fid))

        # 10. cross_product_platform_match (negative): EXACT match, NOT same-product.
        platform_fn = _make_function(conn, fw, 0x5d00, "PlatformFn")
        _make_residual(conn, fw, platform_fn)
        _make_features(conn, fw, platform_fn)
        conn.execute("INSERT INTO library_matches (firmware_id, function_id, confidence, method, "
                     "matched_firmware_key, matched_function_id, matched_function_name, "
                     "reference_source_confirmed, reference_source_citation, source) "
                     "VALUES (?,?,'EXACT','exact-byte-hash','othermando',NULL,'OtherFn',0,NULL,'test')",
                     (fw, platform_fn))

        # 10b. a SAME-PRODUCT EXACT match must NOT trigger the negative signal.
        sameproduct_fn = _make_function(conn, fw, 0x5e00, "SameProductFn")
        _make_residual(conn, fw, sameproduct_fn)
        _make_features(conn, fw, sameproduct_fn)
        conn.execute("INSERT INTO library_matches (firmware_id, function_id, confidence, method, "
                     "matched_firmware_key, matched_function_id, matched_function_name, "
                     "reference_source_confirmed, reference_source_citation, source) "
                     "VALUES (?,?,'EXACT','exact-byte-hash-same-product','sibling915',NULL,'SiblingFn',0,NULL,"
                     "'test')", (fw, sameproduct_fn))

        # 11. only_reached_via_confirmed_library (negative): the ONLY resolved caller is reference_source_confirmed.
        confirmed_caller_fn = _make_function(conn, fw, 0x5f00, "ConfirmedCallerFn")
        _make_features(conn, fw, confirmed_caller_fn)
        conn.execute("INSERT INTO library_matches (firmware_id, function_id, confidence, method, "
                     "matched_firmware_key, matched_function_id, matched_function_name, "
                     "reference_source_confirmed, reference_source_citation, source) "
                     "VALUES (?,?,'EXACT','reference-source-confirmed',NULL,NULL,NULL,1,'cited','test')",
                     (fw, confirmed_caller_fn))
        lib_reached_fn = _make_function(conn, fw, 0x6000, "LibReachedFn")
        _make_residual(conn, fw, lib_reached_fn)
        _make_features(conn, fw, lib_reached_fn)
        conn.execute("INSERT INTO edges (firmware_id, from_addr, to_addr, kind, resolved, from_function_id, "
                     "to_function_id, source) VALUES (?,0x5f04,0x6000,'call',1,?,?,'ghidra-basicblockmodel')",
                     (fw, confirmed_caller_fn, lib_reached_fn))

        conn.commit()

        rows = residual_priority.compute(conn, fw)
        by_fid = {r["function_id"]: r for r in rows}
        signals_of = lambda fid: {r["signal"] for r in json.loads(by_fid[fid]["reasons_json"])}  # noqa: E731

        check("mmio+pin function scores HIGH", by_fid[mmio_pin_fn]["tier"] == "HIGH", by_fid[mmio_pin_fn])
        check("mmio+pin function's reasons include exactly mmio_access + pin_access",
              signals_of(mmio_pin_fn) == {"mmio_access", "pin_access"}, signals_of(mmio_pin_fn))

        check("isolated leaf function scores LOW", by_fid[isolated_fn]["tier"] == "LOW", by_fid[isolated_fn])
        check("isolated leaf function's reasons include both negative signals",
              signals_of(isolated_fn) == {"isolated_leaf_utility", "no_external_state_interaction"},
              signals_of(isolated_fn))

        check("irq-related function's reasons include irq_relationship",
              "irq_relationship" in signals_of(irq_related_fn), signals_of(irq_related_fn))

        check("NVM function's reasons include nvm_access", "nvm_access" in signals_of(nvm_fn), signals_of(nvm_fn))

        check("called-from-covered-code function's reasons include called_from_covered_code",
              "called_from_covered_code" in signals_of(called_fn), signals_of(called_fn))

        check("shared-RAM function's reasons include shared_ram_with_covered_code",
              "shared_ram_with_covered_code" in signals_of(shared_ram_fn), signals_of(shared_ram_fn))

        check("protocol-RAM function's reasons include protocol_data_path",
              "protocol_data_path" in signals_of(protocol_fn), signals_of(protocol_fn))

        check("indirect-site function's reasons include unresolved_indirect_involvement",
              "unresolved_indirect_involvement" in signals_of(indirect_site_fn), signals_of(indirect_site_fn))

        check("component-partial-coverage function's reasons include component_partial_dynamic_coverage",
              "component_partial_dynamic_coverage" in signals_of(comp_partial_fn), signals_of(comp_partial_fn))

        check("cross-product EXACT match triggers cross_product_platform_match (negative)",
              "cross_product_platform_match" in signals_of(platform_fn), signals_of(platform_fn))
        check("a SAME-PRODUCT EXACT match does NOT trigger cross_product_platform_match",
              "cross_product_platform_match" not in signals_of(sameproduct_fn), signals_of(sameproduct_fn))

        check("function reached only via a confirmed-library caller triggers only_reached_via_confirmed_library",
              "only_reached_via_confirmed_library" in signals_of(lib_reached_fn), signals_of(lib_reached_fn))

        for r in rows:
            reasons = json.loads(r["reasons_json"])
            recomputed = sum(x["points"] for x in reasons)
            check(f"function_id={r['function_id']}: stored score matches sum of its own disclosed reasons "
                  f"(never a hidden adjustment)", r["score"] == recomputed, (r["score"], recomputed))
    finally:
        conn.close()
        d.cleanup()


# --- hardware contract ----------------------------------------------------

def test_hardware_contract_generation():
    print("test_hardware_contract_generation (raw register values preserved alongside whatever mechanical "
          "decode is actually available; ownership-by-function/component attached)")
    d, conn = _scratch_db()
    try:
        fw = _make_firmware(conn, "contractfw")
        owner = _make_function(conn, fw, 0x4000, "TcOwnerFn")
        conn.execute("INSERT INTO components (firmware_id, component_index, n_functions, source) "
                     "VALUES (?,0,1,'test')", (fw,))
        comp_id = conn.execute("SELECT id FROM components WHERE firmware_id=?", (fw,)).fetchone()["id"]
        conn.execute("INSERT INTO component_members (firmware_id, component_id, function_id) VALUES (?,?,?)",
                     (fw, comp_id, owner))

        conn.execute("INSERT INTO hardware_snapshot (firmware_id, addr, peripheral, register_name, width, "
                     "raw_value, source) VALUES (?,0x40001800,'TC1','COUNT16.CTRLA',4,'01000000','test')", (fw,))
        conn.execute("INSERT INTO mmio_accesses (firmware_id, from_addr, from_function_id, to_addr, width, "
                     "direction, peripheral, register_name, resolution_note, source) "
                     "VALUES (?,0x4004,?,0x40001800,4,'WRITE','TC1','COUNT16.CTRLA',NULL,'test')", (fw, owner))

        conn.execute("INSERT INTO pin_snapshot (firmware_id, pin_name, group_index, pin_index, direction, "
                     "output_value, input_value, pincfg_raw, pmuxen, pmux_nibble, source) "
                     "VALUES (?,'PA08',0,8,'OUT',1,0,0x02,1,3,'test')", (fw,))

        conn.execute("INSERT INTO vectors (firmware_id, vector_index, raw_value, target_addr, name, is_irq, "
                     "landed_in_known_function, source) VALUES (?,17,0x4001,0x4000,NULL,1,1,'test')", (fw,))

        conn.execute("INSERT INTO hardware_snapshot_runs (firmware_id, boot_method, init_status, stop_addr, "
                     "instructions_executed, stop_reason, completed_init, notes, assumptions_json, ran_at) "
                     "VALUES (?,'testfw','complete',NULL,1000,'steady state',1,'notes','[{\"kind\":\"x\"}]',"
                     "'now')", (fw,))
        conn.commit()

        contract = hardware_contract.build_contract(conn, fw, "contractfw")

        check("MCU part is ATSAMD51J19A", contract["mcu"]["part"] == "ATSAMD51J19A")
        check("hardware_snapshot_status.init_status reflects the real run",
              contract["hardware_snapshot_status"]["init_status"] == "complete")
        check("hardware_snapshot_status.assumptions is the disclosed list, not hidden",
              contract["hardware_snapshot_status"]["assumptions"] == [{"kind": "x"}])

        tc = contract["tc_tcc"]["TC1"]
        check("TC1's raw register value is preserved exactly", tc["registers"][0]["raw_value"] == "01000000")
        check("TC1's register carries a 'decoded' field (never silently dropped, even if just a disclosure note)",
              "decoded" in tc["registers"][0])
        check("TC1 is owned_by the function that statically writes it",
              tc["owned_by_functions"][0]["entry"] == "0x00004000")
        check("TC1 is owned_by the component that function belongs to", tc["owned_by_components"] == [0])

        pin = contract["port"][0]
        check("PA08 direction/output/input/pincfg/pmux are all preserved", (
            pin["pin_name"], pin["direction"], pin["output_value"], pin["pincfg_raw"], pin["pmux_nibble"]
        ) == ("PA08", "OUT", 1, 0x02, 3))

        irq = [v for v in contract["irq_vectors"] if v["is_irq"]][0]
        check("IRQ vector's target function name is resolved", irq["target_function"] == "TcOwnerFn")
        check("IRQ vector's owning component is resolved", irq["owned_by_component"] == 0)

        check("ADC block is present but empty (no evidence -- not fabricated)", contract["adc"] == {})
    finally:
        conn.close()
        d.cleanup()


# --- 868 vs 915 structured diff --------------------------------------------

def test_firmware_diff_structured():
    print("test_firmware_diff_structured (mechanical fact diff: only genuine differences are reported, "
          "identical facts are silent)")
    d, conn = _scratch_db()
    try:
        fa = _make_firmware(conn, "diffA")
        fb = _make_firmware(conn, "diffB")

        # A byte-identical (EXACT-fingerprint-paired) function present in both,
        # but with DIFFERENT residual_priority scores -- a real diff.
        fn_a = _make_function(conn, fa, 0x1000, "SharedFn")
        fn_b = _make_function(conn, fb, 0x1010, "SharedFn")
        for fw, fid in ((fa, fn_a), (fb, fn_b)):
            conn.execute("INSERT INTO function_fingerprints (firmware_id, function_id, exact_hash, "
                         "normalized_hash, byte_size, block_count, edge_count, callee_count, source) "
                         "VALUES (?,?,'sharedhash','sharedhash',4,1,0,0,'test')", (fw, fid))
        conn.execute("INSERT INTO residual_priority (firmware_id, function_id, score, tier, reasons_json, "
                     "source) VALUES (?,?,6,'HIGH','[]','test')", (fa, fn_a))
        conn.execute("INSERT INTO residual_priority (firmware_id, function_id, score, tier, reasons_json, "
                     "source) VALUES (?,?,0,'LOW','[]','test')", (fb, fn_b))
        conn.execute("INSERT INTO function_features (firmware_id, function_id, n_callers, n_callees, "
                     "n_basic_blocks, n_ram_reads, n_ram_writes, n_mmio_reads, n_mmio_writes, n_literal_refs, "
                     "n_strings, n_pins, n_indirect_edges_from, is_irq_handler, n_dynamic_runs, "
                     "n_dynamic_scenarios, source) VALUES (?,?,0,0,1,0,0,1,0,3,0,0,0,0,0,0,'test')", (fa, fn_a))
        conn.execute("INSERT INTO function_features (firmware_id, function_id, n_callers, n_callees, "
                     "n_basic_blocks, n_ram_reads, n_ram_writes, n_mmio_reads, n_mmio_writes, n_literal_refs, "
                     "n_strings, n_pins, n_indirect_edges_from, is_irq_handler, n_dynamic_runs, "
                     "n_dynamic_scenarios, source) VALUES (?,?,0,0,1,0,0,1,0,5,0,0,0,0,0,0,'test')", (fb, fn_b))

        # Functions only in A / only in B.
        only_a_fn = _make_function(conn, fa, 0x2000, "OnlyAFn")
        conn.execute("INSERT INTO function_fingerprints (firmware_id, function_id, exact_hash, "
                     "normalized_hash, byte_size, block_count, edge_count, callee_count, source) "
                     "VALUES (?,?,'onlyahash',NULL,4,1,0,0,'test')", (fa, only_a_fn))
        only_b_fn = _make_function(conn, fb, 0x2000, "OnlyBFn")
        conn.execute("INSERT INTO function_fingerprints (firmware_id, function_id, exact_hash, "
                     "normalized_hash, byte_size, block_count, edge_count, callee_count, source) "
                     "VALUES (?,?,'onlybhash',NULL,4,1,0,0,'test')", (fb, only_b_fn))

        # Hardware register diff: same (peripheral, register, addr), different raw value.
        conn.execute("INSERT INTO hardware_snapshot (firmware_id, addr, peripheral, register_name, width, "
                     "raw_value, source) VALUES (?,0x40001800,'TC1','CTRLA',4,'01000000','test')", (fa,))
        conn.execute("INSERT INTO hardware_snapshot (firmware_id, addr, peripheral, register_name, width, "
                     "raw_value, source) VALUES (?,0x40001800,'TC1','CTRLA',4,'02000000','test')", (fb,))
        # A register present ONLY in A.
        conn.execute("INSERT INTO hardware_snapshot (firmware_id, addr, peripheral, register_name, width, "
                     "raw_value, source) VALUES (?,0x40001900,'TC2','CTRLA',4,'00000000','test')", (fa,))
        # An identical register in both -- must NOT appear in the diff.
        conn.execute("INSERT INTO hardware_snapshot (firmware_id, addr, peripheral, register_name, width, "
                     "raw_value, source) VALUES (?,0x41000000,'PORT','GROUP0.DIR',4,'ffffffff','test')", (fa,))
        conn.execute("INSERT INTO hardware_snapshot (firmware_id, addr, peripheral, register_name, width, "
                     "raw_value, source) VALUES (?,0x41000000,'PORT','GROUP0.DIR',4,'ffffffff','test')", (fb,))

        # MMIO site diff: a peripheral/register touched only in B.
        conn.execute("INSERT INTO mmio_accesses (firmware_id, from_addr, to_addr, width, direction, "
                     "peripheral, register_name, source) VALUES (?,0x1020,0x42000000,4,'WRITE','ADC0','CTRLA',"
                     "'test')", (fb,))

        # Pin config diff: same pin, different direction.
        conn.execute("INSERT INTO pin_snapshot (firmware_id, pin_name, group_index, pin_index, direction, "
                     "output_value, input_value, pincfg_raw, pmuxen, pmux_nibble, source) "
                     "VALUES (?,'PA08',0,8,'OUT',1,0,2,1,3,'test')", (fa,))
        conn.execute("INSERT INTO pin_snapshot (firmware_id, pin_name, group_index, pin_index, direction, "
                     "output_value, input_value, pincfg_raw, pmuxen, pmux_nibble, source) "
                     "VALUES (?,'PA08',0,8,'IN',0,1,2,1,3,'test')", (fb,))

        # String diff.
        conn.execute("INSERT INTO strings (firmware_id, addr, length, data_type, value, source) "
                     "VALUES (?,0x9000,4,'string','ONLY_A','test')", (fa,))
        conn.execute("INSERT INTO strings (firmware_id, addr, length, data_type, value, source) "
                     "VALUES (?,0x9000,4,'string','ONLY_B','test')", (fb,))
        conn.commit()

        result = firmware_diff.diff_firmwares(conn, "diffA", "diffB")

        check("two hardware register diffs (one changed value, one present only in A)",
              result["counts"]["hardware_register_diffs"] == 2, result["hardware_register_diffs"])
        tc1_diff = next(d for d in result["hardware_register_diffs"] if d["peripheral"] == "TC1")
        check("the changed-value diff correctly reports value_a/value_b",
              tc1_diff["value_a"] == "01000000" and tc1_diff["value_b"] == "02000000")
        tc2_diff = next(d for d in result["hardware_register_diffs"] if d["peripheral"] == "TC2")
        check("the only-in-A register reports value_b=None (never fabricated)", tc2_diff["value_b"] is None)
        check("identical registers in both images produce NO diff entry",
              not any(d["peripheral"] == "PORT" for d in result["hardware_register_diffs"]))

        check("MMIO site diff: one site only in B, none only in A",
              result["counts"]["mmio_sites_only_in_b"] == 1 and result["counts"]["mmio_sites_only_in_a"] == 0)

        check("exactly one pin config diff (PA08 direction differs)",
              result["counts"]["pin_config_diffs"] == 1, result["pin_config_diffs"])
        check("the pin diff names the changed field",
              "direction" in result["pin_config_diffs"][0]["changed_fields"])

        check("one function only in A, one only in B",
              result["counts"]["functions_only_in_a"] == 1 and result["counts"]["functions_only_in_b"] == 1)
        check("the byte-identical shared function is correctly paired",
              result["residual_diffs"]["byte_identical_function_count"] == 1)
        check("its residual priority diff is reported (HIGH/6 in A vs LOW/0 in B)",
              result["counts"]["residual_priority_diffs"] == 1, result["residual_diffs"]["residual_priority_diffs"])

        check("string diff: one only in A, one only in B",
              result["counts"]["strings_only_in_a"] == 1 and result["counts"]["strings_only_in_b"] == 1)

        check("hardware-relevant constant diff: the MMIO-touching paired function's differing "
              "n_literal_refs (3 vs 5) is flagged",
              result["counts"]["hardware_relevant_constant_diffs"] == 1, result["hardware_relevant_constant_diffs"])
    finally:
        conn.close()
        d.cleanup()


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

    n_priority = conn.execute("SELECT COUNT(*) FROM residual_priority WHERE firmware_id=?", (fw,)).fetchone()[0]
    check("residual_priority was populated for autopilot868", n_priority > 0, n_priority)
    bad_tier = conn.execute(
        "SELECT COUNT(*) FROM residual_priority WHERE firmware_id=? AND tier NOT IN ('HIGH','MEDIUM','LOW')",
        (fw,)).fetchone()[0]
    check("every residual_priority row has one of the three documented tiers", bad_tier == 0, bad_tier)
    empty_reasons = conn.execute(
        "SELECT COUNT(*) FROM residual_priority WHERE firmware_id=? AND (reasons_json IS NULL OR "
        "reasons_json='')", (fw,)).fetchone()[0]
    check("every residual_priority row has a reasons_json column (never NULL, even if score is 0)",
          empty_reasons == 0, empty_reasons)

    contract_row = conn.execute("SELECT * FROM hardware_contract_runs WHERE firmware_id=?", (fw,)).fetchone()
    check("a hardware_contract_runs row exists for autopilot868", contract_row is not None)
    if contract_row:
        contract = json.loads(contract_row["contract_json"])
        check("the persisted contract names the right firmware_key", contract["firmware_key"] == "autopilot868")
        check("the persisted contract carries an MCU identity fact", contract["mcu"]["part"] == "ATSAMD51J19A")
        check("the persisted contract's port block is non-empty (real pin evidence exists)",
              len(contract["port"]) > 0, len(contract["port"]))
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
    test_components_shared_ram_respects_owner_threshold()
    test_components_shared_low_fan_out_caller()
    test_components_shared_low_fan_out_caller_respects_threshold()
    test_components_shared_string_reference()
    test_decode_pins()
    test_boot_recipe_reference_lookup()
    test_init_status_classification()
    test_remap_code_and_ram_addr()
    test_remap_code_addr_nearby_gap_fallback_is_tagged()
    test_reference_library_confirms_autopilot868_and_propagates()
    test_recompute_all_matches_preserves_reference_confirmation()
    test_cross_image_match_alone_is_not_reference_confirmed()
    test_residual_priority_tier_boundaries()
    test_residual_priority_signals()
    test_hardware_contract_generation()
    test_firmware_diff_structured()
    test_real_reduce_data()

    print()
    if FAILURES:
        print(f"{len(FAILURES)} check(s) FAILED: {FAILURES}")
        sys.exit(1)
    print("All checks passed.")
    sys.exit(0)
