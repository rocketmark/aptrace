#!/usr/bin/env python3
"""APTrace census: regression coverage for computed/indexed RAM-write
recovery (tools/census/indexed_writes.py). Same convention as
test_census.py/test_reduce.py -- plain assertions via check(), not
pytest fixtures. Every synthetic byte sequence is hand-encoded Thumb-16/
Thumb-2 and round-trip-verified against Capstone's own disassembly
before being used as a test fixture (see `_verify` below), so a test
failure means the SCANNER is wrong, never a miscoded fixture. Run with
the Unicorn venv:

    tools/unicorn/.venv/bin/python3 tools/census/test_indexed_writes.py
"""
import struct
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import db as census_db  # noqa: E402
import indexed_writes  # noqa: E402
from capstone import CS_ARCH_ARM, CS_MODE_THUMB, Cs  # noqa: E402

FAILURES = []


def check(name, condition, detail=""):
    status = "ok" if condition else "FAIL"
    print(f"  [{status}] {name}" + (f" -- {detail}" if detail and not condition else ""))
    if not condition:
        FAILURES.append(name)


# --- hand-encoded Thumb, round-trip-verified against Capstone --------------

def _verify(bs, addr, expected_text):
    """Decode `bs` at `addr` and assert its FIRST instruction's
    'mnemonic op_str' equals `expected_text` -- catches a miscoded test
    fixture immediately, at encode time, rather than as a confusing
    scanner failure later."""
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    insns = list(md.disasm(bs, addr))
    assert insns, f"fixture at 0x{addr:x} failed to decode at all: {bs.hex()}"
    got = f"{insns[0].mnemonic} {insns[0].op_str}"
    assert got == expected_text, f"fixture at 0x{addr:x} encoded '{got}', expected '{expected_text}' ({bs.hex()})"
    return bs


def enc16(op):
    return op.to_bytes(2, "little")


def enc32(hw1, hw2):
    return hw1.to_bytes(2, "little") + hw2.to_bytes(2, "little")


def movs(addr, rd, imm8):
    return _verify(enc16(0x2000 | (rd << 8) | (imm8 & 0xFF)), addr, f"movs r{rd}, #{imm8 & 0xFF}")


def ldr_pc(addr, rd, imm8):
    target = ((addr + 4) & ~3) + imm8 * 4
    return _verify(enc16(0x4800 | (rd << 8) | (imm8 & 0xFF)), addr, f"ldr r{rd}, [pc, #{imm8 * 4}]"), target


def strb_reg(addr, rt, rn, rm):
    return _verify(enc16(0x5400 | (rm << 6) | (rn << 3) | rt), addr, f"strb r{rt}, [r{rn}, r{rm}]")


def strb_imm(addr, rt, rn, imm5):
    return _verify(enc16(0x7000 | ((imm5 & 0x1F) << 6) | (rn << 3) | rt), addr, f"strb r{rt}, [r{rn}, #{imm5}]")


def strw_scaled(addr, rt, rn, rm, imm2):
    hw1 = 0xF840 | rn
    hw2 = (rt << 12) | ((imm2 & 3) << 4) | rm
    return _verify(enc32(hw1, hw2), addr, f"str.w r{rt}, [r{rn}, r{rm}, lsl #{imm2}]")


def cmp_imm(addr, rn, imm8):
    return _verify(enc16(0x2800 | (rn << 8) | (imm8 & 0xFF)), addr, f"cmp r{rn}, #{imm8 & 0xFF}")


def beq(addr, target):
    imm8 = ((target - (addr + 4)) // 2) & 0xFF
    return _verify(enc16(0xD000 | imm8), addr, f"beq #0x{target:x}")


def blt(addr, target):
    imm8 = ((target - (addr + 4)) // 2) & 0xFF
    return _verify(enc16(0xD000 | (0xB << 8) | imm8), addr, f"blt #0x{target:x}")


def nop(addr):
    return _verify(enc16(0x46C0), addr, "mov r8, r8")


# --- synthetic DB scaffolding (mirrors test_reduce.py's own helpers) -------

def _scratch_db():
    d = tempfile.TemporaryDirectory()
    conn = census_db.connect(Path(d.name) / "scratch.sqlite3")
    return d, conn


def _make_firmware(conn, key, flash_base=0x4000):
    conn.execute(
        "INSERT INTO firmware (key, path, sha256, flash_base, size_bytes, ram_base, ram_size, "
        "mmio_base, mmio_size, built_at) VALUES (?,'x','y',?,0x10000,0x20000000,0x8000,0x40000000,0x1000,'now')",
        (key, flash_base))
    conn.commit()
    return census_db.get_firmware_id(conn, key)


def _make_function(conn, fw, entry, name="scratch_fn", size=64):
    conn.execute(
        "INSERT INTO functions (firmware_id, entry, name, size, thunk, external, source) "
        "VALUES (?,?,?,?,0,0,'test')", (fw, entry, name, size))
    conn.commit()
    return conn.execute("SELECT id FROM functions WHERE firmware_id=? AND entry=?", (fw, entry)).fetchone()["id"]


def _make_block(conn, fw, func_id, start, end):
    conn.execute(
        "INSERT INTO basic_blocks (firmware_id, start_addr, end_addr, function_id, source) VALUES (?,?,?,?,'test')",
        (fw, start, end, func_id))
    conn.commit()


def _make_edge(conn, fw, func_id, from_addr, to_addr, kind):
    conn.execute(
        "INSERT INTO edges (firmware_id, from_addr, to_addr, kind, resolved, from_function_id, source) "
        "VALUES (?,?,?,?,1,?,'test')", (fw, from_addr, to_addr, kind, func_id))
    conn.commit()


def _image(flash_base, size, chunks):
    """A flat bytearray covering [flash_base, flash_base+size), with each
    (addr, bytes) in `chunks` written at its own offset -- lets test
    cases lay out code/literal-pool words at whatever addresses are
    convenient without worrying about gaps (left as zero bytes, never
    disassembled since scans are block-bounded)."""
    buf = bytearray(size)
    for addr, data in chunks:
        off = addr - flash_base
        buf[off:off + len(data)] = data
    return bytes(buf)


# --- _store_candidate: immediate-offset stores are never candidates -------

def test_store_candidate_ignores_immediate_offset():
    print("test_store_candidate_ignores_immediate_offset")
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    md.detail = True
    bs = strb_imm(0x1000, 2, 3, 5)
    insn = list(md.disasm(bs, 0x1000))[0]
    cand = indexed_writes._store_candidate(insn)
    check("strb rT,[rN,#imm] is NOT a register-indexed candidate", cand is None)

    bs2 = strb_reg(0x1000, 2, 3, 0)
    insn2 = list(md.disasm(bs2, 0x1000))[0]
    cand2 = indexed_writes._store_candidate(insn2)
    check("strb rT,[rN,rM] IS a register-indexed candidate", cand2 is not None)
    check("candidate reports base/index/width correctly",
          cand2 == {"from_addr": 0x1000, "mnemonic": "strb", "width": 1,
                     "base_reg": "r3", "index_reg": "r0", "effective_scale": 1, "disp": 0},
          cand2)


# --- end-to-end: direct (immediate-offset) store produces NO indexed row --

def test_direct_store_end_to_end_produces_no_indexed_writer():
    print("test_direct_store_end_to_end_produces_no_indexed_writer")
    d, conn = _scratch_db()
    fb = 0x4000
    fw = _make_firmware(conn, "direct", fb)
    ARRAY_BASE = 0x200025bc
    func = _make_function(conn, fw, fb)

    ldr_bytes, lit_target = ldr_pc(fb, 3, 0)
    mv = movs(fb + 2, 2, 5)
    st = strb_imm(fb + 4, 2, 3, 5)  # strb r2,[r3,#5] -- immediate, not indexed
    end = fb + 5
    _make_block(conn, fw, func, fb, end)

    img = _image(fb, 0x40, [(fb, ldr_bytes + mv + st), (lit_target, struct.pack("<I", ARRAY_BASE))])
    results = indexed_writes.find_computed_writers(conn, fw, img, fb, ARRAY_BASE, 18, 1)
    check("a plain immediate-offset store yields zero computed-write candidates", results == [], results)
    d.cleanup()


# --- scaled index, constant value -> INDEXED_WRITER_EXACT_SLOT ------------

def test_scaled_constant_index_is_exact_slot():
    print("test_scaled_constant_index_is_exact_slot")
    d, conn = _scratch_db()
    fb = 0x4000
    fw = _make_firmware(conn, "exact", fb)
    ARRAY_BASE = 0x20003000
    func = _make_function(conn, fw, fb)

    ldr_bytes, lit_target = ldr_pc(fb, 3, 1)  # imm8=1 -> literal 4 bytes after word-aligned pc+4
    mv = movs(fb + 2, 0, 2)                    # r0 = 2
    st = strw_scaled(fb + 4, 2, 3, 0, 2)        # str.w r2,[r3,r0,lsl #2]  (word width, scale 4)
    end = fb + 7
    _make_block(conn, fw, func, fb, end)

    img = _image(fb, 0x40, [(fb, ldr_bytes + mv + st), (lit_target, struct.pack("<I", ARRAY_BASE))])
    results = indexed_writes.find_computed_writers(conn, fw, img, fb, ARRAY_BASE, 8, 4)
    check("exactly one candidate found", len(results) == 1, results)
    if results:
        r = results[0]
        check("classified EXACT_SLOT", r["classification"] == "INDEXED_WRITER_EXACT_SLOT", r)
        check("resolves to slot 2 (base + 2*4)", r["slots"] == [2], r)
        check("scale recovered as 4 (lsl #2)", r["scale"] == 4, r)
        check("access width recovered as 4 (str.w)", r["access_width"] == 4, r)
    d.cleanup()


# --- fully unbounded index, no predecessor evidence -> UNKNOWN -----------

def test_unbounded_index_with_no_predecessors_is_unknown():
    print("test_unbounded_index_with_no_predecessors_is_unknown")
    d, conn = _scratch_db()
    fb = 0x4000
    fw = _make_firmware(conn, "unknown", fb)
    ARRAY_BASE = 0x200025bc
    func = _make_function(conn, fw, fb)

    ldr_bytes, lit_target = ldr_pc(fb, 3, 1)
    st = strb_reg(fb + 2, 2, 3, 0)  # strb r2,[r3,r0] -- r0 never defined anywhere
    end = fb + 3
    _make_block(conn, fw, func, fb, end)

    img = _image(fb, 0x40, [(fb, ldr_bytes + st), (lit_target, struct.pack("<I", ARRAY_BASE))])
    results = indexed_writes.find_computed_writers(conn, fw, img, fb, ARRAY_BASE, 18, 1)
    check("exactly one candidate found", len(results) == 1, results)
    if results:
        r = results[0]
        check("classified UNKNOWN_COMPUTED_WRITE", r["classification"] == "UNKNOWN_COMPUTED_WRITE", r)
        check("applies_to_all_slots is set (bound not determined)", r["applies_to_all_slots"] is True, r)
        check("slots left empty, not guessed", r["slots"] == [], r)
        check("derivation records the base literal and the failed index resolution",
              r["derivation"]["base_resolution"]["kind"] == "literal" and
              r["derivation"]["index_resolution"]["kind"] == "not_found", r["derivation"])
    d.cleanup()


# --- equality-gated fan-in -> INDEXED_WRITER_FINITE_SLOT_SET --------------

def test_finite_equality_fan_in():
    print("test_finite_equality_fan_in")
    d, conn = _scratch_db()
    fb = 0x4000
    fw = _make_firmware(conn, "finite", fb)
    ARRAY_BASE = 0x200025bc
    func = _make_function(conn, fw, fb)

    store_addr = fb + 8
    p1 = cmp_imm(fb, 0, 2) + beq(fb + 2, store_addr)          # P1: cmp r0,#2; beq STORE
    p2 = cmp_imm(fb + 4, 0, 5) + beq(fb + 6, store_addr)       # P2: cmp r0,#5; beq STORE
    ldr_bytes, lit_target = ldr_pc(store_addr, 3, 1)
    st = strb_reg(store_addr + 2, 2, 3, 0)                     # STORE: ldr r3,[pc,#..]; strb r2,[r3,r0]

    _make_block(conn, fw, func, fb, fb + 3)
    _make_block(conn, fw, func, fb + 4, fb + 7)
    _make_block(conn, fw, func, store_addr, store_addr + 3)
    _make_edge(conn, fw, func, fb, store_addr, "cbranch")
    _make_edge(conn, fw, func, fb + 4, store_addr, "cbranch")

    img = _image(fb, 0x40, [(fb, p1), (fb + 4, p2), (store_addr, ldr_bytes + st),
                             (lit_target, struct.pack("<I", ARRAY_BASE))])
    results = indexed_writes.find_computed_writers(conn, fw, img, fb, ARRAY_BASE, 18, 1)
    check("exactly one candidate found", len(results) == 1, results)
    if results:
        r = results[0]
        check("classified FINITE_SLOT_SET", r["classification"] == "INDEXED_WRITER_FINITE_SLOT_SET", r)
        check("slots = {2, 5}, exactly the two equality-gated values", r["slots"] == [2, 5], r)
    d.cleanup()


# --- init + upper-bound guard, single predecessor -> INDEXED_WRITER_RANGE

def test_bounded_range_init_plus_guard():
    print("test_bounded_range_init_plus_guard")
    d, conn = _scratch_db()
    fb = 0x4000
    fw = _make_firmware(conn, "range", fb)
    ARRAY_BASE = 0x200025bc
    func = _make_function(conn, fw, fb)

    guard_addr = fb + 2
    store_addr = fb + 6
    init = movs(fb, 0, 0)                                   # INIT: movs r0,#0
    guard = cmp_imm(guard_addr, 0, 3) + blt(guard_addr + 2, store_addr)  # GUARD: cmp r0,#3; blt STORE
    ldr_bytes, lit_target = ldr_pc(store_addr, 3, 1)
    st = strb_reg(store_addr + 2, 2, 3, 0)                   # STORE: ldr r3,[pc,#..]; strb r2,[r3,r0]

    _make_block(conn, fw, func, fb, fb + 1)
    _make_block(conn, fw, func, guard_addr, guard_addr + 3)
    _make_block(conn, fw, func, store_addr, store_addr + 3)
    _make_edge(conn, fw, func, fb, guard_addr, "fallthrough")
    _make_edge(conn, fw, func, guard_addr, store_addr, "cbranch")

    img = _image(fb, 0x40, [(fb, init), (guard_addr, guard), (store_addr, ldr_bytes + st),
                             (lit_target, struct.pack("<I", ARRAY_BASE))])
    results = indexed_writes.find_computed_writers(conn, fw, img, fb, ARRAY_BASE, 18, 1)
    check("exactly one candidate found", len(results) == 1, results)
    if results:
        r = results[0]
        check("classified INDEXED_WRITER_RANGE", r["classification"] == "INDEXED_WRITER_RANGE", r)
        check("slots = [0,1,2] (init=0, upper bound exclusive at 3)", r["slots"] == [0, 1, 2], r)
    d.cleanup()


# --- an unrelated, unconditional predecessor must NOT be mistaken for a
# --- finite/range shape -- still UNKNOWN, not a false-positive bound -----

def test_unconstrained_predecessor_stays_unknown():
    print("test_unconstrained_predecessor_stays_unknown")
    d, conn = _scratch_db()
    fb = 0x4000
    fw = _make_firmware(conn, "misleading", fb)
    ARRAY_BASE = 0x200025bc
    func = _make_function(conn, fw, fb)

    store_addr = fb + 2
    pred = nop(fb)  # a predecessor that does NOT constrain r0 at all
    ldr_bytes, lit_target = ldr_pc(store_addr, 3, 1)
    st = strb_reg(store_addr + 2, 2, 3, 0)

    _make_block(conn, fw, func, fb, fb + 1)
    _make_block(conn, fw, func, store_addr, store_addr + 3)
    _make_edge(conn, fw, func, fb, store_addr, "fallthrough")

    img = _image(fb, 0x40, [(fb, pred), (store_addr, ldr_bytes + st),
                             (lit_target, struct.pack("<I", ARRAY_BASE))])
    results = indexed_writes.find_computed_writers(conn, fw, img, fb, ARRAY_BASE, 18, 1)
    check("exactly one candidate found", len(results) == 1, results)
    if results:
        check("an unconstrained fallthrough predecessor does NOT get guessed into a bound "
              "(still UNKNOWN_COMPUTED_WRITE)",
              results[0]["classification"] == "UNKNOWN_COMPUTED_WRITE", results[0])
    d.cleanup()


# --- base register resolving outside the mapped array -> no candidate ----

def test_base_outside_array_is_not_a_candidate():
    print("test_base_outside_array_is_not_a_candidate")
    d, conn = _scratch_db()
    fb = 0x4000
    fw = _make_firmware(conn, "elsewhere", fb)
    ARRAY_BASE = 0x200025bc
    OTHER_BASE = 0x20009000  # far away -- not the array being mapped
    func = _make_function(conn, fw, fb)

    ldr_bytes, lit_target = ldr_pc(fb, 3, 1)
    st = strb_reg(fb + 2, 2, 3, 0)
    _make_block(conn, fw, func, fb, fb + 3)

    img = _image(fb, 0x40, [(fb, ldr_bytes + st), (lit_target, struct.pack("<I", OTHER_BASE))])
    results = indexed_writes.find_computed_writers(conn, fw, img, fb, ARRAY_BASE, 18, 1)
    check("a resolved base pointing at an unrelated array yields no candidate for THIS array",
          results == [], results)
    d.cleanup()


# --- real-firmware validation: a known real indexed write ------------------

def test_real_known_indexed_write():
    print("test_real_known_indexed_write (against the actual built census database, if present)")
    db_path = census_db.DEFAULT_DB_PATH
    if not db_path.exists():
        print("  (no census database built yet -- skipping)")
        return
    conn = census_db.connect(db_path, create=False)
    try:
        fw = census_db.get_firmware_id(conn, "autopilot868")
    except ValueError:
        print("  (autopilot868 not yet built -- skipping)")
        return
    n_blocks = conn.execute("SELECT COUNT(*) FROM basic_blocks WHERE firmware_id=?", (fw,)).fetchone()[0]
    if n_blocks == 0:
        print("  (autopilot868 has no basic_blocks yet -- skipping)")
        return

    sys.path.insert(0, str(HERE.parent / "ghidra"))
    import aptrace_ghidra as ghidra  # noqa: E402
    fw_path, _flash_base_s, _labels = ghidra.firmware_info("autopilot868")
    fw_row = conn.execute("SELECT flash_base FROM firmware WHERE id=?", (fw,)).fetchone()
    firmware_bytes = fw_path.read_bytes()
    flash_base = fw_row["flash_base"]

    # 0x20002524: the real per-channel STATE array the I<channel><mode>|
    # handler indexes into with a register-computed channel offset
    # (0x8774: `strb r2, [r6, r3]`) -- already independently confirmed,
    # by real Unicorn execution in prior work, to have NO enforced bound
    # (the real "I9|" short form writes index 8, out of the declared
    # 4-channel range) -- so this scanner correctly finding no safe bound
    # here is a real validation against known firmware behavior, not an
    # assumption.
    results = indexed_writes.find_computed_writers(conn, fw, firmware_bytes, flash_base, 0x20002524, 4, 1)
    check("at least one real register-indexed write found into 0x20002524", len(results) >= 1, results)
    hit = next((r for r in results if r["from_addr"] == 0x8774), None)
    check("the known real write site (0x8774: strb r2,[r6,r3]) is among the candidates found",
          hit is not None, [hex(r["from_addr"]) for r in results])
    if hit:
        check("classified UNKNOWN_COMPUTED_WRITE (matches the real, independently-confirmed unbounded "
              "channel index -- 'I9|' really does write out of range on real hardware)",
              hit["classification"] == "UNKNOWN_COMPUTED_WRITE", hit)


if __name__ == "__main__":
    test_store_candidate_ignores_immediate_offset()
    test_direct_store_end_to_end_produces_no_indexed_writer()
    test_scaled_constant_index_is_exact_slot()
    test_unbounded_index_with_no_predecessors_is_unknown()
    test_finite_equality_fan_in()
    test_bounded_range_init_plus_guard()
    test_unconstrained_predecessor_stays_unknown()
    test_base_outside_array_is_not_a_candidate()
    test_real_known_indexed_write()

    print()
    if FAILURES:
        print(f"{len(FAILURES)} check(s) FAILED: {FAILURES}")
        sys.exit(1)
    print("All checks passed.")
    sys.exit(0)
