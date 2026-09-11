#!/usr/bin/env python3
"""APTrace census: regression coverage for the minimal, bounded one-hop
interprocedural RAM-write recovery pass (tools/census/interproc_writes.py).
Same convention as test_indexed_writes.py -- plain assertions via
check(), hand-encoded Thumb bytes round-trip-verified against Capstone.
Reuses test_indexed_writes.py's own encoder helpers/DB scaffolding
rather than duplicating them. Run with the Unicorn venv:

    tools/unicorn/.venv/bin/python3 tools/census/test_interproc_writes.py
"""
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import interproc_writes  # noqa: E402
import test_indexed_writes as TIW  # noqa: E402

FAILURES = []


def check(name, condition, detail=""):
    status = "ok" if condition else "FAIL"
    print(f"  [{status}] {name}" + (f" -- {detail}" if detail and not condition else ""))
    if not condition:
        FAILURES.append(name)


def bl(addr, target):
    """Thumb-2 BL (immediate), T1 encoding -- round-trip-verified below."""
    imm32 = target - (addr + 4)
    S = (imm32 >> 24) & 1
    I1 = (imm32 >> 23) & 1
    I2 = (imm32 >> 22) & 1
    J1 = 1 ^ I1 ^ S
    J2 = 1 ^ I2 ^ S
    imm10 = (imm32 >> 12) & 0x3FF
    imm11 = (imm32 >> 1) & 0x7FF
    hw1 = 0xF000 | (S << 10) | imm10
    hw2 = 0xD000 | (J1 << 13) | (J2 << 11) | imm11
    return TIW._verify(TIW.enc32(hw1, hw2), addr, f"bl #0x{target:x}")


def adds_imm(addr, rd, rn, imm3):
    return TIW._verify(TIW.enc16(0x1C00 | ((imm3 & 7) << 6) | (rn << 3) | rd), addr, f"adds r{rd}, r{rn}, #{imm3}")


# --- 1. helper(ptr) -> *ptr = value ----------------------------------------

def test_helper_star_ptr_equals_value():
    print("test_helper_star_ptr_equals_value")
    d, conn = TIW._scratch_db()
    fb = 0x4000
    fw = TIW._make_firmware(conn, "h1", fb)
    ARRAY_BASE = 0x200025bc

    callee_addr = fb + 0x100
    callee_func = TIW._make_function(conn, fw, callee_addr, "callee")
    callee_store = TIW.strb_imm(callee_addr, 1, 0, 0)  # strb r1,[r0]  (offset 0)
    TIW._make_block(conn, fw, callee_func, callee_addr, callee_addr + 1)

    caller_func = TIW._make_function(conn, fw, fb, "caller")
    ldr_bytes, lit_target = TIW.ldr_pc(fb, 0, 1)   # r0 = ARRAY_BASE
    mv1 = TIW.movs(fb + 2, 1, 7)
    bl_bytes = bl(fb + 4, callee_addr)
    TIW._make_block(conn, fw, caller_func, fb, fb + 7)
    TIW._make_edge(conn, fw, caller_func, fb + 4, callee_addr, "call", to_function_id=callee_func)

    img = TIW._image(fb, 0x200, [
        (fb, ldr_bytes + mv1 + bl_bytes), (lit_target, struct.pack("<I", ARRAY_BASE)),
        (callee_addr, callee_store),
    ])
    results = interproc_writes.find_interproc_writers(conn, fw, img, fb, ARRAY_BASE, 18, 1)
    check("exactly one interprocedural writer found", len(results) == 1, results)
    if results:
        r = results[0]
        check("classified INTERPROC_EXACT_WRITER", r["classification"] == "INTERPROC_EXACT_WRITER", r)
        check("resolves to slot 0", r["slots"] == [0], r)
    d.cleanup()


# --- 2. helper(ptr+K) -- constant offset folded at the CALLSITE -----------

def test_helper_ptr_plus_k():
    print("test_helper_ptr_plus_k")
    d, conn = TIW._scratch_db()
    fb = 0x4000
    fw = TIW._make_firmware(conn, "h2", fb)
    ARRAY_BASE = 0x200025bc

    callee_addr = fb + 0x100
    callee_func = TIW._make_function(conn, fw, callee_addr, "callee")
    callee_store = TIW.strb_imm(callee_addr, 1, 0, 0)  # strb r1,[r0]
    TIW._make_block(conn, fw, callee_func, callee_addr, callee_addr + 1)

    caller_func = TIW._make_function(conn, fw, fb, "caller")
    ldr_bytes, lit_target = TIW.ldr_pc(fb, 6, 1)          # r6 = ARRAY_BASE
    add_bytes = adds_imm(fb + 2, 0, 6, 4)                 # r0 = r6 + 4
    mv1 = TIW.movs(fb + 4, 1, 7)
    bl_bytes = bl(fb + 6, callee_addr)
    TIW._make_block(conn, fw, caller_func, fb, fb + 9)
    TIW._make_edge(conn, fw, caller_func, fb + 6, callee_addr, "call", to_function_id=callee_func)

    img = TIW._image(fb, 0x200, [
        (fb, ldr_bytes + add_bytes + mv1 + bl_bytes), (lit_target, struct.pack("<I", ARRAY_BASE)),
        (callee_addr, callee_store),
    ])
    results = interproc_writes.find_interproc_writers(conn, fw, img, fb, ARRAY_BASE, 18, 1)
    check("exactly one interprocedural writer found", len(results) == 1, results)
    if results:
        r = results[0]
        check("classified INTERPROC_EXACT_WRITER", r["classification"] == "INTERPROC_EXACT_WRITER", r)
        check("resolves to slot 4 (base+4)", r["slots"] == [4], r)
    d.cleanup()


# --- 3. unresolved pointer -> no claim -------------------------------------

def test_unresolved_pointer_makes_no_claim():
    print("test_unresolved_pointer_makes_no_claim")
    d, conn = TIW._scratch_db()
    fb = 0x4000
    fw = TIW._make_firmware(conn, "h3", fb)
    ARRAY_BASE = 0x200025bc

    callee_addr = fb + 0x100
    callee_func = TIW._make_function(conn, fw, callee_addr, "callee")
    callee_store = TIW.strb_imm(callee_addr, 1, 0, 0)
    TIW._make_block(conn, fw, callee_func, callee_addr, callee_addr + 1)

    caller_func = TIW._make_function(conn, fw, fb, "caller")
    # r0 defined by an ordinary memory read (not a literal, not chased):
    # ldrb r0,[r4] -- T1 encoding 0111100nnnnnttt = 0x7800 | (Rn<<3) | Rt
    ldrb_r0 = TIW._verify(TIW.enc16(0x7800 | (4 << 3) | 0), fb, "ldrb r0, [r4]")
    mv1 = TIW.movs(fb + 2, 1, 7)
    bl_bytes = bl(fb + 4, callee_addr)
    TIW._make_block(conn, fw, caller_func, fb, fb + 7)
    TIW._make_edge(conn, fw, caller_func, fb + 4, callee_addr, "call", to_function_id=callee_func)

    img = TIW._image(fb, 0x200, [(fb, ldrb_r0 + mv1 + bl_bytes), (callee_addr, callee_store)])
    results = interproc_writes.find_interproc_writers(conn, fw, img, fb, ARRAY_BASE, 18, 1)
    check("an unresolved callsite pointer yields NO reported writer (never guessed)", results == [], results)
    d.cleanup()


if __name__ == "__main__":
    test_helper_star_ptr_equals_value()
    test_helper_ptr_plus_k()
    test_unresolved_pointer_makes_no_claim()

    print()
    if FAILURES:
        print(f"{len(FAILURES)} check(s) FAILED: {FAILURES}")
        sys.exit(1)
    print("All checks passed.")
    sys.exit(0)
