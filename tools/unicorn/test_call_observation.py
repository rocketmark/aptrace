#!/usr/bin/env python3
"""APTrace: regression coverage for tools/unicorn/call_observation.py and
ConcreteMachine.run's `watch_reg_pointee`.

Plain assertions via check(), same convention as the census tests. A tiny
hand-assembled Thumb image (round-trip-verified against Capstone) is run in
real Unicorn: a callee that dereferences r0, a function that only loads and
compares an MMIO-looking constant, and callers that pass a RAM pointer, an
MMIO pointer, an indirect BLX, and a tail branch. Run with the Unicorn venv:

    tools/unicorn/.venv/bin/python3 tools/unicorn/test_call_observation.py
"""
import struct
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import capstone  # noqa: E402

import call_observation as CO  # noqa: E402
from concrete import ConcreteMachine  # noqa: E402

FAILURES = []
FB = 0x4000
RAM, MMIO = 0x20000000, 0x40000000
REGIONS = [("FLASH", FB, 0x1000), ("RAM", RAM, 0x30000), ("MMIO", MMIO, 0x100000)]
SERCOM0 = 0x40003000

CALLEE, CONST_ONLY, CALLER_RAM, CALLER_MMIO, TAIL, CALLER_TAIL = (
    FB, FB + 0x10, FB + 0x20, FB + 0x40, FB + 0x60, FB + 0x70)


def check(name, condition, detail=""):
    print(f"  [{'ok' if condition else 'FAIL'}] {name}" + (f" -- {detail}" if detail and not condition else ""))
    if not condition:
        FAILURES.append(name)


_MD = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB | capstone.CS_MODE_MCLASS)


def _verify(code, addr, expect):
    insns = list(_MD.disasm(code, addr))
    text = f"{insns[0].mnemonic} {insns[0].op_str}".strip() if insns else "?"
    assert len(insns) == 1 and text == expect, f"encoding mismatch at 0x{addr:x}: {text!r} != {expect!r}"
    return code


def h(addr, hw, expect):
    return _verify(struct.pack("<H", hw), addr, expect)


def bl(addr, target):
    imm32 = target - (addr + 4)
    s = (imm32 >> 24) & 1
    j1 = 1 ^ ((imm32 >> 23) & 1) ^ s
    j2 = 1 ^ ((imm32 >> 22) & 1) ^ s
    hw1 = 0xF000 | (s << 10) | ((imm32 >> 12) & 0x3FF)
    hw2 = 0xD000 | (j1 << 13) | (j2 << 11) | ((imm32 >> 1) & 0x7FF)
    return _verify(struct.pack("<HH", hw1, hw2), addr, f"bl #0x{target:x}")


def b16(addr, target):
    return h(addr, 0xE000 | (((target - (addr + 4)) >> 1) & 0x7FF), f"b #0x{target:x}")


def ldr_lit(addr, rt, pool):
    off = pool - ((addr + 4) & ~3)
    return h(addr, 0x4800 | (rt << 8) | (off >> 2), f"ldr r{rt}, [pc, #{off if off < 10 else hex(off)}]")


NOP = 0xBF00


def image():
    code = {}

    def put(addr, data):
        code[addr] = data

    put(CALLEE, h(CALLEE, 0x6803, "ldr r3, [r0]"))                         # r3 = *r0 (a real dereference)
    put(CALLEE + 2, h(CALLEE + 2, 0x4770, "bx lr"))
    put(CONST_ONLY, ldr_lit(CONST_ONLY, 2, CONST_ONLY + 8))                 # r2 = 0x40003000 (constant only)
    put(CONST_ONLY + 2, h(CONST_ONLY + 2, 0x4290, "cmp r0, r2"))
    put(CONST_ONLY + 4, h(CONST_ONLY + 4, 0x4770, "bx lr"))
    put(CONST_ONLY + 8, struct.pack("<I", SERCOM0))
    put(CALLER_RAM, ldr_lit(CALLER_RAM, 0, CALLER_RAM + 0xC))               # r0 = RAM pointer
    put(CALLER_RAM + 2, bl(CALLER_RAM + 2, CALLEE))
    put(CALLER_RAM + 6, bl(CALLER_RAM + 6, CONST_ONLY))
    put(CALLER_RAM + 0xA, struct.pack("<H", NOP))
    put(CALLER_RAM + 0xC, struct.pack("<I", RAM + 0x100))
    put(CALLER_MMIO, ldr_lit(CALLER_MMIO, 0, CALLER_MMIO + 0xC))            # r0 = SERCOM0 base
    put(CALLER_MMIO + 2, bl(CALLER_MMIO + 2, CALLEE))
    put(CALLER_MMIO + 6, ldr_lit(CALLER_MMIO + 6, 3, CALLER_MMIO + 0x10))   # r3 = CALLEE|1
    put(CALLER_MMIO + 8, h(CALLER_MMIO + 8, 0x4798, "blx r3"))
    put(CALLER_MMIO + 0xA, struct.pack("<H", NOP))
    put(CALLER_MMIO + 0xC, struct.pack("<I", SERCOM0))
    put(CALLER_MMIO + 0x10, struct.pack("<I", CALLEE | 1))
    put(TAIL, b16(TAIL, CALLEE))                                             # tail branch into CALLEE
    put(CALLER_TAIL, ldr_lit(CALLER_TAIL, 0, CALLER_TAIL + 8))
    put(CALLER_TAIL + 2, bl(CALLER_TAIL + 2, TAIL))
    put(CALLER_TAIL + 6, struct.pack("<H", NOP))
    put(CALLER_TAIL + 8, struct.pack("<I", RAM + 0x200))

    buf = bytearray(0x100)
    for addr, data in code.items():
        buf[addr - FB:addr - FB + len(data)] = data
    return bytes(buf)


IMAGE = image()


def read_halfword(addr):
    off = addr - FB
    return struct.unpack_from("<H", IMAGE, off)[0] if 0 <= off <= len(IMAGE) - 2 else None


def run(machine, entry, stop):
    res = machine.run(entry, stop_at=[stop], watch=[CALLEE, CONST_ONLY], watch_reg_pointee=[("r0", 4)],
                      log_mmio=True, max_instructions=200)
    return res, CO.summarize_entry_observations(res.watch_hits, entry=CALLEE, regions=REGIONS,
                                                read_halfword=read_halfword)


def site(summary, call_site):
    return next((s for s in summary["call_sites"] if s["call_site"] == call_site), None)


def test_decoder():
    print("test_decoder")
    hw1, hw2 = struct.unpack("<HH", bl(0x4022, CALLEE))
    check("BL target decoded", CO.bl_target(hw1, hw2, 0x4022) == CALLEE)
    hw1, hw2 = struct.unpack("<HH", bl(0x9000, 0x4000))
    check("backward BL target decoded", CO.bl_target(hw1, hw2, 0x9000) == 0x4000)
    check("non-BL rejected", CO.bl_target(0x6803, 0x4770, 0x4000) is None)


def test_concrete_runs():
    with tempfile.TemporaryDirectory() as d:
        fw = Path(d) / "fw.bin"
        fw.write_bytes(IMAGE)
        m = ConcreteMachine(fw, flash_base=FB, ram_base=RAM, ram_size=0x30000, mmio_base=MMIO, mmio_size=0x100000)

        print("test_ram_caller (concrete caller argument recovery; RAM classification)")
        res, summary = run(m, CALLER_RAM, CALLER_RAM + 0xA)
        s = site(summary, f"0x{CALLER_RAM + 2:08x}")
        check("stopped at caller end", (res.stop_reason or "").startswith("reached stop address"), res.stop_reason)
        check("one entry observed", summary["observed_entries"] == 1, summary)
        check("direct BL attributed", s is not None and s["call_kind"] == "BL", s)
        r0 = s["arguments"]["r0"][0] if s else {}
        check("r0 concrete RAM pointer", r0.get("value") == f"0x{RAM + 0x100:08x}" and r0.get("region") == "RAM", r0)
        check("pointee captured", r0.get("pointee_bytes") == "00000000", r0)
        check("RAM dereference is not an MMIO access", res.mmio_log == [], res.mmio_log)
        const = [w for w in res.watch_hits if w["address"] == f"0x{CONST_ONLY:08x}"]
        check("constant-only function was entered", len(const) == 1)
        check("loading/comparing 0x40003000 without dereference: no MMIO access", res.mmio_log == [])
        check("constant was really loaded into r2 (observed after return)", res.registers["r2"] == SERCOM0)

        print("test_mmio_caller (real MMIO dereference at a concrete address; BLX attribution)")
        res, summary = run(m, CALLER_MMIO, CALLER_MMIO + 0xA)
        bl_site = site(summary, f"0x{CALLER_MMIO + 2:08x}")
        blx_site = site(summary, f"0x{CALLER_MMIO + 8:08x}")
        check("two entries observed", summary["observed_entries"] == 2, summary)
        r0 = bl_site["arguments"]["r0"][0] if bl_site else {}
        check("r0 classified MMIO", r0.get("value") == f"0x{SERCOM0:08x}" and r0.get("region") == "MMIO", r0)
        check("indirect call attributed as BLX_REG", blx_site is not None and blx_site["call_kind"] == "BLX_REG", blx_site)
        reads = [e for e in res.mmio_log if e["pc"] == f"0x{CALLEE:08x}"]
        check("each dereference logged as an MMIO read of SERCOM0",
              len(reads) == 2 and all(e["address"] == f"0x{SERCOM0:08x}" and e["direction"] == "read" for e in reads),
              res.mmio_log)
        check("pointee capture fires no MMIO hook (log holds only the 2 real reads)", len(res.mmio_log) == 2,
              res.mmio_log)

        print("test_tail_branch (LR names an earlier frame: no call site attributed)")
        res, summary = run(m, CALLER_TAIL, CALLER_TAIL + 6)
        s = summary["call_sites"][0] if summary["call_sites"] else {}
        check("tail-branched entry is OTHER with no call site",
              s.get("call_kind") == "OTHER" and s.get("call_site") is None
              and s.get("decoded_target") == f"0x{TAIL:08x}", s)


def test_unmapped_pointee_and_ordering():
    print("test_unmapped_pointee_and_ordering")
    regs = {"r0": "0x10000000", "r1": "0x0", "r2": "0x0", "r3": "0x0", "lr": f"0x{CALLER_RAM + 7:08x}"}
    hits = [
        {"address": f"0x{CALLEE:08x}", "instruction": 5, "registers": regs,
         "reg_pointee": {"r0": {"address": "0x10000000", "bytes": None}}},
        {"address": "0x00009999", "instruction": 6, "registers": regs},
    ]
    summary = CO.summarize_entry_observations(hits, entry=CALLEE, regions=REGIONS, read_halfword=read_halfword)
    r0 = summary["call_sites"][0]["arguments"]["r0"][0]
    check("only entry hits counted", summary["observed_entries"] == 1)
    check("unmapped value has no region", r0["region"] is None)
    check("unmapped pointee recorded as None", r0["pointee_bytes"] is None and r0["pointee_word"] is None)
    again = CO.summarize_entry_observations(list(reversed(hits)), entry=CALLEE, regions=REGIONS,
                                            read_halfword=read_halfword)
    check("summary independent of unrelated hit order", again == summary)


def main():
    test_decoder()
    test_concrete_runs()
    test_unmapped_pointee_and_ordering()
    if FAILURES:
        print(f"\n{len(FAILURES)} FAILURE(S): {FAILURES}")
        sys.exit(1)
    print("\nall call_observation checks passed")


if __name__ == "__main__":
    main()
