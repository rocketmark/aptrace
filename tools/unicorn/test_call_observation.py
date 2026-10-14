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
# WRITER initializes a RAM field (object base OBJ, field at +4) through the
# object pointer, calls CALLEE with r0 at the field, rewrites the field with
# an indexed store, calls again, then stores one byte into it.
WRITER = FB + 0x90
OBJ = RAM + 0x300
FIELD = OBJ + 4
UNWRITTEN = RAM + 0x310


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

    w = WRITER
    put(w, ldr_lit(w, 0, w + 0x20))                                          # r0 = OBJ
    put(w + 0x02, ldr_lit(w + 0x02, 1, w + 0x24))                            # r1 = 0x40003000 (peripheral-like value)
    put(w + 0x04, h(w + 0x04, 0x6041, "str r1, [r0, #4]"))                   # init through the object pointer
    put(w + 0x06, h(w + 0x06, 0x3004, "adds r0, #4"))
    put(w + 0x08, bl(w + 0x08, CALLEE))                                      # call 1: r0 = FIELD
    put(w + 0x0C, ldr_lit(w + 0x0C, 0, w + 0x20))
    put(w + 0x0E, h(w + 0x0E, 0x2204, "movs r2, #4"))
    put(w + 0x10, ldr_lit(w + 0x10, 1, w + 0x28))                            # r1 = 0x41012000
    put(w + 0x12, h(w + 0x12, 0x5081, "str r1, [r0, r2]"))                   # computed (indexed) store
    put(w + 0x14, h(w + 0x14, 0x3004, "adds r0, #4"))
    put(w + 0x16, bl(w + 0x16, CALLEE))                                      # call 2: after the change
    put(w + 0x1A, h(w + 0x1A, 0x7042, "strb r2, [r0, #1]"))                  # 1-byte store into the field
    put(w + 0x1C, struct.pack("<HH", NOP, NOP))
    put(w + 0x20, struct.pack("<III", OBJ, SERCOM0, 0x41012000))

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


FIELDS = [{"name": "obj.f4", "address": FIELD, "size": 4, "object_base": OBJ},
          {"name": "unwritten", "address": UNWRITTEN, "size": 4}]


def read_code(addr):
    off = addr - FB
    return IMAGE[off:off + 4] if 0 <= off < len(IMAGE) else None


def run_writer(machine, max_mem_write_log=2000):
    res = machine.run(WRITER, stop_at=[WRITER + 0x1C], watch=[CALLEE], watch_reg_pointee=[("r0", 4)],
                      watch_mem_write=[(f["address"], f["size"]) for f in FIELDS],
                      max_mem_write_log=max_mem_write_log, dump_mem=[(f["address"], f["size"]) for f in FIELDS],
                      log_mmio=True, max_instructions=200)
    final = {f["name"]: res.mem(f["address"], f["size"]).hex() for f in FIELDS}
    watched = CO.summarize_watched_writes(res.mem_write_hits, fields=FIELDS, read_code=read_code,
                                          function_of=lambda pc: "WRITER" if pc >= WRITER else None,
                                          final_bytes=final, dropped=res.mem_write_dropped)
    return res, watched


def test_watched_writes():
    with tempfile.TemporaryDirectory() as d:
        fw = Path(d) / "fw.bin"
        fw.write_bytes(IMAGE)
        m = ConcreteMachine(fw, flash_base=FB, ram_base=RAM, ram_size=0x30000, mmio_base=MMIO, mmio_size=0x100000)

        print("test_watched_writes (address, width, previous/new, addressing form)")
        res, watched = run_writer(m)
        check("writer reached its end", res.stopped_at(WRITER + 0x1C), res.stop_reason)
        field, unwritten = watched["fields"]
        events = field["events"]
        check("three stores to the field observed", len(events) == 3, events)
        init, indexed, byte = events + [{}] * (3 - len(events))
        check("init store: previous 0, new 0x40003000, first write",
              (init.get("previous"), init.get("new"), init.get("changed"), init.get("first_write"))
              == ("0x00000000", "0x40003000", True, True), init)
        check("init store is base+imm through the object pointer",
              init.get("addressing", {}).get("form") == "base+imm"
              and init["addressing"].get("base_value") == f"0x{OBJ:08x}" and init["addressing"].get("object_relative") is True,
              init.get("addressing"))
        check("init store attributed to its pc and function",
              init.get("pc") == f"0x{WRITER + 4:08x}" and init.get("function") == "WRITER", init)
        check("indexed store observed as a computed (base+reg) address",
              indexed.get("addressing", {}).get("form") == "base+reg"
              and (indexed.get("previous"), indexed.get("new")) == ("0x40003000", "0x41012000"), indexed)
        check("byte store: width 1 at field+1 with the byte it overwrote",
              (byte.get("address"), byte.get("width"), byte.get("previous"), byte.get("new"))
              == (f"0x{FIELD + 1:08x}", 1, "0x20", "0x04"), byte)
        check("byte store base is not the object base", byte.get("addressing", {}).get("object_relative") is False,
              byte.get("addressing"))
        check("initialization is the first value-changing store",
              field["initialization"] == {"leg": 0, "instruction": init.get("instruction"), "pc": f"0x{WRITER + 4:08x}",
                                          "function": "WRITER", "new": "0x40003000"}, field["initialization"])
        check("change after initialization reported", field["changed_after_initialization"] is True)
        check("final bytes recorded", field["final_bytes"] == "00040141", field["final_bytes"])
        check("unwritten field: no events, no initialization (absence only for this run)",
              unwritten["writes"] == 0 and unwritten["initialization"] is None and unwritten["final_bytes"] == "00000000",
              unwritten)
        check("complete when no store was dropped", watched["complete"] is True and watched["dropped_writes"] == 0)

        print("test_call_field_correlation (RAM read of a peripheral-looking word is not MMIO)")
        groups = CO.correlate_calls_with_fields(res.watch_hits, entry=CALLEE, register="r0", watched=watched,
                                                regions=REGIONS, read_halfword=read_halfword)
        first = next((g for g in groups if g["call_site"] == f"0x{WRITER + 8:08x}"), {})
        second = next((g for g in groups if g["call_site"] == f"0x{WRITER + 0x16:08x}"), {})
        check("argument value lies in RAM, in the watched field",
              first.get("value_region") == "RAM" and first.get("field") == "obj.f4", first)
        check("the loaded word looks like SERCOM0 but is content, not an access",
              first.get("pointee_words") == [{"word": f"0x{SERCOM0:08x}", "region": "MMIO"}], first)
        check("no MMIO access although the RAM word holds a peripheral address", res.mmio_log == [], res.mmio_log)
        check("first call saw the initialized value", first.get("field_state") == "initialized value unchanged at every call",
              first)
        check("second call saw a value changed after initialization",
              second.get("field_state") == "changed after initialization before some calls", second)

        print("test_write_log_truncation")
        res, watched = run_writer(m, max_mem_write_log=1)
        check("dropped stores counted", res.mem_write_dropped == 2, res.mem_write_dropped)
        check("watch reported incomplete", watched["complete"] is False and watched["dropped_writes"] == 2, watched)

        print("test_write_watch_is_passive")
        plain = m.run(WRITER, stop_at=[WRITER + 0x1C], watch=[CALLEE], max_instructions=200, dump_mem=[(OBJ, 0x20)])
        watched_run = m.run(WRITER, stop_at=[WRITER + 0x1C], watch=[CALLEE], max_instructions=200,
                            dump_mem=[(OBJ, 0x20)], watch_mem_write=[(FIELD, 4)])
        check("same instructions, registers and memory with and without the write watch",
              (plain.instructions_executed, plain.registers, plain.mem(OBJ, 0x20))
              == (watched_run.instructions_executed, watched_run.registers, watched_run.mem(OBJ, 0x20)))


def main():
    test_decoder()
    test_concrete_runs()
    test_unmapped_pointee_and_ordering()
    test_watched_writes()
    if FAILURES:
        print(f"\n{len(FAILURES)} FAILURE(S): {FAILURES}")
        sys.exit(1)
    print("\nall call_observation checks passed")


if __name__ == "__main__":
    main()
