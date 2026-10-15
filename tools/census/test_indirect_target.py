#!/usr/bin/env python3
"""APTrace census: regression coverage for register-indirect target
derivation (tools/census/indirect_target.py). Same convention as
test_fnptr_resolve.py -- plain assertions via check(), hand-encoded Thumb
round-trip-verified against Capstone, a scratch census database. Run with
the Unicorn venv:

    tools/unicorn/.venv/bin/python3 tools/census/test_indirect_target.py
"""
import hashlib
import json
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import indirect_target as it  # noqa: E402
import test_indexed_writes as TIW  # noqa: E402
from test_fnptr_resolve import b, ldr_word, str_word  # noqa: E402
from test_interproc_writes import bl  # noqa: E402

FAILURES = []
FB = 0x4000
SIZE = 0x1000
VT, VT2 = 0x4800, 0x4880          # two vtables (address points)
OBJ_A, OBJ_B = 0x20000100, 0x20000200


def check(name, condition, detail=""):
    status = "ok" if condition else "FAIL"
    print(f"  [{status}] {name}" + (f" -- {detail}" if detail and not condition else ""))
    if not condition:
        FAILURES.append(name)


def _imm(v):
    return f"#{v}" if v < 10 else f"#0x{v:x}"


def ldr_lit(addr, rd, imm8):
    """ldr rd, [pc, #imm8*4]; returns (bytes, literal address)."""
    target = ((addr + 4) & ~3) + imm8 * 4
    return TIW._verify(TIW.enc16(0x4800 | (rd << 8) | imm8), addr, f"ldr r{rd}, [pc, {_imm(imm8 * 4)}]"), target


def ldr_imm(addr, rt, rn, offset):
    text = f"ldr r{rt}, [r{rn}]" if offset == 0 else f"ldr r{rt}, [r{rn}, {_imm(offset)}]"
    return TIW._verify(TIW.enc16(0x6800 | ((offset // 4) << 6) | (rn << 3) | rt), addr, text)


def ldr_sp(addr, rt, offset):
    return TIW._verify(TIW.enc16(0x9800 | (rt << 8) | (offset // 4)), addr, f"ldr r{rt}, [sp, #{offset}]")


def blx(addr, rm):
    return TIW._verify(TIW.enc16(0x4780 | (rm << 3)), addr, f"blx r{rm}")


def bx(addr, rm):
    return TIW._verify(TIW.enc16(0x4700 | (rm << 3)), addr, "bx lr" if rm == 14 else f"bx r{rm}")


def it_eq_ldr_pc(addr, rd, imm8):
    """`it eq; ldreq rd, [pc, #imm8*4]` -- verified as a pair, since only the
    IT state gives the load its condition."""
    bs = TIW.enc16(0xBF08) + TIW.enc16(0x4800 | (rd << 8) | imm8)
    md = TIW.Cs(TIW.CS_ARCH_ARM, TIW.CS_MODE_THUMB)
    got = [f"{x.mnemonic} {x.op_str}" for x in md.disasm(bs, addr)]
    assert got == ["it eq", f"ldreq r{rd}, [pc, {_imm(imm8 * 4)}]"], got
    return bs


def ldrd(addr, rt, rt2, rn):
    return TIW._verify(TIW.enc32(0xE9D0 | rn, (rt << 12) | (rt2 << 8)), addr, f"ldrd r{rt}, r{rt2}, [r{rn}]")


def str_post(addr, rt, rn, imm8):
    return TIW._verify(TIW.enc32(0xF840 | rn, (rt << 12) | 0x0B00 | imm8), addr, f"str r{rt}, [r{rn}], #{imm8}")


def word(value):
    return struct.pack("<I", value)


def build():
    """Scratch census + image. Returns (conn, image, sites by name)."""
    d, conn = TIW._scratch_db()
    fw = TIW._make_firmware(conn, "it")
    chunks, sites, fns = [], {}, {}

    def fn(name, entry, blocks, edges=()):
        fid = TIW._make_function(conn, fw, entry, name=name)
        fns[name] = fid
        for start, end in blocks:
            TIW._make_block(conn, fw, fid, start, end)
        for frm, to, kind in edges:
            TIW._make_edge(conn, fw, fid, frm, to, kind)

    # constant target: ldr r3,=0x4401 ; blx r3
    lit = ldr_lit(0x4000, 3, 1)
    chunks += [(0x4000, lit[0]), (0x4002, blx(0x4002, 3)), (lit[1], word(0x4401))]
    fn("const", 0x4000, [(0x4000, 0x4003)])
    sites["const"] = 0x4002

    # vtable slot 8 tail dispatch on the incoming receiver
    chunks += [(0x4040, ldr_word(0x4040, 3, 0)), (0x4042, ldr_imm(0x4042, 3, 3, 0x20)), (0x4044, bx(0x4044, 3))]
    fn("slot8", 0x4040, [(0x4040, 0x4045)])
    sites["slot8"] = 0x4044

    # vtable slot 7 through an unrelated instruction
    chunks += [(0x4080, ldr_word(0x4080, 3, 0)), (0x4082, ldr_imm(0x4082, 3, 3, 0x1c)),
               (0x4084, TIW.movs(0x4084, 2, 1)), (0x4086, blx(0x4086, 3))]
    fn("slot7", 0x4080, [(0x4080, 0x4087)])
    sites["slot7"] = 0x4086

    # receiver ambiguity: a join of the incoming r0 and a constant object
    lit = ldr_lit(0x40c4, 0, 6)
    chunks += [(0x40c0, TIW.cmp_imm(0x40c0, 1, 0)), (0x40c2, TIW.beq(0x40c2, 0x40c8)),
               (0x40c4, lit[0]), (0x40c6, TIW.nop(0x40c6)), (lit[1], word(OBJ_A)),
               (0x40c8, ldr_word(0x40c8, 3, 0)), (0x40ca, ldr_imm(0x40ca, 3, 3, 4)), (0x40cc, blx(0x40cc, 3))]
    fn("join", 0x40c0, [(0x40c0, 0x40c3), (0x40c4, 0x40c7), (0x40c8, 0x40cd)],
       [(0x40c2, 0x40c8, "cbranch"), (0x40c2, 0x40c4, "fallthrough"), (0x40c6, 0x40c8, "fallthrough")])
    sites["join"] = 0x40cc

    # a block also entered through a code pointer (cf. a tail-branched vtable entry)
    lit = ldr_lit(0x4130, 0, 1)
    chunks += [(0x4130, lit[0]), (0x4132, b(0x4132, 0x4140)), (lit[1], word(OBJ_B)),
               (0x4140, ldr_word(0x4140, 3, 0)), (0x4142, ldr_word(0x4142, 3, 3)), (0x4144, bx(0x4144, 3)),
               (0x4900, word(0x4141))]
    fn("entered", 0x4130, [(0x4130, 0x4133), (0x4140, 0x4145)], [(0x4132, 0x4140, "branch")])
    sites["entered"] = 0x4144

    # unknown: a stack slot
    chunks += [(0x4180, ldr_sp(0x4180, 3, 4)), (0x4182, blx(0x4182, 3))]
    fn("stack", 0x4180, [(0x4180, 0x4183)])
    sites["stack"] = 0x4182

    # non-vtable: a function pointer kept in an object field, and a callback argument
    chunks += [(0x41c0, ldr_imm(0x41c0, 3, 0, 8)), (0x41c2, blx(0x41c2, 3)), (0x4200, blx(0x4200, 1))]
    fn("field", 0x41c0, [(0x41c0, 0x41c3)])
    fn("callback", 0x4200, [(0x4200, 0x4201)])
    sites["field"], sites["callback"] = 0x41c2, 0x4200

    # two constant targets: an IT-conditional redefinition
    lit = ldr_lit(0x4240, 3, 7)
    chunks += [(0x4240, lit[0]), (0x4242, it_eq_ldr_pc(0x4242, 3, 7)),
               (0x4246, blx(0x4246, 3)), (lit[1], word(0x4501)), (0x4264, word(0x4521))]
    fn("cond", 0x4240, [(0x4240, 0x4247)])
    sites["cond"] = 0x4246

    # call clobbers r3; r0 after a call is its result
    lit = ldr_lit(0x4280, 3, 7)
    chunks += [(0x4280, lit[0]), (0x4282, bl(0x4282, 0x4400)), (0x4286, blx(0x4286, 3)), (lit[1], word(0x4401)),
               (0x42c0, bl(0x42c0, 0x4400)), (0x42c4, blx(0x42c4, 0))]
    fn("clobber", 0x4280, [(0x4280, 0x4287)])
    fn("result", 0x42c0, [(0x42c0, 0x42c5)])
    sites["clobber"], sites["result"], sites["bl"] = 0x4286, 0x42c4, 0x4282

    # a writeback updates the slot base: never read through as the constant
    lit = ldr_lit(0x4300, 0, 7)
    chunks += [(0x4300, lit[0]), (0x4302, str_post(0x4302, 2, 0, 4)), (0x4306, ldr_word(0x4306, 3, 0)),
               (0x4308, blx(0x4308, 3)), (lit[1], word(OBJ_A))]
    fn("writeback", 0x4300, [(0x4300, 0x4309)])
    sites["writeback"] = 0x4308

    # dual loads: the first destination is the vptr, the second the next word
    chunks += [(0x4400, ldrd(0x4400, 3, 2, 0)), (0x4404, ldr_word(0x4404, 3, 3)), (0x4406, bx(0x4406, 3)),
               (0x4440, ldrd(0x4440, 2, 3, 0)), (0x4444, ldr_imm(0x4444, 3, 3, 8)), (0x4446, bx(0x4446, 3))]
    fn("ldrd_first", 0x4400, [(0x4400, 0x4407)])
    fn("ldrd_second", 0x4440, [(0x4440, 0x4447)])
    sites["ldrd_first"], sites["ldrd_second"] = 0x4406, 0x4446

    # constant slots: immutable flash vs RAM
    lit = ldr_lit(0x4340, 2, 7)
    chunks += [(0x4340, lit[0]), (0x4342, ldr_imm(0x4342, 3, 2, 4)), (0x4344, blx(0x4344, 3)),
               (lit[1], word(0x4a00)), (0x4a04, word(0x4561))]
    fn("flashslot", 0x4340, [(0x4340, 0x4345)])
    lit = ldr_lit(0x4380, 2, 7)
    chunks += [(0x4380, lit[0]), (0x4382, ldr_imm(0x4382, 3, 2, 4)), (0x4384, blx(0x4384, 3)),
               (lit[1], word(OBJ_B))]
    fn("ramslot", 0x4380, [(0x4380, 0x4385)])
    sites["flashslot"], sites["ramslot"] = 0x4344, 0x4384

    # constructors: one installs VT (a table), one stores a lone code pointer
    lit = ldr_lit(0x43c0, 3, 7)
    chunks += [(0x43c0, lit[0]), (0x43c2, str_word(0x43c2, 3, 0)), (0x43c4, bx(0x43c4, 14)), (lit[1], word(VT))]
    fn("ctor", 0x43c0, [(0x43c0, 0x43c5)])
    lit = ldr_lit(0x4600, 3, 7)
    chunks += [(0x4600, lit[0]), (0x4602, str_word(0x4602, 3, 0)), (0x4604, bx(0x4604, 14)),
               (lit[1], word(0x4a40)), (0x4a40, word(0x4401))]
    fn("notctor", 0x4600, [(0x4600, 0x4605)])

    chunks += [(VT + 4 * i, word(0x4401 + 0x10 * i)) for i in range(11)]
    chunks += [(VT2 + 4 * i, word(0x4701 + 0x10 * i)) for i in range(9)]
    image = TIW._image(FB, SIZE, chunks)
    conn.execute("UPDATE firmware SET sha256=?, size_bytes=? WHERE id=?",
                 (hashlib.sha256(image).hexdigest(), len(image), fw))
    conn.commit()
    return d, conn, image, sites


def resolve(conn, image, site, **kw):
    return it.resolve_indirect_call(conn, "it", image, site, **kw)


def main():
    print("test_indirect_target")
    _d, conn, image, s = build()

    r = resolve(conn, image, s["const"])
    check("constant-derived target is statically established",
          r["pattern"] == "constant-target" and r["resolution_status"] == "STATICALLY_ESTABLISHED", r["pattern"])
    t = r["candidate_targets"][0]
    check("Thumb bit normalized, raw word kept",
          (t["raw_value"], t["target"], t["thumb_bit"], t["normalization"]) ==
          ("0x00004401", "0x00004400", 1, "thumb-bit-cleared"), t)

    r = resolve(conn, image, s["slot8"], vtables=[VT])
    p = r["patterns"][0]
    check("vtable slot shape recovered",
          (p["pattern"], p["slot_offset"], p["slot_index"], p["table_pointer_offset"]) == ("vtable-slot", 0x20, 8, 0), p)
    check("receiver is the incoming r0", p["receiver"] == {"kind": "argument", "arg": 0, "function_entry": "0x00004040"},
          p["receiver"])
    t = r["candidate_targets"]
    check("slot 8 of the supplied vtable is the candidate",
          [(c["entry_addr"], c["target"]) for c in t] == [("0x00004820", "0x00004480")], t)
    check("a vtable candidate is conditional, never established", r["resolution_status"] == "CONDITIONALLY_POSSIBLE",
          r["resolution_status"])
    r_none = resolve(conn, image, s["slot8"])
    check("no vtable supplied: shape known, no candidates",
          r_none["candidate_targets"] == [] and r_none["resolution_status"] == "UNRESOLVED", r_none["resolution_status"])
    r2 = resolve(conn, image, s["slot8"], vtables=[VT, VT2])
    check("multiple vtables: one candidate per vtable",
          sorted(c["target"] for c in r2["candidate_targets"]) == ["0x00004480", "0x00004780"], r2["candidate_targets"])

    r = resolve(conn, image, s["slot7"], vtables=[VT])
    p = r["patterns"][0]
    check("slot offset 0x1c through an unrelated instruction is slot 7",
          (p["slot_offset"], p["slot_index"], r["candidate_targets"][0]["entry_addr"]) == (0x1c, 7, "0x0000481c"), p)

    r = resolve(conn, image, s["join"])
    recv = r["patterns"][0]["receiver"]
    check("join: both receivers reach (argument and constant object)",
          recv["kind"] == "multiple" and recv["kinds"] == ["argument", "constant"], recv)
    check("join: derivation still complete (both paths resolved)", r["derivation_status"] == "ESTABLISHED",
          r["derivation_status"])
    check("join: the constant receiver is object A", f'"0x{OBJ_A:08x}"' in json.dumps(r["reaching_definitions"]),
          r["reaching_definitions"])

    r = resolve(conn, image, s["entered"])
    recv = r["patterns"][0]["receiver"]
    check("block entered through a code pointer: indirect entry kept beside the constant",
          recv["kind"] == "multiple" and recv["kinds"] == ["constant", "indirect-entry"], recv)
    check("indirect entry makes the derivation partial", r["derivation_status"] == "PARTIAL", r["derivation_status"])
    check("the constant receiver is the object the recorded path loads",
          f'"0x{OBJ_B:08x}"' in json.dumps(r["reaching_definitions"]), r["reaching_definitions"])

    r = resolve(conn, image, s["stack"])
    check("entry-block stack load with no prologue is incoming stack argument 5 (v2; spills: test_callback_provenance)",
          r["pattern"] == "argument" and r["patterns"][0]["arg"] == 5 and r["patterns"][0]["location"] == "stack"
          and r["resolution_status"] == "UNRESOLVED", r["patterns"])

    r = resolve(conn, image, s["field"], vtables=[VT])
    check("object-field function pointer is not a vtable dispatch",
          r["pattern"] == "object-field" and r["patterns"][0]["field_offset"] == 8 and r["candidate_targets"] == [],
          r["patterns"])
    r = resolve(conn, image, s["callback"])
    check("callback argument", r["pattern"] == "argument" and r["patterns"][0]["arg"] == 1, r["patterns"])

    r = resolve(conn, image, s["cond"])
    check("IT-conditional redefinition: both constants reach",
          r["pattern"] == "multiple" and sorted(c["target"] for c in r["candidate_targets"]) ==
          ["0x00004500", "0x00004520"], r["candidate_targets"])

    r = resolve(conn, image, s["clobber"])
    check("a call between definition and use clobbers r3",
          r["pattern"] == "unresolved" and "clobbered" in r["patterns"][0]["reason"], r["patterns"])
    r = resolve(conn, image, s["result"])
    check("r0 after a call is the call result",
          r["pattern"] == "call-result" and r["patterns"][0]["callee"] == "0x00004400", r["patterns"])

    r = resolve(conn, image, s["writeback"])
    check("a writeback base update is not read through as the constant",
          r["pattern"] == "object-field" and r["patterns"][0]["pointer"]["kind"] == "unknown", r["patterns"])

    r = resolve(conn, image, s["ldrd_first"])
    p = r["patterns"][0]
    check("LDRD first destination is the vptr: a slot-0 vtable dispatch",
          (p["pattern"], p["slot_offset"], p["table_pointer_offset"]) == ("vtable-slot", 0, 0), p)
    r = resolve(conn, image, s["ldrd_second"])
    p = r["patterns"][0]
    check("LDRD second destination is the next word: a table pointer at object offset 4",
          (p["pattern"], p["slot_offset"], p["table_pointer_offset"]) == ("object-table-slot", 8, 4), p)

    r = resolve(conn, image, s["flashslot"])
    check("constant slot in immutable flash: its word is the target",
          r["pattern"] == "constant-slot" and r["patterns"][0]["slot_region"] == "flash"
          and r["candidate_targets"][0]["target"] == "0x00004560"
          and r["resolution_status"] == "STATICALLY_ESTABLISHED", r["candidate_targets"])
    r = resolve(conn, image, s["ramslot"])
    check("constant slot in RAM: runtime state, no constant writer, unresolved",
          r["patterns"][0]["slot_region"] == "ram" and r["patterns"][0]["slot_writers"] == 0
          and r["resolution_status"] == "UNRESOLVED", r["patterns"])

    r = resolve(conn, image, s["bl"])
    check("a direct call is not a register-indirect site",
          r["derivation_status"] == "NOT_APPLICABLE" and r["instruction_shape"] != "reg-indirect", r["instruction_shape"])
    r = resolve(conn, image, 0x4ff0)
    check("a site outside every census block is unknown, not guessed",
          r["derivation_status"] in ("UNKNOWN", "NOT_APPLICABLE") and r["candidate_targets"] == [], r)

    try:
        it.resolve_indirect_call(conn, "it", image[:-1] + b"\x01", s["const"])
        check("an image that is not the census firmware is refused", False)
    except ValueError:
        check("an image that is not the census firmware is refused", True)

    r = resolve(conn, image, s["join"], max_blocks=1)
    check("block bound: reported as incomplete, never dropped",
          r["derivation_status"] != "ESTABLISHED"
          and "incomplete" in json.dumps(r["reaching_definitions"]), r["derivation_status"])
    r = resolve(conn, image, s["slot8"], vtables=[VT], max_depth=0)
    check("depth bound: receiver incomplete", r["patterns"][0]["pattern"] != "vtable-slot"
          or r["derivation_status"] != "ESTABLISHED", r["patterns"])

    r = resolve(conn, image, s["slot8"], vtables=[VT])
    check("provenance carried",
          all(k in r for k in ("analysis", "analysis_version", "firmware_sha256", "site", "bounds", "limitations",
                               "vtables_supplied")) and r["firmware_sha256"] == hashlib.sha256(image).hexdigest(), r)
    check("a possible target is labeled as not a dispatch or reachability claim",
          any("not an observed or reachable dispatch" in x for x in r["limitations"]), r["limitations"])
    check("deterministic output", json.dumps(r, sort_keys=True) ==
          json.dumps(resolve(conn, image, s["slot8"], vtables=[VT]), sort_keys=True))

    inst = it.vptr_installations(conn, "it", image)
    check("vptr installation found; a lone code pointer is not a vtable",
          [(i["store_addr"], i["vtable"], i["object_offset"], len(i["entries"])) for i in inst] ==
          [("0x000043c2", "0x00004800", 0, 11)], inst)

    if FAILURES:
        print(f"\n{len(FAILURES)} FAILURE(S): {FAILURES}")
        sys.exit(1)
    print("\nall indirect_target checks passed")


if __name__ == "__main__":
    main()
