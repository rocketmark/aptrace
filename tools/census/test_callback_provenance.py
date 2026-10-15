#!/usr/bin/env python3
"""APTrace census: regression coverage for one-hop caller-argument
provenance (tools/census/callback_provenance.py) and the indirect_target v2
changes it relies on (jump-table predecessors, stack arguments, movw/adr/
arithmetic constants). Same convention as test_indirect_target.py --
hand-encoded Thumb round-trip-verified against Capstone, a scratch census
database. Run with the Unicorn venv:

    tools/unicorn/.venv/bin/python3 tools/census/test_callback_provenance.py
"""
import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import callback_provenance as cp  # noqa: E402
import indirect_target as it  # noqa: E402
import test_indexed_writes as TIW  # noqa: E402
from test_fnptr_resolve import b  # noqa: E402
from test_indirect_target import blx, bx, ldr_imm, ldr_lit, ldr_sp, word  # noqa: E402
from test_interproc_writes import bl  # noqa: E402

FAILURES = []
FB = 0x4000
SIZE = 0x2000
# Callback values (zero-filled code: every halfword decodes).
T1, T2, T3, T4, T5, T6, T7 = 0x5e01, 0x5e21, 0x5e41, 0x5e61, 0x5e81, 0x5ea1, 0x5ec1
T_EVEN = 0x5e00          # Thumb bit clear
T_JT = 0x5ee1


def check(name, condition, detail=""):
    status = "ok" if condition else "FAIL"
    print(f"  [{status}] {name}" + (f" -- {detail}" if detail and not condition else ""))
    if not condition:
        FAILURES.append(name)


def _branch_imm(addr, target):
    imm = target - (addr + 4)
    s = (imm >> 24) & 1
    j1 = 1 ^ ((imm >> 23) & 1) ^ s
    j2 = 1 ^ ((imm >> 22) & 1) ^ s
    return imm, s, j1, j2


def b_w(addr, target):
    imm, s, j1, j2 = _branch_imm(addr, target)
    return TIW._verify(TIW.enc32(0xF000 | (s << 10) | ((imm >> 12) & 0x3FF),
                                 0x9000 | (j1 << 13) | (j2 << 11) | ((imm >> 1) & 0x7FF)), addr, f"b.w #0x{target:x}")


def beq_w(addr, target):
    imm = target - (addr + 4)
    hw1 = 0xF000 | (((imm >> 20) & 1) << 10) | (0 << 6) | ((imm >> 12) & 0x3F)
    hw2 = 0x8000 | (((imm >> 18) & 1) << 13) | (((imm >> 19) & 1) << 11) | ((imm >> 1) & 0x7FF)
    return TIW._verify(TIW.enc32(hw1, hw2), addr, f"beq.w #0x{target:x}")


def blx_imm(addr, target):
    """BLX immediate (T2, ARM-state target). Decoded in plain Thumb mode only."""
    imm = target - ((addr + 4) & ~3)
    s = (imm >> 24) & 1
    j1 = 1 ^ ((imm >> 23) & 1) ^ s
    j2 = 1 ^ ((imm >> 22) & 1) ^ s
    return TIW._verify(TIW.enc32(0xF000 | (s << 10) | ((imm >> 12) & 0x3FF),
                                 0xC000 | (j1 << 13) | (j2 << 11) | (((imm >> 2) & 0x3FF) << 1)), addr,
                       f"blx #0x{target:x}")


def mov_reg(addr, rd, rm):
    return TIW._verify(TIW.enc16(0x4600 | ((rd >> 3) << 7) | (rm << 3) | (rd & 7)), addr, f"mov r{rd}, r{rm}")


def str_sp(addr, rt, offset):
    text = f"str r{rt}, [sp]" if offset == 0 else f"str r{rt}, [sp, #{offset}]"
    return TIW._verify(TIW.enc16(0x9000 | (rt << 8) | (offset // 4)), addr, text)


def push_r4_lr(addr):
    return TIW._verify(TIW.enc16(0xB510), addr, "push {r4, lr}")


def movw(addr, rd, imm):
    hw1 = 0xF240 | (((imm >> 11) & 1) << 10) | ((imm >> 12) & 0xF)
    hw2 = (((imm >> 8) & 7) << 12) | (rd << 8) | (imm & 0xFF)
    return TIW._verify(TIW.enc32(hw1, hw2), addr, f"movw r{rd}, #0x{imm:x}")


def adr(addr, rd, imm):
    return TIW._verify(TIW.enc16(0xA000 | (rd << 8) | (imm // 4)), addr, f"adr r{rd}, #{imm}")


def adds8(addr, rd, imm):
    return TIW._verify(TIW.enc16(0x3000 | (rd << 8) | imm), addr, f"adds r{rd}, #{imm}")


def ldr_pc_table(addr):
    return TIW._verify(TIW.enc32(0xF850, 0xF023), addr, "ldr.w pc, [r0, r3, lsl #2]")


def build():
    d, conn = TIW._scratch_db()
    fw = TIW._make_firmware(conn, "cp")
    chunks, fns = [], {}

    def fn(name, entry, blocks, edges=()):
        fid = TIW._make_function(conn, fw, entry, name=name)
        fns[name] = fid
        for start, end in blocks:
            TIW._make_block(conn, fw, fid, start, end)
        for frm, to, kind in edges:
            TIW._make_edge(conn, fw, fid, frm, to, kind)
        return fid

    def lit(addr, rd, value, imm8=7):
        code, at = ldr_lit(addr, rd, imm8)
        chunks.extend([(addr, code), (at, word(value))])

    # A: callback in r3, copied to r7 (register copy), many callers
    chunks += [(0x4000, mov_reg(0x4000, 7, 3)), (0x4002, blx(0x4002, 7))]
    fn("A", 0x4000, [(0x4000, 0x4003)])
    lit(0x4100, 3, T1)
    chunks.append((0x4102, bl(0x4102, 0x4000)))
    a1 = fn("A1", 0x4100, [(0x4100, 0x4105)])
    TIW._make_edge(conn, fw, a1, 0x4102, 0x4000, "call", fns["A"])
    # A2: a join of two literals before the call
    lit(0x4140, 3, T2)
    lit(0x4146, 3, T3)
    chunks += [(0x4142, TIW.cmp_imm(0x4142, 0, 0)), (0x4144, TIW.beq(0x4144, 0x4148)), (0x4148, bl(0x4148, 0x4000))]
    fn("A2", 0x4140, [(0x4140, 0x4145), (0x4146, 0x4147), (0x4148, 0x414b)],
       [(0x4144, 0x4148, "cbranch"), (0x4144, 0x4146, "fallthrough"), (0x4146, 0x4148, "fallthrough")])
    # A3: forwards its own r1
    chunks += [(0x4180, mov_reg(0x4180, 3, 1)), (0x4182, bl(0x4182, 0x4000))]
    fn("A3", 0x4180, [(0x4180, 0x4185)])
    # A4: loads it from an object field
    chunks += [(0x41c0, ldr_imm(0x41c0, 3, 0, 8)), (0x41c2, bl(0x41c2, 0x4000))]
    fn("A4", 0x41c0, [(0x41c0, 0x41c5)])
    # A5: tail-branches with an even (non-Thumb) value
    lit(0x4200, 3, T_EVEN)
    chunks.append((0x4202, b_w(0x4202, 0x4000)))
    fn("A5", 0x4200, [(0x4200, 0x4205)])

    # B: callback in r0
    chunks.append((0x4300, blx(0x4300, 0)))
    fn("B", 0x4300, [(0x4300, 0x4301)])
    chunks += [(0x4340, movw(0x4340, 0, T4)), (0x4344, bl(0x4344, 0x4300))]
    fn("B1", 0x4340, [(0x4340, 0x4347)])
    # B2: adr in one block, +1 in the next (arithmetic across a block edge)
    chunks += [(0x4380, adr(0x4380, 0, 8)), (0x4382, adds8(0x4382, 0, 1)), (0x4384, bl(0x4384, 0x4300))]
    fn("B2", 0x4380, [(0x4380, 0x4381), (0x4382, 0x4387)], [(0x4380, 0x4382, "fallthrough")])
    # B3: r0 is a call result
    chunks += [(0x43c0, bl(0x43c0, 0x4fe0)), (0x43c4, bl(0x43c4, 0x4300))]
    fn("B3", 0x43c0, [(0x43c0, 0x43c7)])
    # B4: BLX immediate to B (ARM state: undefined on M-profile)
    chunks.append((0x4400, blx_imm(0x4400, 0x4300)))
    fn("B4", 0x4400, [(0x4400, 0x4403)])
    # B5: conditional wide tail branch forwarding its own r0
    chunks.append((0x4440, beq_w(0x4440, 0x4300)))
    fn("B5", 0x4440, [(0x4440, 0x4443)])
    # B6: 16-bit tail branch with NULL
    chunks += [(0x4480, TIW.movs(0x4480, 0, 0)), (0x4482, b(0x4482, 0x4300))]
    fn("B6", 0x4480, [(0x4480, 0x4483)])

    # C: a stack argument (arg 4) read after the prologue
    chunks += [(0x4500, push_r4_lr(0x4500)), (0x4502, ldr_sp(0x4502, 4, 8)), (0x4504, blx(0x4504, 4))]
    fn("C", 0x4500, [(0x4500, 0x4505)])
    lit(0x4540, 3, T5)
    chunks += [(0x4542, str_sp(0x4542, 3, 0)), (0x4544, bl(0x4544, 0x4500))]
    fn("C1", 0x4540, [(0x4540, 0x4547)])
    chunks.append((0x4580, bl(0x4580, 0x4500)))
    fn("C2", 0x4580, [(0x4580, 0x4583)])
    # D: a genuine spill (stored into the frame, then reloaded)
    chunks += [(0x45c0, push_r4_lr(0x45c0)), (0x45c2, str_sp(0x45c2, 1, 8)), (0x45c4, ldr_sp(0x45c4, 4, 8)),
               (0x45c6, blx(0x45c6, 4))]
    fn("D", 0x45c0, [(0x45c0, 0x45c7)])
    # E: a stack load outside the entry block
    chunks += [(0x4640, TIW.nop(0x4640)), (0x4642, ldr_sp(0x4642, 4, 4)), (0x4644, blx(0x4644, 4))]
    fn("E", 0x4640, [(0x4640, 0x4641), (0x4642, 0x4645)], [(0x4640, 0x4642, "fallthrough")])

    # F: address-taken entry (a flash Thumb pointer to it)
    chunks += [(0x4700, blx(0x4700, 1)), (0x4f00, word(0x4701))]
    fn("F", 0x4700, [(0x4700, 0x4701)])
    lit(0x4740, 1, T6)
    chunks.append((0x4742, bl(0x4742, 0x4700)))
    fn("F1", 0x4740, [(0x4740, 0x4745)])
    # G: a MOVW materialization, and a census edge with no decoded transfer
    chunks.append((0x4780, blx(0x4780, 1)))
    fn("G", 0x4780, [(0x4780, 0x4781)])
    lit(0x47c0, 1, T7)
    chunks.append((0x47c2, bl(0x47c2, 0x4780)))
    fn("G1", 0x47c0, [(0x47c0, 0x47c5)])
    chunks.append((0x4800, movw(0x4800, 2, 0x4781)))
    g2 = fn("G2", 0x4800, [(0x4800, 0x4803)])
    TIW._make_edge(conn, fw, g2, 0x4800, 0x4780, "call", fns["G"])

    # H: three callers (caller bound)
    chunks.append((0x4880, blx(0x4880, 2)))
    fn("H", 0x4880, [(0x4880, 0x4881)])
    for n, at in enumerate((0x48c0, 0x4900, 0x4940)):
        lit(at, 2, T1 + 0x40 * n)
        chunks.append((at + 2, bl(at + 2, 0x4880)))
        fn(f"H{n}", at, [(at, at + 5)])

    # J: callback read after a resolved jump table (indirect_target v2)
    chunks += [(0x4a00, mov_reg(0x4a00, 7, 3)), (0x4a02, adr(0x4a02, 0, 4)), (0x4a04, ldr_pc_table(0x4a04)),
               (0x4a08, word(0x4a11)), (0x4a0c, word(0x4a15)), (0x4a10, blx(0x4a10, 7)), (0x4a14, bx(0x4a14, 14))]
    j = fn("J", 0x4a00, [(0x4a00, 0x4a07), (0x4a10, 0x4a11), (0x4a14, 0x4a15)],
           [(0x4a04, 0x4a10, "computed-jump"), (0x4a04, 0x4a14, "computed-jump")])
    conn.execute("INSERT INTO indirect_edge_resolutions (firmware_id, from_addr, from_function_id, instr_mnemonic, "
                 "instr_shape, classification, source) VALUES (?,?,?,'ldr.w','mem-indirect','STATICALLY_RESOLVED','t')",
                 (fw, 0x4a04, j))
    for case in (0x4a10, 0x4a14):
        conn.execute("INSERT INTO indirect_edge_candidates (firmware_id, from_addr, candidate_addr, confidence, source) "
                     "VALUES (?,?,?,'EXACT','ghidra-basicblockmodel')", (fw, 0x4a04, case))
    lit(0x4a40, 3, T_JT)
    chunks.append((0x4a42, bl(0x4a42, 0x4a00)))
    fn("J1", 0x4a40, [(0x4a40, 0x4a45)])

    # K: a constant target (no argument)
    lit(0x4b00, 3, T1)
    chunks.append((0x4b02, blx(0x4b02, 3)))
    fn("K", 0x4b00, [(0x4b00, 0x4b03)])

    # reachability and recorded coverage for A1
    conn.execute("INSERT INTO function_reachability (firmware_id, function_id, status, nearest_root_addr, "
                 "nearest_root_kind, hops, source) VALUES (?,?, 'DEFINITELY_REACHABLE', ?, 'reset-vector', 2, 't')",
                 (fw, a1, 0x4100))
    conn.execute("INSERT INTO dynamic_runs (firmware_id, scenario, leg_index, ran_at, source_file) "
                 "VALUES (?,'boot',0,'now','t')", (fw,))
    run = conn.execute("SELECT id FROM dynamic_runs").fetchone()[0]
    conn.execute("INSERT INTO dynamic_coverage (dynamic_run_id, firmware_id, pc) VALUES (?,?,?)", (run, fw, 0x4102))

    image = TIW._image(FB, SIZE, chunks)
    conn.execute("UPDATE firmware SET sha256=?, size_bytes=? WHERE id=?",
                 (hashlib.sha256(image).hexdigest(), len(image), fw))
    conn.commit()
    return d, conn, image


def trace(conn, image, site, **kw):
    return cp.trace_callback_argument(conn, "cp", image, site, **kw)


def callers_of(r, origin=0):
    return {c["site"]: c for c in r["argument_origins"][origin]["callers"]}


def main():
    print("test_callback_provenance")
    _d, conn, image = build()

    # -- indirect_target v2 -------------------------------------------------
    r = it.resolve_indirect_call(conn, "cp", image, 0x4504)
    p = r["patterns"][0]
    check("stack argument: entry-block load after the prologue is incoming argument 4",
          (r["pattern"], p["arg"], p.get("location"), p.get("entry_sp_offset"), r["derivation_status"]) ==
          ("argument", 4, "stack", 0, "ESTABLISHED"), p)
    r = it.resolve_indirect_call(conn, "cp", image, 0x45c6)
    check("a slot stored into before the load stays a spill (unresolved)",
          r["pattern"] == "unresolved" and "stack slot" in r["patterns"][0]["reason"], r["patterns"])
    r = it.resolve_indirect_call(conn, "cp", image, 0x4644)
    check("a stack load outside the entry block stays unresolved", r["pattern"] == "unresolved", r["patterns"])
    r = it.resolve_indirect_call(conn, "cp", image, 0x4a10)
    check("resolved jump-table case edges are predecessors: the argument reaches",
          (r["pattern"], r["derivation_status"], r["patterns"][0].get("arg")) == ("argument", "ESTABLISHED", 3),
          r.get("reaching_definitions"))
    row = conn.execute("SELECT * FROM firmware WHERE key='cp'").fetchone()
    ctx = it._Ctx(conn, row, image, 64, 3)
    check("jump-table words and cases are not code-pointer entries",
          0x4a10 not in ctx.pointer_targets and 0x4a14 not in ctx.pointer_targets and 0x4700 in ctx.pointer_targets,
          sorted(hex(x) for x in ctx.pointer_targets))
    check("indirect_target analysis version bumped", r["analysis_version"] == 2, r["analysis_version"])

    # -- site A: register copy, many callers ------------------------------------
    r = trace(conn, image, 0x4002)
    o = r["argument_origins"][0]
    check("argument origin: incoming r3 of the callee (copied to r7 before the blx)",
          (r["target_register"], o["argument"], o["function_entry"], r["containing_function"]) ==
          ("r7", "r3", "0x00004000", "0x00004000"), (r["target_register"], o["argument"]))
    cs = callers_of(r)
    check("every direct transfer into the entry is a caller (BL x4, B.W tail)",
          sorted(cs) == ["0x00004102", "0x00004148", "0x00004182", "0x000041c2", "0x00004202"], sorted(cs))
    c = cs["0x00004102"]
    check("literal callback: CONCRETE, Thumb bit normalized, raw kept",
          (c["value_status"], c["components"][0]["raw_value"], c["components"][0]["target"],
           c["components"][0]["thumb_bit"], c["components"][0]["basis"]) ==
          ("CONCRETE", "0x00005e01", "0x00005e00", 1, "literal at 0x00004120"), c["components"])
    check("caller site identity differs from the caller's function entry",
          (c["site"], c["caller_function"], c["block"], c["transfer_kind"]) ==
          ("0x00004102", "0x00004100", "0x00004100", "call"), c)
    check("a census call edge corroborates the decoded transfer", c["census_edge"] is True, c)
    check("caller reachability from the census table", c["caller_reachability"]["status"] == "ESTABLISHED"
          and c["caller_reachability"]["census"] == "DEFINITELY_REACHABLE", c["caller_reachability"])
    c = cs["0x00004148"]
    check("CFG join: both literals reach, FINITE_TARGET_SET",
          c["value_status"] == "FINITE_TARGET_SET" and sorted(x["raw_value"] for x in c["components"]) ==
          ["0x00005e21", "0x00005e41"], c["components"])
    c = cs["0x00004182"]
    check("forwarded argument: names the upstream function and register, not followed",
          c["value_status"] == "FORWARDED_ARGUMENT" and c["next_hop"] == [{"function_entry": "0x00004180",
                                                                          "argument": "r1"}], c)
    c = cs["0x000041c2"]
    check("object-field load: MEMORY_DEPENDENT",
          c["value_status"] == "MEMORY_DEPENDENT" and c["components"][0]["shape"] == "object-field", c["components"])
    c = cs["0x00004202"]
    check("tail transfer recorded as such", (c["transfer"], c["transfer_kind"]) == ("b.w", "tail"), c)
    check("an even value is kept, labeled THUMB_BIT_CLEAR, never a target",
          c["components"][0]["validity"] == "THUMB_BIT_CLEAR" and not c["components"][0]["callable"]
          and "0x00005e00" in r["non_callable_values"]
          and all(t["target"] != "0x00005e00" or "0x00005e01" in t["raw_values"] for t in r["candidate_targets"]),
          c["components"])
    check("site status: the most limiting caller value; set OPEN",
          r["provenance_status"] == "MEMORY_DEPENDENT" and r["target_set"] == "OPEN", r["open_reasons"])
    check("candidate targets: only callable caller-supplied values, each with its caller",
          [t["target"] for t in r["candidate_targets"]] == ["0x00005e00", "0x00005e20", "0x00005e40"]
          and [v["caller_site"] for v in r["candidate_targets"][0]["via"]] == ["0x00004102"], r["candidate_targets"])
    check("candidates are conditional: callee-to-site feasibility is stated, never assumed",
          all(any("feasibility not established" in x for x in v["conditions"])
              for t in r["candidate_targets"] for v in t["via"]), r["candidate_targets"])
    check("next hops collected at site level", r["next_hops"] == [{"argument": "r1", "function_entry": "0x00004180"}],
          r["next_hops"])
    check("recorded coverage reported by scenario",
          r["recorded_coverage"]["0x00004102"] == {"executed_in": ["boot"], "not_executed_in": []}
          and r["recorded_coverage"]["0x00004002"]["executed_in"] == [], r["recorded_coverage"])

    # -- site B: r0; movw, adr+add across blocks, call result, BLX imm, conditional, NULL --
    r = trace(conn, image, 0x4300)
    cs = callers_of(r)
    check("callback in r0", r["argument_origins"][0]["argument"] == "r0", r["argument_origins"][0]["argument"])
    check("movw constant: CONCRETE",
          cs["0x00004344"]["value_status"] == "CONCRETE"
          and cs["0x00004344"]["components"][0]["raw_value"] == f"0x{T4:08x}", cs["0x00004344"]["components"])
    check("adr then +1 in the next block: CONCRETE Thumb pointer",
          cs["0x00004384"]["value_status"] == "CONCRETE"
          and cs["0x00004384"]["components"][0]["raw_value"] == "0x0000438d"
          and cs["0x00004384"]["components"][0]["callable"], cs["0x00004384"]["components"])
    check("call result: UNKNOWN with reason",
          cs["0x000043c4"]["value_status"] == "UNKNOWN"
          and "returned by the call" in cs["0x000043c4"]["components"][0]["reason"], cs["0x000043c4"]["components"])
    inv = r["argument_origins"][0]["invalid_transfers"]
    check("BLX immediate is an invalid transfer on Cortex-M, not a caller",
          [i["site"] for i in inv] == ["0x00004400"] and "0x00004400" not in cs, inv)
    check("conditional wide tail branch: conditional and forwarded",
          cs["0x00004440"]["conditional"] and cs["0x00004440"]["value_status"] == "FORWARDED_ARGUMENT"
          and any("conditional" in x for x in cs["0x00004440"]["conditions"]), cs["0x00004440"])
    check("16-bit B tail with NULL: CONCRETE value, NULL, not callable",
          cs["0x00004482"]["transfer"] == "b" and cs["0x00004482"]["components"][0]["validity"] == "NULL"
          and not cs["0x00004482"]["components"][0]["callable"], cs["0x00004482"])
    check("UNKNOWN dominates the site status", r["provenance_status"] == "UNKNOWN", r["provenance_status"])

    # -- site C: stack argument ---------------------------------------------------
    r = trace(conn, image, 0x4504)
    cs = callers_of(r)
    c = cs["0x00004544"]
    check("stack argument: caller's outgoing store located, value CONCRETE",
          c["value_status"] == "CONCRETE" and c["stack_store"]["store_addr"] == "0x00004542"
          and c["components"][0]["raw_value"] == f"0x{T5:08x}", c)
    check("stack argument condition stated",
          any("outgoing stack slot" in x for x in c["conditions"]), c["conditions"])
    c = cs["0x00004580"]
    check("no outgoing store before the call: UNKNOWN with reason",
          c["value_status"] == "UNKNOWN" and "no store" in c["components"][0]["reason"], c["components"])
    r = trace(conn, image, 0x45c6)
    check("a spilled (non-argument) target: NOT_APPLICABLE, nothing invented",
          r["provenance_status"] == "NOT_APPLICABLE" and r["candidate_targets"] == [], r["provenance_status"])

    # -- caller-set completeness ---------------------------------------------------
    r = trace(conn, image, 0x4700)
    check("address-taken entry: value CONCRETE but the set stays OPEN",
          r["provenance_status"] == "CONCRETE" and r["target_set"] == "OPEN"
          and r["argument_origins"][0]["address_taken"][0]["location"] == "0x00004f00", r["open_reasons"])
    r = trace(conn, image, 0x4780)
    o = r["argument_origins"][0]
    check("MOVW materialization of the entry is address-taken",
          any(a["kind"] == "movw" and a["location"] == "0x00004800" for a in o["address_taken"]), o["address_taken"])
    check("census edge without a decoded transfer keeps the set OPEN",
          o["census_only_edges"] and not o["caller_set_complete"], o["census_only_edges"])
    r = trace(conn, image, 0x4a10)
    check("closed set: one caller, complete derivation, no other entry",
          (r["provenance_status"], r["target_set"], [t["target"] for t in r["candidate_targets"]]) ==
          ("CONCRETE", "CLOSED", ["0x00005ee0"]), r["open_reasons"])
    r = trace(conn, image, 0x4b02)
    check("a constant-target site is NOT_APPLICABLE for argument provenance",
          r["provenance_status"] == "NOT_APPLICABLE", r["provenance_status"])

    # -- bounds ------------------------------------------------------------------
    r = trace(conn, image, 0x4880, max_callers=2)
    o = r["argument_origins"][0]
    check("caller bound: truncation reported, set OPEN, remaining callers listed",
          len(o["callers"]) == 2 and o["callers_not_analyzed"] == ["0x00004942"] and r["target_set"] == "OPEN"
          and any("caller bound" in x for x in r["incomplete_reasons"]), (o.get("callers_not_analyzed"),
                                                                          r["incomplete_reasons"]))
    r = trace(conn, image, 0x4002, max_work=0)
    c = callers_of(r)["0x00004148"]
    check("work budget: the join caller is UNKNOWN, reported as incomplete",
          c["value_status"] == "UNKNOWN" and any("work budget" in x for x in r["incomplete_reasons"]),
          (c["components"], r["incomplete_reasons"]))
    r = trace(conn, image, 0x4002, max_targets=1)
    c = callers_of(r)["0x00004148"]
    check("target-set bound: two constants over a bound of one is UNKNOWN",
          c["value_status"] == "UNKNOWN" and any("distinct constants" in x.get("reason", "") for x in c["components"]),
          c["components"])
    r = trace(conn, image, 0x4002, max_defs=1)
    c = callers_of(r)["0x00004148"]
    check("reaching-definition bound: UNKNOWN", c["value_status"] == "UNKNOWN", c["components"])

    # -- provenance and determinism ---------------------------------------------------
    r = trace(conn, image, 0x4002)
    check("provenance carried",
          all(k in r for k in ("analysis", "analysis_version", "firmware_sha256", "site", "bounds", "limitations",
                               "site_analysis", "work"))
          and r["firmware_sha256"] == hashlib.sha256(image).hexdigest()
          and r["site_analysis"] == {"analysis": "indirect_target", "analysis_version": 2}, r.keys())
    check("deterministic output", json.dumps(r, sort_keys=True) == json.dumps(trace(conn, image, 0x4002),
                                                                              sort_keys=True))
    try:
        cp.trace_callback_argument(conn, "cp", image[:-1] + b"\x01", 0x4002)
        check("an image that is not the census firmware is refused", False)
    except ValueError:
        check("an image that is not the census firmware is refused", True)
    check("argument sites enumerated from the census inventory only",
          cp.argument_sites(conn, "cp", image) == [], cp.argument_sites(conn, "cp", image))

    if FAILURES:
        print(f"\n{len(FAILURES)} FAILURE(S): {FAILURES}")
        sys.exit(1)
    print("\nall callback_provenance checks passed")


if __name__ == "__main__":
    main()
