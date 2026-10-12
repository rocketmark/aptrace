#!/usr/bin/env python3
"""APTrace census: regression coverage for statically initialized RAM
function-pointer recovery (tools/census/fnptr_resolve.py). Same
convention as test_interproc_writes.py -- plain assertions via check(),
hand-encoded Thumb bytes round-trip-verified against Capstone, reusing
test_indexed_writes.py's encoder helpers/DB scaffolding. Run with the
Unicorn venv:

    tools/unicorn/.venv/bin/python3 tools/census/test_fnptr_resolve.py
"""
import json
import sqlite3
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent.parent
sys.path.insert(0, str(HERE))

import fnptr_resolve  # noqa: E402
import test_indexed_writes as TIW  # noqa: E402
from test_interproc_writes import bl  # noqa: E402

FAILURES = []
FB = 0x4000
SLOT = 0x20000100
CONSUMER, SETTER, INIT, STUB, BODY, OTHER = FB, FB + 0x40, FB + 0x80, FB + 0x100, FB + 0x140, FB + 0x200


def check(name, condition, detail=""):
    status = "ok" if condition else "FAIL"
    print(f"  [{status}] {name}" + (f" -- {detail}" if detail and not condition else ""))
    if not condition:
        FAILURES.append(name)


def str_word(addr, rt, rn):
    return TIW._verify(TIW.enc16(0x6000 | (rn << 3) | rt), addr, f"str r{rt}, [r{rn}]")


def ldr_word(addr, rt, rn):
    return TIW._verify(TIW.enc16(0x6800 | (rn << 3) | rt), addr, f"ldr r{rt}, [r{rn}]")


def bx(addr, rm):
    return TIW._verify(TIW.enc16(0x4700 | (rm << 3)), addr, "bx lr" if rm == 14 else f"bx r{rm}")


def b(addr, target):
    return TIW._verify(TIW.enc16(0xE000 | (((target - (addr + 4)) >> 1) & 0x7FF)), addr, f"b #0x{target:x}")


def _unresolved_site(conn, fw, func_id, addr):
    conn.execute(
        "INSERT INTO edges (firmware_id, from_addr, to_addr, kind, resolved, from_function_id, source) "
        "VALUES (?,?,0,'computed-jump-unresolved',0,?,'test')", (fw, addr, func_id))
    conn.commit()


def _scenario(init="callsite-literal", stored=STUB | 1, ghidra_block_edge=False):
    """consumer: r3 = *SLOT; bx r3.  setter(r0): *SLOT = r0.  init: setter(<value>).
    `init` picks how the stored value is produced."""
    d, conn = TIW._scratch_db()
    fw = TIW._make_firmware(conn, "fp", FB)
    chunks = []

    consumer = TIW._make_function(conn, fw, CONSUMER, "consumer")
    ldr, lit = TIW.ldr_pc(CONSUMER, 3, 1)
    chunks += [(CONSUMER, ldr + ldr_word(CONSUMER + 2, 3, 3) + bx(CONSUMER + 4, 3)), (lit, struct.pack("<I", SLOT))]
    TIW._make_block(conn, fw, consumer, CONSUMER, CONSUMER + 5)
    _unresolved_site(conn, fw, consumer, CONSUMER + 4)

    setter = TIW._make_function(conn, fw, SETTER, "setter")
    if init == "intraprocedural":
        ldr_v, lit_v = TIW.ldr_pc(SETTER, 0, 1)
        ldr_s, lit_s = TIW.ldr_pc(SETTER + 2, 3, 2)
        chunks += [(SETTER, ldr_v + ldr_s + str_word(SETTER + 4, 0, 3) + bx(SETTER + 6, 14)),
                   (lit_v, struct.pack("<I", stored)), (lit_s, struct.pack("<I", SLOT))]
        store_addr = SETTER + 4
        TIW._make_block(conn, fw, setter, SETTER, SETTER + 7)
    else:
        ldr_s, lit_s = TIW.ldr_pc(SETTER, 3, 1)
        chunks += [(SETTER, ldr_s + str_word(SETTER + 2, 0, 3) + bx(SETTER + 4, 14)), (lit_s, struct.pack("<I", SLOT))]
        store_addr = SETTER + 2
        TIW._make_block(conn, fw, setter, SETTER, SETTER + 5)
    conn.execute("INSERT INTO memory_accesses (firmware_id, from_addr, from_function_id, to_addr, width, direction, source) "
                 "VALUES (?,?,?,?,4,'WRITE','test')", (fw, store_addr, setter, SLOT))

    initf = TIW._make_function(conn, fw, INIT, "init")
    TIW._make_function(conn, fw, OTHER, "other")
    if init == "callsite-literal":
        ldr_v, lit_v = TIW.ldr_pc(INIT, 0, 2)
        code = ldr_v + TIW.movs(INIT + 2, 1, 7) + bl(INIT + 4, SETTER) + bx(INIT + 8, 14)
        call_at = INIT + 4
        chunks += [(lit_v, struct.pack("<I", stored))]
    elif init == "callsite-ldrb":
        code = TIW._verify(TIW.enc16(0x7800 | (4 << 3) | 0), INIT, "ldrb r0, [r4]") + TIW.movs(INIT + 2, 1, 7) \
            + bl(INIT + 4, SETTER) + bx(INIT + 8, 14)
        call_at = INIT + 4
    elif init == "callsite-clobbered":
        ldr_v, lit_v = TIW.ldr_pc(INIT, 0, 2)
        code = ldr_v + bl(INIT + 2, OTHER) + bl(INIT + 6, SETTER) + bx(INIT + 10, 14)
        call_at = INIT + 6
        chunks += [(lit_v, struct.pack("<I", stored))]
    else:  # intraprocedural: init just calls the setter
        code = bl(INIT, SETTER) + bx(INIT + 4, 14)
        call_at = INIT
    chunks += [(INIT, code)]
    TIW._make_block(conn, fw, initf, INIT, INIT + len(code) - 1)
    # Ghidra's block model reports the call from the BLOCK start; Capstone
    # from the instruction -- both shapes must resolve to the same callsite.
    TIW._make_edge(conn, fw, initf, INIT if ghidra_block_edge else call_at, SETTER, "call", to_function_id=setter)

    chunks += [(STUB, TIW.movs(STUB, 0, 5) + b(STUB + 2, BODY)), (BODY, bx(BODY, 14))]
    return d, conn, fw, TIW._image(FB, 0x400, chunks), call_at


# --- 1, 2. constant store from a call argument; raw != canonical --------------

def test_callsite_argument_constant_pointer():
    print("test_callsite_argument_constant_pointer")
    for ghidra_edge in (False, True):
        d, conn, fw, img, call_at = _scenario("callsite-literal", ghidra_block_edge=ghidra_edge)
        rows = fnptr_resolve.resolve_function_pointers(conn, fw, img, FB)
        tag = "block-start edge" if ghidra_edge else "instruction edge"
        check(f"[{tag}] one resolved record", len(rows) == 1, rows)
        if rows:
            r = rows[0]
            check(f"[{tag}] slot recovered from the consumer's load", r["slot_addr"] == SLOT, r)
            check(f"[{tag}] derivation is callsite-argument via r0 at the bl",
                  (r["derivation"], r["arg_reg"], r["callsite_addr"]) == ("callsite-argument", "r0", call_at), r)
            check(f"[{tag}] raw Thumb value preserved", r["raw_value"] == STUB | 1, r)
            check(f"[{tag}] canonical target has bit 0 cleared and is a separate field",
                  r["canonical_target"] == STUB and r["canonical_target"] != r["raw_value"] and r["thumb_bit"] == 1, r)
            prov = json.loads(r["provenance_json"])
            check(f"[{tag}] canonicalization recorded explicitly",
                  prov["pointer"]["canonicalization"] == "thumb-bit-cleared", prov["pointer"])
            check(f"[{tag}] sole agreeing constant writer -> STRONG", r["confidence"] == "STRONG", r)
        d.cleanup()


def test_intraprocedural_constant_pointer():
    print("test_intraprocedural_constant_pointer")
    d, conn, fw, img, _ = _scenario("intraprocedural")
    rows = fnptr_resolve.resolve_function_pointers(conn, fw, img, FB)
    check("one record, derived inside the writer",
          len(rows) == 1 and rows[0]["derivation"] == "intraprocedural-constant" and rows[0]["callsite_addr"] is None, rows)
    check("canonical target resolved", rows and rows[0]["canonical_target"] == STUB, rows)
    d.cleanup()


# --- 3, 4. only mechanically constant values are resolved ---------------------

def test_non_constant_values_stay_unresolved():
    print("test_non_constant_values_stay_unresolved")
    for variant, why, reason in (("callsite-ldrb", "memory-loaded argument", "unrecognized def (ldrb r0, [r4])"),
                                 ("callsite-clobbered", "argument clobbered by an intervening call",
                                  f"clobbered by call at 0x{INIT + 2:x}")):
        d, conn, fw, img, _ = _scenario(variant)
        rows = fnptr_resolve.resolve_function_pointers(conn, fw, img, FB)
        check(f"{why}: store recorded but unresolved",
              len(rows) == 1 and rows[0]["value_kind"] == "unresolved", rows)
        check(f"{why}: reason disclosed",
              rows and reason in json.loads(rows[0]["provenance_json"])["writer"]["reason"], rows)
        check(f"{why}: no raw value, target or confidence invented",
              rows and rows[0]["raw_value"] is None and rows[0]["canonical_target"] is None
              and rows[0]["confidence"] is None, rows)
        check(f"{why}: nothing to seed", fnptr_resolve.seed_targets(rows) == [])
        d.cleanup()


def test_constant_that_is_not_a_code_pointer():
    print("test_constant_that_is_not_a_code_pointer")
    d, conn, fw, img, _ = _scenario("callsite-literal", stored=STUB)  # even: data, not a Thumb code pointer
    rows = fnptr_resolve.resolve_function_pointers(conn, fw, img, FB)
    check("constant kept as constant", rows and rows[0]["value_kind"] == "constant" and rows[0]["raw_value"] == STUB, rows)
    check("but no code target or seed", rows and rows[0]["canonical_target"] is None
          and fnptr_resolve.seed_targets(rows) == [], rows)
    d.cleanup()


# --- 5, 6. bounded forwarding -------------------------------------------------

def test_forwarding_records_hop_and_constant_args():
    print("test_forwarding_records_hop_and_constant_args")
    d, conn, fw, img, _ = _scenario("callsite-literal")
    rows = fnptr_resolve.resolve_function_pointers(conn, fw, img, FB)
    r = rows[0]
    fwd = json.loads(r["forwarding_json"])
    check("terminal target follows the stub's unconditional branch", r["terminal_target"] == BODY, r)
    check("original target kept alongside the terminal", r["canonical_target"] == STUB, r)
    hop = fwd["hops"][0] if fwd["hops"] else {}
    check("one hop with provenance", len(fwd["hops"]) == 1 and hop["from"] == STUB and hop["to"] == BODY, fwd)
    check("constant argument setup recorded", hop.get("constant_args") == [
        {"addr": STUB, "instruction": "movs r0, #5", "reg": "r0", "value": 5, "literal_addr": None}], hop)
    check("seeds are the pointer target and the terminal",
          [s["addr"] for s in fnptr_resolve.seed_targets(rows)] == [STUB, BODY])
    check("a non-branch target is not forwarded",
          fnptr_resolve.follow_forwarding(img, FB, BODY) == {"terminal_target": BODY, "hops": [],
                                                              "stopped": "not a forwarding stub"})
    d.cleanup()


def test_forwarding_hop_limit():
    print("test_forwarding_hop_limit")
    chain = [FB + 0x10 * i for i in range(6)]
    img = TIW._image(FB, 0x100, [(a, b(a, nxt)) for a, nxt in zip(chain, chain[1:])] + [(chain[-1], bx(chain[-1], 14))])
    out = fnptr_resolve.follow_forwarding(img, FB, chain[0])
    check("stops at MAX_FORWARD_HOPS", len(out["hops"]) == fnptr_resolve.MAX_FORWARD_HOPS and out["stopped"] == "hop limit", out)
    check("terminal is the last hop reached, not the chain end",
          out["terminal_target"] == chain[fnptr_resolve.MAX_FORWARD_HOPS], out)


# --- 8, 9. real AutoPilot868 census ------------------------------------------

def test_real_usb_callback_slot():
    print("test_real_usb_callback_slot")
    db = REPO_ROOT / "cases" / "performing-rigs" / "research" / "runs" / "census" / "census.sqlite3"
    fw_path = REPO_ROOT / "cases" / "performing-rigs" / "research" / "firmware" / "originals" / "firmware_autopilot868.bin"
    if not db.is_file() or not fw_path.is_file():
        print("  [skip] case census or firmware image not present")
        return
    conn = sqlite3.connect(f"{db.resolve().as_uri()}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    fw = conn.execute("SELECT id, flash_base FROM firmware WHERE key='autopilot868'").fetchone()
    if fw is None:
        print("  [skip] autopilot868 not in census")
        return
    rows = fnptr_resolve.resolve_function_pointers(conn, fw["id"], fw_path.read_bytes(), fw["flash_base"])
    usb = [r for r in rows if r["slot_addr"] == 0x200052e8]
    check("USB IRQ dispatch slot 0x200052e8 resolves from its bx site",
          len(usb) == 1 and usb[0]["consumer_site"] == 0xcc1a, usb)
    if usb:
        r = usb[0]
        check("derived from r0 at the bl in USB init",
              (r["store_addr"], r["derivation"], r["arg_reg"], r["callsite_addr"]) ==
              (0xccc6, "callsite-argument", "r0", 0xbcda), r)
        check("raw 0xc725, canonical 0xc724, STRONG",
              (r["raw_value"], r["canonical_target"], r["confidence"]) == (0xc725, 0xc724, "STRONG"), r)
        check("0xc724 forwards (with a constant r0) to 0xc5cc", r["terminal_target"] == 0xc5cc, r)

    entries = {row["entry"]: row["id"] for row in conn.execute(
        "SELECT id, entry FROM functions WHERE firmware_id=? AND entry IN (0xc724, 0xc5cc)", (fw["id"],))}
    if len(entries) < 2:
        print("  [skip] census predates fnptr-seeded Ghidra build (run fnptr-seeds, then build + reduce)")
        return
    body = conn.execute("SELECT size FROM functions WHERE id=?", (entries[0xc5cc],)).fetchone()["size"]
    check("seeded discovery recovers the orphan body 0xc5cc..0xc705", body == 0x13a, body)
    cand = conn.execute(
        "SELECT candidate_function_id, confidence, source FROM indirect_edge_candidates WHERE firmware_id=? "
        "AND from_addr=0xcc1a", (fw["id"],)).fetchall()
    check("pointer edge is an indirect candidate, not a direct edge",
          [tuple(c) for c in cand] == [(entries[0xc724], "STRONG", fnptr_resolve.SOURCE)], [tuple(c) for c in cand])
    direct = conn.execute("SELECT COUNT(*) FROM edges WHERE firmware_id=? AND from_addr=0xcc1a AND resolved=1",
                          (fw["id"],)).fetchone()[0]
    check("no direct edge invented at the dispatch site", direct == 0, direct)
    still = conn.execute("SELECT classification FROM indirect_edge_resolutions WHERE firmware_id=? AND from_addr=0xc6d8",
                         (fw["id"],)).fetchone()
    check("the body's own computed call 0xc6d8 stays UNRESOLVED", still and still[0] == "UNRESOLVED", still)


if __name__ == "__main__":
    test_callsite_argument_constant_pointer()
    test_intraprocedural_constant_pointer()
    test_non_constant_values_stay_unresolved()
    test_constant_that_is_not_a_code_pointer()
    test_forwarding_records_hop_and_constant_args()
    test_forwarding_hop_limit()
    test_real_usb_callback_slot()

    print()
    if FAILURES:
        print(f"{len(FAILURES)} check(s) FAILED: {FAILURES}")
        sys.exit(1)
    print("All checks passed.")
    sys.exit(0)
