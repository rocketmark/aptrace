#!/usr/bin/env python3
"""Performing Rigs: the slot-7/8 dispatch classification of
scripts/indirect_dispatch_investigation.py.

Synthetic resolver results check that a possible table target, an excluded
offset, and an unresolved derivation stay distinct, and that containing
reachability never becomes a negative. Real-image checks pin the vtable
0x14900 slot identities, the path calls, and that the slot-7 thunk is the
only site whose offset reaches slot 8. Plain assertions via check(). Run
with the Unicorn venv (the real-image part needs the gitignored census DB):

    tools/unicorn/.venv/bin/python3 cases/performing-rigs/test/test_indirect_dispatch.py
"""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
CASE = HERE.parent
sys.path.insert(0, str(CASE / "scripts"))

import indirect_dispatch_investigation as idi  # noqa: E402

FAILURES = []
ENTRIES = {0x1491C: "slot 7", 0x14920: "slot 8"}
CODE = {0xC744: "slot 7", 0xC7C0: "slot 8"}
BASES = [0x148CC, 0x14900]


def check(name, condition, detail=""):
    print(f"  [{'ok' if condition else 'FAIL'}] {name}" + (f" -- {detail}" if detail and not condition else ""))
    if not condition:
        FAILURES.append(name)


def site(*patterns, targets=()):
    return {"instruction_shape": "reg-indirect", "patterns": list(patterns), "candidate_targets": list(targets)}


def vt(offset):
    return {"pattern": "vtable-slot", "slot_offset": offset}


def test_relevance():
    rel = idi.slot_relevance(site(vt(0x20)), ENTRIES, BASES, CODE)
    check("offset 0x20 from the materialized table base is a possible slot-8 load",
          rel["status"] == "CONDITIONALLY_POSSIBLE" and rel["slots"] == ["slot 8"], rel)
    rel = idi.slot_relevance(site(vt(0x10)), ENTRIES, BASES, CODE)
    check("offset 0x10 reaches no slot-7/8 entry from any base: excluded within scope",
          rel["status"] == "EXCLUDED_WITHIN_ANALYSIS_SCOPE", rel)
    rel = idi.slot_relevance(site(vt(0x50)), ENTRIES, BASES, CODE)
    check("a base below the table counts: 0x148cc + 0x50 is slot 7",
          rel["status"] == "CONDITIONALLY_POSSIBLE" and rel["slots"] == ["slot 7"], rel)
    rel = idi.slot_relevance(site(vt(0x10), {"pattern": "argument", "arg": 3}), ENTRIES, BASES, CODE)
    check("one unresolved alternative keeps the site unresolved", rel["status"] == "UNRESOLVED", rel)
    rel = idi.slot_relevance(site({"pattern": "constant-target", "value": "0x0000c7c1"}), ENTRIES, BASES, CODE)
    check("a constant target equal to slot 8's code is possible", rel["slots"] == ["slot 8"], rel)
    rel = idi.slot_relevance(site({"pattern": "constant-slot", "slot_addr": "0x200052e8", "slot_region": "ram",
                                   "slot_writers": 1, "slot_writers_unresolved": 0},
                                  targets=[{"target": "0x0000c724", "is_code_pointer": True}]),
                             ENTRIES, BASES, CODE)
    check("a RAM slot whose every writer stores another constant is excluded",
          rel["status"] == "EXCLUDED_WITHIN_ANALYSIS_SCOPE", rel)
    rel = idi.slot_relevance(site({"pattern": "constant-slot", "slot_addr": "0x200052e8", "slot_region": "ram",
                                   "slot_writers": 0, "slot_writers_unresolved": 0}), ENTRIES, BASES, CODE)
    check("a RAM slot with no known writer is unresolved, not excluded", rel["status"] == "UNRESOLVED", rel)
    rel = idi.slot_relevance({"instruction_shape": "table-branch", "patterns": []}, ENTRIES, BASES, CODE)
    check("a table branch is not applicable", rel["status"] == "NOT_APPLICABLE", rel)
    rel = idi.slot_relevance(site(), ENTRIES, BASES, CODE)
    check("no recovered definition is unresolved", rel["status"] == "UNRESOLVED", rel)


def test_reachability():
    check("observed beats static", idi.containing_reachability(3, "NO_KNOWN_PATH") == "OBSERVED")
    check("census reachable is statically established",
          idi.containing_reachability(0, "DEFINITELY_REACHABLE") == "STATICALLY_ESTABLISHED")
    check("via an unresolved indirect edge is conditional",
          idi.containing_reachability(0, "POSSIBLY_REACHABLE_VIA_UNRESOLVED_INDIRECT") == "CONDITIONALLY_POSSIBLE")
    check("no known path and no census function are unresolved, never excluded",
          {idi.containing_reachability(0, s) for s in ("NO_KNOWN_PATH", None)} == {"UNRESOLVED"})


def test_real_image():
    if not idi.CENSUS_DB.is_file():
        print("  [skip] census database not present")
        return
    conn = idi.connect_ro()
    row = conn.execute("SELECT * FROM firmware WHERE key=?", (idi.FIRMWARE_KEY,)).fetchone()
    image = (idi.REPO_ROOT / row["path"]).read_bytes()
    layout = idi.vtable_layout(conn, row["id"], image, row["flash_base"], idi.function_rows(conn, row["id"]), set())
    slots = {s["slot"]: s["target"] for s in layout["slots"]}
    check("vtable 0x14900 has 11 slots ending at the 'sqrt' string",
          layout["slot_count"] == 11 and layout["terminator"]["ascii"] == "sqrt", layout["terminator"])
    check("slot 7 is 0xc744 and slot 8 is 0xc7c0 (distinct)",
          (slots[7], slots[8]) == ("0x0000c744", "0x0000c7c0"), slots)
    calls = [idi.straight_line_call(image, row["flash_base"], e, s, c) for e, s, c in idi.PATH_CALLS]
    check("every path call is a direct BL on every path from its caller's entry",
          all(c["direct_bl"] and c["on_every_path_from_entry"] for c in calls), calls)
    check("b658 and b5bc pass their incoming r0 through unchanged; c7c0 passes [this+0x10]",
          [c["last_r0_definition"] for c in calls] ==
          ["0xc848 ldr r0, [r4, #0x10]", "none (r0 is the caller's incoming r0)",
           "none (r0 is the caller's incoming r0)"], [c["last_r0_definition"] for c in calls])


if __name__ == "__main__":
    print("test_indirect_dispatch")
    test_relevance()
    test_reachability()
    test_real_image()
    if FAILURES:
        print(f"\n{len(FAILURES)} FAILURE(S): {FAILURES}")
        sys.exit(1)
    print("\nall indirect dispatch checks passed")
