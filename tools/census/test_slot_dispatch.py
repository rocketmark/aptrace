#!/usr/bin/env python3
"""APTrace: regression coverage for tools/census/slot_dispatch.py on a
hand-assembled Thumb image (encodings checked against Capstone).

    python3 tools/census/test_slot_dispatch.py
"""
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import slot_dispatch  # noqa: E402

BASE = 0x4000
FAILURES = []


def check(name, condition, detail=""):
    print(f"  [{'ok' if condition else 'FAIL'}] {name}" + (f" -- {detail}" if detail and not condition else ""))
    if not condition:
        FAILURES.append(name)


def image():
    buf = bytearray(0x40)
    put = lambda off, hws: buf.__setitem__(slice(off, off + 2 * len(hws)), struct.pack(f"<{len(hws)}H", *hws))  # noqa: E731
    put(0x00, [0x6803, 0x6A1B, 0x4718])          # ldr r3,[r0]; ldr r3,[r3,#0x20]; bx r3   (slot 8 dispatch)
    put(0x06, [0x6803, 0x69DB, 0x2201, 0x4798])  # ldr r3,[r0]; ldr r3,[r3,#0x1c]; movs r2,#1; blx r3 (slot 7)
    put(0x0E, [0x6A1B, 0x681B, 0x4718])          # ldr r3,[r3,#0x20]; ldr r3,[r3]; bx r3   (redefined: not slot 8)
    put(0x14, [0xF000, 0xF804])                  # bl 0x4020
    put(0x18, [0xF000, 0xB802])                  # b.w 0x4020 (tail branch)
    put(0x1C, [0xF000, 0x8000])                  # beq.w 0x4020
    struct.pack_into("<I", buf, 0x30, 0x4021)    # Thumb pointer to 0x4020
    return bytes(buf)


def main():
    print("test_slot_dispatch")
    out = slot_dispatch.sweep(image(), BASE, [0x1C, 0x20], [0x4020])
    loads = {(d["load"], d["offset"], d["branch_text"]) for d in out["dispatch_sites"]}
    check("slot 8 tail dispatch found", ("0x00004002", 0x20, "bx r3") in loads, loads)
    check("slot 7 dispatch through an unrelated instruction found", ("0x00004008", 0x1C, "blx r3") in loads, loads)
    check("a load whose register is redefined before the branch is not a dispatch",
          not any(d["load"] == "0x0000400e" for d in out["dispatch_sites"]), out["dispatch_sites"])
    check("direct BL to a target found", out["direct_calls"] == [{"site": "0x00004014", "target": "0x00004020"}],
          out["direct_calls"])
    check("direct B.W and B<c>.W tail branches to a target found",
          out["direct_branches"] == [{"site": "0x00004018", "kind": "b.w", "target": "0x00004020"},
                                     {"site": "0x0000401c", "kind": "b<c>.w", "target": "0x00004020"}],
          out["direct_branches"])
    check("aligned Thumb pointer word found",
          out["thumb_pointer_words"] == [{"location": "0x00004030", "value": "0x00004021"}], out["thumb_pointer_words"])
    if FAILURES:
        print(f"\n{len(FAILURES)} FAILURE(S): {FAILURES}")
        sys.exit(1)
    print("\nall slot_dispatch checks passed")


if __name__ == "__main__":
    main()
