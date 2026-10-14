"""APTrace census: where can a function-pointer table slot be dispatched?

Given an image and a set of table slot offsets (e.g. the byte offsets of a
vtable's entries), a linear Thumb sweep reports every

    ldr  rX, [rY, #off]      (off in the requested offsets)
    ...                      (at most `window` instructions, rX not redefined)
    blx rX | bx rX

shape, plus every BL whose decoded target is in a requested target set and
every aligned Thumb pointer word equal to one of those targets. It is a
pattern scan over every halfword offset, independent of any function
boundary, so it also covers code a disassembler left unattributed.

What it establishes is static and pattern-matched: a site it reports is a
candidate dispatch, not an observed call; a slot it finds no site for is
not thereby unreachable (an offset computed in a register, a copied
pointer, or code that decodes only from another alignment would escape it).

    python3 tools/census/slot_dispatch.py IMAGE --base 0x4000 \\
        --offset 0x1c --offset 0x20 --target 0xc744 --target 0xc7c0
"""
import argparse
import json
import re
import sys

import capstone

_LOAD = re.compile(r"(r\d+|ip|lr), \[(r\d+|ip|lr), #(0x[0-9a-f]+|\d+)\]$")


def _md():
    return capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB | capstone.CS_MODE_MCLASS)


def _bl_target(hw1, hw2, address):
    if (hw1 & 0xF800) != 0xF000 or (hw2 & 0xD000) != 0xD000:
        return None
    s = (hw1 >> 10) & 1
    i1 = 1 ^ (((hw2 >> 13) & 1) ^ s)
    i2 = 1 ^ (((hw2 >> 11) & 1) ^ s)
    imm = (s << 24) | (i1 << 23) | (i2 << 22) | ((hw1 & 0x3FF) << 12) | ((hw2 & 0x7FF) << 1)
    if s:
        imm -= 1 << 25
    return (address + 4 + imm) & 0xFFFFFFFF


def sweep(image, base, offsets, targets, window=6):
    md = _md()
    offsets, targets = set(offsets), {t & ~1 for t in targets}
    dispatches, calls, pointers = [], [], []

    for off in range(0, len(image) - 4, 2):
        address = base + off
        hw1 = int.from_bytes(image[off:off + 2], "little")
        hw2 = int.from_bytes(image[off + 2:off + 4], "little")
        target = _bl_target(hw1, hw2, address)
        if target is not None and target & ~1 in targets:
            calls.append({"site": f"0x{address:08x}", "target": f"0x{target:08x}"})

        if off % 4 == 0:
            word = int.from_bytes(image[off:off + 4], "little")
            if word & 1 and word & ~1 in targets:
                pointers.append({"location": f"0x{address:08x}", "value": f"0x{word:08x}"})

        insns = list(md.disasm(image[off:off + 4 * (window + 1)], address, count=window + 1))
        if not insns:
            continue
        load = insns[0]
        m = _LOAD.match(load.op_str)
        if (not load.mnemonic.startswith("ldr") or load.mnemonic.startswith(("ldrb", "ldrh", "ldrs", "ldrd"))
                or m is None or int(m.group(3), 0) not in offsets):
            continue
        reg = m.group(1)
        for nxt in insns[1:]:
            if nxt.mnemonic in ("blx", "bx") and nxt.op_str == reg:
                dispatches.append({"load": f"0x{load.address:08x}", "load_text": f"{load.mnemonic} {load.op_str}",
                                   "offset": int(m.group(3), 0), "branch": f"0x{nxt.address:08x}",
                                   "branch_text": f"{nxt.mnemonic} {nxt.op_str}"})
                break
            if nxt.op_str.startswith(reg + ",") and not nxt.mnemonic.startswith(("str", "cmp", "tst")):
                break

    return {
        "analysis": "slot_dispatch_sweep",
        "analysis_version": 1,
        "basis": "static linear Thumb pattern sweep over every halfword offset (pattern-matched)",
        "offsets": sorted(f"0x{o:x}" for o in offsets),
        "targets": sorted(f"0x{t:08x}" for t in targets),
        "window": window,
        "dispatch_sites": dispatches,
        "direct_calls": calls,
        "thumb_pointer_words": pointers,
    }


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("image")
    p.add_argument("--base", type=lambda s: int(s, 0), required=True)
    p.add_argument("--offset", type=lambda s: int(s, 0), action="append", required=True)
    p.add_argument("--target", type=lambda s: int(s, 0), action="append", default=[])
    p.add_argument("--window", type=int, default=6)
    args = p.parse_args(argv)
    with open(args.image, "rb") as f:
        image = f.read()
    print(json.dumps(sweep(image, args.base, args.offset, args.target, args.window), indent=1, sort_keys=True))


if __name__ == "__main__":
    sys.exit(main())
