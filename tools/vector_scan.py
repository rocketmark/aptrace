#!/usr/bin/env python3
"""aptrace vectors -- scan a raw Cortex-M firmware image for plausible vector tables.

Standalone Python prototype (Step 4 of the APTrace spike). Not the final Haskell
CLI -- this exists to establish ground truth about the firmware layout before any
Macaw code is written.

Usage:
    vector_scan.py FIRMWARE.bin [--flash-base 0x4000] [--ram-base 0x20000000] \
                    [--ram-size 0x30000] [--num-irq 32] [--scan]

Without --scan, only offset 0 is checked (the common case for an application
image with no separate bootloader/header). With --scan, every 4-byte-aligned
offset in the file is scored and candidates above a threshold are printed.
"""
import argparse
import struct
import sys

SYSTEM_HANDLER_NAMES = [
    "Initial_SP",       # 0
    "Reset_Handler",    # 1
    "NMI_Handler",       # 2
    "HardFault_Handler", # 3
    "MemManage_Handler", # 4
    "BusFault_Handler",  # 5
    "UsageFault_Handler",# 6
    "Reserved_7",
    "Reserved_8",
    "Reserved_9",
    "Reserved_10",
    "SVC_Handler",       # 11
    "DebugMon_Handler",  # 12
    "Reserved_13",
    "PendSV_Handler",    # 14
    "SysTick_Handler",   # 15
]
RESERVED_INDICES = {7, 8, 9, 10, 13}


def read_words(data, offset, count):
    words = []
    for i in range(count):
        o = offset + 4 * i
        if o + 4 > len(data):
            words.append(None)
        else:
            words.append(struct.unpack_from("<I", data, o)[0])
    return words


def score_candidate(words, ram_base, ram_size, flash_base, flash_size):
    """Return (score, reasons) for a candidate vector table starting at `words[0]`."""
    reasons = []
    score = 0

    sp = words[0]
    if sp is None:
        return -1, ["truncated"]

    ram_lo, ram_hi = ram_base, ram_base + ram_size
    if ram_lo <= sp <= ram_hi and sp % 4 == 0:
        score += 3
        reasons.append(f"SP=0x{sp:08x} within RAM [0x{ram_lo:08x},0x{ram_hi:08x}]")
    else:
        reasons.append(f"SP=0x{sp:08x} NOT plausible RAM top")
        score -= 3

    reset = words[1]
    if reset is None:
        return score, reasons
    if reset & 1 == 0:
        reasons.append(f"Reset=0x{reset:08x} missing Thumb bit")
        score -= 3
    else:
        target = reset & ~1
        flash_lo, flash_hi = flash_base, flash_base + flash_size
        if flash_lo <= target <= flash_hi:
            score += 3
            reasons.append(f"Reset=0x{reset:08x} -> 0x{target:08x} within flash range")
        else:
            reasons.append(f"Reset=0x{reset:08x} -> 0x{target:08x} outside assumed flash range")
            score -= 2

    plausible_handlers = 0
    for i in range(2, len(words)):
        w = words[i]
        if w is None:
            continue
        if i in RESERVED_INDICES:
            if w == 0:
                score += 1
            else:
                score -= 1
            continue
        if w == 0:
            continue  # unpopulated IRQ, neutral
        if w & 1 == 1:
            plausible_handlers += 1
            score += 1
        else:
            score -= 1
            reasons.append(f"word[{i}]=0x{w:08x} odd handler missing Thumb bit")

    reasons.append(f"{plausible_handlers} plausible (Thumb-tagged) handler pointers")
    return score, reasons


def dump_table(data, offset, flash_base, num_irq):
    n = 16 + num_irq
    words = read_words(data, offset, n)
    print(f"\nVector table at file offset 0x{offset:x} "
          f"(assumed load address 0x{flash_base + offset:08x}):")
    for i, w in enumerate(words):
        if w is None:
            break
        name = SYSTEM_HANDLER_NAMES[i] if i < 16 else f"IRQ{i - 16}_Handler"
        note = ""
        if i == 0:
            note = "(initial MSP)"
        elif w != 0:
            target = w & ~1
            tag = "thumb" if w & 1 else "ARM(!)"
            note = f"-> 0x{target:08x} [{tag}]"
        print(f"  [{i:3d}] {name:22s} = 0x{w:08x} {note}")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("firmware")
    ap.add_argument("--flash-base", type=lambda x: int(x, 0), default=0x0000,
                     help="Flash address corresponding to file offset 0 (default 0x0)")
    ap.add_argument("--flash-size", type=lambda x: int(x, 0), default=0x100000,
                     help="Assumed flash size in bytes for plausibility checks (default 1MB)")
    ap.add_argument("--ram-base", type=lambda x: int(x, 0), default=0x20000000)
    ap.add_argument("--ram-size", type=lambda x: int(x, 0), default=0x30000,
                     help="Assumed SRAM size in bytes (default 0x30000 = 192KB, ATSAMD51x20/x19)")
    ap.add_argument("--num-irq", type=int, default=32,
                     help="Number of external IRQ vectors to dump after the 16 system handlers")
    ap.add_argument("--scan", action="store_true",
                     help="Scan every 4-byte offset in the file for candidate tables, not just offset 0")
    ap.add_argument("--scan-limit", type=lambda x: int(x, 0), default=0x1000,
                     help="When --scan is set, only scan file offsets below this limit")
    args = ap.parse_args()

    with open(args.firmware, "rb") as f:
        data = f.read()

    print(f"{args.firmware}: {len(data)} bytes")

    candidates = []
    offsets = [0] if not args.scan else range(0, min(len(data), args.scan_limit), 4)
    for off in offsets:
        words = read_words(data, off, 16)
        if any(w is None for w in words):
            continue
        score, reasons = score_candidate(words, args.ram_base, args.ram_size,
                                          args.flash_base, args.flash_size)
        if score >= 4:
            candidates.append((off, score, reasons))

    if not candidates:
        print("No plausible vector table found with current assumptions.")
        sys.exit(1)

    candidates.sort(key=lambda c: -c[1])
    print(f"\n{len(candidates)} candidate offset(s) found (score >= 4):")
    for off, score, reasons in candidates[:10]:
        print(f"\n  offset=0x{off:x} score={score}")
        for r in reasons:
            print(f"    - {r}")

    best_off = candidates[0][0]
    dump_table(data, best_off, args.flash_base, args.num_irq)


if __name__ == "__main__":
    main()
