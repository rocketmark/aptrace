"""APTrace census: raw-firmware-bytes scans that don't need Ghidra at
all -- the vector table and a mechanical function-pointer-candidate scan.

Deliberately independent of Ghidra (reads the .bin file directly, the
same way tools/ghidra/aptrace_ghidra.py's own `literal`/`dump` commands
and tools/ghidra/scripts/APTraceSeedVectorTable.java's own vector-table
parsing do) -- this is the raw-instruction/raw-data-scan leg of the
census's evidence model, kept separate from (and cross-checked against,
not assumed subordinate to) Ghidra's own function discovery.
"""
import struct

# Standard ARMv7-M system exception vector names, indices 1-15 (index 0
# is the initial stack pointer, not a handler). This is fixed ARM
# architecture layout, not a firmware-specific interpretation -- see the
# ARMv7-M Architecture Reference Manual, table B1-1. Reserved slots are
# named as such; a firmware may still populate them with a real handler
# address (harmless on real silicon, just never taken), which this
# module records like any other vector regardless of the slot's name.
SYSTEM_VECTOR_NAMES = {
    1: "Reset", 2: "NMI", 3: "HardFault", 4: "MemManage", 5: "BusFault",
    6: "UsageFault", 7: "Reserved7", 8: "Reserved8", 9: "Reserved9",
    10: "Reserved10", 11: "SVCall", 12: "DebugMonitor", 13: "Reserved13",
    14: "PendSV", 15: "SysTick",
}


def read_vectors(firmware_path, flash_base, num_vectors=56, known_function_entries=()):
    """Read the ARMv7-M vector table directly from flash: vector 0 is the
    initial SP (not code), vectors 1..num_vectors are Thumb handler
    pointers (low bit conventionally set). Mirrors
    APTraceSeedVectorTable.java's own parsing (same num_vectors default,
    56 = 16 system + 40 IRQ, per docs/firmware/firmware-layout.md) --
    independent of it, since that script only ever *seeds* Ghidra and
    keeps no queryable record of its own.

    Returns a list of dicts, one per vector (0..num_vectors inclusive).
    `landed_in_known_function` is None for vector 0 or an empty
    (0x00000000 / 0xFFFFFFFF) slot, else 0/1 depending on whether
    target_addr is in `known_function_entries`."""
    known = set(known_function_entries)
    data = firmware_path.read_bytes()
    out = []
    for i in range(0, num_vectors + 1):
        off = i * 4
        if off + 4 > len(data):
            break
        (raw,) = struct.unpack_from("<I", data, off)
        if i == 0:
            out.append({
                "vector_index": 0, "raw_value": raw, "target_addr": None,
                "name": "InitialSP", "is_irq": 0, "landed_in_known_function": None,
            })
            continue
        empty = raw in (0, 0xFFFFFFFF)
        target = None if empty else (raw & ~1)
        is_irq = 1 if i > 15 else 0
        name = None if is_irq else SYSTEM_VECTOR_NAMES.get(i)
        landed = None if empty else (1 if target in known else 0)
        out.append({
            "vector_index": i, "raw_value": raw, "target_addr": target,
            "name": name, "is_irq": is_irq, "landed_in_known_function": landed,
        })
    return out


def scan_function_pointer_candidates(firmware_path, flash_base, function_ranges,
                                      known_function_entries):
    """Scan every 4-byte-aligned flash word OUTSIDE any known function's
    own body for a mechanical function-pointer signature: Thumb bit set
    (odd value) AND (value - 1) equal to a known function's entry point.

    This is a *candidate* list, not an assertion -- a coincidental match
    is possible (any odd word equal to a real function entry plus one),
    which is exactly why `matches_known_function` is stored as an
    explicit column rather than this function silently filtering to only
    "confirmed" pointers. Restricting to addresses outside function
    bodies avoids the much larger false-positive rate a whole-image scan
    would have (Thumb instruction encodings routinely produce odd
    16/32-bit values that are not pointers at all).

    `function_ranges`: iterable of (entry, size) tuples.
    `known_function_entries`: set of entry addresses (ints).
    """
    known = set(known_function_entries)
    ranges = sorted(function_ranges)
    data = firmware_path.read_bytes()
    size = len(data)

    def in_any_function(addr):
        # Linear scan is fine here (a few hundred functions, a few
        # thousand candidate words) -- not a hot loop worth a bisect.
        for entry, fsize in ranges:
            if entry <= addr < entry + max(fsize, 1):
                return True
            if entry > addr:
                break
        return False

    out = []
    aligned_start = flash_base if flash_base % 4 == 0 else flash_base + (4 - flash_base % 4)
    off = aligned_start - flash_base
    while off + 4 <= size:
        addr = flash_base + off
        (raw,) = struct.unpack_from("<I", data, off)
        off += 4
        if raw & 1 == 0:
            continue  # no Thumb bit -- not a plausible code pointer
        if in_any_function(addr):
            continue  # inside a known function's own body -- this is an instruction word, not a data slot
        target = raw & ~1
        if target in known:
            out.append({
                "location_addr": addr, "raw_value": raw, "target_addr": target,
                "matches_known_function": 1,
            })
    return out
