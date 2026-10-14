"""Caller-grounded argument observation from a concrete run.

Summarizes the `watch_hits` a ConcreteMachine run recorded at one function
entry into per-call-site argument observations: what values actually
reached the function, through which call instruction, and which mapped
region each value (and, optionally, the word it points at) lies in.

Everything here is a deterministic function of the run's recorded hits,
the caller-supplied target geometry and the firmware's own code bytes. It
knows nothing about any target function. What it reports is what was
observed in that run; a call site, value or region that was not observed
is not thereby unreachable or impossible.

Call-site attribution uses the link register at entry. LR is the return
address of the most recent BL/BLX, so the instruction ending there is
decoded from the image:

  * ``BL``       32-bit BL immediate whose decoded target is the entry
                 (a direct call to this function);
  * ``BLX_REG``  16-bit ``blx rm`` (an indirect call; its target register
                 held the entry, so the transfer was observed, not decoded);
  * ``OTHER``    anything else, including a BL to a different target: the
                 entry was reached by a tail branch or other transfer, so LR
                 identifies an earlier frame, not this call. No call site
                 is attributed.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence

ANALYSIS_VERSION = 1

ARGUMENT_REGISTERS = ("r0", "r1", "r2", "r3")

Region = tuple[str, int, int]  # (name, base, size)


def _hex(value: int) -> str:
    return f"0x{value:08x}"


def region_of(value: int, regions: Sequence[Region]) -> str | None:
    for name, base, size in regions:
        if base <= value < base + size:
            return name
    return None


def bl_target(hw1: int, hw2: int, address: int) -> int | None:
    """Target of a Thumb-2 BL (immediate, T1) at `address`, else None."""

    if (hw1 & 0xF800) != 0xF000 or (hw2 & 0xD000) != 0xD000:
        return None

    s = (hw1 >> 10) & 1
    i1 = 1 ^ (((hw2 >> 13) & 1) ^ s)
    i2 = 1 ^ (((hw2 >> 11) & 1) ^ s)
    imm = (s << 24) | (i1 << 23) | (i2 << 22) | ((hw1 & 0x3FF) << 12) | ((hw2 & 0x7FF) << 1)

    if s:
        imm -= 1 << 25

    return (address + 4 + imm) & 0xFFFFFFFF


def classify_return_address(read_halfword: Callable[[int], int | None], return_address: int, entry: int) -> dict:
    """Attribute an entry observation to the call instruction ending at LR."""

    ret = return_address & ~1

    hw1, hw2 = read_halfword(ret - 4), read_halfword(ret - 2)
    if hw1 is not None and hw2 is not None:
        target = bl_target(hw1, hw2, ret - 4)
        if target is not None:
            if (target & ~1) == (entry & ~1):
                return {"call_site": _hex(ret - 4), "call_kind": "BL", "decoded_target": _hex(target)}
            return {"call_site": None, "call_kind": "OTHER", "decoded_target": _hex(target),
                    "note": "LR follows a BL to a different target: entry reached by a tail branch or other transfer"}

    if hw2 is not None and (hw2 & 0xFF87) == 0x4780:
        return {"call_site": _hex(ret - 2), "call_kind": "BLX_REG", "decoded_target": None,
                "target_register": f"r{(hw2 >> 3) & 0xF}"}

    return {"call_site": None, "call_kind": "OTHER", "decoded_target": None,
            "note": "no BL/BLX ends at LR"}


def _pointee_word(entry: dict | None) -> int | None:
    if not entry or entry.get("bytes") is None:
        return None
    data = bytes.fromhex(entry["bytes"])
    if len(data) < 4:
        return None
    return int.from_bytes(data[:4], "little")


def summarize_entry_observations(
    hits: Iterable[dict],
    *,
    entry: int,
    regions: Sequence[Region],
    read_halfword: Callable[[int], int | None],
    registers: Sequence[str] = ARGUMENT_REGISTERS,
) -> dict:
    """Per-call-site argument observations for every hit at `entry`.

    `hits` are ConcreteMachine watch hits (any address; only `entry` is
    used). A hit's optional `reg_pointee` (from `watch_reg_pointee`) adds
    the observed bytes at each register value and the region of the
    little-endian word they hold.
    """

    entry &= ~1
    sites: dict[tuple, dict] = {}
    total = 0

    for hit in hits:
        if int(hit["address"], 16) & ~1 != entry:
            continue

        total += 1
        regs = hit["registers"]
        lr = int(regs["lr"], 16)
        attribution = classify_return_address(read_halfword, lr, entry)
        key = (attribution["call_site"], attribution["call_kind"], _hex(lr & ~1))
        site = sites.setdefault(key, {
            **attribution,
            "return_address": _hex(lr & ~1),
            "hits": 0,
            "first_instruction": hit.get("instruction"),
            "arguments": {reg: {} for reg in registers},
        })
        site["hits"] += 1

        pointees = hit.get("reg_pointee") or {}
        for reg in registers:
            value = int(regs[reg], 16)
            pointee = pointees.get(reg)
            word = _pointee_word(pointee)
            vkey = (value, pointee.get("bytes") if pointee else None)
            seen = site["arguments"][reg].setdefault(vkey, {
                "value": _hex(value),
                "region": region_of(value, regions),
                **({"pointee_bytes": pointee.get("bytes"),
                    "pointee_word": _hex(word) if word is not None else None,
                    "pointee_word_region": region_of(word, regions) if word is not None else None}
                   if pointee is not None else {}),
                "count": 0,
            })
            seen["count"] += 1

    call_sites = []
    for key in sorted(sites, key=lambda k: (k[0] is None, k[0] or "", k[2])):
        site = sites[key]
        site["arguments"] = {
            reg: [values[v] for v in sorted(values, key=lambda v: (v[0], v[1] or ""))]
            for reg, values in site["arguments"].items()
        }
        call_sites.append(site)

    return {
        "analysis": "call_observation",
        "analysis_version": ANALYSIS_VERSION,
        "entry": _hex(entry),
        "observed_entries": total,
        "call_sites": call_sites,
    }
