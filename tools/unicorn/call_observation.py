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

Watched fields (`summarize_watched_writes`) are small, explicitly named
memory ranges whose CPU stores the run recorded (`watch_mem_write`, with the
bytes each store overwrote). Every store is reported in run order with its
width, previous and new bytes, and the addressing form of the store
instruction. On Thumb every store address is register-computed; the form
says whether it was a base register plus an immediate (and, when the field
declares its object base, whether that base was the object pointer) or an
indexed/multiple store. A field with no observed store was not written in
that run; that is not evidence it cannot change.

`correlate_calls_with_fields` joins entry observations to those fields: for
each call it names the watched field the argument points into and whether a
value-changing store to that field happened between its first value-changing
store (its initialization in this run) and the call.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence

ANALYSIS_VERSION = 2

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


# -- watched fields --------------------------------------------------------

Field = dict  # {"name": str, "address": int, "size": int, "object_base": int | None}


def _le(hex_bytes: str | None) -> int | None:
    return int.from_bytes(bytes.fromhex(hex_bytes), "little") if hex_bytes is not None else None


def store_addressing(code: bytes, pc: int, address: int) -> dict:
    """Addressing form of the Thumb store at `pc` that wrote `address`.

    `code` holds the instruction bytes at `pc` (4 suffice). Uses Capstone
    when it is installed; otherwise the form is ``undecoded``.
    """

    try:
        import capstone
        from capstone import arm as arm_const
    except ImportError:
        return {"form": "undecoded"}

    md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB | capstone.CS_MODE_MCLASS)
    md.detail = True
    insn = next(md.disasm(code, pc, count=1), None)

    if insn is None:
        return {"form": "undecoded"}

    text = f"{insn.mnemonic} {insn.op_str}".strip()
    mnemonic = insn.mnemonic.split(".")[0]

    if mnemonic.startswith(("stm", "push")) or mnemonic in ("strd", "strexd"):
        return {"form": "multiple", "instruction": text}

    mems = [op for op in insn.operands if op.type == arm_const.ARM_OP_MEM]

    if not mnemonic.startswith("str") or len(mems) != 1:
        return {"form": "other", "instruction": text}

    mem = mems[0].mem
    base = insn.reg_name(mem.base) if mem.base else None

    if mem.index:
        return {"form": "base+reg", "instruction": text, "base_register": base,
                "index_register": insn.reg_name(mem.index)}

    # Post-indexed stores write at the base itself; capstone reports disp 0.
    return {"form": "base+imm", "instruction": text, "base_register": base, "offset": mem.disp,
            "base_value": _hex((address - mem.disp) & 0xFFFFFFFF)}


def _field_of(fields: Sequence[Field], address: int, size: int) -> Field | None:
    for field in fields:
        if address < field["address"] + field["size"] and field["address"] < address + size:
            return field
    return None


def summarize_watched_writes(
    writes: Iterable[dict],
    *,
    fields: Sequence[Field],
    read_code: Callable[[int], bytes | None],
    function_of: Callable[[int], str | None] = lambda pc: None,
    final_bytes: dict[str, str | None] | None = None,
    dropped: int = 0,
) -> dict:
    """Per-field store events, in run order, for the declared watched fields.

    `writes` are ConcreteMachine `mem_write_hits` (any range), each carrying
    an added ``leg`` (0 for a single run). Stores overlapping no declared
    field are ignored. `final_bytes` maps a field name to its bytes at the
    end of the run. `dropped` is the number of stores the run's write log
    could not hold; when non-zero the event list is incomplete.
    """

    ordered = sorted(writes, key=lambda w: (w.get("leg", 0), w["instruction"], int(w["address"], 16)))
    out: dict[str, dict] = {
        f["name"]: {
            "name": f["name"], "address": _hex(f["address"]), "size": f["size"],
            **({"object_base": _hex(f["object_base"])} if f.get("object_base") is not None else {}),
            "events": [],
        }
        for f in fields
    }
    addressing_cache: dict[tuple[int, int], dict] = {}

    for w in ordered:
        address, size = int(w["address"], 16), int(w["size"])
        field = _field_of(fields, address, size)

        if field is None:
            continue

        pc = int(w["pc"], 16)
        key = (pc, address)

        if key not in addressing_cache:
            code = read_code(pc)
            addressing_cache[key] = store_addressing(code, pc, address) if code else {"form": "undecoded"}

        addressing = dict(addressing_cache[key])

        # At offset 0 every pointer to the field equals the object base, so
        # the comparison would say nothing; it is reported only otherwise.
        if (field.get("object_base") not in (None, field["address"])
                and addressing.get("base_value") is not None):
            addressing["object_relative"] = int(addressing["base_value"], 16) == field["object_base"]

        new = int(w["value"], 16) & ((1 << (8 * size)) - 1)
        previous = _le(w.get("previous"))
        events = out[field["name"]]["events"]
        events.append({
            "leg": w.get("leg", 0),
            "instruction": w["instruction"],
            "pc": _hex(pc),
            "function": function_of(pc),
            "address": _hex(address),
            "width": size,
            "previous": None if previous is None else f"0x{previous:0{2 * size}x}",
            "new": f"0x{new:0{2 * size}x}",
            "changed": None if previous is None else previous != new,
            "first_write": not events,
            "addressing": addressing,
        })

    for name, summary in out.items():
        events = summary["events"]
        changing = [e for e in events if e["changed"]]
        summary["writes"] = len(events)
        summary["value_changing_writes"] = len(changing)
        summary["initialization"] = (
            {k: changing[0][k] for k in ("leg", "instruction", "pc", "function", "new")} if changing else None)
        summary["changed_after_initialization"] = len(changing) > 1
        summary["final_bytes"] = (final_bytes or {}).get(name)

    return {
        "analysis": "watched_writes",
        "analysis_version": ANALYSIS_VERSION,
        "fields": [out[f["name"]] for f in fields],
        "dropped_writes": dropped,
        "complete": dropped == 0,
    }


def correlate_calls_with_fields(
    hits: Iterable[dict],
    *,
    entry: int,
    register: str,
    watched: dict,
    regions: Sequence[Region],
    read_halfword: Callable[[int], int | None],
    width: int = 4,
) -> list[dict]:
    """For each (call site, argument value), the watched field it points into.

    `watched` is a `summarize_watched_writes` result from the same run; hits
    carry the same ``leg`` numbering. Reports where the argument value lies
    (`value_region`), where the word stored there points (`pointee_word_region`,
    content only: a stored address is not an access to it), the field, and
    whether the field held its initialized value at every such call.
    """

    entry &= ~1
    fields = [
        {"name": f["name"], "address": int(f["address"], 16), "size": f["size"],
         "changes": [(e["leg"], e["instruction"]) for e in f["events"] if e["changed"]]}
        for f in watched["fields"]
    ]
    groups: dict[tuple, dict] = {}

    for hit in sorted(hits, key=lambda h: (h.get("leg", 0), h["instruction"])):
        if int(hit["address"], 16) & ~1 != entry:
            continue

        value = int(hit["registers"][register], 16)
        attribution = classify_return_address(read_halfword, int(hit["registers"]["lr"], 16), entry)
        pointee = (hit.get("reg_pointee") or {}).get(register)
        word = _pointee_word(pointee)
        field = _field_of(fields, value, width)
        at = (hit.get("leg", 0), hit["instruction"])
        key = (attribution["call_site"], value)
        group = groups.setdefault(key, {
            "call_site": attribution["call_site"],
            "call_kind": attribution["call_kind"],
            "register": register,
            "value": _hex(value),
            "value_region": region_of(value, regions),
            "pointee_words": set(),
            "field": None if field is None else field["name"],
            "calls": 0,
            "first_call": {"leg": at[0], "instruction": at[1]},
            "calls_before_initialization": 0,
            "calls_after_a_later_change": 0,
        })
        group["calls"] += 1
        group["last_call"] = {"leg": at[0], "instruction": at[1]}

        if word is not None:
            group["pointee_words"].add(word)

        if field is not None:
            before = [c for c in field["changes"] if c < at]
            if not before:
                group["calls_before_initialization"] += 1
            elif len(before) > 1:
                group["calls_after_a_later_change"] += 1

    out = []
    for key in sorted(groups, key=lambda k: (k[0] is None, k[0] or "", k[1])):
        group = groups[key]
        words = sorted(group.pop("pointee_words"))
        group["pointee_words"] = [{"word": _hex(w), "region": region_of(w, regions)} for w in words]
        if group["field"] is None:
            group["field_state"] = "argument does not point into a watched field"
        elif group["calls_before_initialization"] == group["calls"]:
            group["field_state"] = "not initialized by an observed store before any call"
        elif group["calls_after_a_later_change"]:
            group["field_state"] = "changed after initialization before some calls"
        elif group["calls_before_initialization"]:
            group["field_state"] = "some calls preceded its initialization"
        else:
            group["field_state"] = "initialized value unchanged at every call"
        out.append(group)

    return out
