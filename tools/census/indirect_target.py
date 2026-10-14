"""APTrace census: how is ONE register-indirect transfer's target derived?

For a `bx rN` / `blx rN` site, this module recovers the set of definitions
of `rN` that reach the site inside its containing function, then names the
dataflow shape those definitions form. It answers a narrow question:

    which instructions define the branch register, from what memory or
    register, and what -- if anything -- does that make the target?

Reaching definitions are computed backward over the census's own basic
blocks and resolved intraprocedural edges (Ghidra's block model plus the
Capstone sweep). Unlike `fnptr_resolve.trace_reg`, a join is not a stopping
point: every predecessor is followed, and the result is the UNION of the
definitions reaching the site, so two paths that disagree stay visible as
two definitions. A conditional (IT-block) definition reaches together with
whatever reached before it. A `bl`/`blx` kills r0-r3/r12. Register moves
are followed. Everything is bounded (`max_blocks`, `max_depth`); a bound
that is hit is reported as an `incomplete` definition, never dropped.

Shapes (`pattern`), from the definitions alone:

  constant-target      every definition is a constant (literal/immediate)
  constant-slot        one plain word load from [constant + d]: a fixed
                       memory word. In immutable flash its content is the
                       target; in RAM, `fnptr_resolve.slot_writers` gives
                       the constant stores the census knows about
  vtable-slot          ldr rT,[rV,#d] with rV = ldr [rO,#0]: the word at
                       slot offset d of the table rO's first word points to
  object-table-slot    the same two-level shape with the table pointer at a
                       nonzero object offset
  object-field         one load [p + d] where p is neither constant nor a
                       table load (a function pointer kept in a structure)
  indexed-table        one load [b + i << s] (a function-pointer array)
  pointer-iteration    one post-indexed load (walking a pointer array)
  argument             the incoming AAPCS argument rK at function entry
  call-result          r0 as returned by a call
  multiple             several reaching definitions (each one classified)
  unresolved           no shape above (the reason is kept)

A vtable-slot site's candidate targets are computed only against vtables
the CALLER supplies (address points it established elsewhere -- e.g. with
`vptr_installations`). Each is a POTENTIAL target, conditional on the
receiver holding that vptr; this module never claims the site dispatches
there, or that the site is reachable.

Not a points-to analysis: no interprocedural propagation, no alias
reasoning, no pointer arithmetic beyond add/sub-immediate on constants, and
the predecessor set is only what the census edges record (a block entered
through an unresolved computed jump has predecessors this cannot see; that
limitation is reported per result).

No names, comments or behavior are consulted -- only operands, flash
bytes, and existing census rows.
"""
import hashlib
import json
import struct
import sys
from pathlib import Path

from capstone.arm_const import (ARM_CC_AL, ARM_CC_INVALID, ARM_INS_LDM, ARM_INS_LDMDB, ARM_INS_LDR, ARM_INS_LDRD, ARM_INS_MOV,
                                ARM_INS_POP, ARM_INS_STR, ARM_OP_IMM, ARM_OP_MEM, ARM_OP_REG, ARM_REG_PC)

import fnptr_resolve as fr
import indexed_writes as iw
from indirect_resolve import decode_instruction, scan_pointer_table

ANALYSIS = "indirect_target"
ANALYSIS_VERSION = 1

MAX_BLOCKS = 64       # predecessor blocks visited per register query
MAX_DEPTH = 3         # nested base-register queries (vptr -> object -> ...)
MAX_TABLE_ENTRIES = 64

ARG_REGS = ("r0", "r1", "r2", "r3")
CALL_CLOBBERED = {"r0", "r1", "r2", "r3", "r12", "ip"}
INTRA_KINDS = ("fallthrough", "branch", "cbranch")
_CAPSTONE_NAMES = {"r9": "sb", "r10": "sl", "r11": "fp", "r12": "ip"}

LIMITATIONS = (
    "intraprocedural: argument and call-result values are not followed into callers or callees",
    "predecessors are the census's resolved fallthrough/branch/cbranch edges; entries through an unresolved "
    "computed jump are invisible, and a block that is a code-pointer target is reported as an indirect entry",
    "the containing function is Ghidra's body attribution, which can include tail-branched code of another "
    "function",
    "a load's memory content is only read for immutable flash; RAM/MMIO words are runtime state",
    "vtable candidates are computed only against the vtables supplied by the caller",
    "a derivation is a possible target relationship, not an observed or reachable dispatch",
)


def _text(insn):
    return f"{insn.mnemonic} {insn.op_str}".strip()


def _cond(insn):
    return insn.cc not in (ARM_CC_AL, ARM_CC_INVALID)


def _written(insn):
    try:
        return {insn.reg_name(r) for r in insn.regs_access()[1]}
    except Exception:  # noqa: BLE001 -- no detail for this insn: fall back to the first operand
        r = iw._reg_written_by(insn)
        return {r} if r else set()


def _is_call(insn):
    return insn.mnemonic.lower().split(".")[0] in ("bl", "blx")


def _region(row, addr):
    if row["flash_base"] <= addr < row["flash_base"] + row["size_bytes"]:
        return "flash"
    if row["ram_base"] <= addr < row["ram_base"] + row["ram_size"]:
        return "ram"
    if row["mmio_base"] <= addr < row["mmio_base"] + row["mmio_size"]:
        return "mmio"
    return "unmapped"


def _pointer_targets(conn, firmware_id, image, flash_base):
    """Code addresses something enters indirectly: every aligned flash word
    that is a Thumb pointer into the image, plus every recorded indirect
    edge candidate."""
    out = set()
    end = flash_base + len(image)
    for off in range(0, len(image) - 3, 4):
        (w,) = struct.unpack_from("<I", image, off)
        if w & 1 and flash_base <= (w & ~1) < end:
            out.add(w & ~1)
    out.update(r[0] for r in conn.execute(
        "SELECT DISTINCT candidate_addr FROM indirect_edge_candidates WHERE firmware_id=?", (firmware_id,)))
    return out


class _Ctx:
    def __init__(self, conn, fw_row, image, max_blocks, max_depth):
        self.conn, self.row, self.image = conn, fw_row, image
        self.fw, self.base = fw_row["id"], fw_row["flash_base"]
        self.max_blocks, self.max_depth = max_blocks, max_depth
        self._blocks = {}
        self.pointer_targets = _pointer_targets(conn, self.fw, image, self.base)

    def block_at(self, addr):
        r = self.conn.execute(
            "SELECT * FROM basic_blocks WHERE firmware_id=? AND start_addr<=? AND end_addr>=? "
            "ORDER BY start_addr DESC LIMIT 1", (self.fw, addr, addr)).fetchone()
        return r

    def decode(self, block):
        key = block["start_addr"]
        if key not in self._blocks:
            self._blocks[key] = iw._decode_block(self.image, self.base, block["start_addr"], block["end_addr"])
        return self._blocks[key]

    def entry_of(self, block):
        if block["function_id"] is None:
            return None
        r = self.conn.execute("SELECT entry FROM functions WHERE id=?", (block["function_id"],)).fetchone()
        return r["entry"] if r else None

    def predecessors(self, block):
        rows = self.conn.execute(
            "SELECT DISTINCT from_addr FROM edges WHERE firmware_id=? AND to_addr=? AND resolved=1 "
            f"AND kind IN ({','.join('?' * len(INTRA_KINDS))})",
            (self.fw, block["start_addr"], *INTRA_KINDS)).fetchall()
        out = {}
        for r in rows:
            b = self.block_at(r["from_addr"])
            if b is not None and b["function_id"] == block["function_id"]:
                out[b["start_addr"]] = b
        return [out[k] for k in sorted(out)]


# -- reaching definitions ----------------------------------------------------

def _definition(ctx, block, insns, i, reg, depth):
    """The definition `insns[i]` gives `reg` (it writes reg)."""
    insn = insns[i]
    base = {"def_addr": insn.address, "instruction": _text(insn)}
    ops = insn.operands
    dest = insn.reg_name(ops[0].reg) if ops and ops[0].type == ARM_OP_REG else None
    if insn.id in (ARM_INS_POP, ARM_INS_LDM, ARM_INS_LDMDB):
        return {**base, "kind": "unknown", "reason": "restored from the stack or a register list"}
    if insn.id == ARM_INS_LDRD and len(ops) >= 3 and ops[2].type == ARM_OP_MEM:
        # A dual load: the first destination is the word at the address,
        # the second the word after it.
        pair = [insn.reg_name(ops[0].reg), insn.reg_name(ops[1].reg)]
        if reg in pair:
            return _load(ctx, block, insns, i, reg, base, ops[2], ops[3:], 4 * pair.index(reg), depth)
    if dest != reg:
        return {**base, "kind": "unknown", "reason": "written as a side effect (writeback or multi-register)"}
    if insn.id == ARM_INS_LDR and len(ops) >= 2 and ops[1].type == ARM_OP_MEM:
        return _load(ctx, block, insns, i, reg, base, ops[1], ops[2:], 0, depth)
    if insn.id == ARM_INS_MOV and len(ops) == 2 and ops[1].type == ARM_OP_REG and not ops[1].shift.type:
        src = insn.reg_name(ops[1].reg)
        alias = _reaching(ctx, block, insns, i, src, depth)
        return {**base, "kind": "move", "from_reg": src, "source": alias}
    res = iw._resolve_reg_value(insns, block["start_addr"], reg, i + 1, ctx.image, ctx.base)
    if res["kind"] in ("imm", "literal"):
        lo = min(res["trace"]) if res["trace"] else insn.address
        if any(_is_call(x) and lo < x.address < insn.address for x in insns):
            return {**base, "kind": "unknown", "reason": "constant chain crosses a call"}
        d = {**base, "kind": "constant", "via": res["kind"], "value": res["value"] & 0xFFFFFFFF}
        if res["kind"] == "literal":
            d["literal_addr"] = res["literal_addr"]
        return d
    return {**base, "kind": "unknown", "reason": res.get("reason", f"unrecognized definition ({_text(insn)})")}


def _load(ctx, block, insns, i, reg, base, mem, rest, word_offset, depth):
    """A word load of `reg` through memory operand `mem` (`rest`: a post-index
    immediate, if any; `word_offset`: 4 for an LDRD second destination)."""
    insn = insns[i]
    if mem.mem.base == ARM_REG_PC:
        lit = iw._literal_pool_target(insn.address, mem.mem.disp) + word_offset
        value = iw._read_flash_word(ctx.image, ctx.base, lit)
        if value is None:
            return {**base, "kind": "unknown", "reason": "literal pool outside the image"}
        return {**base, "kind": "constant", "via": "literal", "literal_addr": lit, "value": value}
    base_reg = insn.reg_name(mem.mem.base)
    if base_reg == "sp":
        return {**base, "kind": "unknown", "reason": "stack slot (spilled or restored value)"}
    if mem.mem.index not in (0, iw.ARM_REG_INVALID):
        d = {**base, "kind": "load", "mode": "indexed", "base_reg": base_reg,
             "index_reg": insn.reg_name(mem.mem.index), "shift": mem.shift.value or 0, "disp": mem.mem.disp}
    elif rest and rest[0].type == ARM_OP_IMM:
        d = {**base, "kind": "load", "mode": "post-index", "base_reg": base_reg, "disp": word_offset,
             "writeback": rest[0].imm}
    else:
        d = {**base, "kind": "load", "mode": "pre-index" if insn.writeback else "offset",
             "base_reg": base_reg, "disp": mem.mem.disp + word_offset}
    if depth < ctx.max_depth:
        d["base"] = _reaching(ctx, block, insns, i, base_reg, depth + 1)
    else:
        d["base"] = {"defs": [{"kind": "incomplete", "reason": "depth limit"}], "complete": False}
    return d


def _reaching(ctx, block, insns, before, reg, depth):
    """Every definition of `reg` reaching `insns[before]` (exclusive)."""
    defs, complete = [], True
    seen = set()
    work = [(block, insns, before)]
    visited = 0
    while work:
        blk, ins, idx = work.pop()
        killed = False
        for i in range(idx - 1, -1, -1):
            x = ins[i]
            if _is_call(x) and reg in CALL_CLOBBERED:
                d = {"def_addr": x.address, "instruction": _text(x)}
                if reg == "r0":
                    target = x.operands[0].imm if x.operands and x.operands[0].type == ARM_OP_IMM else None
                    defs.append({**d, "kind": "call-result", "callee": target})
                else:
                    defs.append({**d, "kind": "unknown", "reason": "clobbered by a call"})
                killed = True
                break
            if reg not in _written(x):
                continue
            defs.append(_definition(ctx, blk, ins, i, reg, depth))
            if not _cond(x):
                killed = True
                break
        if killed:
            continue
        entry = ctx.entry_of(blk)
        if entry is not None and blk["start_addr"] == entry:
            if reg in ARG_REGS:
                defs.append({"kind": "argument", "arg": ARG_REGS.index(reg), "function_entry": entry})
            else:
                defs.append({"kind": "entry-live-in", "reg": reg, "function_entry": entry})
            continue
        if blk["start_addr"] in ctx.pointer_targets:
            # Entered through a code pointer (a vtable word, a callback, an
            # observed indirect target): those entries carry values this
            # walk cannot see, so the recorded predecessors are not all.
            defs.append({"kind": "indirect-entry", "reg": reg, "block": blk["start_addr"],
                         "reason": "block is the target of a code pointer; entries through it are not followed"})
            complete = False
        preds = ctx.predecessors(blk)
        if not preds:
            defs.append({"kind": "block-live-in", "reg": reg, "block": blk["start_addr"],
                         "reason": "no recorded predecessor and not a known function entry"})
            complete = False
            continue
        for p in preds:
            if p["start_addr"] in seen:
                continue
            seen.add(p["start_addr"])
            visited += 1
            if visited > ctx.max_blocks:
                defs.append({"kind": "incomplete", "reason": f"block limit {ctx.max_blocks}"})
                return {"defs": _dedupe(defs), "complete": False}
            pins = ctx.decode(p)
            work.append((p, pins, len(pins)))
    defs = _dedupe(defs)
    complete = complete and all(_def_complete(d) for d in defs)
    return {"defs": defs, "complete": complete}


def _def_complete(d):
    if d["kind"] in ("unknown", "incomplete", "block-live-in", "indirect-entry"):
        return False
    if d["kind"] == "move":
        return d["source"]["complete"]
    if d["kind"] == "load":
        return d["base"]["complete"]
    return True


def _dedupe(defs):
    out, keys = [], set()
    for d in defs:
        k = json.dumps(d, sort_keys=True, default=str)
        if k not in keys:
            keys.add(k)
            out.append(d)
    return sorted(out, key=lambda d: (d.get("def_addr") is None, d.get("def_addr") or 0, d["kind"]))


def _flatten(defset):
    """Follow register moves: the underlying definitions."""
    out = []
    for d in defset["defs"]:
        if d["kind"] == "move":
            out.extend(_flatten(d["source"]))
        else:
            out.append(d)
    return out


# -- shape -------------------------------------------------------------------

def _origin(defset):
    """A short description of a pointer's origin, for receivers and bases."""
    flat = _flatten(defset)
    if len(flat) != 1:
        return {"kind": "multiple" if flat else "none", "count": len(flat),
                "kinds": sorted({d["kind"] for d in flat})}
    d = flat[0]
    out = {"kind": d["kind"]}
    for k in ("def_addr", "instruction", "arg", "function_entry", "callee", "value", "reason", "reg", "disp",
              "mode", "base_reg"):
        if k in d:
            out[k] = d[k]
    if d["kind"] == "load":
        out["base"] = _origin(d["base"])
    return out


def _shape(ctx, d):
    """Pattern for ONE (move-flattened) definition."""
    if d["kind"] == "constant":
        return {"pattern": "constant-target", "value": d["value"]}
    if d["kind"] == "argument":
        return {"pattern": "argument", "arg": d["arg"], "function_entry": d["function_entry"]}
    if d["kind"] == "call-result":
        return {"pattern": "call-result", "call_addr": d["def_addr"], "callee": d.get("callee")}
    if d["kind"] != "load":
        return {"pattern": "unresolved", "reason": d.get("reason", d["kind"])}
    load = {"load_addr": d["def_addr"], "load_instruction": d["instruction"]}
    if d["mode"] == "indexed":
        return {"pattern": "indexed-table", **load, "index_reg": d["index_reg"], "shift": d["shift"],
                "table_base": _origin(d["base"])}
    if d["mode"] == "post-index":
        return {"pattern": "pointer-iteration", **load, "stride": d["writeback"], "cursor": _origin(d["base"])}
    bases = _flatten(d["base"])
    if len(bases) == 1 and bases[0]["kind"] == "constant":
        slot = (bases[0]["value"] + d["disp"]) & 0xFFFFFFFF
        return {"pattern": "constant-slot", **load, "slot_addr": slot, "slot_region": _region(ctx.row, slot)}
    if len(bases) == 1 and bases[0]["kind"] == "load" and bases[0]["mode"] in ("offset", "pre-index"):
        inner = bases[0]
        kind = "vtable-slot" if inner["disp"] == 0 else "object-table-slot"
        return {"pattern": kind, **load, "slot_offset": d["disp"],
                "slot_index": d["disp"] // 4 if d["disp"] % 4 == 0 else None,
                "table_pointer_load": inner["def_addr"], "table_pointer_instruction": inner["instruction"],
                "table_pointer_offset": inner["disp"], "receiver": _origin(inner["base"])}
    return {"pattern": "object-field", **load, "field_offset": d["disp"], "pointer": _origin(d["base"])}


def _code_pointer(ctx, raw):
    p = fr.canonical_code_pointer(raw, ctx.image, ctx.base)
    return {"raw_value": f"0x{raw:08x}", "thumb_bit": p["thumb_bit"], "target": f"0x{p['canonical_target']:08x}",
            "normalization": p["canonicalization"], "is_code_pointer": p["is_code_pointer"]}


def _targets(ctx, shape, vtables):
    """Candidate targets and the resolution status a shape supports."""
    pat = shape["pattern"]
    if pat == "constant-target":
        ptr = _code_pointer(ctx, shape["value"])
        return [{**ptr, "basis": "constant"}], "STATICALLY_ESTABLISHED" if ptr["is_code_pointer"] else "UNRESOLVED"
    if pat == "constant-slot":
        if shape["slot_region"] == "flash":
            word = iw._read_flash_word(ctx.image, ctx.base, shape["slot_addr"])
            ptr = _code_pointer(ctx, word)
            return ([{**ptr, "basis": f"immutable flash word at 0x{shape['slot_addr']:08x}"}],
                    "STATICALLY_ESTABLISHED" if ptr["is_code_pointer"] else "UNRESOLVED")
        writers = fr.slot_writers(ctx.conn, ctx.fw, ctx.image, ctx.base, shape["slot_addr"])
        out = [{**_code_pointer(ctx, w["raw_value"]), "basis": f"constant store at 0x{w['store_addr']:08x}"}
               for w in writers if w["value_kind"] == "constant"]
        shape["slot_writers"] = len(writers)
        shape["slot_writers_unresolved"] = sum(1 for w in writers if w["value_kind"] != "constant")
        return out, "CONDITIONALLY_POSSIBLE" if out else "UNRESOLVED"
    if pat == "vtable-slot" and vtables:
        out = []
        for v in sorted(vtables):
            entry = v + shape["slot_offset"]
            word = iw._read_flash_word(ctx.image, ctx.base, entry)
            if word is None:
                continue
            ptr = _code_pointer(ctx, word)
            out.append({**ptr, "vtable": f"0x{v:08x}", "entry_addr": f"0x{entry:08x}",
                        "basis": f"word at vtable 0x{v:08x} + 0x{shape['slot_offset']:x}, IF the receiver's vptr "
                                 f"is 0x{v:08x}"})
        return out, "CONDITIONALLY_POSSIBLE" if any(t["is_code_pointer"] for t in out) else "UNRESOLVED"
    return [], "UNRESOLVED"


def resolve_indirect_call(conn, firmware_key, image, site, vtables=(), max_blocks=MAX_BLOCKS, max_depth=MAX_DEPTH):
    """Target derivation for the register-indirect transfer at `site`.

    `vtables`: vptr values (table address points) the caller has
    established; only these produce vtable-slot candidates. Returns a
    deterministic, JSON-serializable dict."""
    row = conn.execute("SELECT * FROM firmware WHERE key=?", (firmware_key,)).fetchone()
    if row is None:
        raise KeyError(f"unknown firmware {firmware_key!r}")
    if hashlib.sha256(image).hexdigest() != row["sha256"]:
        raise ValueError("image does not match the census firmware digest")
    ctx = _Ctx(conn, row, image, max_blocks, max_depth)
    out = {"analysis": ANALYSIS, "analysis_version": ANALYSIS_VERSION, "firmware_key": firmware_key,
           "firmware_sha256": row["sha256"], "site": f"0x{site:08x}",
           "bounds": {"max_blocks": max_blocks, "max_depth": max_depth},
           "vtables_supplied": [f"0x{v:08x}" for v in sorted(vtables)], "limitations": list(LIMITATIONS)}
    mnemonic, shape, reg = decode_instruction(image, row["flash_base"], site)
    out.update({"mnemonic": mnemonic, "instruction_shape": shape, "target_reg": reg})
    if shape != "reg-indirect":
        out.update({"derivation_status": "NOT_APPLICABLE", "resolution_status": "UNRESOLVED", "patterns": [],
                    "candidate_targets": [], "reason": f"not a register-indirect transfer ({shape})"})
        return out
    block = ctx.block_at(site)
    insns = ctx.decode(block) if block is not None else []
    idx = next((i for i, x in enumerate(insns) if x.address == site), None)
    if idx is None:
        out.update({"derivation_status": "UNKNOWN", "resolution_status": "UNRESOLVED", "patterns": [],
                    "candidate_targets": [], "reason": "site is not inside a census basic block"})
        return out
    out["containing_block"] = f"0x{block['start_addr']:08x}"
    out["containing_function"] = ctx.entry_of(block)
    out["function_attributed"] = block["function_id"] is not None
    defset = _reaching(ctx, block, insns, idx, _CAPSTONE_NAMES.get(reg, reg), 0)
    flat = _flatten(defset)
    shapes = [_shape(ctx, d) for d in flat]
    targets, statuses = [], []
    for s in shapes:
        t, st = _targets(ctx, s, vtables)
        targets.extend(t)
        statuses.append(st)
    if not shapes:
        status = "UNRESOLVED"
    elif all(s == "STATICALLY_ESTABLISHED" for s in statuses) and defset["complete"]:
        status = "STATICALLY_ESTABLISHED"
    elif any(s in ("STATICALLY_ESTABLISHED", "CONDITIONALLY_POSSIBLE") for s in statuses):
        status = "CONDITIONALLY_POSSIBLE"
    else:
        status = "UNRESOLVED"
    known = [s for s in shapes if s["pattern"] != "unresolved"]
    out.update({
        "derivation_status": ("ESTABLISHED" if defset["complete"] and known and len(known) == len(shapes)
                              else "PARTIAL" if known else "UNKNOWN"),
        "pattern": shapes[0]["pattern"] if len(shapes) == 1 else "multiple",
        "patterns": shapes,
        "reaching_definitions": defset,
        "candidate_targets": targets,
        "resolution_status": status,
    })
    if out["containing_function"] is not None:
        out["containing_function"] = f"0x{out['containing_function']:08x}"
    return _hexify(json.loads(json.dumps(out, sort_keys=True, default=str)))


_ADDRESS_KEYS = {"def_addr", "load_addr", "table_pointer_load", "literal_addr", "block", "function_entry", "callee",
                 "call_addr", "value", "slot_addr"}


def _hexify(obj):
    if isinstance(obj, dict):
        return {k: (f"0x{v:08x}" if k in _ADDRESS_KEYS and isinstance(v, int) else _hexify(v)) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_hexify(v) for v in obj]
    return obj


# -- vtable installations ------------------------------------------------------

def vptr_installations(conn, firmware_key, image, min_entries=2):
    """Every word store of a flash constant V into [rB, #k] (any census
    block) where V starts a run of >= `min_entries` Thumb code pointers:
    the constructor shape that installs a vptr. Pattern-matched: a store
    through a computed value, or of a table built in RAM, is invisible."""
    row = conn.execute("SELECT * FROM firmware WHERE key=?", (firmware_key,)).fetchone()
    ctx = _Ctx(conn, row, image, MAX_BLOCKS, 0)
    out = []
    for blk in conn.execute("SELECT * FROM basic_blocks WHERE firmware_id=? ORDER BY start_addr", (row["id"],)):
        insns = ctx.decode(blk)
        for i, x in enumerate(insns):
            if x.id != ARM_INS_STR or len(x.operands) < 2:
                continue
            mem = x.operands[1]
            if mem.type != ARM_OP_MEM or mem.mem.base == ARM_REG_PC or mem.mem.index not in (0, iw.ARM_REG_INVALID):
                continue
            post = len(x.operands) == 3
            value_reg = x.reg_name(x.operands[0].reg)
            res = iw._resolve_reg_value(insns, blk["start_addr"], value_reg, i, image, row["flash_base"])
            if res["kind"] not in ("imm", "literal") or _region(row, res["value"]) != "flash":
                continue
            entries = scan_pointer_table(image, row["flash_base"], res["value"], MAX_TABLE_ENTRIES)
            if len(entries) < min_entries:
                continue
            out.append({"store_addr": f"0x{x.address:08x}", "store_instruction": _text(x),
                        "block": f"0x{blk['start_addr']:08x}",
                        "function": (f"0x{ctx.entry_of(blk):08x}" if ctx.entry_of(blk) is not None else None),
                        "object_reg": x.reg_name(mem.mem.base), "object_offset": 0 if post else mem.mem.disp,
                        "vtable": f"0x{res['value']:08x}", "value_resolution": res["kind"],
                        "literal_addr": (f"0x{res['literal_addr']:08x}" if "literal_addr" in res else None),
                        "entries": [{"slot": n, "offset": f"0x{4 * n:x}", "target": f"0x{t:08x}"}
                                    for n, t in entries]})
    return out


def main(argv=None):
    import argparse
    import sqlite3

    import db as census_db
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("firmware")
    p.add_argument("--db", default=None)
    p.add_argument("--site", type=lambda s: int(s, 0), action="append", default=[])
    p.add_argument("--vtable", type=lambda s: int(s, 0), action="append", default=[])
    p.add_argument("--installations", action="store_true", help="list vptr installation stores")
    p.add_argument("--vtables-from-installations", action="store_true",
                   help="use every vtable vptr_installations finds as the candidate vtable set")
    p.add_argument("--all-register-indirect", action="store_true",
                   help="every census indirect site whose shape is reg-indirect")
    args = p.parse_args(argv)
    # Read-only: the census database is an input artifact of this analysis.
    conn = sqlite3.connect(f"file:{Path(args.db or census_db.DEFAULT_DB_PATH).resolve()}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT * FROM firmware WHERE key=?", (args.firmware,)).fetchone()
    path = Path(row["path"])
    image = (path if path.is_absolute() else census_db.REPO_ROOT / path).read_bytes()
    doc = {}
    vtables = list(args.vtable)
    if args.installations or args.vtables_from_installations:
        doc["vptr_installations"] = vptr_installations(conn, args.firmware, image)
    if args.vtables_from_installations:
        vtables += [int(i["vtable"], 16) for i in doc["vptr_installations"]]
    sites = list(args.site)
    if args.all_register_indirect:
        sites += [r["from_addr"] for r in conn.execute(
            "SELECT from_addr FROM indirect_edge_resolutions WHERE firmware_id=? AND instr_shape='reg-indirect' "
            "ORDER BY from_addr", (row["id"],))]
    doc["sites"] = [resolve_indirect_call(conn, args.firmware, image, s, sorted(set(vtables)))
                    for s in sorted(set(sites))]
    print(json.dumps(doc, indent=1, sort_keys=True))


if __name__ == "__main__":
    sys.exit(main())
