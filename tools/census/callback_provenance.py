"""APTrace census: where does a callback target passed into ONE register-
indirect site come from, one call boundary up?

`indirect_target.resolve_indirect_call` stops at the containing function's
entry when the branch register is an incoming AAPCS argument. This module
takes exactly one more step:

  1. the site's derivation names the argument (r0-r3, or a stack argument
     read in the entry block) and the entry it is live-in at;
  2. every DIRECT transfer into that entry is enumerated by a halfword
     sweep (BL, B.W, B<c>.W, 16-bit B / B<c>), kept only where the census
     decodes an instruction there, and cross-checked with census edges;
  3. at each transfer, the reaching definitions of the same argument (the
     register, or the outgoing stack slot stored in the transfer's block)
     are computed with the same machinery as the site itself;
  4. each caller's value is classified:

       CONCRETE            one constant
       FINITE_TARGET_SET   several constants (a join, an IT definition)
       FORWARDED_ARGUMENT  the caller's own incoming argument: another hop
                           (named, never taken)
       MEMORY_DEPENDENT    a load from memory whose content is not
                           established (RAM, an object field, a table)
       UNKNOWN             anything else, including a hit bound

     and every constant is checked as a Cortex-M code pointer: the Thumb bit
     must be set, the address inside the image and decodable. An even
     address is kept and labeled -- BLX to it faults (INVSTATE) -- never
     silently normalized into a target.

The callers' targets together form the site's candidate set. It is CLOSED
only when the site's own derivation is complete, every argument origin's
caller set is complete (no address-taken entry, no census-only edge, no
transfer outside census code, no truncation) and every caller's value is
CONCRETE or FINITE_TARGET_SET. Only then is an address absent from the set
excluded -- and only under the stated assumptions. Otherwise the set is
OPEN and the reasons are listed.

A caller passing a value is not the callee reaching the site, the site
branching to that value, the target being reachable from a root, or the
target executing: those stay separate fields. No hop beyond the first, no
alias or points-to reasoning, no names or comments consulted.
"""
import hashlib
import json
import sys
from pathlib import Path

from capstone.arm_const import ARM_CC_AL, ARM_CC_INVALID, ARM_OP_MEM

import fnptr_resolve as fr
import indirect_target as it
import indexed_writes as iw
from slot_dispatch import _bl_target, _t4_target, _wide_branch_target

ANALYSIS = "callback_provenance"
ANALYSIS_VERSION = 1

MAX_CALLERS = 16      # direct transfers analyzed per argument origin
MAX_BLOCKS = 128      # predecessor blocks per register query (site and callers)
MAX_DEFS = 16         # flattened reaching definitions per caller value
MAX_TARGETS = 16      # distinct constants per caller value
MAX_WORK = 4096       # blocks visited across all caller queries of one site
MAX_PATH_BLOCKS = 512  # forward CFG search (entry -> site / call)

STATUSES = ("CONCRETE", "FINITE_TARGET_SET", "FORWARDED_ARGUMENT", "MEMORY_DEPENDENT", "UNKNOWN")
# Most limiting first: a value is as constrained as its least constrained component.
_LIMITING = ("UNKNOWN", "MEMORY_DEPENDENT", "FORWARDED_ARGUMENT")
_REACH = {"DEFINITELY_REACHABLE": "ESTABLISHED", "POSSIBLY_REACHABLE_VIA_UNRESOLVED_INDIRECT": "CONDITIONAL",
          "NO_KNOWN_PATH": "UNRESOLVED"}
_MEMORY_SHAPES = ("constant-slot", "vtable-slot", "object-table-slot", "object-field", "indexed-table",
                  "pointer-iteration")

LIMITATIONS = (
    "one hop: a caller's own incoming argument is reported as FORWARDED_ARGUMENT, never followed",
    "callers are direct transfers (BL, B.W, B<c>.W, 16-bit B/B<c>) at instructions the census decodes; an entry "
    "whose address is materialized as a code pointer has indirect callers this does not enumerate",
    "a caller's value is its intraprocedural reaching definitions over census blocks and edges; RAM, MMIO and "
    "object contents are runtime state",
    "address-taken entries are found as aligned flash words, MOVW/MOVT in census code and recorded indirect "
    "candidates; ADR or computed materializations are not swept",
    "a stack argument is the word the caller stores at the outgoing slot in the transfer's own block; stores "
    "through another register aliasing the stack are not modeled",
    "a candidate target is a value some caller passes, not a dispatch: whether the callee reaches the site with "
    "it, and whether the caller runs at all, are not established",
    "function and block boundaries are Ghidra's and the Capstone sweep's (heuristic)",
)


def _h(v):
    return None if v is None else f"0x{v:08x}"


def _cond(insn):
    return insn.cc not in (ARM_CC_AL, ARM_CC_INVALID)


# -- direct transfers into an entry ----------------------------------------------

def _b16_target(hw, address):
    """16-bit B (T2) or B<c> (T1); None for anything else."""
    if (hw & 0xF800) == 0xE000:
        imm = (hw & 0x7FF) << 1
        return "b", (address + 4 + (imm - (1 << 12) if imm & 0x800 else imm)) & 0xFFFFFFFF
    if (hw & 0xF000) == 0xD000 and ((hw >> 8) & 0xF) < 0xE:
        imm = (hw & 0xFF) << 1
        return "b<c>", (address + 4 + (imm - (1 << 9) if imm & 0x100 else imm)) & 0xFFFFFFFF
    return None


def _blx_imm_target(hw1, hw2, address):
    """BLX immediate (T2): an ARM-state call, UNDEFINED on M-profile."""
    if (hw1 & 0xF800) != 0xF000 or (hw2 & 0xD001) != 0xC000:
        return None
    return (((address + 4) & ~3) + (_t4_target(hw1, hw2, address) - (address + 4))) & 0xFFFFFFFF


def _sweep_transfers(image, base, entry):
    """Every halfword offset whose 32- or 16-bit direct-transfer encoding
    targets `entry` (pattern-matched; verified against census code later)."""
    out = []
    for off in range(0, len(image) - 1, 2):
        address = base + off
        hw1 = int.from_bytes(image[off:off + 2], "little")
        hw2 = int.from_bytes(image[off + 2:off + 4], "little") if off + 4 <= len(image) else None
        if hw2 is not None:
            t = _bl_target(hw1, hw2, address)
            if t == entry:
                out.append({"address": address, "kind": "bl", "width": 4})
            wide = _wide_branch_target(hw1, hw2, address)
            if wide is not None and wide[1] == entry:
                out.append({"address": address, "kind": wide[0], "width": 4})
            t = _blx_imm_target(hw1, hw2, address)
            if t is not None and t == entry & ~3:
                out.append({"address": address, "kind": "blx-imm", "width": 4})
        short = _b16_target(hw1, address)
        if short is not None and short[1] == entry:
            out.append({"address": address, "kind": short[0], "width": 2})
    return out


def _instruction_at(ctx, address):
    """(block, insns, index) when the census decodes an instruction starting at `address`."""
    block = ctx.block_at(address)
    if block is None:
        return None
    insns = ctx.decode(block)
    idx = next((i for i, x in enumerate(insns) if x.address == address), None)
    return None if idx is None else (block, insns, idx)


def _function_row(ctx, block):
    if block is None or block["function_id"] is None:
        return None
    return ctx.conn.execute("SELECT * FROM functions WHERE id=?", (block["function_id"],)).fetchone()


def _movw_imm(hw1, hw2):
    """(kind, rd, imm16) for MOVW/MOVT (T3), else None."""
    if (hw1 & 0xFBF0) not in (0xF240, 0xF2C0) or hw2 & 0x8000:
        return None
    imm = ((hw1 & 0xF) << 12) | (((hw1 >> 10) & 1) << 11) | (((hw2 >> 12) & 7) << 8) | (hw2 & 0xFF)
    return ("movw" if (hw1 & 0xFBF0) == 0xF240 else "movt"), (hw2 >> 8) & 0xF, imm


def _next_use(ctx, address):
    """The first later instruction in the same census block that reads the
    register `address` loads (mechanical; not a use analysis)."""
    found = _instruction_at(ctx, address)
    if found is None:
        return None
    _block, insns, idx = found
    reg = it._written(insns[idx])
    for x in insns[idx + 1:]:
        try:
            read = {x.reg_name(r) for r in x.regs_access()[0]}
        except Exception:  # noqa: BLE001
            read = set()
        if reg & read:
            return {"addr": _h(x.address), "instruction": f"{x.mnemonic} {x.op_str}"}
        if reg & it._written(x):
            return {"addr": _h(x.address), "instruction": f"{x.mnemonic} {x.op_str}", "redefines": True}
    return None


def _address_taken(ctx, entry):
    """Where the entry's address exists as a callable value: aligned flash
    Thumb-pointer words (with the instructions that load them and their next
    use), MOVW(/MOVT) materializations in census-decoded code, and recorded
    indirect-edge candidates that are not resolved jump-table cases. Other
    materializations (ADR plus arithmetic, computed values) are not swept."""
    out = []
    value = entry | 1
    for off in range(0, len(ctx.image) - 3, 2):
        hw1 = int.from_bytes(ctx.image[off:off + 2], "little")
        hw2 = int.from_bytes(ctx.image[off + 2:off + 4], "little")
        if off % 4 == 0 and (hw2 << 16 | hw1) == value:
            loc = ctx.base + off
            loads = [{"addr": _h(r[0]), "next_use": _next_use(ctx, r[0])} for r in ctx.conn.execute(
                "SELECT DISTINCT from_addr FROM literal_refs WHERE firmware_id=? AND to_addr=? ORDER BY from_addr",
                (ctx.fw, loc))]
            out.append({"kind": "flash-word", "location": _h(loc), "value": _h(value), "loaded_by": loads})
        mv = _movw_imm(hw1, hw2)
        if mv is None or mv[0] != "movw" or mv[2] != value & 0xFFFF or _instruction_at(ctx, ctx.base + off) is None:
            continue
        if value >> 16 == 0:
            out.append({"kind": "movw", "location": _h(ctx.base + off), "value": _h(value)})
            continue
        for k in range(4, 20, 2):
            nxt = off + k
            mt = _movw_imm(int.from_bytes(ctx.image[nxt:nxt + 2], "little"),
                           int.from_bytes(ctx.image[nxt + 2:nxt + 4], "little"))
            if mt is not None and mt[0] == "movt" and mt[1] == mv[1] and mt[2] == value >> 16:
                out.append({"kind": "movw-movt", "location": _h(ctx.base + off), "value": _h(value)})
                break
    for r in ctx.conn.execute(
            "SELECT DISTINCT from_addr, source FROM indirect_edge_candidates WHERE firmware_id=? AND candidate_addr=? "
            "ORDER BY from_addr, source", (ctx.fw, entry)):
        if r["from_addr"] not in ctx.table_sites:
            out.append({"kind": "indirect-edge-candidate", "site": _h(r["from_addr"]), "source": r["source"]})
    return out


def direct_transfers(ctx, entry):
    """Direct transfers into `entry`, verified against census code."""
    entry_block = ctx.block_at(entry)
    entry_fid = entry_block["function_id"] if entry_block is not None and entry_block["start_addr"] == entry else None
    callers, intra, invalid, unverified = [], [], [], []
    for hit in _sweep_transfers(ctx.image, ctx.base, entry):
        found = _instruction_at(ctx, hit["address"])
        rec = {"site": _h(hit["address"]), "transfer": hit["kind"]}
        if found is None:
            if hit["width"] == 4:
                unverified.append({**rec, "reason": "not an instruction the census decodes"})
            continue  # a 16-bit pattern outside decoded code is ordinary data
        block, insns, idx = found
        insn = insns[idx]
        rec["instruction"] = f"{insn.mnemonic} {insn.op_str}".strip()
        if hit["kind"] == "blx-imm":
            invalid.append({**rec, "reason": "BLX immediate switches to ARM state: UNDEFINED on Cortex-M"})
            continue
        if hit["kind"] not in ("bl",) and entry_fid is not None and block["function_id"] == entry_fid:
            intra.append(rec)  # a branch back to the entry inside its own function
            continue
        fn = _function_row(ctx, block)
        rec.update({"block": _h(block["start_addr"]), "caller_function": _h(fn["entry"]) if fn else None,
                    "caller_function_name": fn["name"] if fn else None,
                    "transfer_kind": "call" if hit["kind"] == "bl" else "tail",
                    "conditional": _cond(insn) or hit["kind"] in ("b<c>.w", "b<c>"),
                    "condition_code": insn.cc if _cond(insn) else None,
                    "_found": found})
        callers.append(rec)
    hit_blocks = {c["block"] for c in callers}
    census_only = []
    for r in ctx.conn.execute(
            "SELECT DISTINCT from_addr, kind, source FROM edges WHERE firmware_id=? AND to_addr=? AND resolved=1 "
            "AND kind IN ('call','branch','cbranch') ORDER BY from_addr", (ctx.fw, entry)):
        b = ctx.block_at(r["from_addr"])
        key = _h(b["start_addr"]) if b is not None else None
        if key in hit_blocks or (b is not None and entry_fid is not None and b["function_id"] == entry_fid
                                 and r["kind"] != "call"):
            continue
        census_only.append({"from": _h(r["from_addr"]), "kind": r["kind"], "source": r["source"]})
    corroborated = {_h(ctx.block_at(r[0])["start_addr"]) for r in ctx.conn.execute(
        "SELECT from_addr FROM edges WHERE firmware_id=? AND to_addr=? AND resolved=1", (ctx.fw, entry))
        if ctx.block_at(r[0]) is not None}
    for c in callers:
        c["census_edge"] = c["block"] in corroborated
    return {"callers": callers, "intraprocedural_entry_branches": intra, "invalid_transfers": invalid,
            "unverified_pattern_hits": unverified, "census_only_edges": census_only}


# -- a caller's argument value -----------------------------------------------------

def _stack_store(ctx, block, insns, idx, offset):
    """The register stored at the outgoing stack slot [sp, #offset] before
    `insns[idx]` in the same block: (store index, register) or a reason."""
    for i in range(idx - 1, -1, -1):
        x = insns[i]
        if it._is_call(x):
            return None, f"a call at 0x{x.address:08x} precedes the transfer before any store to the slot"
        d = it._sp_delta(x)
        if d is None or d != 0:
            return None, f"SP changes at 0x{x.address:08x} between the store and the transfer"
        m = x.mnemonic.lower()
        if not m.startswith(("str", "stm", "vst")):
            continue
        mem = next((o for o in x.operands if o.type == ARM_OP_MEM), None)
        if mem is None:
            return None, f"multi-register store at 0x{x.address:08x}"
        if x.reg_name(mem.mem.base) != "sp":
            continue
        if mem.mem.index not in (0, iw.ARM_REG_INVALID) or x.writeback:
            return None, f"indexed or writeback stack store at 0x{x.address:08x}"
        if m.split(".")[0] == "str" and mem.mem.disp == offset:
            return (i, x.reg_name(x.operands[0].reg)), None
        if m.split(".")[0] != "str" and mem.mem.disp <= offset < mem.mem.disp + 8:
            return None, f"slot written by {x.mnemonic} at 0x{x.address:08x}"
    return None, "no store to the outgoing slot in the transfer's block"


def _pointer(ctx, raw):
    p = fr.canonical_code_pointer(raw, ctx.image, ctx.base)
    if raw == 0:
        validity = "NULL"
    elif p["is_code_pointer"]:
        validity = "VALID_THUMB_CODE_POINTER"
    elif not p["in_image"]:
        validity = "OUTSIDE_IMAGE"
    elif not raw & 1:
        validity = "THUMB_BIT_CLEAR"
    else:
        validity = "DOES_NOT_DECODE"
    out = {"raw_value": _h(raw), "thumb_bit": raw & 1, "region": it._region(ctx.row, raw), "validity": validity,
           "callable": validity == "VALID_THUMB_CODE_POINTER"}
    if validity == "THUMB_BIT_CLEAR":
        out["note"] = "an even address: BLX/BX to it raises an INVSTATE fault on Cortex-M; not a callable target"
    if out["callable"]:
        target = p["canonical_target"]
        out["target"] = _h(target)
        fn = ctx.conn.execute("SELECT entry, name FROM functions WHERE firmware_id=? AND entry=?",
                              (ctx.fw, target)).fetchone()
        out["target_function"] = fn["name"] if fn else None
        out["target_reachability"] = _function_reach(ctx, target)
    return out


def _component(ctx, d):
    """One flattened reaching definition of a caller's value."""
    where = {k: (_h(d[k]) if k == "def_addr" else d[k]) for k in ("def_addr", "instruction") if k in d}
    shape = it._shape(ctx, d)
    pat = shape["pattern"]
    if pat == "constant-target":
        basis = f"literal at 0x{d['literal_addr']:08x}" if "literal_addr" in d else f"{d.get('via', 'immediate')}"
        return {"kind": "constant", **where, "basis": basis, **_pointer(ctx, d["value"])}
    if pat == "argument":
        out = {"kind": "forwarded", **where, "function_entry": _h(d["function_entry"]), "arg": d["arg"],
               "argument": f"r{d['arg']}" if d["arg"] < 4 else f"stack argument {d['arg']}"}
        if d.get("location") == "stack":
            out.update({"location": "stack", "entry_sp_offset": d["entry_sp_offset"]})
        return out
    if pat == "constant-slot" and shape["slot_region"] == "flash":
        word = iw._read_flash_word(ctx.image, ctx.base, shape["slot_addr"])
        return {"kind": "constant", **where, "basis": f"immutable flash word at 0x{shape['slot_addr']:08x}",
                **_pointer(ctx, word)}
    if pat in _MEMORY_SHAPES:
        out = {"kind": "memory", **where, "shape": pat,
               **{k: v for k, v in shape.items() if k in ("slot_addr", "slot_region", "slot_offset", "field_offset",
                                                          "table_pointer_offset")}}
        if pat == "constant-slot":
            targets, _ = it._targets(ctx, shape, ())
            out["conditional_values"] = [{"basis": t["basis"], **_pointer(ctx, int(t["raw_value"], 16))}
                                         for t in targets]
            out["slot_writers_unresolved"] = shape.get("slot_writers_unresolved", 0)
        return out
    if pat == "call-result":
        return {"kind": "unknown", **where, "reason": f"value returned by the call at 0x{d['def_addr']:08x}"}
    return {"kind": "unknown", **where, "reason": shape.get("reason", pat)}


def _classify(components, complete, max_targets):
    kinds = {c["kind"] for c in components}
    consts = sorted({c["raw_value"] for c in components if c["kind"] == "constant"})
    if not components or "unknown" in kinds or not complete:
        return "UNKNOWN"
    if "memory" in kinds:
        return "MEMORY_DEPENDENT"
    if "forwarded" in kinds:
        return "FORWARDED_ARGUMENT"
    if len(consts) > max_targets:
        return "UNKNOWN"
    return "CONCRETE" if len(consts) == 1 else "FINITE_TARGET_SET"


def caller_value(ctx, caller, arg, max_defs, max_targets):
    block, insns, idx = caller.pop("_found")
    reg = f"r{arg['arg']}" if arg["arg"] < 4 else None
    out = {"argument": reg or f"stack argument {arg['arg']} ([sp, #0x{4 * (arg['arg'] - 4):x}] at the transfer)"}
    if reg is None:
        store, reason = _stack_store(ctx, block, insns, idx, 4 * (arg["arg"] - 4))
        if store is None:
            out.update({"value_status": "UNKNOWN", "components": [{"kind": "unknown", "reason": reason}],
                        "complete": False})
            return out
        si, reg = store
        out["stack_store"] = {"store_addr": _h(insns[si].address),
                              "instruction": f"{insns[si].mnemonic} {insns[si].op_str}", "stored_register": reg}
        idx = si
    work_before = ctx.work
    defset = it._reaching(ctx, block, insns, idx, it._CAPSTONE_NAMES.get(reg, reg), 0)
    flat = it._flatten(defset)
    complete = defset["complete"]
    if len(flat) > max_defs:
        components = [{"kind": "unknown", "reason": f"{len(flat)} reaching definitions exceed the bound {max_defs}"}]
        complete = False
    else:
        components = [_component(ctx, d) for d in flat]
        if not defset["complete"] and not any(c["kind"] == "unknown" for c in components):
            components.append({"kind": "unknown", "reason": "reaching definitions incomplete"})
    status = _classify(components, complete, max_targets)
    if status == "UNKNOWN" and len({c.get("raw_value") for c in components if c["kind"] == "constant"}) > max_targets:
        components.append({"kind": "unknown", "reason": f"more than {max_targets} distinct constants"})
    out.update({"value_status": status, "components": components, "complete": complete,
                "reaching_definitions": it._hexify(json.loads(json.dumps(defset, default=str))),
                "blocks_visited": ctx.work - work_before})
    return out


# -- static paths and reachability ------------------------------------------------

def _successors(ctx, block):
    rows = ctx.conn.execute(
        "SELECT DISTINCT from_addr, to_addr, kind FROM edges WHERE firmware_id=? AND from_addr BETWEEN ? AND ? "
        "AND resolved=1 AND kind IN ('fallthrough','branch','cbranch','computed-jump')",
        (ctx.fw, block["start_addr"], block["end_addr"])).fetchall()
    out = []
    for r in rows:
        if r["kind"] == "computed-jump" and r["from_addr"] not in ctx.table_sites:
            continue
        b = ctx.block_at(r["to_addr"])
        if b is not None and b["function_id"] == block["function_id"]:
            out.append(b)
    return out


def static_path(ctx, entry, address):
    """Is there a CFG path (census edges, no feasibility) from `entry` to the
    block holding `address`? True / False / None (bound hit or no blocks)."""
    start, goal = ctx.block_at(entry), ctx.block_at(address)
    if start is None or goal is None:
        return None
    seen, work = {start["start_addr"]}, [start]
    while work:
        b = work.pop()
        if b["start_addr"] == goal["start_addr"]:
            return True
        for s in _successors(ctx, b):
            if s["start_addr"] not in seen:
                if len(seen) >= MAX_PATH_BLOCKS:
                    return None
                seen.add(s["start_addr"])
                work.append(s)
    return False


def _function_reach(ctx, entry):
    if entry is None:
        return {"status": "UNRESOLVED", "census": None, "reason": "unattributed code"}
    r = ctx.conn.execute(
        "SELECT r.status, r.nearest_root_addr, r.nearest_root_kind, r.hops FROM function_reachability r "
        "JOIN functions f ON f.id=r.function_id WHERE r.firmware_id=? AND f.entry=?", (ctx.fw, entry)).fetchone()
    if r is None:
        return {"status": "UNRESOLVED", "census": None, "reason": "no census reachability row"}
    out = {"status": _REACH.get(r["status"], "UNRESOLVED"), "census": r["status"]}
    if r["nearest_root_addr"]:
        out.update({"nearest_root": _h(r["nearest_root_addr"]), "root_kind": r["nearest_root_kind"],
                    "hops": r["hops"]})
    return out


def _coverage(ctx, pcs):
    """Recorded census dynamic coverage of each pc, by scenario."""
    out = {}
    runs = [r["scenario"] for r in ctx.conn.execute(
        "SELECT DISTINCT scenario FROM dynamic_runs WHERE firmware_id=? ORDER BY scenario", (ctx.fw,))]
    for pc in pcs:
        hit = [r["scenario"] for r in ctx.conn.execute(
            "SELECT DISTINCT r.scenario FROM dynamic_coverage c JOIN dynamic_runs r ON r.id=c.dynamic_run_id "
            "WHERE c.firmware_id=? AND c.pc=? ORDER BY r.scenario", (ctx.fw, pc))]
        out[_h(pc)] = {"executed_in": hit, "not_executed_in": [s for s in runs if s not in hit]}
    return out


# -- the operation ----------------------------------------------------------------

def trace_callback_argument(conn, firmware_key, image, site, *, max_callers=MAX_CALLERS, max_blocks=MAX_BLOCKS,
                            max_defs=MAX_DEFS, max_targets=MAX_TARGETS, max_work=MAX_WORK):
    """One-hop caller-argument provenance for the register-indirect `site`.
    Deterministic and JSON-serializable; never follows a second hop."""
    row = conn.execute("SELECT * FROM firmware WHERE key=?", (firmware_key,)).fetchone()
    if row is None:
        raise KeyError(f"unknown firmware {firmware_key!r}")
    if hashlib.sha256(image).hexdigest() != row["sha256"]:
        raise ValueError("image does not match the census firmware digest")
    bounds = {"max_callers": max_callers, "max_blocks": max_blocks, "max_defs": max_defs,
              "max_targets": max_targets, "max_work": max_work, "max_path_blocks": MAX_PATH_BLOCKS}
    base = it.resolve_indirect_call(conn, firmware_key, image, site, max_blocks=max_blocks)
    out = {"analysis": ANALYSIS, "analysis_version": ANALYSIS_VERSION,
           "site_analysis": {"analysis": base["analysis"], "analysis_version": base["analysis_version"]},
           "firmware_key": firmware_key, "firmware_sha256": row["sha256"], "site": _h(site), "bounds": bounds,
           "limitations": list(LIMITATIONS), "instruction": f"{base.get('mnemonic')} {base.get('target_reg') or ''}".strip(),
           "target_register": base.get("target_reg"), "containing_function": base.get("containing_function"),
           "site_pattern": base.get("pattern"), "site_derivation_status": base.get("derivation_status")}
    ctx = it._Ctx(conn, row, image, max_blocks, it.MAX_DEPTH, max_work=max_work)
    patterns = base.get("patterns") or []
    origins = [p for p in patterns if p["pattern"] == "argument"]
    others = [p for p in patterns if p["pattern"] != "argument"]
    out["other_site_components"] = others
    open_reasons, incomplete = [], []
    if base.get("derivation_status") != "ESTABLISHED":
        open_reasons.append(f"the site's own derivation is {base.get('derivation_status')}")
    for p in others:
        if p["pattern"] == "constant-target":
            continue
        open_reasons.append(f"the site's target also derives from {p['pattern']}"
                            + (f" ({p['reason']})" if p.get("reason") else ""))
    if not origins:
        out.update({"provenance_status": "NOT_APPLICABLE", "argument_origins": [], "candidate_targets": [],
                    "target_set": "OPEN", "open_reasons": open_reasons or ["the target does not derive from an "
                                                                          "incoming argument"],
                    "incomplete_reasons": [], "work": {"blocks_visited": 0}})
        return out
    seen_origins, results, statuses, constants, next_hops = set(), [], [], set(), []
    targets = {}
    for p in origins:
        key = (p["function_entry"], p["arg"])
        if key in seen_origins:
            continue
        seen_origins.add(key)
        entry = int(p["function_entry"], 16)
        arg = {"arg": p["arg"], "location": p.get("location", "register")}
        tr = direct_transfers(ctx, entry)
        fn = ctx.conn.execute("SELECT name FROM functions WHERE firmware_id=? AND entry=?", (ctx.fw, entry)).fetchone()
        origin = {"function_entry": p["function_entry"], "function_name": fn["name"] if fn else None,
                  "argument": f"r{p['arg']}" if p["arg"] < 4 else f"stack argument {p['arg']}",
                  "arg": p["arg"], "location": arg["location"],
                  "site_static_path_from_entry": static_path(ctx, entry, site),
                  "entry_reachability": _function_reach(ctx, entry),
                  "address_taken": _address_taken(ctx, entry),
                  **{k: tr[k] for k in ("intraprocedural_entry_branches", "invalid_transfers",
                                        "unverified_pattern_hits", "census_only_edges")}}
        if p.get("location") == "stack":
            origin.update({"entry_sp_offset": p["entry_sp_offset"], "callee_load": p["load_addr"]})
        reasons = []
        if origin["address_taken"]:
            reasons.append(f"the entry {p['function_entry']} is address-taken; indirect callers are not enumerated")
        if tr["census_only_edges"]:
            reasons.append("census edges into the entry have no decoded direct transfer")
        if tr["unverified_pattern_hits"]:
            reasons.append("direct-transfer encodings outside census-decoded code")
        if tr["intraprocedural_entry_branches"]:
            reasons.append("branches back to the entry inside its own function are not followed")
        callers = tr["callers"]
        if len(callers) > max_callers:
            reasons.append(f"{len(callers)} direct transfers exceed the bound {max_callers}")
            incomplete.append(f"caller bound {max_callers} at {p['function_entry']}")
            for c in callers[max_callers:]:
                c.pop("_found", None)
            origin["callers_not_analyzed"] = [c["site"] for c in callers[max_callers:]]
            callers = callers[:max_callers]
        if not callers:
            reasons.append("no direct transfer into the entry was found")
        done, value_reasons = [], []
        for c in callers:
            v = caller_value(ctx, c, arg, max_defs, max_targets)
            caller_entry = int(c["caller_function"], 16) if c["caller_function"] else None
            path = static_path(ctx, caller_entry, int(c["site"], 16)) if caller_entry is not None else None
            reach = _function_reach(ctx, caller_entry)
            conditions = []
            if c["conditional"]:
                conditions.append(f"the transfer at {c['site']} is conditional (cc {c['condition_code']})"
                                  if c["condition_code"] is not None else f"the transfer at {c['site']} is conditional")
            if origin["site_static_path_from_entry"] is not True:
                conditions.append(f"no static path from {p['function_entry']} to {_h(site)} was established")
            conditions.append(f"{p['function_entry']} reaches {_h(site)} with the value unchanged: CFG path only, "
                              "branch feasibility not established")
            if arg["location"] == "stack":
                conditions.append("the outgoing stack slot is not overwritten between the store and the callee's load")
            if path is not True and caller_entry is not None:
                conditions.append(f"no static path from {c['caller_function']} to the transfer {c['site']}")
            rec = {**c, **v, "caller_static_path_to_transfer": path, "caller_reachability": reach,
                   "conditions": conditions}
            if caller_entry is None:
                rec["caller_block_address_taken"] = _address_taken(ctx, int(c["block"], 16))
            hops = [{"function_entry": comp["function_entry"], "argument": comp["argument"]}
                    for comp in v["components"] if comp["kind"] == "forwarded"]
            if hops:
                rec["next_hop"] = hops
                next_hops.extend(hops)
            done.append(rec)
            statuses.append(v["value_status"])
            if v["value_status"] not in ("CONCRETE", "FINITE_TARGET_SET"):
                value_reasons.append(f"caller {c['site']} value is {v['value_status']}")
            for comp in v["components"]:
                if comp["kind"] == "unknown" and comp.get("reason", "").startswith(("block limit", "work budget")):
                    incomplete.append(f"{comp['reason']} at caller {c['site']}")
                if comp["kind"] == "constant":
                    constants.add(comp["raw_value"])
                if comp["kind"] != "constant" or not comp["callable"]:
                    continue
                t = targets.setdefault(comp["target"], {
                    "target": comp["target"], "raw_values": set(), "target_function": comp["target_function"],
                    "target_reachability": comp["target_reachability"], "via": []})
                t["raw_values"].add(comp["raw_value"])
                t["via"].append({"argument_function": p["function_entry"], "argument": origin["argument"],
                                 "caller_site": c["site"], "caller_function": c["caller_function"],
                                 "basis": comp["basis"], "def_addr": comp.get("def_addr"),
                                 "caller_value_status": v["value_status"], "conditions": conditions})
        origin["callers"] = done
        origin["caller_set_complete"] = not reasons
        origin["open_reasons"] = reasons + value_reasons
        open_reasons.extend(reasons + value_reasons)
        results.append(origin)
    if any("bound" in r for r in open_reasons):
        incomplete.extend(r for r in open_reasons if "bound" in r and r not in incomplete)
    worst = next((s for s in _LIMITING if s in statuses), None)
    if worst is None:
        worst = "UNKNOWN" if not statuses else "CONCRETE" if len(constants) == 1 else "FINITE_TARGET_SET"
    invalid_values = sorted({comp["raw_value"] for o in results for c in o["callers"] for comp in c["components"]
                             if comp["kind"] == "constant" and not comp["callable"]})
    out.update({
        "argument_origins": results,
        "candidate_targets": [{**t, "raw_values": sorted(t["raw_values"])} for _, t in sorted(targets.items())],
        "non_callable_values": invalid_values,
        "next_hops": [dict(t) for t in sorted({tuple(sorted(h.items())) for h in next_hops})],
        "caller_value_statuses": {s: statuses.count(s) for s in STATUSES if statuses.count(s)},
        "provenance_status": worst,
        "target_set": "CLOSED" if not open_reasons else "OPEN",
        "open_reasons": sorted(dict.fromkeys(open_reasons)),
        "incomplete_reasons": sorted(dict.fromkeys(incomplete)),
        "work": {"blocks_visited": ctx.work},
    })
    pcs = {site} | {int(o["function_entry"], 16) for o in results} | {int(c["site"], 16) for o in results
                                                                      for c in o["callers"]}
    out["recorded_coverage"] = _coverage(ctx, sorted(pcs))
    return json.loads(json.dumps(out, sort_keys=True, default=str))


def argument_sites(conn, firmware_key, image, max_blocks=MAX_BLOCKS):
    """Census register-indirect sites whose derivation has an argument component."""
    fw = conn.execute("SELECT id FROM firmware WHERE key=?", (firmware_key,)).fetchone()["id"]
    out = []
    for (addr,) in conn.execute("SELECT from_addr FROM indirect_edge_resolutions WHERE firmware_id=? AND "
                                "instr_shape='reg-indirect' ORDER BY from_addr", (fw,)):
        r = it.resolve_indirect_call(conn, firmware_key, image, addr, max_blocks=max_blocks)
        if any(p["pattern"] == "argument" for p in r.get("patterns") or []):
            out.append(addr)
    return out


def main(argv=None):
    import argparse
    import sqlite3

    import db as census_db
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("firmware")
    p.add_argument("--db", default=None)
    p.add_argument("--site", type=lambda s: int(s, 0), action="append", default=[])
    p.add_argument("--all-argument-sites", action="store_true",
                   help="every census register-indirect site whose target derives from an incoming argument")
    p.add_argument("--max-callers", type=int, default=MAX_CALLERS)
    p.add_argument("--max-blocks", type=int, default=MAX_BLOCKS)
    p.add_argument("--max-work", type=int, default=MAX_WORK)
    args = p.parse_args(argv)
    # Read-only: the census database is an input artifact of this analysis.
    conn = sqlite3.connect(f"file:{Path(args.db or census_db.DEFAULT_DB_PATH).resolve()}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT * FROM firmware WHERE key=?", (args.firmware,)).fetchone()
    path = Path(row["path"])
    image = (path if path.is_absolute() else census_db.REPO_ROOT / path).read_bytes()
    sites = list(args.site)
    if args.all_argument_sites:
        sites += argument_sites(conn, args.firmware, image, args.max_blocks)
    doc = {"sites": [trace_callback_argument(conn, args.firmware, image, s, max_callers=args.max_callers,
                                             max_blocks=args.max_blocks, max_work=args.max_work)
                     for s in sorted(set(sites))]}
    print(json.dumps(doc, indent=1, sort_keys=True))


if __name__ == "__main__":
    sys.exit(main())
