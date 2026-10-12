"""APTrace census: statically initialized RAM function-pointer recovery.

Answers exactly one question, mechanically: an UNRESOLVED register-
indirect transfer (`bx rN` / `blx rN`) takes its target from ONE fixed
RAM word (a "slot"); every store into that slot this census knows about
stores a MECHANICALLY CONSTANT value; is that constant a Thumb code
pointer into the image, and where does it lead?

Evidence chain, each link kept separately in the result (never collapsed
to "the target is X"):

  1. Slot load at the consumer site: the branch register is defined by a
     plain word `ldr rN, [rB, #d]` whose base `rB` resolves to a constant
     (literal pool / immediate, via `indexed_writes`' own resolver).
  2. Slot store sites: Ghidra's own reference manager WRITE rows to the
     slot (`memory_accesses`), re-decoded with Capstone and accepted only
     if the store's base register independently resolves to the slot.
  3. Stored value, exactly one of:
       - 'intraprocedural-constant': the value register resolves to a
         literal/immediate inside the writer function;
       - 'callsite-argument': the value register is one of the writer's
         own incoming AAPCS arguments (`interproc_writes`' strict
         linear-chain test) AND, at a resolved direct call edge into the
         writer, that argument register resolves to a literal/immediate.
     Anything else is kept as an UNRESOLVED store -- never guessed.
  4. Thumb canonicalization: the raw stored word is preserved; the
     executable address is `raw & ~1`, recorded with the Thumb bit.
  5. Bounded forwarding: from the canonical target, at most
     MAX_FORWARD_HOPS unconditional direct branches (`b`/`b.w`), each
     optionally preceded by at most MAX_FORWARD_SETUP constant argument
     loads into r0-r3 (a tail-call stub). Every hop and every constant
     argument is recorded. Nothing else is followed.

Register resolution here is CALL-CLOBBER AWARE: a `bl`/`blx` between a
definition and its use kills r0-r3/r12, and the result is then unknown.
Cross-block resolution only walks a strict single-predecessor chain.

Deliberately NOT a points-to analysis: no pointer arithmetic on the slot,
no indexed slots, no multi-hop argument propagation, no aliasing. The set
of store sites is bounded by what Ghidra attributed to the slot's
constant address; a store through a computed pointer is invisible here,
which is why a resolution is graded STRONG (static, every known writer
constant and agreeing), never EXACT.

No names, comments or behavior are consulted -- only operands, literal-
pool bytes, and existing census rows.
"""
from capstone.arm_const import ARM_CC_AL, ARM_CC_INVALID, ARM_OP_IMM, ARM_OP_MEM, ARM_OP_REG, ARM_REG_PC

import indexed_writes as iw
import interproc_writes as ipw

MAX_TRACE_HOPS = 8        # strict single-predecessor chain bound
MAX_FORWARD_HOPS = 3      # unconditional-branch forwarding bound
MAX_FORWARD_SETUP = 2     # constant argument loads allowed before a forwarding branch

ARG_REGS = ("r0", "r1", "r2", "r3")
CALL_CLOBBERED = {"r0", "r1", "r2", "r3", "r12", "ip"}
_CALL_MNEMONICS = ("bl", "blx")
_BRANCH_MNEMONICS = ("b", "b.w")

SOURCE = "ram-fnptr-constant-store"


def _is_call(insn):
    return insn.mnemonic.lower() in _CALL_MNEMONICS


def _writes_reg(insn, reg):
    try:
        _read, written = insn.regs_access()
    except Exception:  # noqa: BLE001 -- capstone without detail for this insn: treat as opaque
        return iw._reg_written_by(insn) == reg
    return reg in {insn.reg_name(r) for r in written}


def _insn_text(insn):
    return f"{insn.mnemonic} {insn.op_str}".strip()


def _plain_load(insn, reg):
    """`ldr reg, [rB, #d]` with a non-PC base and no index register."""
    if insn.mnemonic.lower().split(".")[0] != "ldr":
        return None
    ops = insn.operands
    if len(ops) != 2 or ops[0].type != ARM_OP_REG or insn.reg_name(ops[0].reg) != reg:
        return None
    if ops[1].type != ARM_OP_MEM or ops[1].mem.base == ARM_REG_PC or ops[1].mem.index not in (0, iw.ARM_REG_INVALID):
        return None
    return {"base_reg": insn.reg_name(ops[1].mem.base), "disp": ops[1].mem.disp}


def trace_reg(conn, firmware_id, function_id, entry_addr, block, insns, before_index, reg,
              firmware_bytes, flash_base, max_hops=MAX_TRACE_HOPS):
    """Backward, call-clobber-aware definition search for `reg` as seen
    just before `insns[before_index]`. Returns a dict tagged by `kind`:
      'imm' / 'literal' -- constant (iw._resolve_reg_value's own shapes);
      'load'            -- defined by a plain `ldr reg, [rB, #d]`
                           (`block`/`index` locate it, for the caller to
                           resolve the base);
      'argument'        -- live-in at the function entry, untouched;
      'unknown'         -- anything else, with a reason.
    `trace` lists the consulted definition/clobber addresses."""
    cur_block, cur_insns, idx = block, insns, before_index
    hops = 0
    while True:
        for i in range(idx - 1, -1, -1):
            insn = cur_insns[i]
            if _is_call(insn) and reg in CALL_CLOBBERED:
                return {"kind": "unknown", "reason": f"clobbered by call at 0x{insn.address:x}",
                        "trace": [insn.address]}
            if not _writes_reg(insn, reg):
                continue
            load = _plain_load(insn, reg)
            if load is not None:
                return {"kind": "load", "block": cur_block, "insns": cur_insns, "index": i,
                        "load_addr": insn.address, "instruction": _insn_text(insn), "trace": [insn.address], **load}
            res = iw._resolve_reg_value(cur_insns, cur_block["start_addr"], reg, i + 1, firmware_bytes, flash_base)
            if res["kind"] in ("imm", "literal"):
                # The alias/offset chain the shared resolver followed must not
                # cross a call that clobbers an intermediate argument register.
                lo = min(res["trace"])
                if any(_is_call(x) and lo < x.address < insn.address for x in cur_insns):
                    return {"kind": "unknown", "reason": "definition chain crosses a call", "trace": res["trace"]}
                return res
            return {"kind": "unknown", "reason": res.get("reason", f"unrecognized def ({_insn_text(insn)})"),
                    "trace": [insn.address]}
        if cur_block["start_addr"] == entry_addr:
            return {"kind": "argument", "arg": ARG_REGS.index(reg) if reg in ARG_REGS else None, "trace": []}
        preds = iw._direct_predecessors(conn, firmware_id, function_id, cur_block["start_addr"])
        if len(preds) != 1:
            return {"kind": "unknown", "reason": f"{len(preds)} predecessors (strict single-predecessor chain only)",
                    "trace": []}
        hops += 1
        if hops > max_hops:
            return {"kind": "unknown", "reason": "hop limit", "trace": []}
        cur_block = preds[0]
        cur_insns = iw._decode_block(firmware_bytes, flash_base, cur_block["start_addr"], cur_block["end_addr"])
        idx = len(cur_insns)


def _function_row(conn, function_id):
    return conn.execute("SELECT * FROM functions WHERE id=?", (function_id,)).fetchone() if function_id else None


def _insn_position(conn, firmware_id, function_id, addr, firmware_bytes, flash_base):
    block = iw._block_for_addr(conn, firmware_id, function_id, addr)
    if block is None:
        return None, None, None
    insns = iw._decode_block(firmware_bytes, flash_base, block["start_addr"], block["end_addr"])
    idx = next((i for i, x in enumerate(insns) if x.address == addr), None)
    return block, insns, idx


def slot_load_at_site(conn, firmware_id, firmware_bytes, flash_base, site_addr, function_id, target_reg):
    """Link 1: the constant RAM word the branch register is loaded from."""
    fn = _function_row(conn, function_id)
    block, insns, idx = _insn_position(conn, firmware_id, function_id, site_addr, firmware_bytes, flash_base)
    if fn is None or idx is None:
        return {"status": "unresolved", "reason": "site not inside a census function block"}
    res = trace_reg(conn, firmware_id, function_id, fn["entry"], block, insns, idx, target_reg,
                    firmware_bytes, flash_base)
    if res["kind"] != "load":
        return {"status": "unresolved", "reason": f"branch register is not a plain RAM load ({res.get('reason', res['kind'])})"}
    base = trace_reg(conn, firmware_id, function_id, fn["entry"], res["block"], res["insns"], res["index"],
                     res["base_reg"], firmware_bytes, flash_base)
    if base["kind"] not in ("imm", "literal"):
        return {"status": "unresolved", "reason": f"slot base register not constant ({base.get('reason', base['kind'])})"}
    return {"status": "resolved", "slot_addr": base["value"] + res["disp"], "load_addr": res["load_addr"],
            "load_instruction": res["instruction"], "base_resolution": _public(base)}


def _public(res):
    return {k: v for k, v in res.items() if k not in ("block", "insns")}


def _store_value(conn, firmware_id, firmware_bytes, flash_base, store_addr, function_id, slot_addr):
    """Links 2-3 for ONE store site. Returns a list of writer records,
    each with `value_kind` 'constant' or 'unresolved'."""
    fn = _function_row(conn, function_id)
    block, insns, idx = _insn_position(conn, firmware_id, function_id, store_addr, firmware_bytes, flash_base)
    base_rec = {"store_addr": store_addr, "writer_function_id": function_id}
    if fn is None or idx is None:
        return [{**base_rec, "value_kind": "unresolved", "reason": "store not inside a census function block"}]
    insn = insns[idx]
    base_rec["store_instruction"] = _insn_text(insn)
    mem = iw._mem_operand(insn)
    if not insn.mnemonic.lower().startswith("str") or iw._access_width(insn.mnemonic) != 4 or mem is None \
            or mem.mem.index not in (0, iw.ARM_REG_INVALID) or insn.operands[0].type != ARM_OP_REG:
        return [{**base_rec, "value_kind": "unresolved", "reason": "not a plain word store"}]
    base = trace_reg(conn, firmware_id, function_id, fn["entry"], block, insns, idx,
                     insn.reg_name(mem.mem.base), firmware_bytes, flash_base)
    if base["kind"] not in ("imm", "literal") or base["value"] + mem.mem.disp != slot_addr:
        return [{**base_rec, "value_kind": "unresolved", "reason": "store base does not independently resolve to the slot"}]
    value_reg = insn.reg_name(insn.operands[0].reg)
    base_rec["value_reg"] = value_reg
    val = trace_reg(conn, firmware_id, function_id, fn["entry"], block, insns, idx, value_reg,
                    firmware_bytes, flash_base)
    if val["kind"] in ("imm", "literal"):
        return [{**base_rec, "value_kind": "constant", "derivation": "intraprocedural-constant",
                 "raw_value": val["value"] & 0xFFFFFFFF, "value_resolution": _public(val)}]

    # One hop through the writer's own argument: same strict test as
    # interproc_writes, then the argument resolved at each direct callsite.
    arg = ipw._reg_traces_to_argument(conn, firmware_id, function_id, fn["entry"], value_reg, block, idx, insns,
                                      firmware_bytes, flash_base)
    if arg is None:
        return [{**base_rec, "value_kind": "unresolved", "reason": f"stored value not constant ({val.get('reason', val['kind'])})"}]

    arg_reg = ARG_REGS[arg]
    out = []
    callsites, unmatched = _direct_call_instructions(conn, firmware_id, fn, firmware_bytes, flash_base)
    for edge_from, caller_id in unmatched:
        out.append({**base_rec, "derivation": "callsite-argument", "arg_reg": arg_reg, "callsite_addr": edge_from,
                    "caller_function_id": caller_id, "value_kind": "unresolved",
                    "reason": "call edge with no direct bl/blx to the writer in its block"})
    for call_addr, caller_id in callsites:
        caller = _function_row(conn, caller_id)
        cblock, cinsns, cidx = _insn_position(conn, firmware_id, caller_id, call_addr, firmware_bytes, flash_base)
        rec = {**base_rec, "derivation": "callsite-argument", "arg_reg": arg_reg,
               "callsite_addr": call_addr, "caller_function_id": caller_id}
        res = trace_reg(conn, firmware_id, caller["id"], caller["entry"], cblock, cinsns, cidx, arg_reg,
                        firmware_bytes, flash_base)
        if res["kind"] in ("imm", "literal"):
            out.append({**rec, "value_kind": "constant", "raw_value": res["value"] & 0xFFFFFFFF,
                        "value_resolution": _public(res)})
        else:
            out.append({**rec, "value_kind": "unresolved",
                        "reason": f"argument not constant at callsite ({res.get('reason', res['kind'])})"})
    if not out:
        out.append({**base_rec, "value_kind": "unresolved", "derivation": "callsite-argument", "arg_reg": arg_reg,
                    "reason": "stored value is an argument but no resolved direct callsite exists"})
    # A writer also reachable by a non-call transfer, or whose address is
    # taken, has callers this pass cannot enumerate.
    other_entries = conn.execute(
        "SELECT COUNT(*) FROM edges WHERE firmware_id=? AND to_addr=? AND kind!='call' "
        "AND (from_function_id IS NULL OR from_function_id!=?)", (firmware_id, fn["entry"], function_id)).fetchone()[0]
    taken = conn.execute(
        "SELECT COUNT(*) FROM function_pointers WHERE firmware_id=? AND target_addr=?",
        (firmware_id, fn["entry"])).fetchone()[0]
    if other_entries or taken:
        out.append({**base_rec, "value_kind": "unresolved", "derivation": "callsite-argument", "arg_reg": arg_reg,
                    "reason": f"writer has {other_entries} non-call entr{'y' if other_entries == 1 else 'ies'} "
                              f"and {taken} flash pointer(s) to it -- caller set incomplete"})
    return out


def _direct_call_instructions(conn, firmware_id, callee, firmware_bytes, flash_base):
    """The exact `bl`/`blx #imm` instructions calling `callee`, from every
    resolved call edge into it. Edge `from_addr` granularity differs by
    source (Ghidra's block model reports the containing BLOCK start, the
    Capstone sweep the instruction itself), so each edge is matched to
    the call instruction(s) in its block whose immediate target is the
    callee entry, then deduplicated. Returns (sorted [(call_addr,
    caller_id)], [(edge_from_addr, caller_id)] for edges with no match)."""
    found, unmatched = set(), []
    for e in conn.execute(
            "SELECT DISTINCT from_addr, from_function_id FROM edges WHERE firmware_id=? AND kind='call' AND resolved=1 "
            "AND to_function_id=? AND from_function_id IS NOT NULL ORDER BY from_addr", (firmware_id, callee["id"])):
        block = iw._block_for_addr(conn, firmware_id, e["from_function_id"], e["from_addr"])
        insns = iw._decode_block(firmware_bytes, flash_base, block["start_addr"], block["end_addr"]) if block else []
        hits = [x.address for x in insns
                if _is_call(x) and x.address >= e["from_addr"] and x.operands
                and x.operands[0].type == ARM_OP_IMM and x.operands[0].imm == callee["entry"]]
        if not hits:
            unmatched.append((e["from_addr"], e["from_function_id"]))
        found.update((a, e["from_function_id"]) for a in hits)
    return sorted(found), unmatched


def slot_writers(conn,firmware_id, firmware_bytes, flash_base, slot_addr):
    """Every store this census attributes to `slot_addr` (Ghidra WRITE
    refs), each classified per `_store_value`."""
    rows = conn.execute(
        "SELECT DISTINCT from_addr, from_function_id FROM memory_accesses WHERE firmware_id=? AND to_addr=? "
        "AND direction='WRITE' ORDER BY from_addr", (firmware_id, slot_addr)).fetchall()
    out = []
    for r in rows:
        out.extend(_store_value(conn, firmware_id, firmware_bytes, flash_base, r["from_addr"],
                                r["from_function_id"], slot_addr))
    return out


def canonical_code_pointer(raw, firmware_bytes, flash_base):
    """Link 4. The raw word is never replaced by the canonical address."""
    canonical = raw & ~1
    in_image = flash_base <= canonical < flash_base + len(firmware_bytes)
    decodes = False
    if in_image:
        off = canonical - flash_base
        decodes = bool(list(iw._md().disasm(firmware_bytes[off:off + 4], canonical, count=1)))
    return {"raw_value": raw, "thumb_bit": raw & 1, "canonical_target": canonical,
            "canonicalization": "thumb-bit-cleared" if raw & 1 else "none",
            "in_image": in_image, "decodes": decodes,
            "is_code_pointer": bool(raw & 1) and in_image and decodes}


def follow_forwarding(firmware_bytes, flash_base, addr, max_hops=MAX_FORWARD_HOPS, max_setup=MAX_FORWARD_SETUP):
    """Link 5. Returns {'terminal_target', 'hops': [...], 'stopped': reason}."""
    end = flash_base + len(firmware_bytes)
    hops = []
    cur = addr
    seen = {addr}
    md = iw._md()
    while True:
        if len(hops) >= max_hops:
            return {"terminal_target": cur, "hops": hops, "stopped": "hop limit"}
        off = cur - flash_base
        insns = list(md.disasm(firmware_bytes[off:off + 4 * (max_setup + 1)], cur, count=max_setup + 1))
        setup = []
        branch = None
        for insn in insns:
            m = insn.mnemonic.lower()
            ops = insn.operands
            if m in _BRANCH_MNEMONICS and len(ops) == 1 and ops[0].type == ARM_OP_IMM \
                    and insn.cc in (ARM_CC_AL, ARM_CC_INVALID):
                branch = insn
                break
            if len(setup) >= max_setup or not ops or ops[0].type != ARM_OP_REG \
                    or insn.reg_name(ops[0].reg) not in ARG_REGS:
                break
            reg = insn.reg_name(ops[0].reg)
            res = iw._resolve_reg_value([insn], insn.address, reg, 1, firmware_bytes, flash_base)
            if res["kind"] not in ("imm", "literal"):
                break
            setup.append({"addr": insn.address, "instruction": _insn_text(insn), "reg": reg,
                          "value": res["value"] & 0xFFFFFFFF, "literal_addr": res.get("literal_addr")})
        if branch is None:
            return {"terminal_target": cur, "hops": hops,
                    "stopped": "no unconditional direct branch" if hops else "not a forwarding stub"}
        target = branch.operands[0].imm
        if not (flash_base <= target < end) or target in seen:
            return {"terminal_target": cur, "hops": hops, "stopped": "branch target outside image or cycle"}
        hops.append({"from": cur, "branch_addr": branch.address, "instruction": _insn_text(branch), "to": target,
                     "kind": "tail-branch-with-constant-args" if setup else "unconditional-branch",
                     "constant_args": setup})
        seen.add(target)
        cur = target


def resolve_function_pointers(conn, firmware_id, firmware_bytes, flash_base):
    """Driver: every unresolved register-indirect transfer -> slot ->
    writers -> code pointers. One row per (site, writer record); sites
    whose branch register is not a constant-slot load produce nothing."""
    from indirect_resolve import decode_instruction  # local: keeps this module importable standalone

    sites = conn.execute(
        "SELECT DISTINCT from_addr, from_function_id FROM edges WHERE firmware_id=? AND kind LIKE 'computed%' "
        "AND resolved=0 AND from_function_id IS NOT NULL ORDER BY from_addr", (firmware_id,)).fetchall()
    rows = []
    for site in sites:
        mnem, shape, reg = decode_instruction(firmware_bytes, flash_base, site["from_addr"])
        if shape != "reg-indirect" or reg is None:
            continue
        reg = {"r9": "sb", "r10": "sl", "r11": "fp", "r12": "ip"}.get(reg, reg)  # back to capstone's own names
        slot = slot_load_at_site(conn, firmware_id, firmware_bytes, flash_base, site["from_addr"],
                                 site["from_function_id"], reg)
        if slot["status"] != "resolved":
            continue
        writers = slot_writers(conn, firmware_id, firmware_bytes, flash_base, slot["slot_addr"])
        constants = [w for w in writers if w["value_kind"] == "constant"]
        unresolved = [w for w in writers if w["value_kind"] != "constant"]
        pointers = {}
        for w in constants:
            ptr = canonical_code_pointer(w["raw_value"], firmware_bytes, flash_base)
            w["pointer"] = ptr
            if ptr["is_code_pointer"]:
                pointers.setdefault(ptr["canonical_target"], ptr)
        # STRONG only when every known writer is a constant code pointer and
        # they all agree; anything else stays visible but WEAK.
        agreed = len(pointers) == 1 and not unresolved and all(w["pointer"]["is_code_pointer"] for w in constants)
        confidence = "STRONG" if agreed else "WEAK"
        for w in writers:
            ptr = w.get("pointer")
            fwd = follow_forwarding(firmware_bytes, flash_base, ptr["canonical_target"]) \
                if ptr and ptr["is_code_pointer"] else None
            rows.append({
                "firmware_id": firmware_id, "consumer_site": site["from_addr"],
                "consumer_function_id": site["from_function_id"], "consumer_instruction": f"{mnem} {reg}",
                "slot_addr": slot["slot_addr"], "slot_load_addr": slot["load_addr"],
                "store_addr": w["store_addr"], "writer_function_id": w["writer_function_id"],
                "value_reg": w.get("value_reg"), "derivation": w.get("derivation"),
                "callsite_addr": w.get("callsite_addr"), "caller_function_id": w.get("caller_function_id"),
                "arg_reg": w.get("arg_reg"), "value_kind": w["value_kind"],
                "raw_value": w.get("raw_value"),
                "thumb_bit": ptr["thumb_bit"] if ptr else None,
                "canonical_target": ptr["canonical_target"] if ptr and ptr["is_code_pointer"] else None,
                "terminal_target": fwd["terminal_target"] if fwd else None,
                "forwarding_json": _json(fwd) if fwd else None,
                "confidence": confidence if ptr and ptr["is_code_pointer"] else None,
                "provenance_json": _json({"slot": slot, "writer": {k: v for k, v in w.items() if k != "pointer"},
                                          "pointer": ptr}),
                "source": SOURCE,
            })
    return rows


def _json(obj):
    import json
    return json.dumps(obj, sort_keys=True, default=str)


def seed_targets(rows):
    """Code addresses a discovery tool should be seeded with: the canonical
    pointer target and its forwarding terminal, for STRONG rows only."""
    out = {}
    for r in rows:
        if r["confidence"] != "STRONG":
            continue
        for addr, role in ((r["canonical_target"], "resolved-function-pointer"),
                           (r["terminal_target"], "forwarding-terminal")):
            if addr is not None:
                out.setdefault(addr, {"addr": addr, "role": role, "consumer_site": r["consumer_site"],
                                      "slot_addr": r["slot_addr"], "raw_value": r["raw_value"]})
    return [out[a] for a in sorted(out)]

