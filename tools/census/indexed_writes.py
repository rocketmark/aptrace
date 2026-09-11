"""APTrace census: mechanical computed/indexed RAM-write recovery.

Ghidra's own reference manager (the source behind `memory_accesses`)
only resolves a STORE whose destination is a single fixed literal
address -- `strb rX, [rBase, #imm]` where `rBase` was itself loaded from
a literal pool folds to one absolute `to_addr`. A `strb rX, [rBase,
rIndex]`-style store (a REGISTER, not an immediate, supplies part of the
address) can never produce one fixed `to_addr`, so it is invisible to
that table even when it demonstrably targets the array being mapped --
this module is the "no xref found is not the same as no writer exists"
gap-closer `docs/tooling/census.md`'s state-map section calls for.

Method (deterministic, bounded, no semantic inference):

1. Every STORE instruction (str/strb/strh, 16- or 32-bit encoding) whose
   Capstone-decoded memory operand carries a REGISTER index (not just an
   immediate displacement) is a candidate -- found by decoding every
   `basic_blocks` row's own byte range (Ghidra's own block boundaries,
   not a blind linear/skipdata sweep).
2. The candidate's BASE register is resolved via a bounded, same-block,
   backward register-definition walk (`_resolve_reg_value`): a plain
   immediate MOV, a PC-relative literal load (resolved by reading the
   flash bytes at the computed literal-pool address), or a short chain
   of ADD/SUB-immediate/MOV-register aliases on top of one of those --
   capped at MAX_CHAIN_DEPTH steps. A base that does not bottom out at a
   literal-pool load is left UNRESOLVED and the candidate is dropped
   (this module cannot confirm it targets the array being mapped, and
   does not guess).
3. Only a candidate whose resolved base falls INSIDE the mapped array's
   own byte range advances further -- this is a membership test, not a
   proximity heuristic.
4. The INDEX register is resolved by the same same-block walk first
   (an immediate index makes the destination slot EXACT). If the index
   is not defined within the same block, a bounded, EXPLICITLY-SCOPED
   two-hop predecessor-block pattern match (`edges`-driven, never a
   general CFG/loop analysis) looks for exactly:
     - FINITE_SLOT_SET: every DIRECT predecessor of the store's block
       ends in `cmp <index_reg>, #imm; beq <store's block>` (an
       equality-gated fan-in), no other predecessor reaches the block
       unconditionally.
     - INDEXED_WRITER_RANGE: a SINGLE direct predecessor block ends in
       `cmp <index_reg>, #N; b<LT/LE/CC/LS> <target reaching the store's
       block>`, AND some block with a direct edge into that same compare
       block ends in a plain `movs <index_reg>, #K` -- the textbook
       `for (i=K; i<N; i++)` compiled shape, nothing more general.
   Anything else -- multi-hop loops, computed indices (shifts, table
   loads, arithmetic between two non-constant registers), or a fan-in
   this module's two shapes don't match -- is recorded as
   UNKNOWN_COMPUTED_WRITE, with whatever partial evidence was found kept
   in `derivation_json`, never discarded and never guessed past.

No variable/function name, comment, or surrounding behavior is consulted
anywhere in this module -- only instruction operands, literal-pool
bytes, and `edges` control-flow rows already in the census database.
"""
import struct

from capstone import CS_ARCH_ARM, CS_MODE_THUMB, Cs
from capstone.arm_const import ARM_OP_IMM, ARM_OP_MEM, ARM_OP_REG, ARM_REG_INVALID, ARM_REG_PC, ARM_SFT_LSL

MAX_CHAIN_DEPTH = 4          # same-block register-alias/offset chase bound
MAX_FINITE_CANDIDATES = 8    # beyond this many equality-gated predecessors, call it UNKNOWN, not "finite"

_WIDTH_BY_MNEMONIC_PREFIX = (("strb", 1), ("strh", 2), ("str", 4))

_STORE_COND_TO_UPPER_BOUND_KIND = {
    "lt": "exclusive", "cc": "exclusive", "lo": "exclusive",  # index < N
    "le": "inclusive", "ls": "inclusive",                      # index <= N
}


def _md():
    m = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    m.detail = True
    return m


def _access_width(mnemonic):
    m = mnemonic.lower().split(".")[0]
    for prefix, width in _WIDTH_BY_MNEMONIC_PREFIX:
        if m == prefix:
            return width
    return None


def _decode_block(firmware_bytes, flash_base, start_addr, end_addr):
    """Every instruction Capstone finds inside [start_addr, end_addr] --
    Ghidra's OWN block boundary, so no skipdata/resync guessing is
    needed. Returns a list of capstone CsInsn, in address order."""
    off = start_addr - flash_base
    length = (end_addr - start_addr) + 1  # end_addr is the block's inclusive last byte per schema.sql
    if off < 0 or off + length > len(firmware_bytes):
        return []
    return list(_md().disasm(firmware_bytes[off:off + length], start_addr))


def _mem_operand(insn):
    for op in insn.operands:
        if op.type == ARM_OP_MEM:
            return op
    return None


def _store_candidate(insn):
    """None, or a dict describing a register-indexed store's raw operand
    shape (no dataflow resolution yet)."""
    if not insn.mnemonic.lower().startswith("str"):
        return None
    width = _access_width(insn.mnemonic)
    if width is None:
        return None
    mem_op = _mem_operand(insn)
    if mem_op is None or mem_op.mem.index in (0, ARM_REG_INVALID):
        return None  # immediate-offset-only store -- already covered by memory_accesses
    scale = mem_op.mem.scale if mem_op.mem.scale else 1
    shift_amount = mem_op.shift.value if mem_op.shift.type == ARM_SFT_LSL else 0
    return {
        "from_addr": insn.address,
        "mnemonic": insn.mnemonic,
        "width": width,
        "base_reg": insn.reg_name(mem_op.mem.base),
        "index_reg": insn.reg_name(mem_op.mem.index),
        "effective_scale": scale * (1 << shift_amount),
        "disp": mem_op.mem.disp,
    }


def _literal_pool_target(insn_addr, disp_bytes):
    """T1 LDR-literal's own PC-relative rule: (address of the LDR + 4),
    word-aligned, plus the byte displacement -- the ARMv7-M architecture's
    own defined encoding, not a guess. `disp_bytes` is Capstone's own
    `mem.disp` field, which is already the fully-scaled byte offset (its
    `#N` in `ldr rD, [pc, #N]`), NOT the raw imm8 encoding field -- do not
    multiply by 4 again here."""
    return ((insn_addr + 4) & ~3) + disp_bytes


def _read_flash_word(firmware_bytes, flash_base, addr):
    off = addr - flash_base
    if off < 0 or off + 4 > len(firmware_bytes):
        return None
    return struct.unpack_from("<I", firmware_bytes, off)[0]


def _reg_written_by(insn):
    """The single register `insn` DEFINES, if it's one of the small set
    of def shapes this module's chain-resolver understands (plain
    immediate MOV, PC-relative literal LDR, register-to-register MOV,
    or ADD/SUB-immediate) -- None for anything else (still a valid,
    disclosed stopping point, just not a shape this module chases)."""
    m = insn.mnemonic.lower().split(".")[0]
    if not insn.operands or insn.operands[0].type != ARM_OP_REG:
        return None
    return insn.reg_name(insn.operands[0].reg)


def _resolve_reg_value(insns, block_start, reg, before_index, firmware_bytes, flash_base, depth=0):
    """Same-block, backward, bounded register-value resolver. Returns a
    dict tagged by `kind`:
      'imm'            -- {'kind':'imm','value':int,'trace':[...]}
      'literal'        -- {'kind':'literal','literal_addr':int,'value':int,'trace':[...]}
      'not_found'      -- defined nowhere earlier in this block (the
                            value comes from a predecessor block)
      'unknown'        -- defined by something this module doesn't
                            interpret (e.g. a memory load, a multiply,
                            two-register arithmetic)
    `trace` lists every instruction address consulted, in order, for
    provenance -- never just the final label."""
    if depth > MAX_CHAIN_DEPTH:
        return {"kind": "unknown", "reason": "chain-depth-exceeded", "trace": []}
    trace = []
    for i in range(before_index - 1, -1, -1):
        insn = insns[i]
        dest = _reg_written_by(insn)
        if dest != reg:
            continue
        trace.append(insn.address)
        m = insn.mnemonic.lower().split(".")[0]
        ops = insn.operands
        if m in ("movs", "mov") and len(ops) == 2 and ops[1].type == ARM_OP_IMM:
            return {"kind": "imm", "value": ops[1].imm, "trace": trace}
        if m == "ldr" and len(ops) == 2 and ops[1].type == ARM_OP_MEM and \
                ops[1].mem.base == ARM_REG_PC and ops[1].mem.index in (0, ARM_REG_INVALID):
            lit_addr = _literal_pool_target(insn.address, ops[1].mem.disp)
            value = _read_flash_word(firmware_bytes, flash_base, lit_addr)
            if value is None:
                return {"kind": "unknown", "reason": "literal-pool-out-of-range", "trace": trace}
            return {"kind": "literal", "literal_addr": lit_addr, "value": value, "trace": trace}
        if m in ("adds", "subs", "add", "sub") and len(ops) == 3 and \
                ops[1].type == ARM_OP_REG and ops[2].type == ARM_OP_IMM:
            delta = ops[2].imm if m.startswith("add") else -ops[2].imm
            src = insn.reg_name(ops[1].reg)
            sub = _resolve_reg_value(insns, block_start, src, i, firmware_bytes, flash_base, depth + 1)
            sub = dict(sub)
            sub["trace"] = trace + sub.get("trace", [])
            if sub["kind"] in ("imm", "literal"):
                sub["value"] = sub["value"] + delta
            return sub
        if m == "mov" and len(ops) == 2 and ops[1].type == ARM_OP_REG:
            src = insn.reg_name(ops[1].reg)
            sub = _resolve_reg_value(insns, block_start, src, i, firmware_bytes, flash_base, depth + 1)
            sub = dict(sub)
            sub["trace"] = trace + sub.get("trace", [])
            return sub
        return {"kind": "unknown", "reason": f"unrecognized def ({insn.mnemonic} {insn.op_str})", "trace": trace}
    return {"kind": "not_found", "trace": trace}


MAX_CROSS_BLOCK_HOPS = 8


def _resolve_reg_across_blocks(conn, firmware_id, function_id, block, reg, before_index, insns,
                                firmware_bytes, flash_base, max_hops=MAX_CROSS_BLOCK_HOPS, _visited=None):
    """Same-block resolution first (`_resolve_reg_value`); if that comes
    back 'not_found' (the register is live-in to this block, defined
    somewhere earlier), walk EVERY direct predecessor (`edges`-driven,
    real control flow, not a guess) and recurse, up to `max_hops` -- a
    compiled function's own "load my literal pointers once, use them
    from many later blocks after a chain of validation branches" shape
    is common and otherwise invisible to a same-block-only resolver.
    Only accepted if ALL predecessor paths bottom out at the SAME
    literal/immediate value -- any disagreement, or any path still
    unresolved at the hop limit, is reported as 'unknown'/'not_found'
    rather than picking one arbitrarily. Cycle-safe via `_visited`
    (block start addresses already walked on this path)."""
    same_block = _resolve_reg_value(insns, block["start_addr"], reg, before_index, firmware_bytes, flash_base)
    if same_block["kind"] != "not_found":
        return same_block
    if max_hops <= 0:
        return same_block
    visited = set(_visited) if _visited else set()
    if block["start_addr"] in visited:
        return {"kind": "unknown", "reason": "cycle in predecessor walk", "trace": same_block["trace"]}
    visited.add(block["start_addr"])

    preds = _direct_predecessors(conn, firmware_id, function_id, block["start_addr"])
    if not preds:
        return same_block  # 'not_found' -- no predecessor evidence at all

    pred_results = []
    for pred in preds:
        pred_insns = _decode_block(firmware_bytes, flash_base, pred["start_addr"], pred["end_addr"])
        pred_results.append(_resolve_reg_across_blocks(
            conn, firmware_id, function_id, pred, reg, len(pred_insns), pred_insns,
            firmware_bytes, flash_base, max_hops - 1, visited))

    kinds = {r["kind"] for r in pred_results}
    if kinds == {"literal"} and len({r["value"] for r in pred_results}) == 1:
        merged = dict(pred_results[0])
        merged["trace"] = same_block["trace"] + [p["trace"] for p in pred_results]
        return merged
    if kinds == {"imm"} and len({r["value"] for r in pred_results}) == 1:
        merged = dict(pred_results[0])
        merged["trace"] = same_block["trace"] + [p["trace"] for p in pred_results]
        return merged
    return {"kind": "unknown",
            "reason": f"{len(preds)} predecessor(s) via edges did not all resolve to one consistent value "
                      f"(kinds found: {sorted(kinds)})",
            "trace": same_block["trace"]}


def _block_for_addr(conn, firmware_id, function_id, addr):
    return conn.execute(
        "SELECT * FROM basic_blocks WHERE firmware_id=? AND function_id=? "
        "AND start_addr<=? AND end_addr>=?", (firmware_id, function_id, addr, addr)).fetchone()


def _direct_predecessors(conn, firmware_id, function_id, block_start):
    """Every block with a fallthrough/branch/cbranch edge landing exactly
    on `block_start`, within the SAME function -- one hop, via `edges`
    (already-collected evidence, no new CFG computation)."""
    rows = conn.execute(
        "SELECT DISTINCT from_addr FROM edges WHERE firmware_id=? AND from_function_id=? "
        "AND to_addr=? AND kind IN ('fallthrough','branch','cbranch')",
        (firmware_id, function_id, block_start)).fetchall()
    out = []
    for r in rows:
        b = _block_for_addr(conn, firmware_id, function_id, r["from_addr"])
        if b:
            out.append(b)
    return out


def _last_two(insns):
    return insns[-2:] if len(insns) >= 2 else None


def _bound_index_cross_block(conn, firmware_id, function_id, block_row, index_reg,
                              firmware_bytes, flash_base):
    """The two explicitly-scoped fan-in shapes described in this module's
    docstring. Returns (classification, detail_dict) where classification
    is one of 'finite', 'range', or None (no recognized shape -- caller
    falls back to UNKNOWN_COMPUTED_WRITE)."""
    preds = _direct_predecessors(conn, firmware_id, function_id, block_row["start_addr"])
    if not preds:
        return None, {"reason": "no direct predecessor block found via edges"}

    # --- FINITE_SLOT_SET: every predecessor ends cmp index_reg,#imm; beq <this block> ---
    finite_values = []
    all_predecessors_are_equality_gated = True
    for pred in preds:
        insns = _decode_block(firmware_bytes, flash_base, pred["start_addr"], pred["end_addr"])
        tail = _last_two(insns)
        if not tail:
            all_predecessors_are_equality_gated = False
            continue
        cmp_insn, branch_insn = tail
        val = _match_cmp_beq(cmp_insn, branch_insn, index_reg, block_row["start_addr"])
        if val is None:
            all_predecessors_are_equality_gated = False
        else:
            finite_values.append({"value": val, "from_addr": cmp_insn.address, "pred_block": pred["start_addr"]})
    if all_predecessors_are_equality_gated and 0 < len(finite_values) <= MAX_FINITE_CANDIDATES:
        return "finite", {"candidates": finite_values}

    # --- INDEXED_WRITER_RANGE: one predecessor ends cmp index_reg,#N; b<LT/LE/CC/LS> <this block or fallthrough> ---
    if len(preds) == 1:
        pred = preds[0]
        insns = _decode_block(firmware_bytes, flash_base, pred["start_addr"], pred["end_addr"])
        tail = _last_two(insns)
        if tail:
            cmp_insn, branch_insn = tail
            bound = _match_cmp_range_guard(cmp_insn, branch_insn, index_reg, block_row["start_addr"])
            if bound is not None:
                n, upper_kind = bound
                init = _find_init_in_predecessors_of(
                    conn, firmware_id, function_id, pred["start_addr"], index_reg, firmware_bytes, flash_base)
                if init is not None:
                    return "range", {
                        "lower_bound": init["value"], "upper_bound": n, "upper_bound_kind": upper_kind,
                        "guard_from_addr": cmp_insn.address, "init_from_addr": init["from_addr"],
                    }
                return None, {"reason": "found upper-bound guard but no confirmed lower-bound "
                                         "initialization in a direct predecessor of the guard block",
                              "guard_from_addr": cmp_insn.address, "upper_bound": n}
    return None, {"reason": "no recognized finite-equality-fan-in or single-guard+init range shape"}


def _match_cmp_beq(cmp_insn, branch_insn, index_reg, target_block_start):
    if cmp_insn.mnemonic.lower().split(".")[0] != "cmp":
        return None
    ops = cmp_insn.operands
    if len(ops) != 2 or ops[0].type != ARM_OP_REG or ops[1].type != ARM_OP_IMM:
        return None
    if cmp_insn.reg_name(ops[0].reg) != index_reg:
        return None
    if not branch_insn.mnemonic.lower().startswith("beq"):
        return None
    if not branch_insn.operands or branch_insn.operands[0].type != ARM_OP_IMM:
        return None
    if branch_insn.operands[0].imm != target_block_start:
        return None
    return ops[1].imm


def _match_cmp_range_guard(cmp_insn, branch_insn, index_reg, target_block_start):
    if cmp_insn.mnemonic.lower().split(".")[0] != "cmp":
        return None
    ops = cmp_insn.operands
    if len(ops) != 2 or ops[0].type != ARM_OP_REG or ops[1].type != ARM_OP_IMM:
        return None
    if cmp_insn.reg_name(ops[0].reg) != index_reg:
        return None
    bm = branch_insn.mnemonic.lower()
    cond = None
    for suffix, kind in _STORE_COND_TO_UPPER_BOUND_KIND.items():
        if bm == f"b{suffix}" or bm == f"b{suffix}.w":
            cond = kind
            break
    if cond is None:
        return None
    if not branch_insn.operands or branch_insn.operands[0].type != ARM_OP_IMM:
        return None
    if branch_insn.operands[0].imm != target_block_start:
        return None
    return ops[1].imm, cond


def _find_init_in_predecessors_of(conn, firmware_id, function_id, guard_block_start, index_reg,
                                   firmware_bytes, flash_base):
    for pred in _direct_predecessors(conn, firmware_id, function_id, guard_block_start):
        insns = _decode_block(firmware_bytes, flash_base, pred["start_addr"], pred["end_addr"])
        for insn in reversed(insns):
            if _reg_written_by(insn) == index_reg:
                m = insn.mnemonic.lower().split(".")[0]
                if m in ("movs", "mov") and len(insn.operands) == 2 and insn.operands[1].type == ARM_OP_IMM:
                    return {"value": insn.operands[1].imm, "from_addr": insn.address}
                break  # nearest def isn't a plain immediate -- don't chase further
    return None


def find_computed_writers(conn, firmware_id, firmware_bytes, flash_base, base, count, width):
    """The whole-image scan: every basic block, every register-indexed
    store, classified against the array [base, base+count*width).
    Returns a list of result dicts (one per candidate whose resolved
    base address falls inside the array), each with `classification` in
    {'INDEXED_WRITER_EXACT_SLOT','INDEXED_WRITER_FINITE_SLOT_SET',
    'INDEXED_WRITER_RANGE','UNKNOWN_COMPUTED_WRITE'} plus the full
    derivation trace and the concrete slot index/indices it resolves to
    (empty for UNKNOWN_COMPUTED_WRITE -- see `applies_to_all_slots`)."""
    array_end = base + count * width
    blocks = conn.execute(
        "SELECT * FROM basic_blocks WHERE firmware_id=? AND function_id IS NOT NULL",
        (firmware_id,)).fetchall()

    results = []
    for block in blocks:
        insns = _decode_block(firmware_bytes, flash_base, block["start_addr"], block["end_addr"])
        for idx, insn in enumerate(insns):
            cand = _store_candidate(insn)
            if cand is None:
                continue
            base_res = _resolve_reg_across_blocks(
                conn, firmware_id, block["function_id"], block, cand["base_reg"], idx, insns,
                firmware_bytes, flash_base)
            if base_res["kind"] != "literal":
                continue  # can't confirm this write targets our array at all -- not a candidate
            resolved_base = base_res["value"] + cand["disp"]
            if not (base <= resolved_base < array_end):
                continue  # resolves to a real address, just not inside the array being mapped

            index_res = _resolve_reg_across_blocks(
                conn, firmware_id, block["function_id"], block, cand["index_reg"], idx, insns,
                firmware_bytes, flash_base)
            derivation = {
                "instruction": f"{insn.mnemonic} {insn.op_str}",
                "base_reg": cand["base_reg"], "index_reg": cand["index_reg"],
                "effective_scale": cand["effective_scale"], "disp": cand["disp"],
                "base_resolution": base_res, "resolved_base_addr": resolved_base,
                "index_resolution": index_res,
            }

            classification = "UNKNOWN_COMPUTED_WRITE"
            slots = []
            applies_to_all = False
            if index_res["kind"] == "imm":
                touched = resolved_base + index_res["value"] * cand["effective_scale"]
                if base <= touched < array_end and (touched - base) % width == 0:
                    classification = "INDEXED_WRITER_EXACT_SLOT"
                    slots = [(touched - base) // width]
                else:
                    continue  # constant index, but lands outside the mapped array -- not this array's writer
            else:
                cross = None
                if index_res["kind"] in ("not_found", "unknown"):
                    kind, detail = _bound_index_cross_block(
                        conn, firmware_id, block["function_id"], block, cand["index_reg"],
                        firmware_bytes, flash_base)
                    derivation["cross_block_search"] = detail
                    cross = kind
                if cross == "finite":
                    vals = sorted({c["value"] for c in derivation["cross_block_search"]["candidates"]})
                    touched_slots = sorted({
                        (resolved_base + v * cand["effective_scale"] - base) // width
                        for v in vals
                        if base <= resolved_base + v * cand["effective_scale"] < array_end
                        and (resolved_base + v * cand["effective_scale"] - base) % width == 0
                    })
                    if touched_slots:
                        classification = "INDEXED_WRITER_FINITE_SLOT_SET"
                        slots = touched_slots
                elif cross == "range":
                    d = derivation["cross_block_search"]
                    lo, hi = d["lower_bound"], d["upper_bound"]
                    hi_slot = hi if d["upper_bound_kind"] == "exclusive" else hi + 1
                    touched_slots = sorted({
                        (resolved_base + v * cand["effective_scale"] - base) // width
                        for v in range(lo, hi_slot)
                        if base <= resolved_base + v * cand["effective_scale"] < array_end
                        and (resolved_base + v * cand["effective_scale"] - base) % width == 0
                    })
                    if touched_slots:
                        classification = "INDEXED_WRITER_RANGE"
                        slots = touched_slots
                if classification == "UNKNOWN_COMPUTED_WRITE":
                    applies_to_all = True

            results.append({
                "from_addr": insn.address, "from_function_id": block["function_id"],
                "mnemonic": insn.mnemonic, "access_width": cand["width"],
                "base_reg": cand["base_reg"], "index_reg": cand["index_reg"],
                "scale": cand["effective_scale"], "disp": cand["disp"],
                "resolved_base_addr": resolved_base,
                "classification": classification,
                "slots": slots, "applies_to_all_slots": applies_to_all,
                "derivation": derivation,
            })
    return results
