"""APTrace census: minimal, bounded one-hop interprocedural RAM-write
recovery.

Answers exactly one question, mechanically: caller passes a pointer (or
pointer + constant) as an argument into a callee; the callee writes
through that argument (at the argument itself, or at a constant offset
from it); does that write land inside the caller-supplied state array?

Deliberately NOT a general alias analyzer:
  - exactly ONE direct, resolved `edges` call edge (no recursion, no
    multi-hop propagation);
  - only the plain AAPCS argument registers r0-r3;
  - a callee effect is recognized ONLY as "writes at argN" or "writes at
    argN + constant offset" (a same-block-or-strict-linear-chain
    immediate-offset store) -- no indexed/register-offset callee stores,
    no finite candidate sets, no bounded ranges, no memcpy/memset
    special-casing;
  - the caller's argument value is resolved by REUSING
    `indexed_writes.py`'s own, already-tested register resolver
    (`_resolve_reg_across_blocks`) as-is -- no new dataflow machinery.
    That resolver already folds a same-block `adds/subs Rd,Rn,#imm`
    chain on top of a literal-pool load, which is exactly "concrete
    address + constant";
  - if the argument does not resolve to a concrete literal (with or
    without a folded constant offset), this module reports nothing for
    that pair -- unresolved, not guessed.

No variable/function name, comment, or surrounding behavior is consulted
anywhere in this module -- only instruction operands, literal-pool
bytes, and `edges` control-flow rows already in the census database.
"""
import indexed_writes as iw

ARG_REGS = ("r0", "r1", "r2", "r3")
MAX_ARG_TRACE_HOPS = 8   # strict single-predecessor linear-chain bound for "is this an argument?"


def _arg_index(reg):
    return ARG_REGS.index(reg) if reg in ARG_REGS else None


def _reg_traces_to_argument(conn, firmware_id, function_id, entry_addr, reg, block, before_index, insns,
                             firmware_bytes, flash_base, max_hops=MAX_ARG_TRACE_HOPS):
    """A STRICT linear-chain backward walk: at each step, `reg` must be
    undefined in the current block, and the current block must have
    EXACTLY ONE direct predecessor (or BE the function's own entry
    block, the walk's success condition). A real merge point (0 or >1
    predecessors) before reaching entry stops the walk as inconclusive.
    Returns the argument index (0-3), or None."""
    arg = _arg_index(reg)
    if arg is None:
        return None
    cur_block, cur_insns, cur_idx = block, insns, before_index
    hops = 0
    while True:
        res = iw._resolve_reg_value(cur_insns, cur_block["start_addr"], reg, cur_idx, firmware_bytes, flash_base)
        if res["kind"] != "not_found":
            return None
        if cur_block["start_addr"] == entry_addr:
            return arg
        preds = iw._direct_predecessors(conn, firmware_id, function_id, cur_block["start_addr"])
        if len(preds) != 1:
            return None
        hops += 1
        if hops > max_hops:
            return None
        cur_block = preds[0]
        cur_insns = iw._decode_block(firmware_bytes, flash_base, cur_block["start_addr"], cur_block["end_addr"])
        cur_idx = len(cur_insns)


def summarize_function_arg_writes(conn, firmware_id, firmware_bytes, flash_base, function_row):
    """Every plain (immediate-offset, non-indexed) store in ONE function
    whose base register traces to one of its own incoming arguments.
    Returns a list of {'arg': N, 'offset': K, 'width': W, 'from_addr'}."""
    entry_addr = function_row["entry"]
    function_id = function_row["id"]
    blocks = conn.execute(
        "SELECT * FROM basic_blocks WHERE firmware_id=? AND function_id=?",
        (firmware_id, function_id)).fetchall()

    effects = []
    for block in blocks:
        insns = iw._decode_block(firmware_bytes, flash_base, block["start_addr"], block["end_addr"])
        for idx, insn in enumerate(insns):
            if not insn.mnemonic.lower().startswith("str"):
                continue
            width = iw._access_width(insn.mnemonic)
            if width is None:
                continue
            mem_op = iw._mem_operand(insn)
            if mem_op is None or mem_op.mem.index not in (0, iw.ARM_REG_INVALID):
                continue  # only plain base(+imm) stores -- no indexed callee stores in this minimal pass
            base_reg = insn.reg_name(mem_op.mem.base)
            arg = _reg_traces_to_argument(
                conn, firmware_id, function_id, entry_addr, base_reg, block, idx, insns,
                firmware_bytes, flash_base)
            if arg is None:
                continue
            effects.append({
                "arg": arg, "offset": mem_op.mem.disp, "width": width, "from_addr": insn.address,
                "instruction": f"{insn.mnemonic} {insn.op_str}",
            })
    return effects


def find_interproc_writers(conn, firmware_id, firmware_bytes, flash_base, base, count, width):
    """The one-hop pass: every real, resolved `edges` call to a function
    with at least one arg-traced store effect, with the relevant
    argument register resolved AT the callsite via
    `indexed_writes._resolve_reg_across_blocks` (concrete literal,
    optionally with a folded constant offset -- nothing more). Returns a
    list of result dicts for every (callsite, effect) pair that resolved
    to an address inside [base, base+count*width)."""
    array_end = base + count * width
    call_edges = conn.execute(
        "SELECT from_addr, from_function_id, to_function_id FROM edges "
        "WHERE firmware_id=? AND kind='call' AND resolved=1 AND to_function_id IS NOT NULL",
        (firmware_id,)).fetchall()

    summary_cache = {}
    results = []
    for edge in call_edges:
        callee_id = edge["to_function_id"]
        if callee_id not in summary_cache:
            func_row = conn.execute("SELECT * FROM functions WHERE id=?", (callee_id,)).fetchone()
            summary_cache[callee_id] = summarize_function_arg_writes(
                conn, firmware_id, firmware_bytes, flash_base, func_row) if func_row is not None else []
        effects = summary_cache[callee_id]
        if not effects:
            continue

        caller_id = edge["from_function_id"]
        caller_block = iw._block_for_addr(conn, firmware_id, caller_id, edge["from_addr"])
        if caller_block is None:
            continue
        caller_insns = iw._decode_block(
            firmware_bytes, flash_base, caller_block["start_addr"], caller_block["end_addr"])
        call_idx = next((i for i, ins in enumerate(caller_insns) if ins.address == edge["from_addr"]), None)
        if call_idx is None:
            continue

        ptr_cache = {}
        for effect in effects:
            arg_reg = ARG_REGS[effect["arg"]]
            if arg_reg not in ptr_cache:
                ptr_cache[arg_reg] = iw._resolve_reg_across_blocks(
                    conn, firmware_id, caller_id, caller_block, arg_reg, call_idx, caller_insns,
                    firmware_bytes, flash_base)
            ptr_res = ptr_cache[arg_reg]
            if ptr_res["kind"] != "literal":
                continue  # unresolved -- report nothing, do not guess

            touched = ptr_res["value"] + effect["offset"]
            if not (base <= touched < array_end) or (touched - base) % width != 0:
                continue

            results.append({
                "callsite_from_addr": edge["from_addr"], "caller_function_id": caller_id,
                "callee_function_id": callee_id, "effect_from_addr": effect["from_addr"],
                "classification": "INTERPROC_EXACT_WRITER", "slots": [(touched - base) // width],
                "applies_to_all_slots": False,
                "derivation": {
                    "effect": effect, "argument_resolution": ptr_res,
                    "resolved_pointer": ptr_res["value"], "touched_addr": touched,
                },
            })
    return results
