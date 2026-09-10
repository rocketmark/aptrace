"""APTrace census: an independent Capstone Thumb branch-target sweep.

Per docs/tooling/tool-selection.md's tool-disagreement discipline, this
is a CROSS-CHECK, not a second authority: Ghidra's own basic-block model
(APTraceExportCensus.java) is the census's primary static source. This
module exists only to answer "does a completely independent Thumb
decoder, walking from the same roots, find any branch/call target Ghidra
didn't end up covering with a basic block?" -- a real disagreement worth
a scan_warning, never a silent override of Ghidra's own result.

Capstone-only, no Ghidra call -- fast enough to run on every `census
build` alongside the (separately cached) Ghidra pass.
"""
from capstone import CS_ARCH_ARM, CS_MODE_THUMB, Cs
from capstone.arm_const import ARM_OP_IMM

MAX_TOTAL_INSTRUCTIONS = 400_000
MAX_INSTRUCTIONS_PER_SEED = 4000

# Mnemonics that end a linear run (the instruction after them is not
# reached by falling through -- so the sweep stops walking forward from
# here, though the branch's own target, if direct, is still recorded and
# queued as a new seed). Deliberately conservative/explicit rather than
# inferring from capstone's flow-control groups, since IT (if-then) and
# other Thumb-2 conditional-execution prefixes make group-based
# stop-detection unreliable for a simple linear sweep like this one.
UNCONDITIONAL_TERMINATORS = {"b", "b.w", "bx", "pop", "pop.w", "udf", "udf.w", "table branch byte", "tbb", "tbh"}


def _is_return_like(mnemonic, op_str):
    m = mnemonic.lower()
    if m in ("bx",) and "lr" in op_str.lower():
        return True
    if m.startswith("pop") and "pc" in op_str.lower():
        return True
    return False


def sweep(firmware_bytes, flash_base, seed_addrs):
    """Walk Thumb code independently from `seed_addrs` (ints, code
    addresses -- NOT Thumb-bit-tagged), following direct branch/call
    targets. Returns (edges, discovered_addrs):

      edges            -- list of (from_addr, to_addr, kind) for every
                           direct branch/call target found, kind in
                           {'branch', 'cbranch', 'call'}.
      discovered_addrs  -- set of every address this sweep decoded an
                           instruction at (for coverage cross-checking).

    Bounded by MAX_TOTAL_INSTRUCTIONS across the whole sweep and
    MAX_INSTRUCTIONS_PER_SEED per linear run, so a bad seed (landing in
    data, decoding indefinitely) can't make this unbounded -- this is a
    best-effort cross-check, not a guaranteed-exhaustive disassembler.
    """
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    md.detail = True

    end = flash_base + len(firmware_bytes)
    visited_starts = set()
    worklist = sorted(set(a for a in seed_addrs if flash_base <= a < end))
    edges = []
    discovered = set()
    total = 0

    while worklist and total < MAX_TOTAL_INSTRUCTIONS:
        addr = worklist.pop(0)
        if addr in visited_starts:
            continue
        visited_starts.add(addr)
        pc = addr
        count = 0
        while count < MAX_INSTRUCTIONS_PER_SEED and total < MAX_TOTAL_INSTRUCTIONS:
            if pc < flash_base or pc >= end:
                break
            off = pc - flash_base
            chunk = firmware_bytes[off:off + 4]
            if not chunk:
                break
            insns = list(md.disasm(chunk, pc, count=1))
            if not insns:
                break  # undecodable at this address -- stop this linear run
            insn = insns[0]
            discovered.add(pc)
            total += 1
            count += 1

            mnemonic = insn.mnemonic.lower()
            is_call = mnemonic in ("bl", "blx")
            is_cond_branch = mnemonic not in ("b", "b.w", "bl", "blx") and mnemonic.startswith("b")
            is_uncond_branch = mnemonic in ("b", "b.w")

            target = None
            if insn.operands and insn.operands[-1].type == ARM_OP_IMM:
                target = insn.operands[-1].imm

            if target is not None and flash_base <= target < end:
                kind = "call" if is_call else ("cbranch" if is_cond_branch else "branch")
                edges.append((pc, target, kind))
                if target not in visited_starts:
                    worklist.append(target)

            stops_here = (mnemonic in UNCONDITIONAL_TERMINATORS and not is_cond_branch) or \
                _is_return_like(mnemonic, insn.op_str)
            if stops_here:
                break
            pc += insn.size

    return edges, discovered
