"""SPIKE ONLY: the same forward pointer-use question, answered the way the
current census tools work -- Python over Capstone-decoded Thumb, with
APTrace supplying instruction semantics.

Everything marked ISA: below is ARM/Thumb-specific knowledge this layer
must own (and re-own for every other ISA). Capstone's regs_access() gives
generic read/write sets; it does not say which read is a stored value vs.
an address, which register list a call consumes, or whether a write is
predicated.

usage: capstone_forward_use.py IMAGE BASE DEF_ADDR [DEF_ADDR...] [--fn LO:HI]
"""
import json
import struct
import sys

from capstone import CS_ARCH_ARM, CS_MODE_THUMB, Cs
from capstone.arm_const import ARM_INS_B, ARM_CC_AL, ARM_CC_INVALID, ARM_OP_IMM, ARM_OP_MEM, ARM_OP_REG

# ISA: AAPCS argument/return/caller-saved registers.
ARG_REGS = {"r0", "r1", "r2", "r3"}
RET_REGS = {"r0"}
CALL_CLOBBERED = {"r0", "r1", "r2", "r3", "r12", "ip", "lr"}
# ISA: Capstone register aliases.
ALIAS = {"sb": "r9", "sl": "r10", "fp": "r11", "ip": "r12"}
MAX_STATES = 20000


def norm(r):
    return ALIAS.get(r, r)


def decode(md, image, base, addr):
    off = addr - base
    if off < 0 or off >= len(image):
        return None
    return next(md.disasm(image[off:off + 4], addr), None)


def reads_writes(insn):
    r, w = insn.regs_access()
    return {norm(insn.reg_name(x)) for x in r}, {norm(insn.reg_name(x)) for x in w}


def classify(insn, live):
    """ISA: which kind of use `insn` makes of the live registers."""
    m = insn.mnemonic.lower().split(".")[0]
    ops = insn.operands
    uses = []
    reads, _ = reads_writes(insn)
    # ISA/ABI: calls and returns consume r0-r3 / r0 implicitly; Capstone's
    # read set does not include them (iteration-2 fix).
    if m in ("bl", "blx") and live & ARG_REGS:
        uses.append(("ARGUMENT", "live in r0-r3 at call"))
    if ((m == "bx" and "lr" in insn.op_str) or (m.startswith("pop") and "pc" in insn.op_str)) and live & RET_REGS:
        uses.append(("RETURN_VALUE", "r0 live at return"))
    if not reads & live:
        return uses
    if m in ("blx", "bx") and ops and ops[0].type == ARM_OP_REG and norm(insn.reg_name(ops[0].reg)) in live:
        if norm(insn.reg_name(ops[0].reg)) == "lr":
            pass
        else:
            uses.append(("CONTROL_TRANSFER", m))
    if m.startswith(("str", "stm", "push")):
        mem = next((o for o in ops if o.type == ARM_OP_MEM), None)
        vals = {norm(insn.reg_name(o.reg)) for o in ops if o.type == ARM_OP_REG}
        if vals & live:
            uses.append(("STORE", insn.op_str))
        if mem is not None and norm(insn.reg_name(mem.mem.base)) in live:
            uses.append(("DEREFERENCE_STORE", insn.op_str))
    if m.startswith("ldr") or m.startswith("ldm"):
        mem = next((o for o in ops if o.type == ARM_OP_MEM), None)
        if mem is not None and norm(insn.reg_name(mem.mem.base)) in live:
            uses.append(("DEREFERENCE_LOAD", insn.op_str))
    if m in ("cmp", "cmn", "tst", "teq", "cbz", "cbnz"):
        uses.append(("COMPARE", m))
    return uses


def propagates(insn):
    """ISA: value-preserving moves/arithmetic whose destination inherits."""
    m = insn.mnemonic.lower().split(".")[0]
    return m in ("mov", "movs", "add", "adds", "sub", "subs", "orr", "and", "bic", "eor", "lsl", "lsr", "asr")


def successors(insn):
    """ISA: Thumb control flow -- fall-through, direct branch targets,
    returns, and computed transfers."""
    m = insn.mnemonic.lower().split(".")[0]
    nxt = insn.address + insn.size
    ops = insn.operands
    if m in ("bl", "blx"):
        return [nxt], None
    if m == "bx" or (m.startswith("pop") and "pc" in insn.op_str):
        return [], "return"
    if m in ("cbz", "cbnz"):
        return [ops[1].imm, nxt], None
    # ISA: b, b<cc>, b.w, b<cc>.w all decode to ARM_INS_B (iteration-2 fix:
    # matching the mnemonic "b" missed every conditional branch).
    if insn.id == ARM_INS_B:
        tgt = ops[0].imm
        if insn.cc in (ARM_CC_AL, ARM_CC_INVALID):
            return [tgt], None
        return [tgt, nxt], None
    if m in ("tbb", "tbh") or (m in ("mov", "ldr") and ops and ops[0].type == ARM_OP_REG and insn.reg_name(ops[0].reg) == "pc"):
        return [], "computed"
    return [nxt], None


def forward(image, base, def_addr, fn_range=None):
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    md.detail = True
    # ISA: an IT block makes the condition of the next 1-4 instructions
    # decoder state, so decoding one address in isolation is wrong inside an
    # IT block (iteration-2 fix). Linear pre-decode of the function keeps it
    # (and is itself only correct when the sweep stays in sync).
    cache = {}
    if fn_range:
        lo, hi = fn_range
        for i in md.disasm(image[lo - base:hi - base], lo):
            cache[i.address] = i

    def decode_at(a):
        return cache.get(a) or decode(md, image, base, a)

    d = decode_at(def_addr)
    _, w = reads_writes(d)
    tracked = set(w) - {"pc"}
    uses, incomplete, seen = [], [], set()
    succ, _ = successors(d)
    work = [(s, frozenset(tracked)) for s in succ]
    states = 0
    while work:
        addr, live = work.pop()
        if not live or (addr, live) in seen:
            continue
        seen.add((addr, live))
        states += 1
        if states > MAX_STATES:
            incomplete.append("state bound")
            break
        if fn_range and not (fn_range[0] <= addr < fn_range[1]):
            uses.append(("ARGUMENT" if live & ARG_REGS else "LEAVES_FUNCTION", hex(addr), "tail transfer"))
            continue
        insn = decode_at(addr)
        if insn is None:
            incomplete.append(f"undecodable at {addr:#x}")
            continue
        for k, detail in classify(insn, live):
            uses.append((k, hex(addr), f"{insn.mnemonic} {insn.op_str} ({detail})"))
        reads, writes = reads_writes(insn)
        new = set(live)
        m = insn.mnemonic.lower().split(".")[0]
        # ISA: an instruction inside an IT block (or any predicated one)
        # only MAY write -- a conditional write cannot kill.
        predicated = insn.cc not in (ARM_CC_AL, ARM_CC_INVALID) and insn.id != ARM_INS_B
        if not predicated:
            new -= writes
        if m in ("bl", "blx"):
            new -= CALL_CLOBBERED
        elif propagates(insn) and (reads & live):
            new |= writes - {"pc", "sp"}
        new.discard("pc")
        if not new:
            uses.append(("DEAD", hex(addr), f"{insn.mnemonic} {insn.op_str}"))
            continue
        nxt, stop = successors(insn)
        if stop == "computed":
            incomplete.append(f"computed transfer at {addr:#x}")
        for s in nxt:
            work.append((s, frozenset(new)))
    kinds = sorted({u[0] for u in uses})
    return {"def_addr": hex(def_addr), "def_instruction": f"{d.mnemonic} {d.op_str}", "tracked": sorted(tracked),
            "use_kinds": kinds, "complete": not incomplete, "incomplete": incomplete, "states": states,
            "uses": sorted(set(uses))}


def main(argv):
    fn = None
    if "--fn" in argv:
        i = argv.index("--fn")
        lo, hi = argv[i + 1].split(":")
        fn = (int(lo, 16), int(hi, 16))
        argv = argv[:i] + argv[i + 2:]
    image = open(argv[1], "rb").read()
    base = int(argv[2], 16)
    out = [forward(image, base, int(a, 16), fn) for a in argv[3:]]
    print(json.dumps(out, indent=1))


if __name__ == "__main__":
    main(sys.argv)
