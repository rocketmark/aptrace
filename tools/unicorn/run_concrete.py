#!/usr/bin/env python3
"""APTrace: minimal Unicorn-based concrete Cortex-M/Thumb execution backend.

See docs/tooling/tool-selection.md for when to reach for this instead of
Crucible: whenever the question is "what does this code concretely do from
a known starting state" rather than "what input satisfies this property" --
Unicorn runs actual Thumb-2 instructions natively (fast), while Crucible
pays for full symbolic evaluation of an already-fixed input, which is the
wrong tool for that job. This script deliberately does NOT try to be a
scenario/harness framework -- it is one reusable building block (load,
seed, run, hook, snapshot), following the same "orchestrate mature tools"
principle as tools/ghidra/analyze_firmware.sh.

Usage example (concretely single-step the '&' character check block that
docs/harness/protocol-harness-results.md solver-confirmed symbolically):

    tools/unicorn/run_concrete.py \\
        --firmware Autopilot_firm/firmware_autopilot868.bin \\
        --entry 0x888c --reg r3=0x26 \\
        --stop-at 0x8890 --stop-at 0x889e \\
        --trace --out /tmp/snapshot.json

Known limitations (see docs/tooling/tool-selection.md and
docs/project-status.md's "Tooling gaps"):
  - The MMIO region is mapped as plain zero-initialized RAM with no
    peripheral behavior (reads return whatever was last written, not a
    real register's semantics). Fine for control-flow/logic questions that
    don't depend on real peripheral state; not fine for anything that does.
  - No ATSAMD51 SVD-based register naming is applied automatically here.
    Use --log-mmio to record every access into the MMIO window, then resolve
    the addresses with tools/svd/resolve_mmio.py (see
    docs/tooling/tool-selection.md's "SVD / MMIO labeling" section).
  - This is a single-shot script (one process per run), not a persistent
    session -- fine for scenario-style concrete replay, not for interactive
    step debugging.
"""
import argparse
import json
import sys

from unicorn import (
    Uc,
    UC_ARCH_ARM,
    UC_MODE_THUMB,
    UC_MODE_MCLASS,
    UC_HOOK_CODE,
    UC_HOOK_MEM_UNMAPPED,
    UC_HOOK_MEM_READ,
    UC_HOOK_MEM_WRITE,
    UC_MEM_READ,
    UcError,
)
from unicorn.arm_const import (
    UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3,
    UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_R7,
    UC_ARM_REG_R8, UC_ARM_REG_R9, UC_ARM_REG_R10, UC_ARM_REG_R11,
    UC_ARM_REG_R12, UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC,
    UC_ARM_REG_CPSR, UC_CPU_ARM_CORTEX_M4,
)

REG_BY_NAME = {
    "r0": UC_ARM_REG_R0, "r1": UC_ARM_REG_R1, "r2": UC_ARM_REG_R2, "r3": UC_ARM_REG_R3,
    "r4": UC_ARM_REG_R4, "r5": UC_ARM_REG_R5, "r6": UC_ARM_REG_R6, "r7": UC_ARM_REG_R7,
    "r8": UC_ARM_REG_R8, "r9": UC_ARM_REG_R9, "r10": UC_ARM_REG_R10, "r11": UC_ARM_REG_R11,
    "r12": UC_ARM_REG_R12, "sp": UC_ARM_REG_SP, "lr": UC_ARM_REG_LR, "pc": UC_ARM_REG_PC,
    "cpsr": UC_ARM_REG_CPSR,
}
NAME_BY_REG = {v: k for k, v in REG_BY_NAME.items()}

PAGE = 0x1000


def align_down(x, page=PAGE):
    return x & ~(page - 1)


def align_up(x, page=PAGE):
    return (x + page - 1) & ~(page - 1)


def parse_hex(s):
    return int(s, 16) if s.lower().startswith("0x") else int(s, 16)


def parse_kv_hex(spec):
    name, value = spec.split("=", 1)
    return name.strip().lower(), parse_hex(value.strip())


def parse_addr_bytes(spec):
    addr_s, data_s = spec.split(":", 1)
    return parse_hex(addr_s), bytes.fromhex(data_s)


def parse_addr_len(spec):
    addr_s, len_s = spec.split(":", 1)
    return parse_hex(addr_s), int(len_s, 0)


def build_argparser():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--firmware", required=True, help="raw firmware .bin (no ELF header)")
    p.add_argument("--flash-base", default="0x4000", help="flash load address (default 0x4000)")
    p.add_argument("--ram-base", default="0x20000000", help="RAM base (default 0x20000000, ATSAMD51)")
    p.add_argument("--ram-size", default="0x30000", help="RAM size (default 0x30000, 192KB)")
    p.add_argument("--mmio-base", default="0x40000000", help="MMIO window base (default 0x40000000)")
    p.add_argument("--mmio-size", default="0x100000", help="MMIO window size (default 1MB; zero-behavior, see module docstring)")
    p.add_argument("--entry", required=True, help="start address (hex); Thumb bit ignored, mode is fixed Thumb/M-class")
    p.add_argument("--sp", default=None, help="initial SP (default: top of RAM)")
    p.add_argument("--reg", action="append", default=[], metavar="NAME=HEX", help="seed a register before execution (repeatable)")
    p.add_argument("--seed-mem", action="append", default=[], metavar="ADDR:HEXBYTES", help="write concrete bytes into memory before execution (repeatable)")
    p.add_argument("--stop-at", action="append", default=[], metavar="HEXADDR", help="halt when this address is reached (repeatable)")
    p.add_argument("--max-instructions", type=lambda s: int(s, 0), default=200000, help="hard instruction cap (default 200000)")
    p.add_argument("--trace", action="store_true", help="log every N instructions to stderr (see --trace-every)")
    p.add_argument("--trace-every", type=int, default=1, help="instruction-log frequency when --trace is set (default 1)")
    p.add_argument("--dump-mem", action="append", default=[], metavar="ADDR:LEN", help="include this memory range (hex bytes) in the snapshot (repeatable)")
    p.add_argument("--watch", action="append", default=[], metavar="HEXADDR", help="record full register state (+ --watch-mem ranges) every time this address is hit, without stopping (repeatable) -- for per-iteration traces of a loop, unlike --stop-at which halts")
    p.add_argument("--watch-mem", action="append", default=[], metavar="ADDR:LEN", help="memory range to capture at every --watch hit, in addition to registers (repeatable)")
    p.add_argument("--max-watch-hits", type=int, default=2000, help="safety cap on total recorded watch hits across all --watch addresses (default 2000)")
    p.add_argument("--log-mmio", action="store_true", help="record every read/write into the MMIO window (address, size, direction, PC) in the snapshot -- observability only, does not change the zero-behavior MMIO model. Resolve addresses to peripheral/register names with tools/svd/resolve_mmio.py")
    p.add_argument("--max-mmio-log", type=int, default=5000, help="cap on recorded MMIO accesses when --log-mmio is set (default 5000)")
    p.add_argument("--watch-mem-write", action="append", default=[], metavar="ADDR:LEN", help="true memory watchpoint (repeatable): record every WRITE that lands in [ADDR, ADDR+LEN), anywhere in the address space, with PC/instruction/old+new bytes -- unlike --watch (which triggers on a CODE address), this catches a store to a RAM range regardless of which instruction or function performs it, including a computed/indirect address a static xref search can't attribute to the range's own literal. Does not stop execution.")
    p.add_argument("--max-mem-write-log", type=int, default=2000, help="cap on recorded hits per --watch-mem-write range (default 2000)")
    p.add_argument("--stub-call", action="append", default=[], metavar="HEXADDR", help="treat this address as an opaque function that immediately returns (PC := LR) instead of executing its body (repeatable). Use for a real, but not-yet-modeled, callee (e.g. a hardware driver call) whose return value this scenario doesn't depend on -- the concrete-execution equivalent of the opaque function-call override already used on the Crucible side (see docs/project-status.md). Does not fabricate a return value; R0 is left exactly as the caller set it up.")
    p.add_argument("--out", default=None, help="write JSON snapshot here (default: stdout)")
    return p


def main(argv):
    args = build_argparser().parse_args(argv)

    flash_base = parse_hex(args.flash_base)
    ram_base = parse_hex(args.ram_base)
    ram_size = parse_hex(args.ram_size)
    mmio_base = parse_hex(args.mmio_base)
    mmio_size = parse_hex(args.mmio_size)
    # Unicorn (like real hardware BX/BLX) reads the *start address's* low bit
    # to decide ARM vs. Thumb state at entry -- UC_MODE_THUMB alone is not
    # enough; the address passed to emu_start (and the initial PC) must carry
    # the Thumb bit. Cortex-M is Thumb-only, so this is always set here.
    entry = parse_hex(args.entry) | 1

    with open(args.firmware, "rb") as f:
        firmware = f.read()

    uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_MCLASS)
    uc.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_M4)

    flash_map_size = align_up(len(firmware))
    uc.mem_map(align_down(flash_base), flash_map_size)
    uc.mem_write(flash_base, firmware)

    uc.mem_map(align_down(ram_base), align_up(ram_size))
    uc.mem_map(align_down(mmio_base), align_up(mmio_size))

    # The ARM-architected Private Peripheral Bus (SysTick, NVIC, SCB, MPU,
    # etc. at 0xE0000000-0xE00FFFFF) is part of every Cortex-M's address map,
    # not board-specific MMIO -- map it too (same zero-behavior stub) so
    # ordinary startup/delay code that touches SysTick/NVIC doesn't fault.
    # Skipped if a custom --mmio-base/--mmio-size already covers it.
    ppb_base, ppb_size = 0xE0000000, 0x100000
    mmio_lo, mmio_hi = align_down(mmio_base), align_down(mmio_base) + align_up(mmio_size)
    if not (mmio_lo <= ppb_base and ppb_base + ppb_size <= mmio_hi):
        uc.mem_map(ppb_base, ppb_size)

    sp = parse_hex(args.sp) if args.sp else (ram_base + ram_size)
    uc.reg_write(UC_ARM_REG_SP, sp)
    uc.reg_write(UC_ARM_REG_PC, entry)

    for spec in args.reg:
        name, value = parse_kv_hex(spec)
        if name not in REG_BY_NAME:
            print(f"error: unknown register '{name}'", file=sys.stderr)
            return 2
        uc.reg_write(REG_BY_NAME[name], value)

    for spec in args.seed_mem:
        addr, data = parse_addr_bytes(spec)
        uc.mem_write(addr, data)

    stop_addrs = {parse_hex(a) & ~1 for a in args.stop_at}
    watch_addrs = {parse_hex(a) & ~1 for a in args.watch}
    stub_addrs = {parse_hex(a) & ~1 for a in args.stub_call}
    watch_mem_ranges = [parse_addr_len(spec) for spec in args.watch_mem]
    mem_write_ranges = [parse_addr_len(spec) for spec in args.watch_mem_write]
    state = {"instructions": 0, "stop_reason": None, "watch_hits": [], "mmio_log": [], "stub_hits": [], "mem_write_hits": []}

    def capture_registers():
        return {NAME_BY_REG[r]: f"0x{uc.reg_read(r):08x}" for r in NAME_BY_REG}

    def capture_watch_memory():
        mem = {}
        for addr, length in watch_mem_ranges:
            try:
                mem[f"0x{addr:08x}"] = uc.mem_read(addr, length).hex()
            except UcError as e:
                mem[f"0x{addr:08x}"] = f"error: {e}"
        return mem

    def hook_code(uc_, address, size, _user_data):
        state["instructions"] += 1
        if args.trace and state["instructions"] % args.trace_every == 0:
            print(f"  [unicorn] #{state['instructions']} pc=0x{address:08x}", file=sys.stderr)
        if address in stub_addrs:
            lr = uc_.reg_read(UC_ARM_REG_LR)
            state["stub_hits"].append({
                "instruction": state["instructions"], "address": f"0x{address:08x}", "lr": f"0x{lr:08x}",
            })
            uc_.reg_write(UC_ARM_REG_PC, lr)
            return
        if address in watch_addrs:
            if len(state["watch_hits"]) >= args.max_watch_hits:
                state["stop_reason"] = f"max watch hits ({args.max_watch_hits}) reached at 0x{address:08x}"
                uc_.emu_stop()
                return
            state["watch_hits"].append({
                "hit": len(state["watch_hits"]),
                "instruction": state["instructions"],
                "address": f"0x{address:08x}",
                "registers": capture_registers(),
                "memory": capture_watch_memory(),
            })
        if address in stop_addrs:
            state["stop_reason"] = f"reached stop address 0x{address:08x}"
            uc_.emu_stop()

    def hook_mem_unmapped(uc_, access, address, size, value, _user_data):
        state["stop_reason"] = f"unmapped memory access (type={access}) at 0x{address:08x} size={size}"
        return False  # let Unicorn raise UcError, caught below

    def hook_mmio(uc_, access, address, size, value, _user_data):
        if len(state["mmio_log"]) >= args.max_mmio_log:
            return
        state["mmio_log"].append({
            "instruction": state["instructions"],
            "pc": f"0x{uc_.reg_read(UC_ARM_REG_PC):08x}",
            "address": f"0x{address:08x}",
            "size": size,
            "direction": "read" if access == UC_MEM_READ else "write",
            "value": f"0x{value:x}" if access != UC_MEM_READ else None,
        })

    def make_mem_write_hook(range_addr, range_len):
        def hook_mem_write(uc_, access, address, size, value, _user_data):
            if len(state["mem_write_hits"]) >= args.max_mem_write_log:
                return
            state["mem_write_hits"].append({
                "range": f"0x{range_addr:08x}:{range_len}",
                "instruction": state["instructions"],
                "pc": f"0x{uc_.reg_read(UC_ARM_REG_PC):08x}",
                "lr": f"0x{uc_.reg_read(UC_ARM_REG_LR):08x}",
                "address": f"0x{address:08x}",
                "size": size,
                "value": f"0x{value:x}",
            })
        return hook_mem_write

    uc.hook_add(UC_HOOK_CODE, hook_code)
    uc.hook_add(UC_HOOK_MEM_UNMAPPED, hook_mem_unmapped)
    if args.log_mmio:
        uc.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, hook_mmio,
                    begin=align_down(mmio_base), end=align_down(mmio_base) + align_up(mmio_size) - 1)
    for addr, length in mem_write_ranges:
        uc.hook_add(UC_HOOK_MEM_WRITE, make_mem_write_hook(addr, length),
                    begin=addr, end=addr + length - 1)

    error = None
    try:
        uc.emu_start(entry, 0, count=args.max_instructions)
        if state["stop_reason"] is None:
            state["stop_reason"] = (
                "instruction limit reached" if state["instructions"] >= args.max_instructions
                else "returned (fell off emu_start)"
            )
    except UcError as e:
        error = str(e)
        if state["stop_reason"] is None:
            state["stop_reason"] = f"error: {error}"

    registers_hex = capture_registers()

    memory = {}
    for spec in args.dump_mem:
        addr, length = parse_addr_len(spec)
        try:
            data = uc.mem_read(addr, length)
            memory[f"0x{addr:08x}"] = data.hex()
        except UcError as e:
            memory[f"0x{addr:08x}"] = f"error: {e}"

    snapshot = {
        "firmware": args.firmware,
        "entry": f"0x{entry:08x}",
        "instructions_executed": state["instructions"],
        "stop_reason": state["stop_reason"],
        "error": error,
        "registers": registers_hex,
        "memory": memory,
        "watch_hits": state["watch_hits"],
        "mmio_log": state["mmio_log"],
        "stub_hits": state["stub_hits"],
        "mem_write_hits": state["mem_write_hits"],
    }

    text = json.dumps(snapshot, indent=2)
    if args.out:
        with open(args.out, "w") as f:
            f.write(text + "\n")
        print(f"Wrote {args.out}", file=sys.stderr)
    else:
        print(text)

    return 0 if error is None else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
