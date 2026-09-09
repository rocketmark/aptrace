#!/usr/bin/env python3
"""APTrace: CLI wrapper around tools/unicorn/concrete.py's ConcreteMachine.

See docs/tooling/tool-selection.md for when to reach for this instead of
Crucible: whenever the question is "what does this code concretely do from
a known starting state" rather than "what input satisfies this property".

This script is a thin translation layer: parse CLI strings into Python
ints/bytes, build a ConcreteMachine, call `.run()` or `.call()` once, and
print the resulting RunResult/CallResult as JSON. All the actual
Unicorn setup/hook/snapshot logic lives in concrete.py, which
tools/unicorn/virtual_link.py also uses directly (as a Python library,
without a subprocess per call) -- see that module for the
multi-leg-scenario layer built on top of this.

Usage example (concretely single-step the '&' character check block that
docs/harness/protocol-harness-results.md solver-confirmed symbolically):

    tools/unicorn/run_concrete.py \\
        --firmware Autopilot_firm/firmware_autopilot868.bin \\
        --entry 0x888c --reg r3=0x26 \\
        --stop-at 0x8890 --stop-at 0x889e \\
        --trace --out /tmp/snapshot.json

Direct-function-call example (ARM AAPCS argument placement, a real
return trampoline, no hand-picked SP/LR -- see concrete.py's
ConcreteMachine.call for what this replaces):

    tools/unicorn/run_concrete.py \\
        --firmware research/firmware/originals/firmware_mando868.bin \\
        --call 0x49c4 --arg 1 --arg 1 --arg 0 --arg 0 --arg 0x62 \\
        --out /tmp/call_snapshot.json

Numeric CLI semantics (see docs/tooling/unicorn-backend.md's "Numeric CLI
semantics" section for the full rationale and migration note): values
that represent a general-purpose quantity (--reg, --arg, lengths/counts
inside ADDR:LEN-style specs) use ordinary `int(value, 0)` parsing --
`28` means decimal 28, `0x28` means hexadecimal 0x28. Address-shaped
values (--entry, --stop-at, --watch, the ADDR half of ADDR:LEN/
ADDR:HEXBYTES specs, --map-page) are still always read as hex regardless
of an 0x prefix, matching how every address in this project's own docs
and scripts is already written. Values that represent a raw hardware bit
pattern (--force-reg's HEX, --mmio-force-bits/--mmio-clear-bits' MASK)
are deliberately kept hex-only, since a bitmask is conventionally always
written in hex and there's no decimal reading anyone would intend there.

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
  - This is a single-shot script (one process per run) at the CLI layer --
    fine for ad-hoc/manual investigation. Python code that wants to reuse
    one machine across many runs without process-per-call overhead should
    import concrete.ConcreteMachine directly (see virtual_link.py).
"""
import argparse
import json
import sys

from concrete import ConcreteMachine, DEFAULT_TRACE_LAST, REG_BY_NAME


def parse_hexaddr(s):
    """Addresses are always hex, 0x prefix optional -- unambiguous by
    convention throughout this project (nobody writes an address in
    decimal), unlike general-purpose values (see module docstring)."""
    return int(s, 16)


def parse_value(s):
    """General-purpose numeric CLI value: ordinary int(s, 0) semantics.
    '28' -> decimal 28, '0x28' -> hex 0x28. This is the fix for the
    exact ambiguity that produced a false investigative path in
    docs/investigations/plus-target-distance-roundtrip.md (a `--reg
    r0=28` meant to seed decimal 28, silently read as hex 0x28=40)."""
    return int(s, 0)


def parse_reg_value(spec):
    name, value = spec.split("=", 1)
    return name.strip().lower(), parse_value(value.strip())


def parse_addr_bytes(spec):
    addr_s, data_s = spec.split(":", 1)
    return parse_hexaddr(addr_s), bytes.fromhex(data_s)


def parse_addr_len(spec):
    addr_s, len_s = spec.split(":", 1)
    return parse_hexaddr(addr_s), parse_value(len_s)


def parse_reg_len(spec):
    reg_s, len_s = spec.split(":", 1)
    return reg_s.strip().lower(), parse_value(len_s)


def parse_addr_reg_hexvalue(spec):
    addr_s, reg_s, value_s = spec.split(":", 2)
    # HEX by design (a forced register value stands in for a raw bit
    # pattern/external-device response) -- see module docstring.
    return parse_hexaddr(addr_s), reg_s.strip().lower(), int(value_s, 16)


def parse_addr_addr_bytes(spec):
    trigger_s, mem_s, data_s = spec.split(":", 2)
    return parse_hexaddr(trigger_s), parse_hexaddr(mem_s), bytes.fromhex(data_s)


def parse_addr_hexmask(spec):
    addr_s, mask_s = spec.split(":", 1)
    # HEX by design (a bitmask) -- see module docstring.
    return parse_hexaddr(addr_s), int(mask_s, 16)


def build_argparser():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--firmware", required=True, help="raw firmware .bin (no ELF header)")
    p.add_argument("--flash-base", default="0x4000", help="flash load address (default 0x4000)")
    p.add_argument("--ram-base", default="0x20000000", help="RAM base (default 0x20000000, ATSAMD51)")
    p.add_argument("--ram-size", default="0x30000", help="RAM size (default 0x30000, 192KB)")
    p.add_argument("--mmio-base", default="0x40000000", help="MMIO window base (default 0x40000000)")
    p.add_argument("--mmio-size", default="0x100000", help="MMIO window size (default 1MB; zero-behavior, see module docstring)")
    p.add_argument("--entry", default=None, help="start address (hex); Thumb bit ignored, mode is fixed Thumb/M-class. Mutually exclusive with --call.")
    p.add_argument("--call", default=None, metavar="HEXADDR", help="call this function directly per ARM AAPCS (see concrete.py ConcreteMachine.call) instead of a raw jump-and-run -- args come from --arg, a real return trampoline and clean-return detection are automatic. Mutually exclusive with --entry.")
    p.add_argument("--arg", action="append", default=[], metavar="VALUE", help="one AAPCS argument for --call (repeatable, in order); int(VALUE,0) semantics (28 decimal, 0x28 hex). First 4 go in r0-r3, the rest on the stack.")
    p.add_argument("--sp", default=None, help="initial SP (default: top of RAM, minus a small reserved trampoline page)")
    p.add_argument("--reg", action="append", default=[], metavar="NAME=VALUE", help="seed a register before execution (repeatable); int(VALUE,0) semantics -- 28 is decimal 28, 0x28 is hex 0x28 (see module docstring)")
    p.add_argument("--seed-mem", action="append", default=[], metavar="ADDR:HEXBYTES", help="write concrete bytes into memory before execution (repeatable)")
    p.add_argument("--map-page", action="append", default=[], metavar="ADDR:SIZE", help="map an additional page-aligned region before execution (repeatable), for a real fixed memory region outside flash/RAM/MMIO -- e.g. the SAMD51 NVM Software Calibration Row (0x00800080), a real, factory-programmed, per-die area the firmware genuinely reads. Use with --seed-mem to fill it; the seeded bytes are then a disclosed placeholder for real silicon-specific data this harness cannot know, not a claim about the true calibration values.")
    p.add_argument("--stop-at", action="append", default=[], metavar="HEXADDR", help="halt when this address is reached (repeatable)")
    p.add_argument("--max-instructions", type=lambda s: int(s, 0), default=200000, help="hard instruction cap (default 200000)")
    p.add_argument("--trace", action="store_true", help="log every N instructions to stderr (see --trace-every)")
    p.add_argument("--trace-every", type=int, default=1, help="instruction-log frequency when --trace is set (default 1)")
    p.add_argument("--trace-last", type=int, default=DEFAULT_TRACE_LAST, metavar="N", help=f"always keep the last N program counters in a cheap ring buffer, included in the snapshot as 'recent_pcs' regardless of success/failure (default {DEFAULT_TRACE_LAST}) -- cheap enough to leave on for normal use; use --trace --trace-every 1 only for the rare case that genuinely needs every instruction. 0 disables.")
    p.add_argument("--dump-mem", action="append", default=[], metavar="ADDR:LEN", help="include this memory range (hex bytes) in the snapshot (repeatable)")
    p.add_argument("--dump-reg-pointee", action="append", default=[], metavar="REG:LEN", help="repeatable: at the stop point, read REG's value and dump LEN bytes from that address, in this SAME run -- both the register value and the dereferenced memory land in the snapshot's 'reg_pointee' field. The pointer is whatever the real firmware computed; this does not pre-suppose an address. Replaces the old two-run 'discover R0, then dump *R0' pattern (see concrete.py's module docstring).")
    p.add_argument("--watch", action="append", default=[], metavar="HEXADDR", help="record full register state (+ --watch-mem ranges) every time this address is hit, without stopping (repeatable) -- for per-iteration traces of a loop, unlike --stop-at which halts")
    p.add_argument("--watch-mem", action="append", default=[], metavar="ADDR:LEN", help="memory range to capture at every --watch hit, in addition to registers (repeatable)")
    p.add_argument("--max-watch-hits", type=int, default=2000, help="safety cap on total recorded watch hits across all --watch addresses (default 2000)")
    p.add_argument("--log-mmio", action="store_true", help="record every read/write into the MMIO window (address, size, direction, PC) in the snapshot -- observability only, does not change the zero-behavior MMIO model. Resolve addresses to peripheral/register names with tools/svd/resolve_mmio.py")
    p.add_argument("--max-mmio-log", type=int, default=5000, help="cap on recorded MMIO accesses when --log-mmio is set (default 5000)")
    p.add_argument("--watch-mem-write", action="append", default=[], metavar="ADDR:LEN", help="true memory watchpoint (repeatable): record every WRITE that lands in [ADDR, ADDR+LEN), anywhere in the address space, with PC/instruction/old+new bytes -- unlike --watch (which triggers on a CODE address), this catches a store to a RAM range regardless of which instruction or function performs it, including a computed/indirect address a static xref search can't attribute to the range's own literal. Does not stop execution.")
    p.add_argument("--max-mem-write-log", type=int, default=2000, help="cap on recorded hits per --watch-mem-write range (default 2000)")
    p.add_argument("--fake-tick", action="append", default=[], metavar="ADDR:PERIOD", help="repeatable: every PERIOD instructions, increment the 4-byte little-endian counter at ADDR by 1. Deliberately NOT a SysTick/timer peripheral model -- it is a direct, labeled stand-in for a firmware-maintained tick/millis variable. Advances on an INSTRUCTION-COUNT cadence, not real time.")
    p.add_argument("--stub-call", action="append", default=[], metavar="HEXADDR", help="treat this address as an opaque function that immediately returns (PC := LR) instead of executing its body (repeatable). Use for a real, but not-yet-modeled, callee whose return value this scenario doesn't depend on. Does not fabricate a return value; R0 is left exactly as the caller set it up.")
    p.add_argument("--mmio-force-bits", action="append", default=[], metavar="ADDR:MASK", help="repeatable: every read of the 4-byte-aligned MMIO register at ADDR is OR'd with MASK (hex) before the CPU sees it. See docs/investigations/reset-handler-clock-init.md for the justification discipline this requires.")
    p.add_argument("--mmio-clear-bits", action="append", default=[], metavar="ADDR:MASK", help="repeatable: every read of the 4-byte-aligned MMIO register at ADDR is AND'd with ~MASK (hex) before the CPU sees it -- the complement of --mmio-force-bits, for a self-clearing bit.")
    p.add_argument("--force-reg", action="append", default=[], metavar="ADDR:REG:HEX", help="repeatable: immediately before executing the instruction at ADDR, set register REG to HEX. Unlike --mmio-force-bits/--mmio-clear-bits, this DOES fabricate a value -- use only as a disclosed environmental/external-device assumption at one exact, narrow program point.")
    p.add_argument("--force-mem", action="append", default=[], metavar="TRIGGER:MEMADDR:HEXBYTES", help="repeatable: immediately before executing the instruction at TRIGGER, write HEXBYTES into memory at MEMADDR. Fires every time TRIGGER is reached, not just the first.")
    p.add_argument("--out", default=None, help="write JSON snapshot here (default: stdout)")
    return p


def main(argv):
    args = build_argparser().parse_args(argv)

    if (args.entry is None) == (args.call is None):
        print("error: specify exactly one of --entry or --call", file=sys.stderr)
        return 2

    machine = ConcreteMachine(
        args.firmware,
        flash_base=parse_hexaddr(args.flash_base),
        ram_base=parse_hexaddr(args.ram_base),
        ram_size=parse_hexaddr(args.ram_size),
        mmio_base=parse_hexaddr(args.mmio_base),
        mmio_size=parse_hexaddr(args.mmio_size),
        extra_maps=[parse_addr_len(spec) for spec in args.map_page],
        track_dirty=False,  # exactly one run()/call() per process here -- nothing to isolate
    )

    reg_seed = [parse_reg_value(spec) for spec in args.reg]
    for name, _ in reg_seed:
        if name not in REG_BY_NAME:
            print(f"error: unknown register '{name}'", file=sys.stderr)
            return 2

    seed_mem = [parse_addr_bytes(spec) for spec in args.seed_mem]
    stop_at = [parse_hexaddr(a) for a in args.stop_at]
    watch = [parse_hexaddr(a) for a in args.watch]
    stub_calls = [parse_hexaddr(a) for a in args.stub_call]
    watch_mem = [parse_addr_len(spec) for spec in args.watch_mem]
    watch_mem_write = [parse_addr_len(spec) for spec in args.watch_mem_write]
    dump_mem = [parse_addr_len(spec) for spec in args.dump_mem]
    dump_reg_pointee = [parse_reg_len(spec) for spec in args.dump_reg_pointee]
    fake_tick = [parse_addr_len(spec) for spec in args.fake_tick]
    mmio_force_bits = [parse_addr_hexmask(spec) for spec in args.mmio_force_bits]
    mmio_clear_bits = [parse_addr_hexmask(spec) for spec in args.mmio_clear_bits]
    force_reg = [parse_addr_reg_hexvalue(spec) for spec in args.force_reg]
    force_mem = [parse_addr_addr_bytes(spec) for spec in args.force_mem]

    common_kwargs = dict(
        seed_mem=seed_mem, stub_calls=stub_calls, dump_mem=dump_mem,
        dump_reg_pointee=dump_reg_pointee, watch=watch, watch_mem=watch_mem,
        max_watch_hits=args.max_watch_hits, max_instructions=args.max_instructions,
        trace=args.trace, trace_every=args.trace_every, trace_last=args.trace_last,
        fake_tick=fake_tick, mmio_force_bits=mmio_force_bits, mmio_clear_bits=mmio_clear_bits,
        force_reg=force_reg, force_mem=force_mem, log_mmio=args.log_mmio,
        max_mmio_log=args.max_mmio_log, watch_mem_write=watch_mem_write,
        max_mem_write_log=args.max_mem_write_log,
    )

    if args.call is not None:
        call_args = [parse_value(a) for a in args.arg]
        sp = parse_hexaddr(args.sp) if args.sp else None
        call_result = machine.call(parse_hexaddr(args.call), args=call_args, sp=sp, reg_seed=reg_seed,
                                    **common_kwargs)
        result = call_result.result
        snapshot = result.to_dict()
        snapshot["call"] = {
            "function": f"0x{parse_hexaddr(args.call):08x}",
            "args": [f"0x{a & 0xFFFFFFFF:08x}" for a in call_args],
            "returned": call_result.returned,
            "return_registers": {r: f"0x{call_result.result.registers[r]:08x}" for r in ("r0", "r1", "r2", "r3")},
        }
    else:
        sp = parse_hexaddr(args.sp) if args.sp else None
        result = machine.run(parse_hexaddr(args.entry), sp=sp, reg_seed=reg_seed, stop_at=stop_at,
                              **common_kwargs)
        snapshot = result.to_dict()

    text = json.dumps(snapshot, indent=2)
    if args.out:
        with open(args.out, "w") as f:
            f.write(text + "\n")
        print(f"Wrote {args.out}", file=sys.stderr)
    else:
        print(text)

    return 0 if result.error is None else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
