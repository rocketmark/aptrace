"""APTrace: a reusable Unicorn-based concrete Cortex-M/Thumb execution
library.

This is the library `tools/unicorn/run_concrete.py` (the CLI) and
`tools/unicorn/virtual_link.py` (the multi-leg scenario scripts) are both
built on. It exists to remove five recurring costs this project's own
investigations kept re-paying by hand:

  1. A fresh `Uc` instance (with a full flash/RAM/MMIO mapping and a
     fresh copy of the firmware image) was created *per subprocess call*,
     even when ten calls in a row targeted the same firmware -- see
     `ConcreteMachine`, which loads the firmware and builds the memory
     map once and offers an explicit, cheap `reset()` between runs.
  2. Capturing "the bytes a register points at, once code reaches some
     address" (`capture_tx_bytes` in `virtual_link.py`) took two full
     concrete runs: one to discover the register's value, one to dump
     memory at that value. `dump_reg_pointee` does both in the run that
     already stops there.
  3. Calling a real function directly (not through its real caller)
     required hand-computing a stack pointer, hand-placing any argument
     beyond the fourth at the exact AAPCS stack offset, and inventing a
     return address -- usually by pointing LR at *some* firmware address
     and accepting a crash once execution got there, then reading
     whatever memory effects happened before the crash. `call()` does
     this properly: real AAPCS argument placement, a real trampoline
     instruction as the return address (so the function's own real
     epilogue returns cleanly), and a structured `CallResult`.
  4. A failed run's JSON snapshot still contains everything about *why*
     it failed, but every investigation that hit a `RuntimeError` from a
     subprocess wrapper had to rerun the same scenario by hand to see it.
     `run()` returns the full `RunResult` on failure too (never raises
     unless asked to), and it always carries a bounded recent-PC ring
     buffer (`recent_pcs`) so "what was it doing right before it died"
     doesn't need `--trace --trace-every 1` for the whole run.
  5. Carrying real, firmware-produced memory from one run into the next
     (e.g. a struct `'+'` wrote, read back into the run that delivers a
     `G` command) was manual hex round-tripping. `RunResult.carry(...)`
     packages exactly the requested bytes, tagged as "carried" rather
     than "seeded", so it stays visibly distinct from a disclosed
     harness assumption in logs/results.

See docs/tooling/unicorn-backend.md for the full design writeup and
docs/investigations/toolchain-cleanup.md for the specific frictions this
replaced. `tools/unicorn/run_concrete.py --help` documents the CLI layer
built on top of this (string parsing, JSON I/O); everything numeric here
is plain Python ints -- there is no hex/decimal ambiguity at this layer,
that concern belongs entirely to the CLI's own argument parsing.
"""
import collections

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
DEFAULT_TRACE_LAST = 64

# The Cortex-M architected Private Peripheral Bus (SysTick, NVIC, SCB, MPU,
# etc.) -- not board-specific MMIO, but part of every Cortex-M's address
# map, so ordinary startup/delay code that touches it doesn't fault.
PPB_BASE, PPB_SIZE = 0xE0000000, 0x100000

# A single "b ." (branch-to-self) Thumb16 instruction (encoding 0xE7FE,
# little-endian bytes FE E7): a real, validly-decodable instruction used
# as a return trampoline for direct-entry calls (see ConcreteMachine.call).
# Unicorn's --stop-at-style hook only fires *after* successfully decoding
# the instruction at that PC, so a synthetic return address must contain
# real code, not data -- this is the smallest such code that is also
# provably harmless if somehow actually executed (it just spins, bounded
# by max_instructions, rather than corrupting anything).
TRAMPOLINE_BYTES = b"\xfe\xe7"


def align_down(x, page=PAGE):
    return x & ~(page - 1)


def align_up(x, page=PAGE):
    return (x + page - 1) & ~(page - 1)


class Carried:
    """Wraps memory bytes that came from a PRIOR concrete run's own real
    output (see `RunResult.carry`), so `ConcreteMachine.run`'s seed_mem
    processing -- and everything it logs -- can tell "the real firmware
    produced these bytes in an earlier run" apart from "the investigator
    is asserting representative prior state" (a plain (addr, bytes)
    tuple). Never construct this with hand-chosen bytes; only pass
    through what a `RunResult` actually recorded."""

    __slots__ = ("addr", "data", "source")

    def __init__(self, addr, data, source):
        self.addr = addr
        self.data = data
        self.source = source  # a short label, e.g. "leg2@0x20001b40"


class RunResult:
    """Everything about one concrete run -- successful or not. A failed
    run (Unicorn exception, unmapped access, hit an unexpected address)
    is still a fully analyzable result: `success` is False and
    `stop_reason`/`error`/`registers`/`recent_pcs`/whatever was requested
    via dump_mem/watch/etc. are all populated exactly as they would be on
    success. Callers that want exception-based control flow can pass
    raise_on_error=True to `ConcreteMachine.run`, which raises
    `ConcreteExecutionError(result)` -- the result is still fully
    inspectable via the exception's own `.result` attribute."""

    def __init__(self, **fields):
        self.__dict__.update(fields)

    @property
    def success(self):
        return self.error is None

    def stopped_at(self, addr):
        return self.stop_reason == f"reached stop address 0x{addr & ~1:08x}"

    def expect_stop(self, addr):
        """Raise (with the full result attached) if this run did not
        cleanly stop at the expected address -- the direct replacement
        for virtual_link.py's old bare `_expect_stop` assertion, now
        carrying the whole structured snapshot on failure instead of a
        bare string mismatch."""
        if not self.stopped_at(addr):
            raise ConcreteExecutionError(self, f"expected to stop at 0x{addr:08x}, got: {self.stop_reason}")
        return self

    def reg(self, name):
        return self.registers[name]

    def mem(self, addr, length=None):
        """Bytes previously captured via dump_mem at exactly this
        (addr, length). Raises KeyError with a helpful message if this
        range wasn't requested -- dump_mem is opt-in per run, on purpose
        (no implicit whole-RAM capture)."""
        for (a, n), data in self.memory.items():
            if a == addr and (length is None or n == length):
                return data
        raise KeyError(f"0x{addr:08x} (len={length}) was not in this run's dump_mem request; "
                        f"available: {[(hex(a), n) for a, n in self.memory]}")

    def reg_pointee(self, reg_name):
        """The (pointer_value, bytes) pair captured via dump_reg_pointee
        for this register, from THIS run's own single execution -- the
        register's value is whatever the real firmware computed, not a
        pre-supplied address (see ConcreteMachine.run's dump_reg_pointee
        parameter)."""
        return self._reg_pointee[reg_name]

    def carry(self, addr, length, label=None):
        """Package bytes this run's own dump_mem actually captured for
        use as a later run's seed_mem -- the mechanism for explicit,
        visible state carry-forward between logically separate concrete
        runs (e.g. a struct one '+' delivery wrote, fed into the G
        delivery that reads it). The returned Carried object's presence
        in a later run's applied_seeds log (tag starts with 'carried:')
        is what keeps this distinguishable from a disclosed harness
        seed -- never hand-construct a Carried with bytes that didn't
        come from a prior RunResult."""
        data = self.mem(addr, length)
        return Carried(addr, data, label or f"0x{addr:08x}+{length}@{self.label}")

    def to_dict(self):
        """The same JSON-serializable shape run_concrete.py's CLI has
        always emitted (field-for-field compatible with every existing
        consumer), plus the new fields this module adds (recent_pcs,
        reg_pointee, applied_seeds) -- additive only, so old code that
        looks up known keys is unaffected."""
        d = {
            "firmware": self.firmware,
            "entry": f"0x{self.entry:08x}",
            "instructions_executed": self.instructions_executed,
            "stop_reason": self.stop_reason,
            "error": self.error,
            "registers": {k: f"0x{v:08x}" for k, v in self.registers.items()},
            "memory": {f"0x{a:08x}": data.hex() for (a, _n), data in self.memory.items()},
            "reg_pointee": {
                r: {"pointer": f"0x{p:08x}", "data": data.hex() if data is not None else None}
                for r, (p, data) in self._reg_pointee.items()
            },
            "recent_pcs": [f"0x{pc:08x}" for pc in self.recent_pcs],
            "applied_seeds": self.applied_seeds,
            "watch_hits": self.watch_hits,
            "mmio_log": self.mmio_log,
            "stub_hits": self.stub_hits,
            "mem_write_hits": self.mem_write_hits,
            "fake_ticks_applied": self.fake_ticks_applied,
            "mmio_force_bits_applied": self.mmio_force_bits_applied,
            "mmio_clear_bits_applied": self.mmio_clear_bits_applied,
            "force_reg_hits": self.force_reg_hits,
            "force_mem_hits": self.force_mem_hits,
        }
        return d


class ConcreteExecutionError(Exception):
    """Raised only when a caller explicitly opts into exception-based
    control flow (raise_on_error=True, or RunResult.expect_stop). Always
    carries the complete RunResult -- 'a failed emulation should still be
    an analyzable result' applies here too; callers should inspect
    `.result`, not just the message."""

    def __init__(self, result, message=None):
        self.result = result
        super().__init__(message or result.stop_reason)


class CallResult:
    """The outcome of `ConcreteMachine.call(...)`: the underlying
    RunResult (for full inspection -- memory dumps, recent_pcs, etc. all
    still work) plus the AAPCS return-value registers, and a `returned`
    flag distinguishing "the function's own real epilogue reached the
    trampoline" (a clean return) from any other outcome (a crash, an
    unexpected stop, hitting max_instructions -- all still fully
    reported via `.result`, never silently swallowed)."""

    def __init__(self, result, returned):
        self.result = result
        self.returned = returned

    @property
    def r0(self):
        return self.result.registers["r0"]

    @property
    def r1(self):
        return self.result.registers["r1"]

    @property
    def r2(self):
        return self.result.registers["r2"]

    @property
    def r3(self):
        return self.result.registers["r3"]

    def signed(self, reg_name):
        v = self.result.registers[reg_name]
        return v - (1 << 32) if v & 0x80000000 else v


class ConcreteMachine:
    """One firmware image's memory map, built once and reused across many
    runs. `run()` resets RAM+registers to a pristine state before each
    call by default (matching the old one-process-per-scenario-leg
    behavior every existing investigation already relied on) -- pass
    fresh=False for the rarer case of genuinely continuing execution
    state across two calls in the same scenario (see `call()`'s own use
    of this for multi-state-machine-transition scenarios).

    MMIO is NOT reset by run()'s default fresh=True -- only RAM and
    registers are (see `reset()`'s own doc for why: MMIO regions are
    frequently mapped at tens of megabytes for --mmio-force-bits/
    --mmio-clear-bits coverage, and copying that on every run would
    reintroduce exactly the setup churn this class exists to remove).
    Call `reset(mmio=True)` explicitly when a scenario's MMIO state must
    not leak into the next one -- 'clear/reset semantics must be
    explicit', not an assumption callers have to verify by reading this
    class's internals.
    """

    def __init__(self, firmware_path, flash_base=0x4000, ram_base=0x20000000, ram_size=0x30000,
                 mmio_base=0x40000000, mmio_size=0x100000, extra_maps=()):
        self.firmware_path = str(firmware_path)
        with open(firmware_path, "rb") as f:
            self.firmware = f.read()
        self.flash_base = flash_base
        self.ram_base = ram_base
        self.ram_size = ram_size
        self.mmio_base = mmio_base
        self.mmio_size = mmio_size
        self.extra_maps = list(extra_maps)

        # The top 0x1000 bytes of RAM are reserved for this class's own
        # bookkeeping (the return trampoline) -- never handed out as the
        # default call-stack top, so a deep/careless stack usage in a
        # called function can't stomp on it (see call()'s stack
        # allocation, which stays below stack_ceiling).
        self.stack_ceiling = ram_base + ram_size - 0x1000
        self.trampoline_addr = ram_base + ram_size - 0x10

        self._build()

    def _build(self):
        uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_MCLASS)
        uc.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_M4)

        flash_map_size = align_up(len(self.firmware))
        uc.mem_map(align_down(self.flash_base), flash_map_size)
        uc.mem_write(self.flash_base, self.firmware)

        uc.mem_map(align_down(self.ram_base), align_up(self.ram_size))
        uc.mem_map(align_down(self.mmio_base), align_up(self.mmio_size))

        mmio_lo = align_down(self.mmio_base)
        mmio_hi = mmio_lo + align_up(self.mmio_size)
        if not (mmio_lo <= PPB_BASE and PPB_BASE + PPB_SIZE <= mmio_hi):
            uc.mem_map(PPB_BASE, PPB_SIZE)

        for addr, size in self.extra_maps:
            uc.mem_map(align_down(addr), align_up(size))

        uc.mem_write(self.trampoline_addr, TRAMPOLINE_BYTES)

        self.uc = uc
        self._pristine_ram = bytes(uc.mem_read(align_down(self.ram_base), align_up(self.ram_size)))

    def reset(self, ram=True, mmio=False, registers=True):
        """Explicit state reset -- see the class docstring for why MMIO
        defaults to NOT being touched. `run(fresh=True)` (the default)
        calls this with its own defaults before every run; call it
        yourself first if you want a clean slate without immediately
        running anything."""
        if ram:
            self.uc.mem_write(align_down(self.ram_base), self._pristine_ram)
        if mmio:
            zeros = bytes(align_up(self.mmio_size))
            self.uc.mem_write(align_down(self.mmio_base), zeros)
        if registers:
            for reg in NAME_BY_REG:
                self.uc.reg_write(reg, 0)

    def rebuild(self):
        """Full teardown/rebuild of the underlying Uc instance -- for the
        rare case where even a full reset() isn't enough assurance (e.g.
        after a scenario that mapped extra pages via seed_mem tricks this
        class doesn't track). Prefer reset() for ordinary use; this is
        the 'when in doubt' escape hatch, not the common path."""
        self._build()

    # -- core execution -----------------------------------------------

    def run(self, entry, sp=None, reg_seed=(), seed_mem=(), stub_calls=(), stop_at=(),
            dump_mem=(), dump_reg_pointee=(), watch=(), watch_mem=(), max_watch_hits=2000,
            max_instructions=200000, trace=False, trace_every=1, trace_last=DEFAULT_TRACE_LAST,
            fake_tick=(), mmio_force_bits=(), mmio_clear_bits=(), force_reg=(), force_mem=(),
            log_mmio=False, max_mmio_log=5000, watch_mem_write=(), max_mem_write_log=2000,
            fresh=True, label=None, raise_on_error=False):
        """Run concretely from `entry` (Thumb bit added automatically).

        All addresses/values are plain ints -- no hex/decimal ambiguity
        exists at this layer (see the module docstring). `seed_mem`
        entries are (addr, bytes) or (addr, bytes, tag) or a `Carried`
        instance (from a prior RunResult.carry(...)); every one is
        recorded in the result's `applied_seeds` log with its tag
        ("seed" by default, "carried:<source>" for Carried instances),
        so a report can always show which inputs were disclosed
        assumptions versus bytes a prior real run actually produced.

        `dump_reg_pointee`: sequence of (reg_name, length) -- at the
        stop point, read the register's value and dump `length` bytes
        from that address, in this SAME run (see the module docstring's
        point 2 -- this is what let capture_tx_bytes drop from two runs
        to one).

        Returns a RunResult always, even on failure, unless
        raise_on_error=True (then a failure raises ConcreteExecutionError
        wrapping the same RunResult).
        """
        if fresh:
            self.reset(ram=True, mmio=False, registers=True)

        uc = self.uc
        entry_addr = (entry | 1)

        stack_top = sp if sp is not None else self.stack_ceiling
        uc.reg_write(UC_ARM_REG_SP, stack_top)
        uc.reg_write(UC_ARM_REG_PC, entry_addr)

        for name, value in reg_seed:
            name = name.lower()
            if name not in REG_BY_NAME:
                raise ValueError(f"unknown register '{name}'")
            uc.reg_write(REG_BY_NAME[name], value)

        applied_seeds = []
        for entry_spec in seed_mem:
            if isinstance(entry_spec, Carried):
                addr, data, tag = entry_spec.addr, entry_spec.data, f"carried:{entry_spec.source}"
            elif len(entry_spec) == 3:
                addr, data, tag = entry_spec
            else:
                addr, data = entry_spec
                tag = "seed"
            uc.mem_write(addr, data)
            applied_seeds.append({"addr": f"0x{addr:08x}", "len": len(data), "tag": tag})

        stop_addrs = {a & ~1 for a in stop_at}
        watch_addrs = {a & ~1 for a in watch}
        stub_addrs = {a & ~1 for a in stub_calls}
        force_reg_by_addr = {}
        for addr, reg_name, value in force_reg:
            if reg_name.lower() not in REG_BY_NAME:
                raise ValueError(f"unknown register '{reg_name}' in force_reg")
            force_reg_by_addr.setdefault(addr, []).append((reg_name.lower(), value))
        force_mem_by_addr = {}
        for trigger, mem_addr, data in force_mem:
            force_mem_by_addr.setdefault(trigger, []).append((mem_addr, data))

        state = {
            "instructions": 0, "stop_reason": None, "watch_hits": [], "mmio_log": [], "stub_hits": [],
            "mem_write_hits": [], "fake_tick_count": [0] * len(fake_tick),
            "mmio_force_count": [0] * len(mmio_force_bits),
            "mmio_clear_count": [0] * len(mmio_clear_bits),
            "force_reg_hits": [], "force_mem_hits": [],
            "recent_pcs": collections.deque(maxlen=trace_last) if trace_last else None,
        }

        def capture_registers():
            return {NAME_BY_REG[r]: uc.reg_read(r) for r in NAME_BY_REG}

        def capture_watch_memory():
            mem = {}
            for addr, length in watch_mem:
                try:
                    mem[f"0x{addr:08x}"] = uc.mem_read(addr, length).hex()
                except UcError as e:
                    mem[f"0x{addr:08x}"] = f"error: {e}"
            return mem

        def hook_code(uc_, address, size, _user_data):
            state["instructions"] += 1
            if state["recent_pcs"] is not None:
                state["recent_pcs"].append(address)
            if trace and state["instructions"] % trace_every == 0:
                import sys
                print(f"  [unicorn] #{state['instructions']} pc=0x{address:08x}", file=sys.stderr)
            for i, (tick_addr, period) in enumerate(fake_tick):
                if period > 0 and state["instructions"] % period == 0:
                    cur = int.from_bytes(uc_.mem_read(tick_addr, 4), "little")
                    uc_.mem_write(tick_addr, ((cur + 1) & 0xFFFFFFFF).to_bytes(4, "little"))
                    state["fake_tick_count"][i] += 1
            if address in force_reg_by_addr:
                hit = {"instruction": state["instructions"], "address": f"0x{address:08x}", "set": []}
                for reg_name, value in force_reg_by_addr[address]:
                    uc_.reg_write(REG_BY_NAME[reg_name], value)
                    hit["set"].append({"reg": reg_name, "value": f"0x{value:08x}"})
                state["force_reg_hits"].append(hit)
            if address in force_mem_by_addr:
                hit = {"instruction": state["instructions"], "address": f"0x{address:08x}", "writes": []}
                for mem_addr, data in force_mem_by_addr[address]:
                    uc_.mem_write(mem_addr, data)
                    hit["writes"].append({"addr": f"0x{mem_addr:08x}", "bytes": data.hex(), "len": len(data)})
                state["force_mem_hits"].append(hit)
            if address in stub_addrs:
                lr = uc_.reg_read(UC_ARM_REG_LR)
                state["stub_hits"].append({
                    "instruction": state["instructions"], "address": f"0x{address:08x}", "lr": f"0x{lr:08x}",
                })
                uc_.reg_write(UC_ARM_REG_PC, lr)
                return
            if address in watch_addrs:
                if len(state["watch_hits"]) >= max_watch_hits:
                    state["stop_reason"] = f"max watch hits ({max_watch_hits}) reached at 0x{address:08x}"
                    uc_.emu_stop()
                    return
                state["watch_hits"].append({
                    "hit": len(state["watch_hits"]),
                    "instruction": state["instructions"],
                    "address": f"0x{address:08x}",
                    "registers": {k: f"0x{v:08x}" for k, v in capture_registers().items()},
                    "memory": capture_watch_memory(),
                })
            if address in stop_addrs:
                state["stop_reason"] = f"reached stop address 0x{address:08x}"
                uc_.emu_stop()

        def hook_mem_unmapped(uc_, access, address, size, value, _user_data):
            state["stop_reason"] = f"unmapped memory access (type={access}) at 0x{address:08x} size={size}"
            return False

        def hook_mmio(uc_, access, address, size, value, _user_data):
            if len(state["mmio_log"]) >= max_mmio_log:
                return
            state["mmio_log"].append({
                "instruction": state["instructions"],
                "pc": f"0x{uc_.reg_read(UC_ARM_REG_PC):08x}",
                "address": f"0x{address:08x}",
                "size": size,
                "direction": "read" if access == UC_MEM_READ else "write",
                "value": f"0x{value:x}" if access != UC_MEM_READ else None,
            })

        def make_mmio_force_hook(i, addr, mask):
            def hook(uc_, access, address, size, value, _user_data):
                cur = int.from_bytes(uc_.mem_read(addr, 4), "little")
                forced = (cur | mask) & 0xFFFFFFFF
                if forced != cur:
                    uc_.mem_write(addr, forced.to_bytes(4, "little"))
                    state["mmio_force_count"][i] += 1
            return hook

        def make_mmio_clear_hook(i, addr, mask):
            def hook(uc_, access, address, size, value, _user_data):
                cur = int.from_bytes(uc_.mem_read(addr, 4), "little")
                cleared = cur & (~mask & 0xFFFFFFFF)
                if cleared != cur:
                    uc_.mem_write(addr, cleared.to_bytes(4, "little"))
                    state["mmio_clear_count"][i] += 1
            return hook

        def make_mem_write_hook(range_addr, range_len):
            def hook(uc_, access, address, size, value, _user_data):
                if len(state["mem_write_hits"]) >= max_mem_write_log:
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
            return hook

        handles = []
        handles.append(uc.hook_add(UC_HOOK_CODE, hook_code))
        handles.append(uc.hook_add(UC_HOOK_MEM_UNMAPPED, hook_mem_unmapped))
        if log_mmio:
            handles.append(uc.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, hook_mmio,
                                        begin=align_down(self.mmio_base),
                                        end=align_down(self.mmio_base) + align_up(self.mmio_size) - 1))
        for addr, length in watch_mem_write:
            handles.append(uc.hook_add(UC_HOOK_MEM_WRITE, make_mem_write_hook(addr, length),
                                        begin=addr, end=addr + length - 1))
        for i, (addr, mask) in enumerate(mmio_force_bits):
            handles.append(uc.hook_add(UC_HOOK_MEM_READ, make_mmio_force_hook(i, addr, mask),
                                        begin=addr, end=addr + 3))
        for i, (addr, mask) in enumerate(mmio_clear_bits):
            handles.append(uc.hook_add(UC_HOOK_MEM_READ, make_mmio_clear_hook(i, addr, mask),
                                        begin=addr, end=addr + 3))

        error = None
        try:
            uc.emu_start(entry_addr, 0, count=max_instructions)
            if state["stop_reason"] is None:
                state["stop_reason"] = (
                    "instruction limit reached" if state["instructions"] >= max_instructions
                    else "returned (fell off emu_start)"
                )
        except UcError as e:
            error = str(e)
            if state["stop_reason"] is None:
                state["stop_reason"] = f"error: {error}"
        finally:
            for h in handles:
                uc.hook_del(h)

        registers = capture_registers()

        memory = {}
        for spec in dump_mem:
            addr, length = spec
            try:
                memory[(addr, length)] = bytes(uc.mem_read(addr, length))
            except UcError as e:
                memory[(addr, length)] = f"error: {e}".encode()

        reg_pointee = {}
        for reg_name, length in dump_reg_pointee:
            ptr = registers[reg_name.lower()]
            try:
                data = bytes(uc.mem_read(ptr, length))
            except UcError:
                data = None
            reg_pointee[reg_name.lower()] = (ptr, data)

        result = RunResult(
            firmware=self.firmware_path,
            entry=entry_addr,
            label=label,
            instructions_executed=state["instructions"],
            stop_reason=state["stop_reason"],
            error=error,
            registers=registers,
            memory=memory,
            _reg_pointee=reg_pointee,
            recent_pcs=list(state["recent_pcs"]) if state["recent_pcs"] is not None else [],
            applied_seeds=applied_seeds,
            watch_hits=state["watch_hits"],
            mmio_log=state["mmio_log"],
            stub_hits=state["stub_hits"],
            mem_write_hits=state["mem_write_hits"],
            fake_ticks_applied=[
                {"addr": f"0x{addr:08x}", "period": period, "count": state["fake_tick_count"][i]}
                for i, (addr, period) in enumerate(fake_tick)
            ],
            mmio_force_bits_applied=[
                {"addr": f"0x{addr:08x}", "mask": f"0x{mask:x}", "count": state["mmio_force_count"][i]}
                for i, (addr, mask) in enumerate(mmio_force_bits)
            ],
            mmio_clear_bits_applied=[
                {"addr": f"0x{addr:08x}", "mask": f"0x{mask:x}", "count": state["mmio_clear_count"][i]}
                for i, (addr, mask) in enumerate(mmio_clear_bits)
            ],
            force_reg_hits=state["force_reg_hits"],
            force_mem_hits=state["force_mem_hits"],
        )
        if raise_on_error and error is not None:
            raise ConcreteExecutionError(result)
        return result

    # -- direct-function-call helper (priority 4) ----------------------

    def call(self, entry, args=(), stub_calls=(), seed_mem=(), reg_seed=(), max_instructions=20000,
             sp=None, fresh=True, label=None, **run_kwargs):
        """Call a real firmware function directly, per ARM AAPCS, without
        going through its real caller. Handles:

          - r0-r3 argument placement (args[0:4])
          - stack arguments beyond r3 (args[4:], placed at [sp+0],
            [sp+4], ... exactly where a real caller's own `str`
            sequence would put them before a `bl`)
          - an 8-byte-aligned stack allocation sized to the extra
            arguments, carved out of the space below stack_ceiling (never
            colliding with this machine's own reserved trampoline page)
          - Thumb entry (the entry address's Thumb bit is set the same
            way `run()` always sets it)
          - a real, valid, harmless return address (this machine's
            trampoline instruction) instead of an arbitrary firmware
            address chosen to crash predictably
          - stopping cleanly the moment the function's own real epilogue
            reaches that trampoline (CallResult.returned is True), rather
            than inferring a return from an intentional PC=0 crash

        Does NOT assume the callee is leaf/simple: it may itself push/pop
        registers, call other real functions (stub non-essential ones via
        stub_calls, exactly as with run()), and use stack space below its
        own entry SP -- all of that happens for real, below the call's
        own stack allocation, with the same generous headroom run()'s
        default SP already provides.

        Returns a CallResult (result + r0-r3 + `returned`); does not
        raise on a non-clean return -- check `.returned` and inspect
        `.result` (recent_pcs, stop_reason, etc. are always populated).
        """
        args = list(args)
        reg_args = args[:4]
        stack_args = args[4:]

        stack_top = sp if sp is not None else self.stack_ceiling
        if stack_args:
            extra_bytes = align_up(len(stack_args) * 4, 8)
            call_sp = align_down(stack_top - extra_bytes, 8)
        else:
            call_sp = align_down(stack_top, 8)

        seed = list(seed_mem)
        for i, value in enumerate(stack_args):
            seed.append((call_sp + i * 4, (value & 0xFFFFFFFF).to_bytes(4, "little"), "abi-stack-arg"))

        # Caller-supplied reg_seed (e.g. non-argument register setup) is
        # applied first; this call's own LR/argument registers are
        # applied after, so they always win if there's any overlap --
        # the ABI's own argument placement is never silently overridden.
        full_reg_seed = list(reg_seed) + [("lr", self.trampoline_addr | 1)]
        reg_names = ("r0", "r1", "r2", "r3")
        for name, value in zip(reg_names, reg_args):
            full_reg_seed.append((name, value & 0xFFFFFFFF))

        result = self.run(
            entry=entry, sp=call_sp, reg_seed=full_reg_seed, seed_mem=seed,
            stub_calls=stub_calls, stop_at=[self.trampoline_addr],
            max_instructions=max_instructions, fresh=fresh, label=label,
            **run_kwargs,
        )
        returned = result.stopped_at(self.trampoline_addr)
        return CallResult(result, returned)
