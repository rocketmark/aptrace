# Unicorn Backend

Concrete Cortex-M/Thumb execution and state capture. See
[`tool-selection.md`](tool-selection.md) for when to reach for this instead
of Crucible — in short: whenever the question is "what does this code do
from a known starting state," not "what input satisfies this property."

## Setup

A project-local, pinned Python venv (not a global install, so it doesn't
touch the user's system Python):

```sh
python3 -m venv tools/unicorn/.venv
tools/unicorn/.venv/bin/pip install -r tools/unicorn/requirements.txt   # unicorn==2.1.4
```

`tools/doctor.sh` checks this venv exists and that `unicorn` imports
correctly, and runs a real functional smoke test (below) if the AutoPilot
firmware is present.

## Usage

```sh
tools/unicorn/.venv/bin/python3 tools/unicorn/run_concrete.py \
    --firmware Autopilot_firm/firmware_autopilot868.bin \
    --entry 0x888c --reg r3=0x26 \
    --stop-at 0x8890 --stop-at 0x889e \
    --trace
```

Key flags: `--reg NAME=HEX` seeds a register before execution (repeatable);
`--seed-mem ADDR:HEXBYTES` writes concrete bytes into memory (repeatable);
`--stop-at HEXADDR` halts when reached (repeatable); `--dump-mem ADDR:LEN`
includes a memory range in the output snapshot; `--trace` logs each
instruction's address to stderr. Full flag list: `run_concrete.py --help`.

**`--watch HEXADDR`** (repeatable): records full register state every time
an address is hit, **without halting** — unlike `--stop-at`. Combine with
**`--watch-mem ADDR:LEN`** (repeatable) to also capture memory ranges at
each hit. This is what a per-iteration loop trace needs (one `--stop-at`
only ever gives you the *first* hit); see
[`docs/investigations/dispatcher-loop-concrete-trace.md`](../investigations/dispatcher-loop-concrete-trace.md)
for a real trace built this way. `--max-watch-hits N` (default 2000) caps
total recorded hits as a safety net against a genuinely unbounded loop.

**`--log-mmio`**: records every read/write into the MMIO window (address,
size, direction, value, PC) as a `mmio_log` list in the snapshot —
observability only, it does not change the zero-behavior MMIO model
(reads still return whatever was last written, with no real peripheral
side effects). Resolve the logged addresses to real ATSAMD51J19A
peripheral/register names with
[`tools/svd/resolve_mmio.py`](../../tools/svd/resolve_mmio.py) — see
[`tool-selection.md`](tool-selection.md)'s "SVD / MMIO labeling" section
and
[`docs/investigations/samd51-peripheral-mapping.md`](../investigations/samd51-peripheral-mapping.md)
for a real use of this (and for what happened when the outbound TX path
was probed this way: zero MMIO accesses on the path up to the TX hook
itself — a genuine, informative negative result, not a tool failure).
`--max-mmio-log N` (default 5000) caps how many accesses are recorded.

**`--stub-call HEXADDR`** (repeatable): treats that address as an opaque
function that returns immediately (`PC := LR`) instead of executing its
body. This is the concrete-execution equivalent of the opaque
function-call override already used on the Crucible side
(`docs/project-status.md`'s "A real calling-convention bug, fixed") — use
it for a real callee whose *internals* the current scenario doesn't
depend on (a hardware driver call, a busy-wait against a real peripheral
that the zero-behavior MMIO stub can never satisfy) and whose return
value is either unused (`void`) or doesn't matter for the property being
checked. It does not fabricate a return value — registers are left
exactly as the caller set them up. See
[`docs/investigations/mando-first-execution.md`](../investigations/mando-first-execution.md)
for a real use (stubbing a radio poll and a SysTick-based delay to let a
real byte-consumption loop run to completion).

**`--watch-mem-write ADDR:LEN`** (repeatable): a *true* memory
watchpoint — unlike `--watch` (which triggers on a **code** address),
this fires on any **write** that lands in `[ADDR, ADDR+LEN)`, anywhere in
the address space, regardless of which instruction or function performs
it. Use it when a static xref/literal search finds no writer for a RAM
address and the leading theory is a computed/indirect store (a pointer
built from a *different* literal plus a runtime offset) that a
literal-value search can't attribute to the target address — this is
exactly the tool for confirming or ruling that out concretely, rather
than reading more decompiles by hand. Added for
[`docs/investigations/channel-busy-gate-search.md`](../investigations/channel-busy-gate-search.md),
which used it to get a genuine negative result (no write observed) after
static search had already checked every function referencing the address
via a direct literal. Each hit records the instruction count, PC, LR,
address, size, and value written. `--max-mem-write-log N` (default 2000)
caps hits per range.

**`--fake-tick ADDR:PERIOD`** (repeatable): every `PERIOD` *instructions*
executed, increments the 4-byte little-endian counter at `ADDR` by 1.
This is deliberately **not** a SysTick/timer peripheral model — it never
touches SysTick's MMIO registers (`CTRL`/`LOAD`/`VAL`) or NVIC. It is a
direct, narrowly-scoped stand-in for a **firmware-maintained tick
variable** (a `millis()`-style counter an ISR increments), for the case
where real elapsed-time delay/timeout logic needs to see time pass to
terminate, and building a real SysTick countdown model would be more
machinery than the question needs. **Find the real variable first**:
locate the firmware's own tick-read function (its body is typically just
`return *some_RAM_address;`) and disassemble the real `SysTick_Handler`
(vector table index 15) to confirm it increments that same address — see
[`docs/investigations/systick-tick-injection.md`](../investigations/systick-tick-injection.md)
for a full worked example on this firmware (`FUN_0000ccd0`/`FUN_0000ccdc`
both derive from a single RAM counter at `0x200052ec`, incremented by the
real `SysTick_Handler` at `0xcca4`). Advancing on an instruction-count
cadence rather than real time means any result obtained this way must be
reported as **"firmware behavior observed after time was advanced by the
harness,"** never as "real hardware timing behavior modeled" — the rate,
jitter, and exact tick/instruction ratio are artifacts of the harness,
not the MCU. A **separate** hardware-timing dependency this does *not*
address: a tight cycle-counter busy-wait (e.g. reading `DWT->CYCCNT` at
`0xE0001000+4` twice and comparing) needs its own treatment —
`--stub-call` the delay function itself if its precise pulse-width
timing isn't what the scenario is testing.

**`--mmio-force-bits ADDR:MASK`** (repeatable): every read of the
4-byte-aligned MMIO register at `ADDR` is OR'd with `MASK` before the CPU
sees it — a specific status/ready bit forced set. This is **not** a
peripheral model: it never fires on a write, never clears anything, and
touches exactly the one named register. Use it only for a bit you can
name from the real SVD (`tools/svd/resolve_mmio.py`) as a documented
completion/ready flag that real hardware sets predictably once the
firmware's own preceding write takes effect — e.g. an oscillator-ready
or PLL-lock bit on hardware already confirmed to boot (see
[`docs/investigations/reset-handler-clock-init.md`](../investigations/reset-handler-clock-init.md),
which used this for `OSC32KCTRL.STATUS.XOSC32KRDY`,
`OSCCTRL.STATUS.DFLLRDY`, and both `DPLLx.DPLLSTATUS.{LOCK,CLKRDY}`
during real clock-init). Never use it for a bit whose true value depends
on something this harness can't establish — an external signal, or
state that belongs in `--seed-mem` instead.

**`--mmio-clear-bits ADDR:MASK`** (repeatable): the complement — every
read is AND'd with `~MASK`, forcing a bit clear. For a bit the firmware
itself just *set* that real hardware self-clears within a few cycles (a
software-reset bit is the textbook case) and the plain read/write memory
model otherwise leaves stuck forever. `reset-handler-clock-init.md` used
this for two SERCOM instances' `CTRLA.SWRST`/`SYNCBUSY.SWRST` (bit 0),
both real, SVD-documented self-clearing bits triggered by the firmware's
own reset write. Same discipline as `--mmio-force-bits`: name the real
register/field first, never use it to paper over a bit whose true
behavior is unknown.

**`--map-page ADDR:SIZE`** (repeatable): maps one additional
page-aligned region before execution, for a real, fixed memory area
outside flash/RAM/MMIO that the firmware genuinely reads — the only
case seen so far is the SAMD51 NVM Software Calibration Row
(`0x00800080`), a real, factory-programmed, per-die area. Pair with
`--seed-mem` to fill it; the seeded bytes are then a **disclosed
placeholder** for real silicon-specific data this harness has no way to
know, not a claim about the true calibration values — document what the
placeholder feeds (in `reset-handler-clock-init.md`'s case, only analog
ADC/DAC/USB trim registers, confirmed to have no path to the digital
state that investigation cared about).

**`--force-reg ADDR:REG:HEX`** (repeatable): immediately before executing
the instruction at `ADDR`, set register `REG` to `HEX`. This is
different in kind from every other hook above, and the only one that
**fabricates** a value rather than modeling documented MCU behavior:
`--mmio-force-bits`/`--mmio-clear-bits` assert what the chip's *own*
silicon guarantees once its preceding register write takes effect;
`--force-reg` asserts something the harness has no way to know — an
external device's response, a value from outside the MCU entirely. Use
it only as a disclosed environmental assumption, scoped to the single
instruction *after* one specific call site returns (not the callee's
entry, so unrelated calls to the same function are unaffected), and say
so plainly wherever the run's results are reported — "harness-supplied
external-device state," never "observed" or "firmware-produced." First
use:
[`docs/investigations/post-homing-radio-probe.md`](../investigations/post-homing-radio-probe.md)'s
follow-up forces `r0 = 0x12` at the one instruction right after a real
SPI chip-ID read returns, standing in for "a radio module is present and
answers this specific read with the value real firmware requires" — not
evidence that a real radio was observed, and not a general SERCOM/SPI
model (every *other* read through the same peripheral is unaffected).

Output is a JSON snapshot: instruction count, why execution stopped, final
register values, any requested memory dumps, a `watch_hits` list (each
entry: hit index, instruction count, address, registers, watched memory),
(with `--log-mmio`) an `mmio_log` list, (with `--stub-call`) a
`stub_hits` list, (with `--watch-mem-write`) a `mem_write_hits` list,
(with `--fake-tick`) a `fake_ticks_applied` list (address, period, and
how many increments actually fired), (with `--mmio-force-bits`/
`--mmio-clear-bits`) `mmio_force_bits_applied`/`mmio_clear_bits_applied`
lists (address, mask, and how many reads actually changed a value —
`count: 0` means the bit was already in the needed state and the hook
never had to do anything), and (with `--force-reg`) a `force_reg_hits`
list (instruction count, address, and which register was set to what).
Written to `--out PATH` or stdout.

## Confirmed smoke test: reproduces the solver-confirmed `&` branch

Running the command above (seeding `r3 = 0x26`, the `&` command's ASCII
value) concretely executes exactly 3 instructions and halts at `0x8890` —
the same handler block
[`docs/harness/protocol-harness-results.md`](../harness/protocol-harness-results.md)
solver-confirmed symbolically. Seeding any other value for `r3` (e.g. `0x0`)
instead halts at the fallthrough `0x889e`. This is a genuine cross-check at
a different evidence level (see `tool-selection.md`'s "Evidence levels"): a
concrete run for one input, agreeing with a solver's proof over all inputs.

## Second confirmed use: locating a real branch a static/symbolic pass missed

Entering at the dispatcher's real caller (`0x8a34`) with a real `&|` packet
and letting the firmware establish its own entry state (see
[`docs/investigations/dispatcher-loop-concrete-trace.md`](../investigations/dispatcher-loop-concrete-trace.md))
found, concretely, that the previously-suspected `0x827e` loop is not even
on the execution path for this command — a `bne` branch at `0x8266`
(`buffer[0] == 0xF0`?) routes around it entirely. This is exactly the kind
of fact concrete execution settles quickly that manual disassembly reading
had missed across several earlier passes.

## A real gotcha this surfaced: the Thumb bit belongs on the *address*, not just the mode flag

Constructing `Uc(UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_MCLASS)` is **not
enough** to get Thumb decoding — the very first instruction fetch will fail
with `UC_ERR_INSN_INVALID` (confirmed: it silently executes 4-byte-aligned
ARM-mode fetches instead, consuming zero-filled memory as bogus
`ANDEQ`-shaped instructions). Unicorn follows the same convention as real
hardware `BX`/`BLX`: **the low bit of the address passed to `emu_start()`
(and of the initial `PC` register value) selects Thumb state**, exactly
like the "Thumb bit" convention already used throughout this project's
Macaw/vector-table work for handler addresses. `run_concrete.py` always
ORs this bit in (Cortex-M is Thumb-only, so it's never optional here) —
see the comment at the top of `main()` in `tools/unicorn/run_concrete.py`.
Also required: `uc.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_M4)` — without an
explicit CPU model, Unicorn's default core does not reliably support the
full Cortex-M4 Thumb-2 instruction set used by this firmware.

## Known limitations

- The MMIO region (`0x40000000` by default, size configurable) is mapped as
  plain zero-initialized RAM — reads return whatever was last written, with
  no real peripheral behavior (no side effects, no status-register
  semantics). Fine for control-flow questions that don't depend on real
  peripheral state; not fine for anything that does — e.g. a status-bit
  polling loop against a real peripheral will spin forever here, since the
  bit never goes high. `--log-mmio` (see above) plus
  `tools/svd/resolve_mmio.py` names *which* addresses are touched.
  **Where a specific bit is a real, SVD-identified, predictably-completing
  status/ready/self-clearing flag** — confirmed for this firmware's real
  `Reset_Handler` clock-init chain and one SERCOM/DMA driver constructor,
  see
  [`docs/investigations/reset-handler-clock-init.md`](../investigations/reset-handler-clock-init.md)
  — use `--mmio-force-bits`/`--mmio-clear-bits` (above) rather than
  `--stub-call`ing the whole poll away; it lets the real surrounding logic
  run and produces a real result instead of skipping it. This is still not
  a general peripheral *behavior* model (see `docs/project-status.md`'s
  "Tooling gaps" — do not build one unless a real use case needs it) —
  each address is named and justified individually, never applied broadly.
  `--stub-call` remains the right tool when a callee's internal behavior
  genuinely doesn't matter to the scenario, or when the bit's true value
  is not something this harness can establish. **When it genuinely is
  external** — a real device's response over a real bus, not MCU-internal
  state — that's exactly the case `--force-reg` (above) is for, with its
  own, stricter disclosure requirement (it fabricates, it doesn't model).
  See
  [`docs/investigations/post-homing-radio-probe.md`](../investigations/post-homing-radio-probe.md)'s
  follow-up for a worked example distinguishing the two.
- The ARM Private Peripheral Bus (`0xE0000000`-`0xE00FFFFF` — SysTick,
  NVIC, SCB, MPU) was unmapped until
  [`docs/investigations/mando-first-execution.md`](../investigations/mando-first-execution.md)
  found real Cortex-M startup/delay code touching it; now mapped
  unconditionally with the same zero-behavior stub (skipped only if a
  custom `--mmio-base`/`--mmio-size` already covers it). Same caveat as
  above: no real SysTick counting, so a delay loop that reads SysTick's
  own MMIO registers directly will spin forever. **Where a delay instead
  reads a firmware-maintained tick/millis *variable*** (the common case —
  confirmed for this firmware's `millis()`/`micros()` equivalents), use
  `--fake-tick` (above) rather than `--stub-call`ing the delay away — it
  lets the real elapsed-time comparison logic run and produce a real
  result instead of skipping it. Still no general SysTick/NVIC emulator,
  and still not planned unless a real use case needs one; a genuine
  cycle-counter (`DWT->CYCCNT`) busy-wait is a separate case (see
  `--fake-tick`'s entry above) — `--stub-call` remains the right tool
  when a callee's internal timing genuinely doesn't matter.
- Single-shot process per run, not a persistent/interactive session — fine
  for scenario-style concrete replay (load, seed, run, snapshot), not for
  step-through debugging.
- No reusable snapshot *format* beyond plain JSON yet — sufficient for this
  pass's smoke tests; if APTrace later wants to feed a Unicorn-captured
  state into a Crucible run (e.g. to seed a symbolic query from a genuinely
  reached concrete state), that hand-off format doesn't exist yet.
