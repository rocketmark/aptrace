# Investigation: Grounding Firmware Analysis in the Confirmed ATSAMD51J19A Hardware

**Question**: now that
[`docs/hardware/autopilot-research-handoff.md`](../hardware/autopilot-research-handoff.md)
confirms the AutoPilot's MCU is **ATSAMD51J19A-AU** (Remote: -AF, same
silicon), can APTrace turn the raw MMIO addresses already visible in its
Ghidra/Unicorn output into real SAMD51 peripheral/register names, and use
that to answer concrete questions about startup, pin configuration, and the
Adafruit/BOSSA hypothesis — without building a general peripheral emulator?

**Scope**: AutoPilot firmware (`firmware_autopilot868.bin`) only, reusing
the existing Ghidra static export
(`research/runs/ghidra/firmware_autopilot868.json`) and the existing
concrete-execution results
([`dispatcher-loop-concrete-trace.md`](dispatcher-loop-concrete-trace.md),
[`tx-hook-verification.md`](tx-hook-verification.md)) as the evidence base.
No Crucible/execution-model changes; no attempt to model real peripheral
*behavior* (register side effects, status flags) — only to *name* what
addresses the firmware touches and interpret that, per this project's
"don't reimplement a mature tool's job" and "don't broaden scope" rules
(`CLAUDE.md`, `docs/tooling/tool-selection.md`).

## New capability: `tools/svd/resolve_mmio.py`

[`docs/tooling/tool-selection.md`](../tooling/tool-selection.md) had
already identified the mechanism (`cmsis-svd/cmsis-svd-data` +
`antoniovazquezblanco/GhidraSVD`) but left it unwired, blocked on not
knowing the exact part number. That block is resolved: the hardware
handoff doc names the part directly (not inferred from RAM size, which is
how `tool-selection.md` previously — and wrongly, see below — guessed at
it).

Rather than install the Ghidra extension (a heavier, less-tested
dependency for this pass — real peripheral names inside Ghidra's own UI is
a reasonable future upgrade, not required to answer the questions here),
this pass downloaded the **real Microchip SVD file**
(`cmsis-svd/cmsis-svd-data`'s `data/Atmel/ATSAMD51J19A.svd`, vendored at
[`tools/svd/ATSAMD51J19A.svd`](../../tools/svd/ATSAMD51J19A.svd)) and wrote
a small (~120 line), standalone resolver:
[`tools/svd/resolve_mmio.py`](../../tools/svd/resolve_mmio.py). It parses
the SVD with the stdlib XML parser (not a hand-rolled SVD format — it
reads the vendor's own peripheral/register/cluster/dim structure directly)
and answers one question: given a raw address, which peripheral and
register (and, for repeated/union structures like `PORT.GROUP0/1` or
`TC.COUNT8/16/32`, which specific instance) does it correspond to.

```
$ python3 tools/svd/resolve_mmio.py 0x40001c04 0x4101c005 0x4100809c
0x40001c04  GCLK.SYNCBUSY (+0x4)
0x4101c005  TC3.COUNT16.CTRLBSET/COUNT32.CTRLBSET/COUNT8.CTRLBSET (+0x5)
0x4100809c  PORT.GROUP1.OUTTGL (+0x9c)
```

This directly answers the "can APTrace turn raw MMIO addresses into
meaningful peripheral/register names" question: **yes**, for any address
already visible in a Ghidra data-reference export or a
`run_concrete.py --log-mmio` capture (new flag, see below).

**Correction to `tool-selection.md`**: its SVD section previously reasoned
"RAM size `0x30000` = 192KB matches the *N19A/N20A/P19A/P20A* variants...
not the smaller G/J variants." That inference was wrong on its own terms —
J19A (the now-confirmed real part) *does* have 192KB SRAM; the SVD's own
`ATSAMD51J19A.svd` file has no separate RAM-size field to check this
against, but the actual silicon does (Microchip's SAMD51 J-variants share
the same 512KB flash / 192KB SRAM as the N/P variants at the "19" tier —
only the package pin count and peripheral instance count differ across
G/J/N/P). Fixed in that doc directly (see below) rather than left standing
now that it's directly relevant.

## New capability: `run_concrete.py --log-mmio`

Added to [`tools/unicorn/run_concrete.py`](../../tools/unicorn/run_concrete.py):
`--log-mmio` installs a Unicorn read/write hook scoped to the MMIO window
and records every access (address, size, direction, value, PC, instruction
count) into the snapshot's new `mmio_log` field. This is purely
observational — it does not add any peripheral behavior to the existing
zero-initialized MMIO stub (see `docs/tooling/unicorn-backend.md`'s "Known
limitations") — but it lets a concrete run answer "what MMIO did the
firmware actually touch on this path," cross-checked against the static
Ghidra xref list. Capped by `--max-mmio-log` (default 5000).

## Q1/Q2: vector-table/application layout and startup peripheral init

`docs/firmware/firmware-layout.md` already identified `Reset_Handler` at
`0xcc24`. Decompiling it (`tools/ghidra/scripts/APTraceDecompileFunctions.java`)
confirms it is the textbook CMSIS Cortex-M startup sequence, byte for byte:

```c
void FUN_0000cc24(void)  // == Reset_Handler
{
  // .data copy (flash -> RAM) and .bss zero, both address-range-driven
  ... 
  *(uint *)(DAT_0000cc98 + 0x88) |= 0xf00000;   // SCB->CPACR |= (0xF << 20)
  DataSynchronizationBarrier(0xf);              // DSB
  InstructionSynchronizationBarrier(0xf);       // ISB
  FUN_0000cdd8();   // clock tree + analog init (see below)
  FUN_0000cd90();   // peripheral init + main loop -- never returns
  do {} while (true);   // dead/defensive: unreachable in practice
}
```

`SCB->CPACR |= (0xF << 20)` followed by `DSB`/`ISB` is the **standard ARM
CMSIS FPU-enable sequence** for a Cortex-M4F, verbatim. This is a new,
concrete, high-confidence data point for the Adafruit/Arduino-core
hypothesis (Q6, below): this is generated startup code following ARM's own
template, not a hand-written minimal reset stub.

`FUN_0000cdd8()` (called first) touches, via literal MMIO addresses:
**MCLK, GCLK, OSCCTRL, OSC32KCTRL, SUPC, NVMCTRL, CMCC, AC, ADC0, ADC1,
DAC, USB** — i.e., the entire clock tree, flash-wait-state/cache setup,
and the full analog subsystem, unconditionally, at startup.

`FUN_0000cd90()` (called second, never returns — it's what "boots into the
main loop") transitively reaches functions touching, via literal MMIO
addresses: **WDT, NVMCTRL, EIC, DMAC, GCLK, MCLK, PORT, TC0, TC1, TC2,
TC3, TCC1, USB** (this project had already identified `FUN_0000cd90` as
the root of the chain leading to the main loop and the RX/TX dispatch
functions — see `tx-hook-verification.md`).

**Answer**: startup initializes essentially every clock source, the full
analog block (AC/ADC0/ADC1/DAC), the watchdog, four general-purpose timers
(TC0-TC3) plus one timer/counter-for-control (TCC1), the external
interrupt controller, DMA, PORT, and USB — *before* the main loop ever
runs. This blanket, unconditional initialization of hardware the
application may not even use (all four TC channels, both ADCs, the DAC)
is itself a signature of Arduino-core-generated `init()` code (which
always brings up every PWM-capable timer and every analog peripheral
regardless of what the sketch uses), not a hand-tuned minimal firmware —
more evidence for Q6.

## Q4: beginning to derive configured pins and mux functions

Resolving the SVD's `PORT` cluster required fixing a real gap in the
resolver: peripherals/registers with SVD `dim`/`dimIncrement` (repeated
structures) weren't being expanded, so `PORT.GROUP1` (PORTB, at `+0x80`)
and the `PMUX[0..15]`/`PINCFG[0..31]` register arrays resolved to nothing.
Fixed directly in `resolve_mmio.py` (dim/dimIncrement expansion, applied
generally — this also correctly expands `GCLK.GENCTRL[0..11]` and
`GCLK.PCHCTRL[0..47]`, not just `PORT`).

With that fixed, decompiling `FUN_0000bc44` (previously flagged by the
peripheral survey as touching `GCLK`, `MCLK`, and `PORT` together, and
called directly from both `FUN_0000cc24`/`Reset_Handler` and
`FUN_0000cd90`) and reading its trailing literal pool (the same
"`DAT_xxxx` is a flash-resident constant, not a mystery RAM value"
technique already used for `FUN_00004328`'s version string in
`tx-hook-verification.md`) gives the real addresses it was written
against:

| Symbol | Value | Resolves to |
|---|---|---|
| `DAT_0000bd50` | `0x40000800` | `MCLK` base |
| `DAT_0000bd58` | `0x41008000` | `PORT.GROUP0` (PORTA) base |
| `DAT_0000bd5c` | `0x40001c00` | `GCLK` base |
| `DAT_0000bd60` | `0xe000e100` | `NVIC->ISER[0]` (ARM core, not SAMD51-vendor) |
| `DAT_0000bd54` | `0x0000c725` | a flash code address (Thumb, low bit set) — an ISR callback pointer |
| `DAT_0000bd4c` | `0x20005158` | a RAM address — a driver-object pointer, not a peripheral base |

Substituting these into the decompile gives a concrete, named sequence:

```
MCLK.APBBMASK |= 1            // enable an APBB peripheral's clock
MCLK.AHBMASK  |= 0x400        // enable its AHB clock (bit 10)
PORT.GROUP0.PINCFG[24] |= 1   // PA24: enable peripheral-mux mode
PORT.GROUP0.PMUX[12] low nibble  = 7   // PA24's mux function = index 7 ("H")
PORT.GROUP0.PINCFG[25] |= 1   // PA25: enable peripheral-mux mode
PORT.GROUP0.PMUX[12] high nibble = 7   // PA25's mux function = index 7 ("H")
GCLK.PCHCTRL[10] = 0x41       // enable peripheral channel 10, clock from generator 1
<register the callback at DAT_0000bd54 with the peripheral pointed to by *DAT_0000bd4c>
NVIC->IP[80..83]   = 0        // priority 0 for four *consecutive* IRQ numbers
NVIC->ISER[2] bits 16..19     // enable IRQ 80, 81, 82, 83 (four separate writes;
                               // ISER is a set-only register, so this is the
                               // normal idiom for NVIC_EnableIRQ() called 4x)
<dereference the driver-object pointer, clear/set two control bits,
 busy-wait on what reads exactly like a SYNCBUSY/ENABLE-complete bit>
```

**This directly answers "can we begin deriving configured PA/PB pins and
mux functions": yes** — `PA24` and `PA25` are concretely confirmed
configured with matching mux function index 7 (letter "H" in Microchip's
A-N mux lettering) and enabled together, from real firmware bytes, not
from documentation or assumption.

**What this does not (yet) claim**: the SVD carries no per-pin table of
what each lettered mux function *means* on a given pin (that mapping is
package/pin-specific and lives in the datasheet's I/O multiplexing table,
not the SVD) — so this pass does not assert *which* peripheral PA24/PA25
are muxed to purely from the mux letter.

**Stronger, independent confirmation this pin pair is USB (not a
SERCOM)**: `docs/firmware/firmware-layout.md`'s vector table only covered
IRQ0-39; re-running `tools/vector_scan.py` with `--num-irq 100` (this
pass) shows IRQ80-83 (the four IRQs `FUN_0000bc44` enables) each have a
**distinct, non-default handler address** — `0xcc14`, `0xccb6`, `0xccba`,
`0xccbe`. Decompiling all four: they are the *same* trampoline body
(Ghidra even names three of them `thunk_FUN_0000cc14`), each checking one
shared RAM callback-pointer slot (`DAT_0000cc20`, flash-resident constant
`0x200052e8`) and, if non-null, calling through it:

```c
void FUN_0000cc14(void) {
  if ((code *)*DAT_0000cc20 != (code *)0x0) {
    (*(code *)*DAT_0000cc20)();
  }
}
```

**All four IRQ vectors share one registered callback slot** — this is the
generic-ISR-plus-registered-callback pattern SAMD USB drivers use (Arduino
core's `USB_Handler` is installed once and shared across all four of the
SAMD51 USB peripheral's IRQ lines: `OTHER`, `SOF_HSOF`, `TRCPT0`,
`TRCPT1`). A SAMD51 SERCOM instance also has four IRQ vectors, but each
normally gets its *own* distinct handler body (DRE/TXC/RXC/error are
different code paths), not one shared indirect-call slot. Combined with
the PA24/PA25 pin pair, this is now strong, multi-signal evidence (pin
assignment *and* interrupt-registration shape both independently pointing
the same way) that `FUN_0000bc44` is the **USB peripheral bring-up**, not
a SERCOM — still not solver-confirmed, but no longer resting on the pin
pair alone.

## A second, fully concrete pin finding: PB22 toggled from a timer ISR

The same `--num-irq 100` re-scan also names **IRQ93** with its own
distinct handler, `0x60ec` — inside the address range the earlier peripheral
survey had already flagged (as `fromFunction: None`, i.e. Ghidra hadn't
cleanly attributed a function there) for reading `TC0`-`TC3` and `TCC1`
`INTFLAG` registers and writing `PORT.GROUP1.OUTTGL`. Decompiling `0x60ec`
directly resolves this completely:

```c
void FUN_000060ec(void)  // IRQ93_Handler
{
  TCC1.INTFLAG |= 0x10000;         // acknowledge one TCC1 interrupt flag (bit 16)
  PORT.GROUP1.OUTTGL = 0x400000;   // toggle PB22 (bit 22 of PORTB)
}
```

(Both `TCC1`'s base and `PORT`'s base here are, again, flash literal-pool
constants read directly from the raw firmware bytes — `0x41018000` and
`0x41008000` respectively — not guesses.)

**This is a fully resolved, concrete finding**: on every TCC1 interrupt,
this handler toggles **PB22**. A GPIO pin toggled from a periodic timer
interrupt (rather than driven by the timer's own hardware waveform-output
pin) is the standard way to generate a *variable-rate* step pulse — exactly
what a variable-speed stepper-motor channel needs. This lines up with
`docs/hardware/autopilot-research-handoff.md`'s "4 motor-output channels"
finding: TC0-TC3 (Q2) are the other three(-ish) timers already confirmed
configured together at startup, and this is now direct, itself-complete
evidence that at least one of that group (TCC1) drives a real, named
GPIO pin (PB22) as its output. Finding the other channels' equivalent
handlers/pins (they almost certainly exist, one per TC, likely adjacent
in flash to this one) is flagged in "Next logical slice" below rather
than done exhaustively here.

## Q5: identifying the hardware peripheral behind an already-confirmed concrete path

Tried against the already-fully-confirmed TX path
(`pending[5]` → `0x9268` → `0x8c10` → `"V01R39"`, from
`tx-hook-verification.md`). Two checks, one static, one freshly concrete:

- **Static**: none of `0x8c10`, `0x7f84`, `0x9268`, or their traced callees
  (`0xb23a`, `0x9e70`, `0x9984`, `0xcd34`, `0xb242`, `0xb406`, `0xb414`, and
  their further descendants) appear in the Ghidra literal-MMIO xref list —
  **with one exception**: `FUN_0000a000`/`FUN_0000a03c` (reached from
  `0x8c10`'s descendants) write `EIC.INTENCLR`/`EIC.INTENSET` — i.e. the TX
  path's descendants bracket a **disable-then-re-enable of one external
  interrupt line** around whatever the actual transmission does. This
  reads as a critical section guarding an interrupt-driven line (a radio
  IRQ/DIO pin, or a UART flow-control pin) during transmission — a real,
  if modest, finding.
- **Concrete (new, via `--log-mmio`)**: re-running the exact
  `tx-hook-verification.md` Unicorn scenario (same seeds, entry `0x9268`,
  `--stop-at 0x8c10`) with `--log-mmio` confirms **zero MMIO accesses**
  on this path, cross-checking the static finding. Continuing execution
  *past* `0x8c10` (removing the stop) diverges into an unmapped read at
  address `0x4` within ~50 instructions — `0x8c10` dispatches on a runtime
  mode byte and a function-pointer/driver-object table that this project's
  existing seeding (RX buffer + pending-event state only) does not
  populate. Reaching further would mean modeling that dispatch table and
  the driver object it points at — exactly the "general peripheral
  emulator" work this task was explicitly scoped to avoid.

**Honest answer for the TX path**: the abstraction boundary here is a
**runtime driver-object pointer**, not a literal peripheral address — the
same C++/HAL-style indirection pattern seen in `FUN_0000bc44` above (base
addresses loaded from a flash literal pool into RAM-resident "driver
objects," then dereferenced indirectly). Naming the exact SERCOM/USART
instance behind it is not free; it would need either (a) statically
resolving what `FUN_0000bc44`-style init function populates the specific
driver-object pointer `0x8c10` reads, or (b) concretely seeding that
mode byte and object pointer and continuing execution. Neither was done
here, by design (see Scope, above) — flagged as the natural next slice.

**Where Q5 *is* answered concretely**: the startup peripheral survey (Q2)
identifies TC0, TC1, TC2, TC3, and TCC1 as configured together at startup
via literal addresses (`FUN_00005570` and siblings) — a strong, named
match for the hardware handoff doc's "AutoPilot has 4 motor-output
channels." The IRQ93/TCC1 handler above (`0x60ec`, "A second, fully
concrete pin finding") completes this for one channel: TCC1's interrupt
concretely toggles PB22, a fully resolved, named GPIO pin — the closest
this pass got to a complete "already-understood firmware behavior, tied
to a named physical pin" result. It stops short of pinning down which of
the *other* three TC channels maps to which physical motor-output
connector (out of scope here — would need the board's own pin-to-connector
wiring, not just the firmware, though each is very likely a near-identical
ISR toggling a different PORT pin, immediately findable by the same
technique — see "Next logical slice").

## Q6: Adafruit M4 / BOSSA / `0x4000` hypothesis — new evidence, still open

New evidence *for* the hypothesis from this pass:

- The CMSIS-standard `SCB->CPACR` FPU-enable sequence in `Reset_Handler`
  (exact match to ARM's own startup template, not hand-written).
- The blanket, unconditional startup initialization of every TC channel,
  both ADCs, and the DAC (Q1/Q2) — a signature of Arduino-core-generated
  `init()`, which always brings up every PWM/analog-capable peripheral
  regardless of sketch usage, rather than a hand-tuned minimal init.
- `FUN_0000bc44`'s PA24/PA25 dual-pin mux configuration, its four enabled
  IRQ vectors (80-83) *all sharing one registered-callback trampoline*
  (`FUN_0000cc14`/`thunk_FUN_0000cc14`), and the fact that vector table
  slots 80-83 have real, distinct (non-default) handlers at all — this
  multi-signal match (pin pair + shared-callback ISR shape + 4-vector
  count) is exactly what an Arduino-core app with `Serial` (native USB
  CDC) brings up early in `init()`.

None of this is new proof of the *specific* falsification tests
`docs/hardware/autopilot-research-handoff.md` §15.4 lists (BOSSA/SAM-BA
protocol compatibility, the missing bootloader region's own contents,
1200-baud touch-reset behavior) — this pass did not have new evidence
to bring to those, since the dumped firmware image is application-only
(the `0x0`-`0x3FFF` bootloader region is not present in
`firmware_autopilot868.bin` at all, so nothing here can directly inspect
it). What this pass *does* add is corroborating evidence from the
*application's own* startup code, independent of the previously-cited
build-path strings and `bossac` command line
(`docs/firmware/firmware-layout.md`) — a second, independent line of
evidence pointing the same direction, not a new falsification result.

## Summary: what's now concretely supported

- Real ATSAMD51J19A peripheral/register naming for any raw address, via
  `tools/svd/resolve_mmio.py`, backed by the actual vendor SVD file.
- Concrete MMIO access logging in Unicorn runs (`--log-mmio`), for
  cross-checking static xref-based peripheral claims against real
  execution — used here to get an honest negative result (TX path touches
  no MMIO before the driver-object boundary) rather than a guess.
- A confirmed, named startup peripheral list (Q1/Q2) tracing all the way
  from the vector table through `Reset_Handler` into the peripheral-init
  chain this project had already partially traced for other reasons.
- A first concretely-named pin-mux fact (PA24/PA25, matching mux values),
  with independent corroborating evidence it's USB (shared-callback
  IRQ80-83 trampoline pattern, re-derived via a wider `vector_scan.py`
  rescan) — from real firmware bytes and the real vector table, not
  documentation or assumption.
- One fully resolved pin-level hardware fact: PB22 is toggled from a real,
  named interrupt handler (IRQ93, TCC1) — a concrete, named GPIO tied to
  an already-understood piece of firmware behavior (Q5), not a guess.
- An honest boundary finding for the TX path: real peripheral identity is
  gated behind runtime driver-object indirection, not literal addresses.

## Next logical slice

In priority order:

1. **Fully close the PA24/PA25 = USB question.** The pin pair plus the
   shared-callback IRQ80-83 pattern is strong multi-signal evidence, but
   still short of solver-confirmed. Either find the ATSAMD51 datasheet's
   per-pin I/O multiplexing table (external reference, not derivable from
   the SVD) to confirm mux function "H" really is USB on this pin pair, or
   find corroborating firmware evidence (e.g. does `FUN_0000bd94`, the
   USB-touching function immediately following `FUN_0000bc44` in flash,
   dereference the same RAM driver-object pointer `0x20005158`?).
1b. ~~Find the other three motor channels' pin/ISR pairs~~ — done:
   TC0/TC1/TC2/TC3 are IRQ107-110 (`0x607c`/`0x6098`/`0x60b4`/`0x60d0`),
   confirmed structurally *different* from TCC1's inline toggle (they
   tail-branch into a shared, table-indexed pulse helper instead) — see
   [`docs/investigations/motor-timer-survey.md`](motor-timer-survey.md)
   for the full mechanism, the flash pin table, the rate-control function
   found along the way, and the honest limit reached (the real per-channel
   pin assignment needs a RAM index this pass couldn't find a producer
   for).
2. **Name the TX path's real transport peripheral.** Trace what populates
   the driver-object pointer `0x8c10` reads at its runtime mode-dispatch
   (likely another `FUN_0000bc44`-style init function, findable by
   searching for other functions that write to the same RAM address(es)
   `0x8c10`'s dispatch reads) — this would close Q5 properly instead of
   stopping at the honest boundary documented here.
3. **Extend the pin/mux survey beyond PA24/PA25** — walk the rest of the
   literal (and, where traceable, literal-pool-indirect) `PORT` writes
   found across the whole firmware to build a fuller PA/PB pin-function
   table, rather than the one function this pass happened to look at.
4. Only if a real use case needs it: install `GhidraSVD` so peripheral
   names show up directly in Ghidra's own listing/decompiler (not
   required for anything in this pass — the standalone resolver was
   sufficient).

None of the above require broadening into real peripheral *behavior*
modeling (a Crucible/MMIO redesign) — they are all naming/tracing work,
consistent with this task's scope.
