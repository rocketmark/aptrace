# Investigation: Modeling `FUN_0000cdd8`'s Real Clock/Peripheral-Init Polls

**Question**: [`systick-tick-injection.md`](systick-tick-injection.md) traced
the null-pointer crash it hit (an uninitialized DMA/SERCOM-shaped driver
object) back to `FUN_0000cdd8`, the clock/peripheral bring-up chain
`Reset_Handler` runs before anything else — entering later (at
`FUN_00009464`) to route around `FUN_0000cdd8`'s own stall skips the code
that would have constructed that object for real. This slice goes back to
`Reset_Handler` and asks, per the task, exactly what `FUN_0000cdd8` is
waiting for, register by register — not "SYNCBUSY, generally."

**Scope, per the task**: identify each blocking poll's exact SVD
register/bit; identify the real preceding write; classify it as a
predictable completion bit, an external-environment-dependent value, or
an unjustifiable assumption; model only the first category, only as
narrowly as needed; prefer an explicit, optional `run_concrete.py` hook
over any default-behavior change. No general SAMD51 peripheral emulator
was built.

## Result

**The primary acceptance target was reached.** A real concrete run,
entering at the true `Reset_Handler`, now runs `FUN_0000cdd8` to genuine
completion, continues into the real SERCOM/DMA driver constructor
(`FUN_0000a0cc` and its callees) without the previous null-pointer
crash, and — confirmed via `--watch` hits — reaches and completes
`FUN_00006968` (homing) via its real timeout exit, exactly as in the
prior slice's partial-boot entry. **The secondary goal (observing a
`0x20001b14` write) was not reached**: continued execution after homing
consumes far more simulated tick-time than expected before reaching the
main loop's packet-receive call, a newly-surfaced characterization gap
distinct from (and downstream of) the dependency this slice resolved —
reported precisely below rather than patched around further.

## `FUN_0000cdd8`, disassembled poll by poll

The full function (`0xcdd8`-`0xcf92`, 444 bytes) was disassembled in
full — not just decompiled, since one poll's exact bit was ambiguous in
the decompiler's pseudo-C (see "A poll the decompile obscured" below).
Every `DAT_` literal was resolved with `tools/svd/resolve_mmio.py`, and
every candidate bit was cross-checked against the real SVD field list.
Sixteen `do{}while` loops appear in total; **twelve pass immediately
under the existing zero-behavior MMIO model** (each is a `SYNCBUSY`- or
`DFLLSYNC`-style "busy" bit, and the polarity those loops test happens to
already match — the loop exits once the bit reads `0`, which cold/
never-written MMIO already provides). **Four do not**, because they wait
for a bit to become *set*, which a plain zero-initialized register never
does on its own:

| # | Address | SVD register.field | Preceding write | Real semantic |
|---|---|---|---|---|
| 1 | `0x4000140c` bit 0 | `OSC32KCTRL.STATUS.XOSC32KRDY` | `OSC32KCTRL.XOSC32K = 0x200e` (crystal enable/config) | "32kHz source has stabilized" |
| 2 | `0x40001010` bit 8 | `OSCCTRL.STATUS.DFLLRDY` | `OSCCTRL.DFLLCTRLB = 0x98` (DFLL48M closed-loop config) | "DFLL has locked/stabilized" |
| 3 | `0x40001040` bits 0-1 | `OSCCTRL.DPLL0.DPLLSTATUS.{LOCK,CLKRDY}` | `DPLL0CTRLB=0x800; DPLL0CTRLA|=2` (enable) | "DPLL0 has locked onto its reference and its output is stable" |
| 4 | `0x40001054` bits 0-1 | `OSCCTRL.DPLL1.DPLLSTATUS.{LOCK,CLKRDY}` | `DPLL1CTRLB=0x800; DPLL1CTRLA|=2` (enable) | same, for DPLL1 |

**Classification**: all four are category **(a)** — a documented
completion/status bit that real hardware sets automatically once its
triggering configuration write takes effect, not a value that depends on
an external peripheral or environment this harness can't establish. This
firmware runs on a real, physically confirmed board
([`docs/hardware/`](../hardware/)) that demonstrably boots — these
oscillators and PLLs reliably lock on that hardware, using clock
references internal to the boot sequence itself (not an unpopulated or
uncertain external component). No category-(c) ("an assumption we
cannot justify") bit was found in this function.

### A poll the decompile obscured

The decompiler's pseudo-C for poll #2 read as `-1 < *(int *)(iVar2 + 0x10) << 0x17`
with `iVar2` reused across several nearby statements, which made it easy
to misattribute to the wrong register on a first pass (an earlier pass
this session did exactly that, missing it initially). Direct
disassembly settled it unambiguously:

```asm
0xce62  ldr  r3,[r2,#0x10]     ; r2 = OSCCTRL base -> r3 = OSCCTRL.STATUS
0xce64  lsls r0,r3,#0x17       ; shift left 23 -> tests bit 8 (DFLLRDY)
0xce66  bpl  0xce62            ; loop while CLEAR, exit when SET
```

This is the project's standing practice (already applied twice before,
in `i-command-motor-chain.md` and `channel-busy-gate-search.md`):
disassembly is the tie-breaker whenever a decompile's variable reuse
makes a register/bit ambiguous, not a place to guess.

## The new mechanism: `--mmio-force-bits` / `--mmio-clear-bits`

Two small, explicit, address-scoped `run_concrete.py` hooks — the
"optional MMIO behavior hook" the task asked for, not a change to the
default zero-behavior model and not a peripheral simulator:

- **`--mmio-force-bits ADDR:MASK`**: every read of the 4-byte register at
  `ADDR` is OR'd with `MASK` before the CPU sees it. Used for the four
  ready/lock bits above (`0x4000140c:1`, `0x40001010:0x100`,
  `0x40001040:3`, `0x40001054:3`).
- **`--mmio-clear-bits ADDR:MASK`**: the complement, AND'd with `~MASK` —
  for a bit the firmware itself just *set* that real hardware
  self-clears within a few cycles (a software-reset bit is the
  textbook case), which the plain read/write memory model otherwise
  leaves stuck forever. Used for `SERCOM5`/`SERCOM2`'s `CTRLA.SWRST`/
  `SYNCBUSY.SWRST` (bit 0), found one level down — see next section.

Each hook only touches the one named register; it never writes on its
own initiative, never runs on a timer, and does nothing unless the
CPU actually performs a read there. The snapshot records how many times
each one actually changed a value (`mmio_force_bits_applied`/
`mmio_clear_bits_applied`), so a hook that never fires (because the bit
was already in the needed state) is visible as `count: 0`, distinct from
one that did real work.

## What was found one level down: the real SERCOM/DMA driver, running for real

With `FUN_0000cdd8` unblocked, execution reached `FUN_0000a0cc` (the
function `systick-tick-injection.md` found crashing on a null pointer)
and this time ran it for real — no crash. Its own polls needed the exact
same *kind* of narrow, SVD-justified treatment:

- **`SERCOM5.CTRLA`/`SYNCBUSY` bit 0 (SWRST)** (`0x43000400`,
  `0x4300041c`) and **`SERCOM2`'s** (`0x41012000`, `0x4101201c`): the
  driver writes `CTRLA.SWRST=1` to reset each SERCOM, then polls both
  bits for the self-clear — `--mmio-clear-bits`, category (a) (SWRST is
  documented as self-clearing on real hardware within a few clock
  cycles).
- **`SERCOM5`/`SERCOM2` `INTFLAG.DRE`** (bit 2, `0x43000418`/
  `0x41012018`, "Data Register Empty"): read as part of the driver's own
  post-reset setup, before any data has been exchanged — real hardware
  sets this the moment the peripheral is enabled with nothing queued,
  independent of any external device responding, so this is still
  category (a) — `--mmio-force-bits`. (Its counterpart flag would
  legitimately move into category (b) — genuinely dependent on an
  external device — the moment the driver waited on it *during* an
  actual data transfer; that point was not reached this pass.)
- **The NVM Software Calibration Row (`0x00800080`/`0x00800084`)**:
  `FUN_0000cdd8`'s tail copies real per-die factory trim bits from this
  fixed flash-adjacent address into `AC`/`ADC0`/`ADC1`/`USB.PADCAL`
  calibration registers — not a poll, but the address was entirely
  unmapped in the existing memory layout, so any read faulted. Added a
  minimal `--map-page ADDR:SIZE` facility (maps one page, filled via the
  existing `--seed-mem`) and seeded zero bytes there — **explicitly a
  placeholder for real, per-die silicon data this harness has no way to
  know**, disclosed as such, not a claim about actual calibration
  values. It only feeds analog trim registers (ADC/DAC/USB), which this
  investigation's target (`0x20001b14`, a digital motor-state byte) has
  no path to depend on.

This is a second SERCOM/DMA-driven peripheral (matching the
"TX/RX descriptor pair" structure `systick-tick-injection.md` already
identified structurally) — two instances processed one after the other
by the same generic driver code, confirmed concretely (not just inferred
from the decompile) by the register bases actually seen in `r3` at each
stall (`0x43000400` then `0x41012000`), resolved to `SERCOM5` and
`SERCOM2` respectively via the SVD.

## Confirmed: real homing runs, exactly as before

With all of the above in place, `--watch` hits confirm the run entered
`FUN_00009464` (instruction 27740), entered `FUN_00006968` (homing,
instruction 27761), and exited the timeout loop at `0x69d8` (instruction
64134) — the identical real exit point `systick-tick-injection.md`
found from its later, routed-around entry point, now reached from the
*true* `Reset_Handler` with every intervening driver dependency resolved
for real rather than skipped. `0x20001b14`-`17` still read `00000000` at
every point checked; the only recorded write remains the already-known
`.bss` clear at boot.

## PA22, preserved as a confirmed dependency, not a claim

Per the task's explicit instruction, the prior slice's PA22
(`PORT.GROUP0.IN` bit 22) high-read seed is carried forward unchanged in
every run this pass — it is still exactly what it was: a confirmed real
GPIO-input dependency of the homing wait loop, disclosed as a boundary
condition, with **no physical function assigned to it** (not "the home
switch," not any other specific claim) beyond what the disassembly
already established.

## The new, precisely-identified open item

Continuing well past homing (up to 60,000,000 instructions, several
independent runs, tick periods from 20 to 5000 instructions/tick), the
run never reaches `0x8960` (the main loop's own packet-receive call,
confirmed absent from `--watch` hits even at 20,000,000 instructions) —
instead it cycles through real, legitimate-looking delay calls
(`FUN_0000cd50`, confirmed via its own `micros()`-based countdown
register genuinely decrementing across runs, e.g. `10 -> 9 -> 8 -> ...`
at a stable ~2 ticks per unit — ruled out as a livelock by direct
measurement, not assumed) at a rate that adds up to far more simulated
boot time than a normal embedded init sequence should need. This is
**not** another missing-completion-bit case: no new busy-loop was found
stuck against a zero-behavior MMIO register. It looks instead like a
**larger number of legitimate, finite delay/init steps than initially
scoped for** (plausibly the calibration/display/status-output sequence
already known from `FUN_00007770`/`FUN_00005d44`, or something not yet
enumerated) — a characterization gap, not a hardware-modeling one.
Per the task's explicit "stop rather than accumulating arbitrary stubs,"
this was not chased further by guessing at more tick-period tuning.

## Confirmed vs. modeled — evidence discipline

| Claim | Status |
|---|---|
| `OSC32KCTRL`/`OSCCTRL`/`DPLL0`/`DPLL1` ready/lock bits, and `SERCOM5`/`SERCOM2` SWRST/DRE bits | **Harness-modeled**, per documented SVD semantics, on a board already confirmed to boot — not observed on real hardware |
| `FUN_0000cdd8` runs to completion; the SERCOM/DMA driver constructs without a null-pointer fault; homing runs and exits via its real timeout | **Firmware behavior, concretely observed**, given the above modeled inputs — a `pc`/`--watch` trace of real, unmodified instructions |
| The NVM calibration values | **Disclosed placeholder** (zero), not a claim about real per-die trim data — irrelevant to the digital motor-state target |
| PA22 reads high throughout | **Confirmed dependency, carried forward** — no physical function claimed |
| `0x20001b14[channel]` is set by some later runtime event | **Still not observed** — this run doesn't reach far enough into steady-state execution to test it |

## Evidence level

Level 1 (static, disassembly-verified against the SVD) for every
register/bit identified. Level 2 (concrete, Unicorn) for the successful
traversal of `FUN_0000cdd8`, the driver constructors, and homing,
including a direct measurement ruling out a livelock in the post-homing
delay sequence. No claim is made at any level about the post-homing
sequence's own correctness or duration meaning beyond "it consumes more
simulated ticks than initially expected."

## Next step

Two independent, narrower continuations, either smaller than this slice:

1. **Enumerate the post-homing delay/init call sites precisely**
   (starting from `FUN_00007770`/`FUN_00005d44`, both already known to
   call `FUN_0000cd50`) to get a real total-tick estimate, rather than
   guessing at a larger instruction budget.
2. **Once past that**, `0x8960` becomes reachable, and the same
   `--watch-mem-write 0x20001b14:4` already in place would catch any
   real write on the way to (or inside) the main loop — at which point,
   per the task's own framing, injecting a real inbound command (an "M"
   or "I" packet) into the now-functional receive path would be the
   natural, explicitly-flagged follow-on slice, not attempted here.
