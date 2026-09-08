# Investigation: Completing the Motor-Timer Survey (TC0/TC1/TC2, vs. the Proven TCC1 -> PB22 Case)

**Question**: [`docs/investigations/samd51-peripheral-mapping.md`](samd51-peripheral-mapping.md)
fully closed one motor-timer channel concretely — TCC1's interrupt
handler (IRQ93, flash `0x60ec`) toggles `PB22` directly — and flagged
finding TC0/TC1/TC2/TC3's own ISR/pin pairs as its own next step. This
slice does that, using the same tools (no new infrastructure), and asks
the follow-on questions roadmap M6 poses: do TC0-TC3 form the same
repeated pattern as TCC1, what (if anything) controls each channel's
output rate, and where would a future protocol-to-pin slice start.

**Scope**: `tools/vector_scan.py` (wider IRQ range), Ghidra decompilation
of exactly the functions the ISRs lead into, `tools/svd/resolve_mmio.py`
for register/pin naming, and `run_concrete.py --log-mmio` for concrete
confirmation — the same four tools already in the workbench. No new
Ghidra scripts, no new Unicorn flags, no peripheral emulation. Explicitly
not a full motor-control reverse-engineering pass: this stops at naming
the mechanism and its pins/registers, not decoding the velocity-ramp
algorithm found along the way (see "What was deliberately not chased
further").

## Finding the vectors: `tools/vector_scan.py --num-irq 139`

`samd51-peripheral-mapping.md`'s own `--num-irq 100` scan (which found
IRQ93/TCC1) didn't go far enough — TC0-TC3 turn out to be IRQ **107-110**,
past that range:

```
[109] IRQ93_Handler   = 0x000060ed -> 0x000060ec [thumb]   (already known: TCC1)
[123] IRQ107_Handler  = 0x0000607d -> 0x0000607c [thumb]
[124] IRQ108_Handler  = 0x00006099 -> 0x00006098 [thumb]
[125] IRQ109_Handler  = 0x000060b5 -> 0x000060b4 [thumb]
[126] IRQ110_Handler  = 0x000060d1 -> 0x000060d0 [thumb]
```

Four **real, distinct, consecutive vector-table entries** — not
incidentally-adjacent code the earlier pass happened to see xrefs into
(that ambiguity, flagged explicitly in `samd51-peripheral-mapping.md`, is
now resolved). Resolving each handler's own literal-pool base address
(the same technique used throughout this project) identifies exactly
which TC each one is, in address order:

| IRQ | Handler | Literal-pool base | Peripheral |
|---:|---|---|---|
| 107 | `0x607c` | `0x40003800` | **TC0** |
| 108 | `0x6098` | `0x40003c00` | **TC1** |
| 109 | `0x60b4` | `0x4101a000` | **TC2** |
| 110 | `0x60d0` | `0x4101c000` | **TC3** |

## The repeated pattern: confirmed, but not identical to TCC1's

Disassembling `0x607c`-`0x60e4` (the four handlers are packed contiguously
in flash, each 28 bytes) shows all four doing the *same* two things, in
the *same* order:

```
ldr  r3, [<TCx base>]
ldrb r2, [r3, #0xa]      ; TCx.INTFLAG
orr  r2, r2, #0x10       ; MC0 (match/compare 0)
strb r2, [r3, #0xa]
ldrb r2, [r3, #0xa]
orr  r2, r2, #0x1        ; OVF (overflow)
strb r2, [r3, #0xa]
[TC1/TC2/TC3: movs r0,#<channel 1/2/3> ; b.w 0x5898]
[TC0:                                    b.w 0x5be8]
```

**Both flags TC0-3 were configured to raise at startup are exactly the
flags each one clears**: `docs/investigations/samd51-peripheral-mapping.md`'s
own startup survey already found `FUN_0000cd90`'s init chain enabling
MC0 and OVF interrupts on all four TCs (`TCx.INTENSET`, offset `0x9`, at
two instructions in `FUN_00005570`) — this pass confirms those are the
exact two bits every handler acknowledges. A closed loop, not two
separately-plausible facts.

**Where it diverges from TCC1**: TCC1's handler does its GPIO write
*inline*, directly (`PORT.GROUP1.OUTTGL = 0x400000`) and returns. TC1,
TC2, and TC3 instead **tail-branch into a shared function, `0x5898`**,
passing their channel number (1, 2, or 3) in R0 — a real ISR-with-shared-
tail-routine idiom (the branch preserves the hardware `EXC_RETURN` value
already sitting in `LR`, so `0x5898`'s own eventual return still returns
correctly from the interrupt). **TC0 is structurally different again**:
it branches to a *different*, much larger function (`0x5be8`, 504 bytes)
that does floating-point velocity/ramp bookkeeping before — conditionally
— reaching the same GPIO mechanism. TC0 is not simply "channel 0"; see
below.

## The shared GPIO mechanism: a table-indexed pulse helper, not a fixed toggle

`FUN_00005898(channel)` (confirmed reached from TC1/TC2/TC3 directly, and
from TC0 via `0x5be8`'s fast path — see below) does, among other
per-channel bookkeeping:

```c
position[channel] += step_delta[channel];   // RAM 0x20002064[channel] += RAM 0x20000094[channel]
if (<a periodic-boundary condition on position[channel]>) {
    pin_idx = pin_index_table[channel];      // RAM 0x20000164[channel]
    FUN_0000d388(pin_idx, 1);                // set that pin HIGH
    FUN_0000d388(pin_idx, 0);                // set it LOW again -- a step pulse
}
```

`FUN_0000d388` (already found and decompiled in `samd51-peripheral-mapping.md`,
called from `FUN_0000bc44` for an unrelated USB-adjacent pin there) is a
**generic, table-driven GPIO setter**: given an index, it looks up a
`(group, pin, ...)` descriptor from a **flash-resident, static** table at
`0x14284` (24 bytes per entry) and does `PORT.GROUPx.OUTSET`/`OUTCLR`
accordingly. Reading that table directly (it's flash, not RAM — no
execution needed to see its contents) gives the full candidate pin pool:

| Index | Group | Pin | Bit |
|---:|---|---|---:|
| 0 | A | PA23 | 23 |
| 1 | A | PA22 | 22 |
| 2 | B | PB17 | 17 |
| 3 | B | PB16 | 16 |
| 4 | B | PB13 | 13 |
| 5 | B | PB14 | 14 |
| 6 | B | PB15 | 15 |
| 7 | B | PB12 | 12 |
| 8 | A | PA21 | 21 |
| 9 | A | PA20 | 20 |

This table's shape (group/pin/mux/ADC-channel-looking fields per entry)
matches the well-known Adafruit/Arduino SAMD `variant.cpp` `PinDescription`
layout — consistent with, though not new proof beyond, this project's
existing Adafruit/BOSSA hypothesis (`docs/firmware/firmware-layout.md`).

**This is a real, load-bearing distinction from TCC1's case, not a minor
detail**: TCC1's `PORT.GROUP1.OUTTGL` write bakes the pin (`PB22`)
directly into the instruction stream — fully static, no runtime
dependency. TC0-3's pin choice is **indirected through a RAM byte per
channel** (`0x20000164`-`0x20000167`, one per channel), selecting *which*
table entry to use. **No static producer for that RAM byte was found** —
searched the same literal-pool/xref data this whole project's static
analysis relies on; only reads, no writes, anywhere in the exported
cross-reference set. This could mean a computed-pointer/loop-indexed
write the static xref scan structurally can't see (the same class of gap
`docs/protocol/open-questions.md` #8/#9 already documents for other
tables), or a value sourced from persistent/NVM config
(`docs/hardware/autopilot-research-handoff.md`'s "persistent storage"
section) rather than plain startup code. **Not resolved this pass** — see
"What remains open" below.

## Concrete confirmation (`run_concrete.py --log-mmio`), and its honest limit

Running all four handlers directly (cold RAM, no seeding) confirms the
mechanism end to end, live:

```
$ tools/unicorn/.venv/bin/python3 tools/unicorn/run_concrete.py \
      --firmware research/firmware/originals/firmware_autopilot868.bin \
      --entry 0x607c --mmio-base 0x40000000 --mmio-size 0x4000000 \
      --log-mmio --max-mmio-log 20 --max-instructions 100
```

```
read  0x4000380a  TC0.INTFLAG          (clear MC0)
write 0x4000380a = 0x10
read  0x4000380a  TC0.INTFLAG          (clear OVF)
write 0x4000380a = 0x11
read  0x41008057  PORT.GROUP0.PINCFG23
write 0x41008057 = 0x4
write 0x41008018 = 0x800000   PORT.GROUP0.OUTSET   (PA23 high)
read  0x41008057  PORT.GROUP0.PINCFG23
write 0x41008057 = 0x0
write 0x41008014 = 0x800000   PORT.GROUP0.OUTCLR   (PA23 low)
```

Real INTFLAG clearing, real `FUN_0000d388` pin-pulse mechanism, exactly
as the decompile predicted — a genuine, concrete (level 2) data point,
not only a static reading.

**Running the same test for TC1, TC2, and TC3 (entries `0x6098`,
`0x60b4`, `0x60d0`) produces the identical result: PA23, every time.**
This is the honest limit this pass ran into, not a new finding about the
hardware: with the per-channel RAM index bytes all cold (`0`), every
channel resolves to the *same* table entry (index 0 = PA23). **This
confirms the mechanism is identical and repeated across all four
channels — the "expected repeated motor-output pattern" the task asked
about — but it does not, and cannot, tell us which of PA23/PA22/PB17/
PB16/etc. each *real, running* channel actually drives.** Presenting
"TC0-3 all pulse PA23" as a hardware fact would be exactly the
"silently choosing values that force an answer" this task explicitly
warned against — recorded here as a limitation, not glossed over.

TC0's own branch to `0x5be8` was also exercised by this same run: cold
RAM's `*0x20005bfc == 0` (the "ramp active" flag `0x5be8` itself checks)
takes its short-circuit path, `FUN_00005898(0)` — i.e. this run exercised
TC0's *simple* path, not its velocity-ramp path (see below).

## Rate/period control: found, and it falls out cleanly

The task asked whether period/frequency-control code falls out naturally
of following the handlers — it does, via the peripherals-touched survey
already built for `docs/investigations/samd51-peripheral-mapping.md`
(re-run here, no new tooling): `FUN_00005c00` **writes `CC0`** (the
compare/period register, SVD-confirmed offset `0x1c`) on **all four TCs
plus TCC1**, and `FUN_00006260` **reads** the same register on all four
TCs.

```c
void FUN_00005c00(int channel, int period, int param_3) {
  ...
  switch (channel) {
    case 0: TC0->COUNT16.CC[0].reg = (uint16_t)period; ...
    case 1: TC1->COUNT16.CC[0].reg = (uint16_t)period; ...
    case 2: TC2->COUNT16.CC[0].reg = (uint16_t)period; ...
    case 3: TC3->COUNT16.CC[0].reg = (uint16_t)period; ...
    case 7: /* a different, non-TC target entirely -- not investigated */
  }
  <SYNCBUSY-gated CTRLBSET = 0x80 (RETRIGGER)>   // apply the new period immediately
}
```

This is a real, correctly-sequenced SAMD51 timer-reconfiguration routine
(wait for the previous SYNCBUSY to clear, write the new `CC0`, issue a
`RETRIGGER` command, wait for that SYNCBUSY too) — **this is the function
that changes a motor channel's step rate**, taking a caller-supplied
period value. `FUN_00005c00` is itself one of the functions
`samd51-peripheral-mapping.md`'s startup survey already found called
during `Reset_Handler`'s init chain (an initial/default period), and is
also called later from two other functions
(`FUN_00005ee8`, `FUN_00005d24`) not traced further this pass — see "Best
next entry point" below.

## What was deliberately not chased further

Per the task's explicit "don't broaden into a full motor-control RE
pass":

- `0x5be8`'s velocity-ramp logic (floating-point speed/position
  comparisons, a state machine with what looks like backlash/direction-
  reversal handling, and a loop that can trigger `FUN_00005898` for
  *multiple* channels from a single TC0 interrupt) was decompiled far
  enough to see its shape and its one guaranteed fast path (`if
  (!ramp_active) { FUN_00005898(0); return; }`), not fully decoded.
- `FUN_00005c00`'s `case 7` (evidently not a TC channel at all) was not
  investigated.
- `FUN_00005ee8`/`FUN_00005d24` (the two callers of the rate-setter) and
  `FUN_00006338` (the one caller of the rate-reader) were named, not
  traced.
- The RAM per-channel pin-index array's real initializer was searched
  for (see above) but not found at the time this was written. **Now
  resolved** — see
  [`pin-index-provenance.md`](pin-index-provenance.md): the values are
  baked into the compiler's `.data` segment and copied into RAM by
  `Reset_Handler`'s own startup copy loop, not written by any application
  instruction, which is why the search here correctly found nothing.

## Confirmed vs. candidate — summary table

| Fact | Status |
|---|---|
| IRQ107/108/109/110 = TC0/TC1/TC2/TC3 (in that order) | **Confirmed** (real vector table entries, literal-pool base address resolved) |
| Each handler clears exactly the MC0+OVF flags enabled for it at startup | **Confirmed** (static + concrete) |
| TC1/TC2/TC3 tail-branch to a shared `FUN_00005898(channel)`; TC0 branches to a different, larger `FUN_00005be8` | **Confirmed** (disassembly) |
| `FUN_00005898` pulses a table-indexed GPIO pin via `FUN_0000d388` (the same helper already found in `samd51-peripheral-mapping.md`) | **Confirmed** (static + concrete, PA23 case) |
| The flash pin-descriptor table at `0x14284` (10 candidate entries: PA23, PA22, PB17, PB16, PB13, PB14, PB15, PB12, PA21, PA20) | **Confirmed** (static, direct flash read) |
| `FUN_00005c00`/`FUN_00006260` write/read each TC's `CC0` (period) with correct SYNCBUSY/RETRIGGER sequencing | **Confirmed** (static; matches the already-known startup peripheral survey) |
| Which specific pin each of TC0/TC1/TC2/TC3 drives on a real, running device | **Confirmed** (static, direct flash read) — TC0->PB10, TC1->PA08, TC2->PB12, TC3->PA10; see [`pin-index-provenance.md`](pin-index-provenance.md). Cold-RAM concrete execution giving PA23 for all four was an artifact of uninitialized state, not a hardware fact — now superseded |
| Any "Motor 1/2/3/4" physical identity for TC0-3 | **Not claimed** — no evidence connecting TC-channel-number to a physical motor connector was sought or found this pass |

## Motor hardware-provenance graph (as far as this slice's evidence supports)

```
TCC1  --IRQ93/0x60ec-->  ISR (inline)  --INTFLAG bit16-->  PORT.GROUP1.OUTTGL  -->  PB22            [fully confirmed]

TC0   --IRQ107/0x607c--> ISR --INTFLAG MC0+OVF--> tail-branch(0x5be8, ramp logic) --fast path--> FUN_00005898(0) --> FUN_0000d388(pin_idx_table[RAM 0x20000164]=41) --> OUTSET/OUTCLR --> PB10 [confirmed, see pin-index-provenance.md]
TC1   --IRQ108/0x6098--> ISR --INTFLAG MC0+OVF--> tail-branch(0x5898, r0=1)       -->                FUN_00005898(1) --> FUN_0000d388(pin_idx_table[RAM 0x20000165]=43) --> OUTSET/OUTCLR --> PA08 [confirmed, see pin-index-provenance.md]
TC2   --IRQ109/0x60b4--> ISR --INTFLAG MC0+OVF--> tail-branch(0x5898, r0=2)       -->                FUN_00005898(2) --> FUN_0000d388(pin_idx_table[RAM 0x20000166]=7)  --> OUTSET/OUTCLR --> PB12 [confirmed, see pin-index-provenance.md]
TC3   --IRQ110/0x60d0--> ISR --INTFLAG MC0+OVF--> tail-branch(0x5898, r0=3)       -->                FUN_00005898(3) --> FUN_0000d388(pin_idx_table[RAM 0x20000167]=45) --> OUTSET/OUTCLR --> PA10 [confirmed, see pin-index-provenance.md]

Rate control (all five timers): FUN_00005c00(channel, period) -> TCx.CC0 (+ RETRIGGER)  <-- callable at runtime, not just startup
Rate readback (TC0-3):          FUN_00006260(channel) -> reads TCx.CC0 + SYNCBUSY
```

## A concrete protocol-level connection, found in passing

`FUN_00005898`'s position accumulator (`position[channel] += step_delta[channel]`)
lives at **RAM `0x20002064`, indexed by channel** — this is *exactly* the
address `research/autopilot_static_inventory/synchronous-responses.md`
already named as event-15's source (`i32[0x20002064[channel]]`, the
result value the AutoPilot sends back for a dynamic `I<channel><mode>|`
query). This was not sought out — it fell out of decompiling
`FUN_00005898` for an unrelated reason (finding the GPIO write) and is a
genuine, address-exact link between the already-mapped protocol layer
and this pass's hardware layer: **the "I" command's numeric result is
this same step-position counter the timer ISR increments on every step
pulse.**

A second, less certain overlap: `FUN_00005898` reads
`*(char*)(0x20002524 + channel)` — `0x20002524` is the *same* address
[`docs/investigations/s-p-roundtrip.md`](s-p-roundtrip.md) identified as
the single-byte "device state/mode" the `S`/`P` handler switches on.
Here it's indexed by channel, suggesting `0x20002524` may actually be the
*base* of a small per-channel state array rather than one global byte
(with the `S` handler reading index 0, or an aggregate). Not resolved
this pass — flagged as a real connection between two previously-separate
investigations, worth keeping in mind for the next slice rather than
assumed either way.

## Evidence level

Ghidra static analysis (decompile + disassembly + direct flash reads) for
the full mechanism and the pin-descriptor table; **concrete (level 2)**
confirmation via `run_concrete.py --log-mmio` for the INTFLAG-clear and
GPIO-pulse mechanism (all four TC channels individually run). The
per-channel pin *assignment* itself is not resolved at any evidence
level — explicitly a gap, not a level-1 (static-only) claim standing in
for a stronger one.

## Best next entry point for connecting `I<channel><mode>|` to this hardware chain

**Not executed this pass**, per the task — but the concrete starting
point is now clear and specific, not a vague "trace the I command more".
Item (1) below is now done — see
[`pin-index-provenance.md`](pin-index-provenance.md) — which removes the
one blocker that made (3) premature; (2) is the natural next slice:

1. ~~Find what writes `0x20000164`-`0x20000167`~~ — **done**: they are
   `.data`-segment initializers copied by `Reset_Handler`, not written by
   application code. TC0->PB10, TC1->PA08, TC2->PB12, TC3->PA10,
   confirmed at the static evidence tier. See
   [`pin-index-provenance.md`](pin-index-provenance.md).
2. **Trace `I<channel><mode>|`'s already-known write sites**
   (`u8[0x20001b14[channel]]`, `u8[0x200029d8[channel]]`, per
   `synchronous-responses.md`) forward to see whether they influence
   `step_delta[channel]` (`RAM 0x20000094`, the per-tick increment
   `FUN_00005898` adds to the position counter) — this is now the single
   remaining link needed to close the full
   `command -> internal state -> timer rate -> ISR -> now-known GPIO`
   chain. This is the recommended next entry point.
3. Once (2) is resolved, a `run_concrete.py`-based concrete run seeding a
   specific `I<channel><mode>|`-derived state and observing the real
   resulting pin toggle (now a *known* pin, not a candidate) would close
   the full chain this project has been building toward since M6 was
   opened.
