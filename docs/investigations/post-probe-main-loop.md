# Investigation: From the Radio-ID Boundary to the Real Main Loop

**Question**: [`post-homing-radio-probe.md`](post-homing-radio-probe.md)
found that `FUN_0000610c`'s real device-ID probe (`FUN_00009d88`, reading
SPI register `0x42`, requiring `0x12`) fails under concrete execution
with no chip attached, sending the firmware into its own real, infinite
retry loop. This slice asks: is there a real bypass for that check, and
if not, can the narrowest possible disclosed assumption get a concrete
run honestly past it and into the real main loop — far enough to resume
the `0x20001b14[channel]` setter hunt?

**Terminology note**: earlier docs call `FUN_00006968` "homing." That is
an analyst label from this project's own decompile-and-guess process,
not a name confirmed by any vendor documentation, string, or comment in
the firmware. This doc uses **"startup reference/input routine"**
instead. Existing docs are not renamed retroactively by this pass (out
of scope, and their own evidence-tier labeling already stands on its
own); new and updated text uses the neutral term.

## Result

**Primary acceptance target reached.** No real bypass exists for the
radio-ID probe (checked, not assumed). A single, narrowly-scoped,
explicitly disclosed harness assumption — "this one SPI register read
returns `0x12`" — let a real concrete run go `Reset_Handler` -> real
clock/peripheral init -> the real startup reference/input routine ->
the disclosed radio-ID assumption -> real post-probe init -> the real
main loop, confirmed stable and repeating (`FUN_00008960` hit five times
in ~400,000 instructions). `0x20001b14` is still unwritten after this —
confirmed across a clean run of the main loop, not merely assumed. A
**second**, deeper dependency was found further into sustained
execution (a real but seemingly-stalled bulk flash operation) and is
reported precisely rather than patched around, since it does not block
the acceptance target and its cause is not yet a documented MCU
completion bit.

## Step 1: is there a real bypass? (checked, not assumed)

Two call sites reach the check:

- `FUN_00009464` (boot, unconditional) — the path already traced.
- `FUN_00008258` (the ASCII command dispatcher, at `0x8914`) — meaning
  some *protocol command* also re-triggers `FUN_0000610c` at runtime
  (plausibly a "reinitialize radio" service command). This is a second
  caller of the *same* check, not a bypass of it.

`FUN_00009d88` (the probe itself) has exactly one caller
(`FUN_0000610c`) and is a straight-line sequence — CS/reset pin setup,
the SPI transceive, the `cmp r0,#0x12` — with no debug flag, no
alternate branch, no config byte read anywhere in it that could skip the
comparison. `FUN_0000610c` calls it unconditionally, with no guard
before the call. **No bypass found.** Per the task's own instruction not
to over-invest here, this is reported as a real, mandatory check in
normal boot and the search stopped there.

## Step 2: the narrowest possible disclosed assumption

A new, explicit `run_concrete.py` flag, **`--force-reg ADDR:REG:HEX`**:
immediately before the instruction at `ADDR` executes, set `REG` to
`HEX`. Used exactly once:

```
--force-reg 0x9dd4:r0:0x12
```

`0x9dd4` is the `cmp r0,#0x12` instruction *immediately after* the SPI
read returns (`0x9dd0: bl 0x99c2`) — not the callee's entry, so every
*other* call to the same read helper (e.g. `FUN_00009d88`'s own later
read of register `0xc`, a handful of instructions on) is untouched. This
is deliberately a different kind of mechanism from
`--mmio-force-bits`/`--mmio-clear-bits`: those model what the MCU's own
documented silicon guarantees; `--force-reg` fabricates a value the
harness has no way to know, standing in for "a radio module is present
and answers this read with the value real firmware requires." It is not
evidence a real radio was observed, and it does not touch the SERCOM
DATA register generally — only this one program point, one time.

Concretely confirmed to work as intended: with the assumption in place,
`r0=0x00000012` at instruction 74157 (`force_reg_hits`), the same
instruction count as the earlier confirmed failure (`r0=0x00000000` in
`post-homing-radio-probe.md`) — same deterministic point, opposite,
disclosed-fabricated outcome.

## Step 3: the real run, `Reset_Handler` through the real main loop

Same MCU-internal modeling as `reset-handler-clock-init.md`
(`OSC32KCTRL`/`OSCCTRL`/`DPLL0`/`DPLL1` ready-bits, two SERCOM
instances' SWRST-clear/DRE-ready), the same PA22 GPIO-input boundary
condition and DWT-delay stub, `--fake-tick 0x200052ec:20`, plus the one
new `--force-reg` above. `--watch-mem-write 0x20001b14:4` live
throughout. Milestones, confirmed via `--watch`:

| Instruction | Address | What |
|---|---|---|
| 27740 | `0x9464` | boot/init entry |
| ~27761-64134 | `0x6968`/`0x69d8` | startup reference/input routine, real exit (already known) |
| 74157 | `0x9dd4` | the disclosed radio-ID assumption fires |
| 87898 | `0x6190` | real post-probe init resumes |
| 96915 | `0x4c20` | |
| 251560 | `0x4328` | |
| 251577 | `0x5d44` | |
| 271845 | `0x7770` | |
| 378402, 381341, 384252, 387163, 390074 | `0x8960` | **the real main loop, receive call — stable, repeating** |

Spacing between consecutive `0x8960` hits is consistent (~2900-2940
instructions per iteration), confirming genuine steady-state operation,
not a stall. Total cost from `Reset_Handler` to the first stable
main-loop entry: **~390,000 instructions, ~19,500 fake ticks** — in the
same rough order as a normal embedded boot, not the tens of millions
`reset-handler-clock-init.md` saw before this dependency was found and
resolved. This directly confirms `post-homing-radio-probe.md`'s own
diagnosis: the earlier large tick counts were entirely the infinite
retry loop, not a sum of legitimate delays needing further
characterization.

## Step 4: `0x20001b14` during real, stable main-loop execution

Across this entire run (through 5 confirmed `0x8960` iterations, ~400,000
instructions), `mem_write_hits` contains exactly one entry — the
already-known `.bss` clear at boot. **No write occurs merely from
reaching and idling in the real main loop.** This is now confirmed
concretely under genuine steady-state execution, not just inferred from
the absence of a static writer (`channel-busy-gate-search.md`) or from
partial/crashed boot attempts (`systick-tick-injection.md`,
`reset-handler-clock-init.md`).

## Step 5: a second, deeper dependency — found, not chased

Pushing the same run much further (tens of millions of instructions)
does not sustain the same clean, fast cadence: execution eventually
reaches a real, legitimate bulk NVM/flash operation —
`FUN_000098d8`/`FUN_000098f0`, a genuine multi-page **erase** loop
(`NVMCTRL` command `0xa501` = key `0xA5` + `EP`, distinct from the
already-known write-page `0xa503`), gated on the same class of bit as
before (`NVMCTRL.INTFLAG.DONE`, bit 0 — confirmed via the SVD, same
completion-bit category, modeled the same way:
`--mmio-force-bits 0x41004010:1`). That force **did** fire once, but the
*outer* erase loop (`0x98f0`-`0x9906`) still does not visibly advance
over millions of instructions: register snapshots taken 16 instructions
apart, repeatedly, show an identical remaining-byte counter (`r4`) and
identical target address (`r1`) every time.

The most likely explanation, from reading the loop's own structure, is
that its per-iteration step size (`*(r0+0xc)`, read once per pass) is
itself `0` — a config-structure field, not a peripheral status bit — in
which case `remaining -= 0` never terminates. This is **not** the same
kind of dependency as the four MCU-completion bits or the one disclosed
radio-ID assumption: it would require either tracing what real code path
initializes that config field (a new, separate question) or fabricating
firmware configuration data outright, which the task's own discipline
excludes. **Not resolved this pass, and not needed to be**: it manifests
only under sustained, long-duration execution, well after the primary
acceptance target and the `0x20001b14` idle-runtime check (Step 4) are
already satisfied.

## Step 6: the real RX injection point, identified but not used

Per the task's instruction to stop with the exact injection point/state
identified rather than start a broader protocol slice: `FUN_00008960`'s
underlying byte source (`FUN_0000801c`/`FUN_00007f38`) is a
mode-selected abstraction over multiple transports. Concretely dumped at
the moment `0x8960` is first reached in this run:

- `*0x20000018 = 0x00`, `*0x2000006a = 0x01` — both flags observed
  (not assumed), and together they select the **plain 100-byte RAM ring
  buffer** branch, not the deeper radio-SPI-FIFO branch
  (`FUN_0000c93e`/`FUN_0000cb18`) the other flag combination would
  select. (`0x20000018` is the same byte `FUN_0000610c` clears to `0`
  on a successful probe — a real, traced connection, not a coincidence.)
- Ring buffer data: `0x2000245c` (100 bytes). Head/tail indices:
  `0x200024c0`/`0x200024c4`.

A future slice's "inject a real `I`/`M` command" would write the command
bytes into `0x2000245c` and advance the index at `0x200024c0` — a
simple, well-identified mechanism, not attempted here.

## Evidence discipline — four distinct classes, kept separate

| Class | Example this pass | What it licenses claiming |
|---|---|---|
| **MCU completion bit, modeled from documented silicon semantics** | `OSC32KCTRL.STATUS.XOSC32KRDY`, `NVMCTRL.INTFLAG.DONE` | "Real hardware, once its own preceding write takes effect, sets this bit" — a claim about the MCU's own guaranteed behavior |
| **External device response, assumed by the harness** | `--force-reg 0x9dd4:r0:0x12` | Nothing about real hardware — a disclosed, narrowly-scoped stand-in, reported as such every time |
| **Firmware control flow, executed concretely** | The real jump from `0x9dd4` into post-probe init; the real, stable `0x8960` cadence | What the actual compiled instructions do, given the inputs above |
| **Observed state change from real execution** | `0x20001b14` unwritten through 5 real main-loop iterations | A concrete fact about this run, not a static inference |

## Confirmed vs. inferred vs. unresolved

| Item | Status |
|---|---|
| No software bypass for the radio-ID probe | **Confirmed** (both call sites checked, probe body fully disassembled) |
| The disclosed assumption reaches the intended instruction and produces the intended, disclosed value | **Confirmed concretely** (`force_reg_hits`) |
| Real post-probe init and the real main loop are reached | **Confirmed concretely** (`--watch` milestones, stable `0x8960` cadence) |
| Total real boot cost, once the radio dependency is resolved, is modest (~400K instructions) | **Confirmed concretely** |
| `0x20001b14` is not written by idle main-loop execution | **Confirmed concretely**, for the duration observed (5 iterations) |
| A second, real bulk-NVM dependency exists further into sustained execution | **Confirmed concretely** (the stall itself); **its root cause (a zero-valued step-size field) is inferred from the loop's structure, not yet independently verified** |
| The RX ring-buffer injection point | **Confirmed concretely** (dumped, not assumed) as the active path at this boot state |
| Whether an inbound `I`/`M` command is what sets `0x20001b14[channel]` | **Still the leading hypothesis, not tested** — injection was identified, not performed, per the task's scope |

## Evidence level

Level 2 (concrete, Unicorn) throughout, with the evidence-class table
above kept explicit rather than blurred into one undifferentiated
"concrete" claim. No new peripheral or scheduler model was built; one
narrow, single-purpose fabrication mechanism (`--force-reg`) was added
and used exactly once, with its own stricter disclosure standard than
the MCU-completion-bit hooks.

## Next step

Two independent options, neither started:

1. **Inject a real `I`/`M` command** into the now-identified ring buffer
   (`0x2000245c`, index `0x200024c0`) and watch `0x20001b14` through a
   real dispatch — the direct continuation this slice was scoped to stop
   short of.
2. **Characterize the bulk-NVM stall's real cause** (what should
   populate the erase loop's step-size field, and whether it's simply
   not reached by this particular concrete-boot path or genuinely
   depends on something not yet modeled) — independent of (1), and not
   a blocker for it.
