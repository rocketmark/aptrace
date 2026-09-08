# Investigation: A Concrete Run Past the Homing Timeout, Looking for the `0x20001b14[channel]` Setter

**Question**: [`channel-busy-gate-search.md`](channel-busy-gate-search.md)
exhausted the static search for what sets `0x20001b14[channel]` nonzero
and named its own next step: resolve enough of the real
`FUN_00006968` homing-timeout stall to run a concrete boot with a live
`--watch-mem-write` on the target bytes, catching the setter regardless
of which function it turns out to be. This is that attempt.

**Scope, per the task**: diagnose the *exact* elapsed-time dependency
first (don't guess), implement the narrowest possible mechanism to
unblock it, run as much of the real startup/homing path as practical
with the watchpoint live, and — if a genuinely different hardware
dependency is hit before reaching the setter — stop and report that
dependency precisely rather than continuing to patch around it. No
general SysTick/NVIC/peripheral emulator was built.

## Result

**Outcome B**: the setter was not reached. The originally-suspected
timing gap was correctly diagnosed and resolved with a narrow, disclosed
mechanism; the run then got well past the homing sequence and hit a
**different, genuine dependency** — an uninitialized DMA-driven
peripheral driver object — before reaching any code that could plausibly
set `0x20001b14[channel]`. `0x20001b14`-`0x20001b17` stayed `00000000`
for the entire run; the one `mem_write_hits` entry recorded was the
already-known `.bss` zero-clear at `Reset_Handler` startup, not a new
event.

## Step 1: what the homing wait loop is actually waiting on

Per the task's explicit instruction not to guess, both tick-reading
functions already used throughout this project were decompiled/
disassembled directly, not assumed:

- **`FUN_0000ccd0`** (used by `FUN_00006968`'s homing-timeout loop):

  ```c
  undefined4 FUN_0000ccd0(void) { return *DAT_0000ccd8; }   // *0x200052ec
  ```

  A **firmware-maintained RAM counter**, not a SysTick MMIO register
  read.

- **`FUN_0000ccdc`** (used by the generic millisecond-delay helper,
  `FUN_0000cd50`, elsewhere in the same boot path): a `micros()`-shaped
  computation, `(millis_snapshot) * 1000 + (SysTick->LOAD -
  SysTick->VAL) * scale`, confirmed by resolving its literals —
  `SysTick->VAL`/`LOAD` at `0xE000E010`+`8`/`+4`, `SCB->ICSR`'s
  `PENDSTSET` bit at `0xE000ED00+4`, and, critically, the *same* RAM
  counter (`0x200052ec`) as `FUN_0000ccd0`. Under the zero-behavior MMIO
  model, `SysTick->VAL`/`LOAD` both read as `0` (never written), so this
  reduces to `millis_snapshot * 1000` — i.e. it derives entirely from the
  one RAM counter too, with no separate dependency.

- **The real `SysTick_Handler`** (vector table index 15, resolved
  directly from the vector table at flash `0x403c` → `0xcca4`),
  disassembled: guarded by a function that unconditionally returns `0`
  (so the guard never skips it), it increments `*0x200052ec` by 1 via a
  tail-jump to a sibling routine, then runs an already-`.bss`-disabled
  watchdog-style reset countdown (confirmed harmless: the countdown
  variable is `0` at cold boot, which the code treats as "already
  fired/disabled" after exactly one tick, not as an active countdown).

**Conclusion**: the elapsed-time source for both the homing timeout and
the generic millisecond delay is a single firmware-maintained tick
variable at `0x200052ec`, normally advanced by the real `SysTick_Handler`
— not a raw SysTick register read. This is exactly the class of gap
`--fake-tick` (added this pass, see
[`docs/tooling/unicorn-backend.md`](../tooling/unicorn-backend.md)) is
for: increment that one RAM address on an instruction-count cadence,
touching no SysTick/NVIC MMIO at all.

## Step 2: a second, independent dependency in the same loop

Advancing the tick alone was not sufficient — a sanity run
(`--fake-tick 0x200052ec:20`, no other change) still spun at the same
program counter after the full instruction budget. Disassembly of the
loop (`0x69ae`-`0x69ca`) showed why: the *outer* loop re-baselines its
timing snapshot every time an inner-loop GPIO read
(`FUN_0000d3dc(1)`) returns `0` — so unless that read is nonzero, elapsed
time can never accumulate past a handful of instructions before being
reset to zero, regardless of how far the underlying tick has advanced.

`FUN_0000d3dc(1)` was disassembled and resolved to a **real PORT input
register read**: bit 22 (`PA22`, the pin descriptor table's index 1 —
the same table [`pin-index-provenance.md`](pin-index-provenance.md)
resolved) of `PORT.GROUP0.IN` (`0x41008020`). Under zero-behavior MMIO
this reads `0` (never written), which is exactly the value that keeps
re-baselining the loop.

**This is a real GPIO input pin, part of the already-known descriptor
table, most plausibly a homing/limit-switch line** — not a
motor/config value in the sense the task warned against fabricating.
Seeding `PORT.GROUP0.IN` bit 22 high is a **disclosed hardware-input
boundary assumption**: "on this concrete run, PA22 reads high
throughout" — not a claim about what a real limit switch's true state
is on real hardware, and not itself part of the tick-injection
mechanism.

With the tick advancing *and* this bit seeded high, the loop escaped
after **1812 ticks** applied (threshold is `0x707` = 1799), landing
exactly where the disassembly said it should (`0x69d8`, the start of
the real homing pulse sequence) — a clean, direct confirmation that both
dependencies were correctly diagnosed, not guessed.

## Step 3: a third, unrelated dependency — ruled out of scope, not modeled

Continuing past this point (still within `FUN_00006968`'s post-timeout
pulse sequence), a *third* timing primitive appeared:
`FUN_0000cd34(n)`, used only for short physical pulse-width delays,
spins on two back-to-back reads of `0xE0001000+4` — **`DWT->CYCCNT`**,
the Cortex-M cycle counter, a hardware dependency structurally unrelated
to the millis/SysTick mechanism above (it needs the register's value to
visibly change *within a few instructions*, which no RAM-variable
injection addresses). Since this primitive only affects the physical
duration of an already-decided pin pulse — not any control-flow decision
this investigation cares about — it was `--stub-call`ed rather than
modeled, consistent with this tool's existing, already-established use
of `--stub-call` for exactly this kind of "real callee whose internals
don't matter here."

## Step 4: the run, and what it actually observed

Entry: `FUN_00009464` (the one-time boot-init function, already
established in `motor-timer-survey.md`/`pin-index-provenance.md` as
running homing and per-channel config init) — chosen over a true
`Reset_Handler` entry after a direct comparison (below). Flags:
`--fake-tick 0x200052ec:20`, `--seed-mem 0x41008020:00004000` (PA22
high), `--stub-call 0xcd34`, `--watch-mem-write 0x20001b14:4`,
3,000,000 instructions.

**Result**: the run passed the homing wait loop (confirmed: 1877-1939
ticks applied across variants, matching the threshold) and executed
well into `FUN_00006968`'s post-homing pulse/init sequence, then hit an
**unmapped memory access at address `0`** — a null-pointer dereference,
not a stall. `mem_write_hits` on the target range: **one entry**, at
instruction 5527 (visible in the separate true-`Reset_Handler` variant,
see below), `pc=0xcc82` — the already-known `.bss` zero-clear loop
writing `0` across the whole `.bss` region including this array. **No
other write occurred.** `0x20001b14`-`0x20001b17` remained `00000000` at
every point this experiment observed.

### The null-pointer dependency, characterized precisely

Trace: `FUN_00006968` calls `FUN_0000a1f4(0x200041e4)` as its very last
action (right after the homing pulse sequence) → `FUN_0000a1f4` →
`FUN_0000a0cc` → `FUN_0000a0a8` → `FUN_0000b4b4`, which dereferences
`*param_1` where `param_1` is itself `*(the passed-in object)` — i.e.
`object->field0`, which is `0` because nothing has run to initialize it
in this boot path.

Decompiling the surrounding functions shows a clear, identifiable shape:
`FUN_0000a0cc` sets up **two sub-structures** at `object+0x10` and
`object+0x24` (matching a TX/RX descriptor pair), heap-allocates
(`FUN_0000e628`) and copies descriptor blocks, and configures **three
pins** via `FUN_0000d40c` using the *same* pin-descriptor table
(`0x14284`) already confirmed for GPIO — a pin count and shape
consistent with a SPI-style peripheral (MOSI/MISO/SCK), driven through a
DMA descriptor pair. `FUN_0000b4b4` itself is a memory-region classifier
comparing a pointer against several peripheral/memory-bank boundary
constants (`0x40003000`, `0x41012000`, `0x43000000`, ...) — the shape of
code that decides which DMA trigger/attribute set to use for a given
buffer's location. This is best described as **a DMA-driven,
SERCOM-shaped (SPI) peripheral driver object that this boot path never
constructs** — not modeled further, per the task's explicit instruction
to identify and stop rather than broaden into peripheral emulation.

**Stubbing this one call site is not sufficient**: with
`--stub-call 0xa1f4` added, the run proceeded further but hit the *same*
class of null dereference again, reached through a second path
(`FUN_00009f60`, called from two addresses Ghidra did not attribute to a
named function, `0xa276`/`0xa28c`, immediately following `0xa1f4`'s own
byte range) — the same uninitialized object, touched from more than one
place. This is exactly the "different genuine hardware dependency, stop
rather than broaden" case the task anticipated, not a one-off fixable by
one more stub.

### Root-caused, not just described

A direct comparison confirms *why* this object is uninitialized here: a
**separate concrete run entering at the true `Reset_Handler`** (`0xcc24`,
with the same tick/GPIO/stub flags) does **not** reach this
dependency at all — it instead stalls inside `FUN_0000cdd8` (the
clock/analog/USB peripheral bring-up chain) at `pc=0xcde8`, spinning for
the full 3,000,000-instruction budget despite 150,000 ticks applied
(confirming this specific stall is **not** a millis/tick dependency —
it's a status-register `SYNCBUSY`-style poll, the same already-documented,
deliberately-unfixed class of gap named in `docs/project-status.md`'s
"Tooling gaps"). Entering later, at `FUN_00009464`, was a deliberate
attempt to route around that known gap — and it worked for the homing
timeout specifically, but the peripheral object above is normal-path
state that `FUN_0000cdd8`'s own chain would have constructed on a real
boot. **The null-pointer dependency is therefore a downstream symptom of
the same already-known clock-init stall, not an independent new
limitation.**

## Distinguishing what was observed from what was modeled

- **Modeled by the harness, disclosed as such**: the tick variable
  `0x200052ec` advancing on an instruction-count cadence
  (`--fake-tick`), not real elapsed time; `PORT.GROUP0.IN` bit 22 (PA22)
  read as constantly high, a boundary assumption about one GPIO input,
  not a modeled switch/sensor; `FUN_0000cd34`'s cycle-count pulse delay
  skipped entirely (`--stub-call`), so no physical pulse-width claim is
  made about this run.
- **Real firmware behavior, observed after that**: the homing-timeout
  loop's real branch structure and exit condition, the real
  `SysTick_Handler`'s increment (confirmed once at the very start via
  the `.bss`-clear write, not via the ISR itself — the ISR was never
  actually executed in this run; only the RAM variable it would have
  written was advanced directly, a distinction worth keeping precise:
  this is "the real *consumer* code's real decisions given an advanced
  tick," not "the real ISR observed running").
- **Not reached, not modeled, not claimed either way**: anything past the
  null-pointer fault, including whichever code eventually sets
  `0x20001b14[channel]`.

## Answering the task's questions

**Primary**: what real runtime event makes `0x20001b14[channel]`
transition from `0` to nonzero? **Not observed this pass** — the run
did not survive long enough past initialization to reach it.

**Secondary** (only answerable if the primary lands): none of "what
nonzero values occur," "homing-specific vs. general move setup,"
"same producer for all four channels," or a semantic-name update can be
answered from this run — no write besides the known `.bss` clear was
observed.

## Evidence level

Level 2 (concrete, Unicorn) for the tick/GPIO diagnosis and the
homing-loop escape (independently corroborated: the loop exited at
almost exactly the predicted threshold, 1812 vs. 1799 ticks). Level 2
also for the null-pointer dependency (a real, reproduced crash, not
inferred). Level 1 (static, decompile) for identifying the dependency's
likely nature (DMA/SERCOM/SPI-shaped) and for root-causing it against
`FUN_0000cdd8`'s independently-confirmed stall.

## Next step

This is now two nested, already-precisely-identified gaps rather than
one vague one:

1. `FUN_0000cdd8`'s `SYNCBUSY`-style clock-init stall (pre-existing,
   documented in `docs/project-status.md`'s "Tooling gaps" — not
   resolved here, and resolving it is a larger undertaking than this
   experiment's scope).
2. The DMA/SERCOM-shaped peripheral object `FUN_0000cdd8`'s chain would
   have constructed, touched from `FUN_00006968`'s tail call and from a
   second, not-fully-attributed call path — newly identified this pass.

Reaching the `0x20001b14[channel]` setter concretely most likely
requires solving (1) for real (letting the genuine boot sequence
construct the object in (2) itself, rather than routing around it) —
which is a materially bigger undertaking than a `--fake-tick`-sized fix,
consistent with why it was left as a separate, already-flagged tooling
gap rather than solved in this pass.
