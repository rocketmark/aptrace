# Investigation: Injecting a Real `G` Command, and Why the Motor Subsystem Never Sees It

**Question**: [`post-probe-main-loop.md`](post-probe-main-loop.md) reached
the real main loop and identified (but did not use) the real RX ring
buffer as an injection point. This slice's task: inject a real,
protocol-legal command into that ring, through the real receive/parser/
dispatch path, and catch the first real `0x20001b14[channel]` write —
without assuming `I` is the trigger, using the existing static protocol
research to pick the strongest candidate first.

**Scope**: concrete Unicorn only (no new symbolic work — nothing here
turned out to need it). No hardcoded/seeded write to the gate itself. No
chasing the previously-identified NVM bulk-erase stall unless the
injected command's own real path needed it (it did not).

## Result

**A real command was successfully delivered end-to-end through the real
receive path for the first time in this project — and that delivery
itself uncovered the actual reason `0x20001b14` has never been observed
to change: the entire motor-phase/ramp/monitor subsystem is not even
reachable from a cold boot without a prior, specific command.**

`G<d><d><seq>|` — chosen because it is this project's own
**execution-confirmed** command (not `I`, which the task said not to
assume) — was injected via a new, disclosed `run_concrete.py
--force-mem` capability into the real 100-byte RX ring
(`0x2000245c`/`0x200024c4`) right after real boot reaches the real main
loop. Delivery required first diagnosing and correcting a genuine
harness-timing artifact (below). Once corrected, the real dispatcher
(`0x8258`) ran to completion on the real bytes, including a **previously
undocumented** write this slice found: the `G` handler arms a state byte
(`0x200025e1 = 2`) that a second function, `FUN_00007e2c`, gates its own
first state on. `0x20001b14` was still not written.

Tracing *why* `FUN_00007e2c` never acted on that arm led to the real
answer: `FUN_00007e2c` (and `FUN_00008e18`, `FUN_00006338`,
`FUN_00008a80` — every function this project has ever described as
running "every main-loop iteration") lives inside `FUN_000093fc`, which
is called only *after* `FUN_00009464` returns — and `FUN_00009464`
contains its own internal, currently-permanent loop (the *real* main
loop actually running today) that never returns. The one and only real
exit from that loop is gated on a byte this slice traced to exactly one
writer in the whole firmware: the **`MC4<...>|`** command (motor
configuration, all four channels). No other code — not `G`, not `I`, not
per-channel `MC<0-3>` — touches it.

## Step 1: candidate selection from existing static research

Per [`command-inventory.md`](../protocol/command-inventory.md), the
motion-adjacent commands are `I<1-4><0-1>|` (already proven, per
[`i-command-motor-chain.md`](i-command-motor-chain.md), to only *read*
the gate), `MC<0-3>/MC4` (motor configuration), `LL1|`/`LL2|` (limit
workflow, unresolved semantics), and `G<d><d><seq>|` (a generic
synchronous request/ack, **execution-confirmed** — the only command in
the whole inventory already proven, concretely, to reach its real
handler end-to-end, via
[`g-ack-roundtrip.md`](g-ack-roundtrip.md)/`tools/unicorn/virtual_link.py`).

`G` was picked first not because it looked motion-specific (it doesn't),
but because it is the cheapest command to deliver with already-trusted
tooling, and — checked directly this slice, not assumed — because a
whole-firmware literal-pool scan for the value `0x200025e1` (the byte
[`i-command-motor-chain.md`](i-command-motor-chain.md) already knows
`FUN_00007e2c` gates its state-0 entry on) turned up exactly four hits:
`FUN_00007e2c` itself (reads it, and clears it to `0` on completion) and
**`FUN_00008258` at `0x83c0`** (inside the `G` branch, `0x83b2`-`0x83ea`)
— a real, previously-undocumented connection from `G` into the same
gate `FUN_00007e2c` waits on. This made `G` the strongest, cheapest-to-
test candidate, not a guess.

## Step 2: `--force-mem`, a new, disclosed RX-injection primitive

`run_concrete.py` gained **`--force-mem TRIGGER:MEMADDR:HEXBYTES`**: the
memory-range counterpart to the existing `--force-reg` (used for the
radio-ID assumption in `post-probe-main-loop.md`) — immediately before
the instruction at `TRIGGER` executes, write `HEXBYTES` into `MEMADDR`.
Same disclosure discipline: this fabricates bytes the harness cannot
know arrived from outside, never a claim about real traffic. Used as:

```
--force-mem 0x94bc:0x2000245c:473030307c   # ring data = "G000|"
--force-mem 0x94bc:0x200024c4:05000000     # ring write index = 5
```

`0x94bc` (`mov r4,r0`, inside `FUN_00009464`) was chosen as the trigger
because it is a genuine **one-time** program point: straight-line code
executed exactly once, immediately after all of real boot's init calls
(homing, the radio-ID probe, post-probe init) and immediately *before*
the real main loop's own back-edge (`0x94be`) is first reached — i.e.
"real boot has finished; the real steady-state loop is about to start
for the first time," exactly the point `post-probe-main-loop.md`
identified as the natural injection moment. `Reset_Handler`'s own
`.bss`-zero loop (which covers the ring buffer) has already run by this
point, so seeding any earlier would be silently wiped.

## Step 3: a real harness-timing artifact, found and fixed

The first attempt (reusing `--fake-tick 0x200052ec:20`, unchanged from
`post-probe-main-loop.md`) placed the bytes correctly but the real parser
never recognized the `'|'` terminator, even though `--watch-mem` on the
ring's read index (`0x200024c0`) showed it walking `0 -> 1 -> 2 -> 3 -> 4`
exactly as expected. Root cause, found by watching the peeked byte value
(`r0` at `0x89f0`) and the packet-assembly index (`0x20001fd4`) together:

- Every single call to the real "is data available" check
  (`FUN_0000801c`) — which the receive loop (`FUN_00008960`) re-executes
  **once per byte consumed**, not once per packet — runs a real SX127x-
  style radio IRQ-flags poll (`FUN_00007fdc` -> `FUN_00009eac`, reading
  register `0x12` (`RegIrqFlags`) and `0x01` (`RegOpMode`) through the
  *same* real SPI transceive helper the original radio-ID probe used).
  Under zero-behavior MMIO this always reports "no radio activity," but
  the *real, unmodified* recovery-mode logic that follows still costs
  ~2,800-38,000 real instructions per check.
- `FUN_00008960` also enforces a real **inter-byte assembly timeout**:
  if more than `0x82` (130) ticks have elapsed since the last byte, it
  resets the in-progress packet (`0x20001fd4 = 0`) before accepting the
  next one — a real, legitimate firmware behavior (protecting against a
  stalled transmitter), not a bug.
- At `--fake-tick` period 20, the radio-poll cost alone (2,800+
  instructions) already exceeds 130 ticks (140+), so **every byte** looked
  like a fresh, stale packet to the firmware — the assembler kept
  resetting mid-packet, and the `'|'` ended up stored as a data byte of a
  *new* (never-completed) packet instead of recognized as a terminator.

This is a genuine harness/firmware-timing mismatch, not evidence about
the protocol or the gate: the instructions-per-tick ratio calibrated for
the (tick-cheap) boot-timeout dependencies in `reset-handler-clock-init.md`
does not hold for this (tick-expensive, real-radio-polling) code path.
Fixed by raising the same, single `--fake-tick` period to **300** — large
enough that the worst observed per-byte cost stays under the 130-tick
threshold — disclosed here as a harness recalibration, not a new model of
anything. (This also, incidentally, is the same class of tick-cost
surprise `reset-handler-clock-init.md` and `post-homing-radio-probe.md`
already had to characterize once each; this is the third, and the fix is
the same in kind: measure the real cost, then choose a period, not guess
one.)

## Step 4: `G000|` delivered for real, end to end

With period 300, one concrete run (`--max-instructions 3000000`)
confirms, via `--watch`, the full real path:

| Instruction | Address | What |
|---|---|---|
| 1,130,845 | `0x94bc` | `--force-mem` fires — ring seeded with `"G000\|"`, write index = 5 |
| 1,159,440 | `0x8a20` | real terminator branch taken — `'\|'` correctly recognized (packet index = 4) |
| 1,162,287 | `0x8258` | real ASCII dispatcher entered with the real assembled packet `"G000"` |
| 1,179,795 | `0x83de` | **`0x200025e1 = 2`** — the arm store, reached for real |

`--dump-mem` confirms `0x2000232a` (the shared packet-assembly buffer —
also, previously unresolved, the very buffer `FUN_00007e2c` reads its
channel/type digits from) holds the real bytes `47 30 30 30` (`"G000"`)
at this point. This is the first concrete confirmation in this project
of a command being fully assembled, byte by byte, through the real ring
buffer and real timeout-and-retry logic, not entered via a shortcut.

`--watch-mem-write 0x20001b14:4` across this entire run (and a repeat
run out to 3,000,000 instructions) recorded **no write beyond the
already-known cold `.bss` clear**. `G` reaching its handler, and its
handler reaching the arm store, did not produce the target write.

## Step 5: why not — `FUN_00007e2c` is unreached, and the real reason is structural

`--watch 0x7e2c` recorded **zero hits** across the full post-injection
run, despite `0x200025e1` now holding `2`. Tracing why, from the calls
graph (`research/runs/ghidra/firmware_autopilot868.json`):

```
FUN_0000cc24 (Reset_Handler)
  -> FUN_0000cd90 (0xcc5c)
       -> FUN_00009464 (0xcdb2)   <-- real boot init + its OWN internal loop
       -> FUN_000093fc (0xcdb6)  <-- calls FUN_00007e2c, FUN_00008e18,
                                      FUN_00006338, FUN_00008a80
       -> FUN_0000cd88 (0xcdba)
```

`FUN_00009464` is not the straight-line init function every prior slice
in this project treated it as. Disassembled in full: after its real init
calls (homing, the radio-ID probe, post-probe init — the same milestones
`post-probe-main-loop.md` already found), it enters its **own** internal
loop at `0x94be`-`0x94e2`, calling only `FUN_00008960` (receive/dispatch —
the loop `post-probe-main-loop.md` was actually watching) and
`FUN_00005dd0` each pass. This loop is a real `do {} while` with **one**
exit: `ldrb r3,[r5,#0]; cbz r3,0x94e4` (`r5 = 0x20000060`, a fixed RAM
byte loaded once at function entry). **This is the loop actually running
today**, and it does not return — so `FUN_0000cd90` never reaches its
next call, `FUN_000093fc`, and therefore never reaches `FUN_00007e2c`,
`FUN_00008e18`, `FUN_00006338`, or `FUN_00008a80` either. Confirmed
concretely: across every run this slice performed (several runs, up to
4,000,000 instructions total after injection), the loop never exited.

**This is a correction to this project's own prior mental model.**
[`i-command-motor-chain.md`](i-command-motor-chain.md),
[`channel-busy-gate-search.md`](channel-busy-gate-search.md), and
`post-probe-main-loop.md` all describe `FUN_00006338`/`FUN_00007e2c`/
`FUN_00008e18`/`FUN_00008a80` as running "every main-loop iteration" —
true of `FUN_000093fc`'s static structure, but **never concretely
confirmed as reachable from a cold boot** until this slice tried to
reach it and found it isn't, without a specific unlock event.

## Step 6: the real unlock trigger, found by the same method

A whole-firmware literal-pool scan for the value `0x20000060` (the exact
technique `channel-busy-gate-search.md` used for `0x20001b14`) finds
**exactly two** flash cells holding it: `0x94ec` (`FUN_00009464`'s own
read, above) and `0x8868` — inside `FUN_00008258`, in the `MC` command's
branch. Disassembled (`0x86f0`-`0x872a`):

```asm
0x86f0  ldrb r0,[r5,#0x2]      ; r0 = packet[2]
0x86f6  cmp  r0,#0x34          ; '4'  -- i.e. is this "MC4..."?
0x86fa  bne  0x0000871c        ; no -> single-channel MC<0-3> path
0x86fc  movs r0,#0x0
0x86fe  bl   0x00007a98        ; FUN_00007a98(0)
0x8702  movs r0,#0x1
0x8704  bl   0x00007a98        ; FUN_00007a98(1)
0x8708  movs r0,#0x2
0x870a  bl   0x00007a98        ; FUN_00007a98(2)
0x870e  mov  r0,r4             ; r4 == 3
0x8710  bl   0x00007a98        ; FUN_00007a98(3)
0x8714  ldr  r3,[0x00008868]   ; r3 = 0x20000060
0x8716  movs r2,#0x0
0x8718  strb r2,[r3,#0x0]      ; *0x20000060 = 0   <-- the unlock
0x871a  b    0x000083ec
0x871c  subs r0,#0x30          ; single-channel path: MC<0-3>
0x871e  uxtb r0,r0
0x8720  cmp  r0,#0x3
0x8722  bhi.w 0x000083ec
0x8726  pop.w {r4,r5,r6,r7,r8,r9,r10,lr}
0x872a  b.w  0x00007a98        ; FUN_00007a98(channel) -- no unlock write
```

**`MC4<a0>,<b0>,<c0>,<d0>,...<a3>,<b3>,<c3>,<d3>,|`** — the "motor
configuration, all four channels" command, per
[`command-inventory.md`](../protocol/command-inventory.md) — is the
**only** place in this firmware image that clears `0x20000060`, and it
does so only on the all-four-channels form, never the per-channel
`MC<0-3>...` form. Clearing it is exactly what would let
`FUN_00009464`'s loop exit on its next `cbz` check and hand control to
`FUN_0000cd90`'s next call, `FUN_000093fc` — unlocking the entire
motor-phase/ramp/monitor subsystem for the first time since boot.

## Step 7: attempted concretely — a second, distinct timing dependency, not chased

A full, correctly-terminated 36-byte `MC4` packet (`"MC4" +
"1,"*16 + "|"` — disclosed placeholder config values, not claimed to be
real/valid motor parameters) was injected the same way, at the same
trigger, with the same `--fake-tick` period 300. It did **not** assemble
successfully: after the first byte, the receive loop settled back into
its ordinary ~2,900-instruction idle cadence and never reached the
terminator (`0x8a20`), the unlock store (`0x8714`), or `FUN_000093fc`,
across 4,000,000 instructions. This looks like the same *class* of
per-byte-timeout artifact Step 3 diagnosed and fixed for `G`, but at a
different, apparently higher, per-byte real-instruction cost — plausibly
because `FUN_00007a98` (the callee `MC4` invokes four times) is
documented, in `channel-busy-gate-search.md`'s own survey, as also
driving a real LCD, a heavier real-hardware interaction than `G`'s SPI
radio poll. Not chased further this slice: repeatedly re-tuning
`--fake-tick`'s period for each new, longer command is exactly the
"arbitrary tuning" the task's scope asked not to do. This is reported as
a precisely-named, distinct dependency for whichever future slice
attempts a real `MC4` delivery, not patched around by guessing at more
periods.

## Evidence discipline — four distinct classes, kept separate

| Class | Example this pass | What it licenses claiming |
|---|---|---|
| **Harness-injected input, disclosed** | `--force-mem` writing `"G000\|"`/`"MC4..."` into the RX ring | Bytes the harness supplied at one exact point, standing in for a real inbound transmission — not observed traffic |
| **Harness timing recalibration, disclosed** | `--fake-tick` period raised 20 -> 300 | A harness proxy-for-time adjustment, justified by a measured real instruction cost; not a claim about real elapsed microseconds |
| **Firmware control flow, executed concretely** | The real terminator match at `0x8a20`, the real dispatch to `0x8258`, the real arm store at `0x83de`, the real loop-exit check at `0x94be`-`0x94c0` | What the actual compiled instructions do, given the inputs above |
| **Observed state change from real execution** | `0x20001b14` unwritten; `0x20000060` never reaches `0` in any run this slice performed | A concrete fact about these specific runs |

## Confirmed vs. inferred vs. unresolved

| Item | Status |
|---|---|
| `G` reaches its handler, produces its already-known event-17 ack scheduling, real bytes end to end | **Confirmed concretely** (byte-exact ring-index walk, real terminator/dispatch/arm-store hits) |
| `G`'s handler also writes `0x200025e1 = 2` (previously undocumented) | **Confirmed** (static disassembly at `0x83de`, hit concretely) |
| `0x20001b14` is unwritten by a real, complete `G` transaction | **Confirmed concretely** |
| `FUN_00007e2c`/`FUN_00008e18`/`FUN_00006338`/`FUN_00008a80` are unreached from cold boot without a prior unlock | **Confirmed concretely** (zero hits, several runs, up to 4,000,000 instructions) and structurally (the only path to them requires `FUN_00009464`'s loop to return) |
| `MC4<...>\|` is the only firmware code that clears the loop-guard byte (`0x20000060`) | **Confirmed statically** (exhaustive 2-hit literal-pool scan + disassembly); **not yet confirmed concretely** — the real `MC4` injection did not complete (Step 7) |
| Whether reaching `FUN_000093fc`'s subtree for real would reveal a new `0x20001b14` writer | **Not established, and not expected to be**, on current evidence: `channel-busy-gate-search.md`'s exhaustive literal-reference search already covers every function in that subtree; no code anywhere in the firmware image writes the byte nonzero, independent of reachability |

## Evidence level

Level 2 (concrete, Unicorn) for the `G` delivery, the arm store, the
`0x20001b14` non-write, and the `FUN_00009464`-loop non-exit. Level 1
(static, disassembly-verified, exhaustive literal-pool scan) for the
`MC4` unlock mechanism — not yet cross-checked concretely. No
solver/symbolic step was used or needed.

## Next step

**Concretely confirm the `MC4` unlock**, once its own per-byte timing
dependency (Step 7) is characterized the same way Step 3 characterized
`G`'s (measure the real per-byte cost under `MC4`'s own code path, then
choose a period — not guess one). Once `FUN_00009464`'s loop is
confirmed, concretely, to exit and hand control to `FUN_000093fc`, the
natural continuation is watching `0x20001b14` through *that* subsystem's
first real execution — though per Step 5's static cross-check, no new
writer is expected to appear there, since `channel-busy-gate-search.md`'s
exhaustive search already covers it. If that expectation holds even once
`FUN_000093fc` is confirmed reachable, the strongest remaining honest
conclusion becomes: **this firmware image contains no code path, reachable
or not, that ever writes `0x20001b14` nonzero** — a materially stronger
and more complete negative result than any prior slice could state, since
none of them knew `FUN_000093fc` required an unlock at all.
