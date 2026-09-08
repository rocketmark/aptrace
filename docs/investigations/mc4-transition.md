# Investigation: What `MC4` Actually Does — the Cold-Boot-to-Motor-Subsystem Transition

**Question**: [`g-command-motor-subsystem-unlock.md`](g-command-motor-subsystem-unlock.md)
found that `MC4<...>|` is the only firmware code that clears `0x20000060`,
the byte gating `FUN_00009464`'s internal boot-phase loop — but did not
confirm this concretely, and did not characterize what `MC4` itself does.
This slice: characterize `MC4` statically first (frame schema, handler,
writes, control-flow transition), then deliver one real frame through the
live RX path and observe the transition for real.

**Scope**: concrete Unicorn only (nothing here needed anything symbolic).
No hardcoded/seeded write to `0x20001b14`. No injecting post-parse state —
every transition below is produced by the real parser and real dispatcher
acting on real, delivered bytes.

## Result

**`MC4` is confirmed, concretely, to be the real, singular transition from
the cold-boot loop into the operational main loop that contains the
motor-phase/ramp/monitor subsystem — and, sent together with a prior `G`,
the newly-reachable subsystem was driven far enough to reach the real
"commit a move" function (`FUN_00006fd8`) for the first time in this
project's history.** `0x20001b14[channel]` was still not written, in any
run performed. The reason, now nailed down precisely rather than left
open: the specific move this run's synthetic inputs produced had a
computed distance of exactly `0`, and `FUN_00006fd8`'s own code takes a
documented "no real move needed" branch below `8` units — not a missing
mechanism.

## Static characterization of `MC4`

### 1. Accepted frame

Per [`command-inventory.md`](../protocol/command-inventory.md):
`MC4<a0>,<b0>,<c0>,<d0>,...<a3>,<b3>,<c3>,<d3>,|` — 16 comma-terminated
decimal fields (4 per channel × 4 channels), each optionally signed
(`FUN_0000799c`, the field parser, accepts a leading `-`). No fixed
field width — parsing walks digits until a `,` or `|`, driven entirely by
the buffer content.

### 2. Parser/handler entry

`FUN_00008258` (the ASCII dispatcher) — the `M` top-level branch,
`packet[1]=='C'` sub-branch (not traced in more depth than needed;
already known from `command-inventory.md`), then `packet[2]` decides
per-channel (`'0'`-`'3'`) vs. all-four (`'4'`, `0x34`) at `0x86f0`-`0x872a`
(full disassembly in
[`g-command-motor-subsystem-unlock.md`](g-command-motor-subsystem-unlock.md#step-6-the-real-unlock-trigger-found-by-the-same-method)).
The `4` form calls `FUN_00007a98(0)`, `FUN_00007a98(1)`, `FUN_00007a98(2)`,
`FUN_00007a98(3)` in sequence — one call per channel, each consuming its
own 4 fields off the *same* packet buffer via a shared cursor.

### 3. State/global writes

`FUN_00007a98(channel)`, decompiled in full, calls `FUN_0000799c()`
(the field parser) exactly 4 times per channel, in order, writing:

| Field | Storage (per-channel array) | Transform |
|---|---|---|
| 1st | `0x2000006c[channel]` | `value * 0x50` (80 decimal) |
| 2nd | `0x200000dc[channel]` | raw value |
| 3rd | `0x200000f0[channel]` | raw value, **except `1 -> 0`** (a remap) |
| 4th | `0x20000138[channel]` | raw value |

`FUN_0000799c` reads directly from the shared packet-assembly buffer
(`0x2000232a`) at a cursor held in `0x20001fd4` — the *same* byte
`FUN_00008960` uses as its receive-assembly length. Confirmed by
disassembly, not inferred: the receive path and the post-dispatch field
parser are two different consumers of one shared cursor byte, reused
across a packet's lifetime (accumulate, then parse).

**Cross-reference (exhaustive, whole-firmware literal-pool scan, the
same method used for `0x20001b14` and `0x20000060`)** finds who *else*
reads these four fields:

- `0x2000006c`, `0x200000f0` -> also read by `FUN_00007514` (see below)
  and `FUN_00007770` (an already-known post-homing display/status
  function, per `post-homing-radio-probe.md`) — **not** the locked
  subsystem.
- `0x200000dc` -> also read by `FUN_00006190` (a known boot-time
  per-channel init function, per `channel-busy-gate-search.md`) — again
  not the locked subsystem.
- **`0x20000138` -> also read by `FUN_00007e2c` and `FUN_00008e18`** —
  the two functions at the heart of the locked subsystem. Both use it as
  an index into a secondary table (`FUN_00007e2c`'s `DAT_00007e24`
  lookup; `FUN_00008e18`'s `DAT_00009154`/`DAT_00009158` pair in its
  `*DAT_00009150==0x14` "all channels" branch). **`MC4`'s 4th field per
  channel is the one piece of `MC4`-supplied configuration the locked
  subsystem actually consumes** — not a guess, a literal-reference fact.

A per-channel timestamp array (`0x200023e8[channel]`) gates one more
piece of real behavior: if more than 300 ticks have passed since the
last `MC`/`MC4` call for that channel (always true from cold `.bss`),
`FUN_00007a98` calls **`FUN_00007514(channel)`** — decompiled in full,
this drives a real LCD/status-display object (position/size/color setup,
then an indirect call through the object's own vtable-like pointer,
flagged by Ghidra as "could not recover jumptable — treating as call").
This is a real display refresh, structurally unrelated to motion, and
confirmed (below) to run under this harness without crashing.

### 4. Control-flow transition

**`0x8714`-`0x8718`, reached only on the `packet[2]=='4'` form, after all
four `FUN_00007a98` calls**: `*0x20000060 = 0`. This is the **only**
place in the whole firmware image that writes this address (confirmed by
an exhaustive literal-pool scan for the value `0x20000060`: exactly two
hits, `0x8868` here and `0x94ec`, `FUN_00009464`'s own read of it).
Per-channel `MC<0-3>` calls `FUN_00007a98` once and returns without
touching it.

### 5. Does the cold-boot main loop exit?

**Yes — concretely confirmed this slice**, not just inferred from (4)'s
static read. `FUN_00009464`'s internal loop (`0x94be`-`0x94e2`, the real,
currently-running main loop identified in
`g-command-motor-subsystem-unlock.md`) exits via `ldrb r3,[r5,#0]; cbz
r3,0x94e4` where `r5 = 0x20000060`. Clearing it on the next pass takes
the exit; `FUN_00009464` returns (`0x94e4: pop {r4,r5,r6,pc}`) to its
caller `FUN_0000cd90`, which then makes its next call — `FUN_000093fc`.

### 6. How the locked subsystem becomes reachable

`FUN_0000cd90`'s call order (`0xcdb2: bl FUN_00009464`, `0xcdb6: bl
FUN_000093fc`, `0xcdba: bl FUN_0000cd88`) means `FUN_000093fc` is called
exactly once `FUN_00009464` returns — a plain, unconditional
control-flow handoff, no new dispatch mechanism. `FUN_000093fc`'s own
body (unconditionally, once per its own call) then calls `FUN_00007b8c`,
`FUN_00007e2c`, `FUN_00005fac`, and — gated only on its own internal
elapsed-tick checks, not on anything `MC4` touches — `FUN_00008e18`,
`FUN_00009268`, `FUN_00008960`, `FUN_00005dd0`, `FUN_00008a80`. `MC4`
does not call any of these directly; it only removes the one obstacle
(`0x20000060`) to `FUN_000093fc` ever being called at all.

## Concrete delivery: `MC4` alone

Reused the real cold-boot recipe from
`g-command-motor-subsystem-unlock.md` (`Reset_Handler` -> real
clock/peripheral init -> real startup-reference routine -> the disclosed
radio-ID assumption -> real post-probe init), with the same one-time
`--force-mem 0x94bc:...` injection point for a real, correctly-terminated
36-byte frame: `"MC4" + "1,"*16 + "|"` — placeholder field values,
disclosed as such, not claimed to be meaningful motor configuration.

### The second real per-byte timing dependency, diagnosed precisely

The first attempt (reusing `G`'s working `--fake-tick` period, 300)
failed the same way `g-command-motor-subsystem-unlock.md`'s own first
`MC4` attempt did: assembly stalled after a handful of bytes. Watching
`0x896a`/`0x8a06` and the timestamp (`0x20002010`) together this time
found the *exact* mechanism, more precisely than the prior slice's report:

`FUN_00008960`'s inter-byte timeout (`0x82`/`0x83` = ~131 ticks) is
measured **cumulatively from the start of the in-progress packet**, not
per byte — the timestamp (`0x20002010`) is only refreshed when the
accumulation index is `0` (a fresh packet) or when the timeout has
already fired (a reset). Mid-packet, it is *not* refreshed on every
byte. So the real constraint is not "each byte's check must cost <131
ticks" (true even at the old period) but **"the entire packet's
assembly time must stay under 131 ticks."** At period 300, one real
byte-check costs a measured, stable **~5,696 instructions** (~19 ticks)
— fine for `G`'s 5 bytes (~76 ticks total), but for `MC4`'s 36 bytes
(~35 checks after the first) that is ~665 ticks, several times over
budget: confirmed concretely — a reset every 7th byte, exactly matching
`35 x 19 ticks / (131/19 ≈ 7)`.

**Fix, sized from the measurement, not guessed**: raise `--fake-tick`'s
period so the *whole* packet's real cost stays under 131 ticks:
`35 x 5,696 / 131 ≈ 1,522` is the break-even; **period 2000** gives
comfortable margin (`35 x 5,696 / 2000 ≈ 100` ticks). This is the same
class of fix as `g-command-motor-subsystem-unlock.md`'s (a harness
timing recalibration, disclosed, not a new model), refined with the
correct cumulative-timeout model rather than a per-byte one.

### Result: unlock confirmed for real

With period 2000, one concrete run (`--max-instructions 9000000`):

| Instruction | Address | What |
|---|---|---|
| 5,817,862 | `0x94bc` | `--force-mem` fires — ring seeded with the 36-byte `MC4` frame |
| 6,023,746 | `0x8a20` | real terminator recognized — the full frame assembled correctly |
| 6,177,986 | **`0x8714`** | **`0x20000060 = 0`** — the real unlock, reached for real |
| 6,180,925 | **`0x93fc`** | **`FUN_000093fc` reached for the first time** — the boot-phase loop exited |
| 6,183,720 | **`0x7e2c`** | `FUN_00007e2c` reached (212 hits total across the observed window) |
| 6,186,687 | **`0x8e18`** | `FUN_00008e18` reached (72 hits total) |

`--watch-mem-write 0x20001b14:4` throughout: **no write beyond the
already-known cold `.bss` clear**, even with the previously-locked
subsystem now confirmed running repeatedly, for real, over more than a
million subsequent instructions.

## Concrete delivery: `MC4` then `G`, properly sequenced

Per the task's question about the relationship between `G`'s
`0x200025e1=2` arm and `MC4`: sending both in the *same* pre-boot
injection (`"G000|MC4...|"` queued together) does **not** cleanly
exercise both — `G`'s full dispatch (including `FUN_00004b64`'s bulk
config load) costs enough real instructions that, by the time the
receive loop resumes, `MC4`'s already-buffered bytes are silently
**discarded** by a real firmware check: `FUN_00008960` tests the
just-dispatched command's own character value and the busy gate
(`(last_cmd != 10 || 0x20001b14[0] != 0) && last_cmd > 9`, true for any
ASCII command letter) and, once enough time has passed, drains the ring
without storing to the assembly buffer — a genuine "was processing;
flush anything that arrived meanwhile" behavior, not a bug and not
evidence of any coupling between `G` and `MC4`.

Fixed by sequencing the injections properly: `MC4` seeded at the usual
one-time `0x94bc` trigger, and a **second** `--force-mem` at `0x94e4`
(`FUN_00009464`'s own real return instruction — confirmed, per
`g-command-motor-subsystem-unlock.md`, to execute exactly once) delivers
`"G000|"` at the moment control is actually handed to `FUN_000093fc`,
after `MC4`'s bytes are already fully consumed. Result:

| Instruction | Address | What |
|---|---|---|
| 6,177,986 | `0x8714` | `MC4` unlock fires |
| 6,180,923 | `0x94e4` | `--force-mem` fires — `"G000\|"` seeded, right as `FUN_00009464` returns |
| 6,180,925 | `0x93fc` | `FUN_000093fc` running |
| 6,240,733 | **`0x83de`** | **`0x200025e1 = 2`** — `G` dispatched for real, through the *new* loop's own receive call |
| 6,250,593 | **`0x6fd8`** | **`FUN_00006fd8` — the real "commit a move" function — fires for the first time in this project** |

`--watch-mem-write 0x20001b14:4`: still only the cold `.bss` clear.

**Why `FUN_00006fd8` didn't lead further**: captured directly at the
call (`--watch 0x6fd8`), the real register arguments were `r0=0`
(channel), `r1=0x1e` (30, the constant `FUN_00007e2c` always passes),
**`r2=0` (distance)**, `r3=0x121fa` (rate). `FUN_00006fd8`'s own first
branch is `if (8 < abs(distance))`; with `distance=0` this takes the
**"8 units or fewer — no real move needed"** branch (clears the segment
tables, `0x20002524[0]=0`), never arming `0x2000310c[0]` (phase). This
is why `FUN_00008e18`'s phase machine never advanced this channel past
phase 0, and why `FUN_00005274`/`FUN_00006338`/`FUN_00005ee8`/
`FUN_00005898` (the rest of the already-proven ramp/timer/GPIO chain)
were not reached this run — a concrete, register-captured fact about
*this run's* synthetic inputs (`G000`'s target/position bookkeeping,
combined with `MC4`'s placeholder field values, computed to a
zero-distance move), not a newly discovered blocker. `FUN_00007e2c`'s
own per-channel-per-mode config struct (base `0x20001b40`, stride
`0x120`) — a *different* structure from the one `MC4`'s four fields
populate — read as `0xff` at its "config valid" byte (`+0x44`) under
this harness's cold-RAM/zero-behavior model; this is disclosed as
uninitialized-pattern RAM, not a claim about what a real, fully
provisioned unit would hold there.

## Answering the six characterization questions

1. **Exact accepted frame**: `MC4<a0>,<b0>,<c0>,<d0>,...,<a3>,<b3>,<c3>,<d3>,|`
   — 16 signed-decimal, comma-terminated fields; confirmed by
   disassembly of the field parser (`FUN_0000799c`), not just the
   existing catalog entry.
2. **Parser/handler entry**: `FUN_00008258` at `0x86f0` (`packet[2]=='4'`
   sub-branch), calling `FUN_00007a98(0..3)`.
3. **State/global writes**: four per-channel arrays
   (`0x2000006c`/`0x200000dc`/`0x200000f0`/`0x20000138`, one of which —
   the 4th — is genuinely consumed by the locked subsystem), a
   per-channel MC-call timestamp (`0x200023e8`), a real LCD refresh
   (`FUN_00007514`, conditional on elapsed time), and — only for the `4`
   form — `0x20000060 = 0`.
4. **Control-flow transition it causes**: none, directly — it removes
   the one condition keeping `FUN_00009464`'s internal loop from
   exiting; the loop's own next pass performs the actual exit and
   handoff.
5. **Does the cold-boot loop exit / switch phase / hand off?**: exits
   and hands off, confirmed concretely — `FUN_00009464` returns to
   `FUN_0000cd90`, which calls `FUN_000093fc` for the first time.
6. **How the locked functions become reachable**: unconditionally, as
   soon as `FUN_000093fc` runs at all — `MC4` does not call them or arm
   anything for them directly; it only clears the one flag standing
   between cold boot and `FUN_000093fc` ever being called.

## Terminology discipline

`MC4` is not claimed to mean "enter motion-control mode" or any similar
paraphrase — no string, comment, or manual reference in this project's
research corpus was consulted or found supporting that reading this
pass. What is established, concretely and statically: it is the single
firmware-defined trigger that (a) writes four real per-channel numeric
fields, one of which the locked subsystem consumes, and (b) is the only
code that ends the boot-phase loop. Whether that is *intended* as "leave
setup mode" (a real semantic hypothesis, given the name and behavior) is
a plausible reading of the evidence above, not an established fact —
kept explicitly separate.

## Is `0x200025e1` (`G`'s arm) related to the `MC4` transition?

**No — independent, confirmed by both xref and control flow, not
assumed:**

- **Literal-pool xref**: the exhaustive scan for `0x200025e1` (four
  hits: `FUN_00007e2c` itself, reading and clearing it; `FUN_00008258`'s
  `G` branch at `0x83de`, setting it) does not overlap with the
  exhaustive scan for `0x20000060` (two hits: `FUN_00009464`'s read,
  `FUN_00008258`'s `MC4` branch at `0x8714`, writing it). No function
  touches both.
- **Control flow**: `FUN_00007e2c`'s only gate is `*0x200025e1==2`;
  nothing about `0x20000060` or `FUN_00009464`'s loop appears anywhere
  in its logic. `FUN_00009464`'s loop exit depends only on `0x20000060`;
  nothing about `0x200025e1` appears anywhere in its logic.
- **The only relationship is emergent, not designed-together**:
  `FUN_00007e2c` happens to be the sole consumer of `0x200025e1`, and
  `FUN_00007e2c` happens to only be reachable once `MC4` has run. Sending
  both is necessary to see `0x200025e1`'s arm produce any real effect
  (confirmed above: `MC4` then `G` reaches `FUN_00006fd8`), but that is a
  property of *reachability*, not of any shared write, read, or
  branch condition between the two commands.
- A same-buffer, back-to-back `G` + `MC4` send is order/timing-sensitive
  at the transport level only (the real "flush stale bytes while busy"
  behavior above) — not evidence of logical coupling.

## Before/after execution model

**BEFORE `MC4`** (cold boot, confirmed in
`g-command-motor-subsystem-unlock.md` and reconfirmed here):

- Reachable: `Reset_Handler` -> real clock/peripheral init -> real
  startup-reference routine -> the disclosed radio-ID assumption -> real
  post-probe init -> `FUN_00009464`'s own internal loop (the only
  running "main loop"), calling only `FUN_00008960`/`FUN_00005dd0` per
  iteration. Any command `FUN_00008258` handles inline (`&`, `G`, `S`,
  per-channel `MC<0-3>`, ...) works normally through this loop.
- Unreachable: `FUN_00007e2c`, `FUN_00008e18`, `FUN_00006338`,
  `FUN_00008a80` — `FUN_000093fc`, their only caller, is never called.
- State: `0x20001b14[channel] = 0` (cold `.bss`, no writer reachable or
  unreachable — see `channel-busy-gate-search.md`'s exhaustive search).
  `0x200025e1` = 0 unless a prior `G` armed it to 2 (independent of
  everything else here). `0x20000060` != 0 (confirmed empirically — the
  loop runs; its cold-boot source not traced further, out of scope).

**`MC4` TRANSITION** (`FUN_00008258` at `0x86f0`-`0x8722`, then
`FUN_00007a98` x4):

- Parser accepts 16 signed-decimal fields, 4 per channel.
- Writes: `0x2000006c`/`0x200000dc`/`0x200000f0`/`0x20000138` per
  channel (only the 4th consumed by the locked subsystem), a per-channel
  timestamp, and (conditionally) drives a real LCD refresh
  (`FUN_00007514`).
- Control-flow change: `*0x20000060 = 0` — the sole real trigger
  (`0x8714`) that lets `FUN_00009464`'s loop exit on its next pass.

**AFTER `MC4`** (confirmed concretely):

- `FUN_00009464` returns; `FUN_0000cd90` calls `FUN_000093fc` for the
  first time; it becomes the new, real, repeating main loop.
- `FUN_00007e2c`, `FUN_00008e18`, `FUN_00008a80` (and `FUN_00006338`,
  its own gate) are now genuinely reached every iteration — hundreds of
  concrete hits observed.
- If `0x200025e1` is (or was already) armed to `2` by a `G` command,
  `FUN_00007e2c`'s state machine now actually executes and reaches the
  real move-commit function `FUN_00006fd8` — concretely observed.
- `0x20001b14[channel]`: **still 0 in every run performed**, including
  the run that reached `FUN_00006fd8` for real. In that run,
  `FUN_00006fd8` itself, given the real inputs this scenario produced
  (`distance=0`), took its own documented no-op branch — a concrete,
  register-captured explanation, not an open question.

## Confirmed vs. inferred vs. unresolved

| Item | Status |
|---|---|
| `MC4`'s exact frame, field storage, and the `packet[2]=='4'` gate | **Confirmed** (static disassembly + decompile) |
| Field 4 is consumed by `FUN_00007e2c`/`FUN_00008e18` | **Confirmed** (exhaustive literal-pool xref) |
| `0x20000060` is cleared only by `MC4`'s all-channel form | **Confirmed** (exhaustive literal-pool scan, 2 hits total) |
| `MC4` alone unlocks `FUN_000093fc` for real | **Confirmed concretely** (`--watch` hits, `0x8714` -> `0x93fc` -> `0x7e2c`/`0x8e18` repeating) |
| The second per-byte timing dependency is a cumulative (not per-byte) inter-byte timeout | **Confirmed** (direct measurement: stable ~5,696-instruction per-byte cost, reset cadence matches the 131-tick/19-tick-per-byte arithmetic exactly) |
| `MC4` then `G`, properly sequenced, reaches `FUN_00006fd8` | **Confirmed concretely** (register-captured call, `r0=0,r1=0x1e,r2=0,r3=0x121fa`) |
| `0x20001b14` unwritten even after `FUN_00006fd8` fires for real | **Confirmed concretely** |
| Why `FUN_00006fd8` didn't cascade further this run | **Confirmed concretely** (`distance=0` register capture, matched to its own documented `<=8` branch) |
| `0x200025e1` and `0x20000060`/`MC4` are independent | **Confirmed** (xref: no shared reference; control flow: no shared condition) |
| Same-buffer `G`+`MC4` back-to-back drops the second command | **Confirmed concretely** (real "flush while busy" branch, register/memory-traced) |
| Whether a real, non-placeholder motor-config value would drive `FUN_00006fd8` past its `<=8` branch into the full ramp/GPIO chain | **Not established, and not chased** — would need real target/position values threaded through `FUN_00007e2c`'s own per-channel-per-mode struct (`0x20001b40`+), a different structure from the one `MC4` populates; a further, narrower follow-up, not this slice's scope |

## Evidence level

Level 2 (concrete, Unicorn) for the `MC4` unlock, `FUN_000093fc`'s first
reach, the `MC4`+`G` sequencing fix, and `FUN_00006fd8`'s real call with
captured arguments. Level 1 (static, disassembly-verified, exhaustive
literal-pool scans) for the frame schema, the field-storage map, and the
`0x200025e1`/`0x20000060` independence proof. No solver/symbolic step
used or needed.

## Next step

Per the task's explicit instruction not to broaden into arbitrary
command fuzzing: **not chased further this slice**. The one narrower,
precisely-scoped follow-up this investigation surfaces: thread a real,
non-zero target/position value through `FUN_00007e2c`'s own
per-channel-per-mode config struct (`0x20001b40`+, offset `0x10` for the
target, offset `0x44` for "valid") so a delivered `G` command computes a
nonzero distance, and watch whether `FUN_00006fd8`'s real-move branch
(the one this run never took) reaches `FUN_00005274`/`FUN_00006338` and,
through the already-proven `FUN_00005ee8`->`FUN_00005c00`->`FUN_00005898`
chain, a real GPIO pulse — completing the full
`I<channel><mode>|`-equivalent chain end to end, concretely, for the
first time. `0x20001b14` remains unwritten throughout every path
exercised so far; per `channel-busy-gate-search.md`'s already-exhaustive
static search (now doubly confirmed by this slice's concrete run of the
previously-unreachable subtree), no further searching for its setter is
expected to find one.
