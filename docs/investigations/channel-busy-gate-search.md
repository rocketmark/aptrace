# Investigation: Searching for What Sets `0x20001b14[channel]` Nonzero

**Question**: [`i-command-motor-chain.md`](i-command-motor-chain.md) closed
every edge of the `I<channel><mode>|` -> motor/timer chain except one:
what sets the per-channel gate byte `0x20001b14[channel]` to a nonzero
value. That byte is read (never written to nonzero) by all twelve
functions that reference it directly, and cleared to `0` by exactly one
(`FUN_00005958`). This slice searches specifically for the kinds of
producer a literal-address xref search structurally cannot see —
computed/indexed stores, pointer arithmetic, indirect calls, copy loops,
and decompiler artifacts that could be masking a real write — per the
same discipline that resolved the GPIO pin-index bytes in
[`pin-index-provenance.md`](pin-index-provenance.md).

## Result

**Not found — a genuine, exhaustively-searched negative result**, not an
assumption. This is reported per the task's own explicit fallback rather
than inventing a semantic or a producer that isn't there. Sections below
document confirmed facts (what the byte's cold value is, what clears it,
what every neighboring address actually is) and the search's coverage, so
the negative result is verifiable and the next slice knows exactly what's
already been ruled out.

## Confirmed: the byte is `.bss`, cold value `0`

`Reset_Handler`'s `.bss`-zero loop (`0xcc76`-`0xcc8a`) clears
`[0x20000830, 0x2000531c)`. `0x20001b14` falls inside this range, so its
value at cold boot is definitively `0`, not a nonzero startup constant —
ruling out "initialization to a nonzero value" as the mechanism (the
task's option 1). Any nonzero value must come from a genuine runtime
write (the task's option 2).

## Confirmed: what clears it, and from where

`FUN_00005958(channel)`, disassembled directly (not just decompiled,
since the decompile's own pseudo-C was misleading here — see "A
decompiler artifact, ruled out" below):

```asm
0x5958  push {r3,lr}
0x595a  mov  r1,r0            ; r1 = channel (preserved across the call)
0x595c  bl   0x5858           ; FUN_00005858(channel) -- never writes r0
0x5960  ldr  r2,[0x5980]      ; r2 = 0x20001b14
0x5962  movs r3,#0
0x5964  strb r3,[r2,r0]       ; 0x20001b14[channel] = 0
0x5966  ldr  r2,[0x5984]
0x5968  strb r3,[r2,r0]       ; a second, sibling per-channel byte = 0
0x596c  ldr.w r0,[r2,r0,lsl #2]  ; (r2 here is 0x5988's value; unrelated lookup)
0x5972  str.w r0,[r2,r1,lsl #2]  ; ...copied into a result array at index `channel`
0x5978  str.w r3,[r2,r1,lsl #2]  ; ...and a companion array zeroed
0x597c  pop {r3,pc}
```

`FUN_00005958` is called from real completion paths, not arbitrarily:

- **`FUN_00006338`** (the ramp/velocity executor, per
  `i-command-motor-chain.md`) calls it after a direction-reversal and
  after a "target reached" branch, in both its phase-2 and phase-1
  bodies.
- **`FUN_00005be8`** (TC0's own, channel-0-only ISR ramp logic — see
  below) calls `FUN_00005958(0)` when the tracked position reaches its
  recorded target *and* either the result-slot count has caught up or
  the remaining delta is within 5 units of zero — a real "this move just
  finished" condition, not an unconditional per-tick clear.

Both call sites are genuine completion detections, consistent with (but
not proof of) a "channel finished moving" semantic for the `0->` side of
this byte's lifecycle. The *symmetrical* question — where does a
completion-detection function set the byte nonzero when a move *starts*
— is exactly what this search failed to find.

## Search coverage (what was checked and ruled out)

**Every direct literal reference (exhaustive, not sampled)** — the same
12 functions already named in `i-command-motor-chain.md`, re-confirmed:
`FUN_00004cdc`, `FUN_00004d18`, an unnamed poller at `0x5420`,
`FUN_00005958` (clears, above), `FUN_00005ee8`, `FUN_00005f8c`,
`FUN_00006338`, `FUN_00007e2c`, `FUN_00008258` (the `I` handler),
`FUN_00008960`, `FUN_00008a80` (the monitor), `FUN_00008e18`. All read;
none set it nonzero.

**Every function one hop from those, on the "commits a new motion
segment" side** (the task's own leading candidates, plus what they lead
to) — all fully decompiled this pass, none touches `0x20001b14`:

| Function | Role (confirmed) | Touches `0x20001b14`? |
|---|---|---|
| `FUN_00006fd8` | Commits a new move: populates segment-breakpoint tables, sets `0x20002524[channel]=1` and ramp-phase `0x2000310c[channel]=1` | No |
| `FUN_00006e68` | Advances to the next segment of an in-progress profile; same two flags, plus resets `0x20002318[channel]` (a *third*, separate per-channel phase byte used only inside `FUN_00008e18`) | No |
| `FUN_0000693c`/`FUN_00006952` | Toggle two fixed GPIO pins (indices `0x31`/`0x32` — a status LED or enable line, not a motor pin) | No |
| `FUN_00004ae4` | Swaps two fields and negates two others in the current segment record (a direction-flip helper for the profile struct) | No |
| `FUN_00007a98` | An onboard calibration/parameter-entry menu reader (`MC<channel>|`), reads config fields and drives an LCD — unrelated subsystem | No |
| `FUN_00005570` | The real one-time TC0-TC3(+TCC1) peripheral bring-up: CTRLA/EVCTRL/NVIC-enable for each channel, plus a sibling flag at `0x20000123[channel]` | No |

**The full one-time-init call chain from `FUN_00009464`** (the boot-time
init function already known from `motor-timer-survey.md`), decompiled
end to end this pass to check for a startup arm-all-channels step:
`FUN_00006968` (homing — already known), `FUN_0000610c`, `FUN_00006190`
(zeros `position[channel]` and other per-channel config for all four
channels — a real init step, but not this byte), `FUN_00004c20`/
`FUN_00004b64` (bulk NVM/config loaders — `FUN_00004b64` loads config
bytes into the `0x20001b40`-based struct and unrolls a 4-channel `+0x40`
field write, confirmed by address arithmetic to land at
`0x20001b80`/`0x1ba0`/`0x1cc0`/`0x1ce0` — 0x6c bytes *after* the target,
not it), `FUN_00004328` (the `V01R39` version-string writer), `FUN_00005d44`.
None touches `0x20001b14`.

**Neighbor-offset check** (the specific "computed pointer from a
*different* literal plus a runtime offset" pattern this search was
designed to catch): every literal-referenced address from `0x20001af0`
to `0x20001b40` (the well-established per-channel struct base) was
enumerated and its referencing function identified —
`0x20001b10` (a single, non-indexed float used by event 9's response
builder, `FUN_00009268`), `0x20001b18`/`0x1b20`/`0x1b2c` (per-channel
`int32` arrays used by `FUN_00005274` and, unindexed, by TC0-only
`FUN_00005be8`), `0x20001b28`/`0x1b34`/`0x1b38` (single globals used by
`FUN_00008258`/`FUN_00008e18`/`FUN_00004c20`). All are distinct,
tightly-packed but non-overlapping globals — `0x20001b14` is a genuine,
standalone 4-byte array (one byte per channel) with no other array's
indexing arithmetic passing through it. This rules out the "value copied
from another state field via nearby-pointer arithmetic" case (the task's
option 3) as cleanly as a static check can.

**A decompiler artifact, ruled out**: `FUN_00005958`'s Ghidra decompile
shows it treating `FUN_00005858`'s return as a 64-bit value and indexing
`0x20001b14` with it — which would have meant the clear isn't simply
`[channel]`. Direct disassembly of `FUN_00005858` (above) shows it never
writes `R0` in any of its five switch cases, so `R0` at the call site in
`FUN_00005958` is left over from `mov r1,r0` and is just the original
channel value — the decompile's 64-bit-return modeling was wrong, not a
real return value. Flagged and resolved by disassembly rather than
trusted from the pseudo-C, consistent with this project's standing
practice of disassembly-checking anything decompiled-only in a
security- or correctness-relevant path.

**Concrete (Unicorn), partial**: entering directly at `FUN_00008e18`
with plausible seeded per-channel state (all four of its phase branches
represented across the four channels in one run) and a genuine
`--watch-mem-write 0x20001b14:4` watchpoint (a new capability added to
`tools/unicorn/run_concrete.py` this pass — see
[`docs/tooling/unicorn-backend.md`](../tooling/unicorn-backend.md)), with
every already-decompiled sub-call stubbed: channel 0's phase-0 branch ran
to completion (confirmed via `stub_hits`) with **zero** writes to the
watched range. The run then hit an unhandled CPU exception starting
channel 1's processing (an FPU/VFP instruction Unicorn's Cortex-M4 model
didn't handle under the seeded state — not investigated further, out of
scope for this question) before reaching channels 1-3. This is a
genuine, if partial, concrete confirmation layered on top of the static
read for the one branch it covered; it does not by itself establish the
other three branches, which rely on the static decompile above.

A full-boot concrete run (real `Reset_Handler` through the main loop,
watching `0x20001b14` the entire time) was not attempted: it is blocked
by the same already-documented, deliberately-unfixed tooling gap as
before (`docs/project-status.md`'s "Tooling gaps") — `FUN_00006968`'s
homing wait loop only exits via a real elapsed-time timeout
(`FUN_0000ccd0() - baseline > 0x707`), which the zero-behavior MMIO model
can never satisfy since the tick source never advances. Solving that gap
is a bigger undertaking than this slice (it needs either a fake
incrementing tick source or a smarter partial-boot entry point) and
wasn't required to reach the result above, which is already a considered
static-plus-concrete negative rather than "couldn't get the harness
running."

## Answering the six questions

1. **What instruction/function sets it nonzero?** Not found. Exhaustive
   search (12 direct-reference functions, 7 one-hop candidates, the full
   one-time-init chain, and a neighbor-offset check) found no setter.
2. **What values can it take?** Every one of the 12 consumers tests it
   as a plain boolean (`==0` / `!=0`); none compares it to a specific
   nonzero constant. So: confirmed `0` (idle/cleared); "nonzero" is
   confirmed to matter but no specific nonzero value (e.g., always `1`)
   is established.
3. **What state transition causes the write?** Unknown — this is the
   unresolved half of the question above.
4. **What clears it?** `FUN_00005958(channel)`, called from
   `FUN_00006338` (ramp executor, on direction-reversal and
   target-reached paths) and from `FUN_00005be8` (TC0's own ISR ramp
   logic, on its own target-reached condition, channel 0 only) — both
   genuine completion detections, confirmed by disassembly.
5. **Best defensible semantic name?** Given the task's explicit caution
   against assuming "busy"/"active"/"move pending" without code support,
   and that the *setter* (the actual triggering event) is unresolved, the
   most defensible name describes what's actually proven about its
   *use*, not a guess about its *cause*: **a per-channel rate-update
   enable gate** — `0x20001b14[channel]` gates (a) whether
   `FUN_00006338`'s ramp pass ever reaches `FUN_00005ee8`/`FUN_00005c00`/
   `FUN_00005898` at all, (b) whether the `I` command's own handler
   triggers `FUN_00005274`, and (c) when the `I`-query monitor considers
   the channel done and replies with event 15. "Motion in progress" is a
   plausible reading consistent with all three confirmed roles, but is
   *not* asserted as confirmed, since nothing here establishes what
   specifically flips it on.
6. **Does resolving it close the chain?** Not yet — this is the one edge
   still missing. Everything else in `i-command-motor-chain.md`'s chain
   is confirmed in terms of this exact byte, so the chain's *shape* is
   complete and this is a precisely-scoped, single-node gap, not a vague
   one.

## Evidence level

Level 1 (static): exhaustive literal-reference and neighbor-offset
search, all candidate functions fully decompiled, one decompiler
ambiguity resolved by disassembly. Level 2 (concrete/Unicorn): a genuine
memory watchpoint (new tool capability) confirmed zero writes across one
full branch of `FUN_00008e18`'s execution; the other three branches rest
on the static reading only, and a full-boot concrete confirmation remains
blocked by an already-documented tooling gap.

## Next step

**Update**: this concrete follow-up was attempted — see
[`systick-tick-injection.md`](systick-tick-injection.md). The
`FUN_0000ccd0` tick-source gap was correctly diagnosed (a
firmware-maintained RAM counter, not a SysTick register) and resolved
with a new, narrow `--fake-tick` capability; a real GPIO-input boundary
condition was also needed and disclosed. The run got past the homing
timeout successfully with `--watch-mem-write 0x20001b14:4` live, but hit
a *different* genuine dependency before reaching the setter — an
uninitialized DMA/SERCOM-shaped peripheral driver object, root-caused to
the same already-documented `FUN_0000cdd8` clock-init stall (not solved,
per the task's explicit scope). No write to `0x20001b14` beyond the
already-known `.bss` clear was observed. The static search here remains
believed exhausted; the concrete path is now blocked by a precisely
identified, different dependency rather than the original tick gap.
