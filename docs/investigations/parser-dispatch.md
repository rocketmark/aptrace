# Investigation: What Does the Dispatcher at 0x8258 Actually Do?

Reconciles the original static-analysis model of the AutoPilot inbound
command dispatcher
(`research/autopilot_static_inventory/parser-dispatch.md`, v0.1) with what
symbolic execution against the real compiled code found
([`docs/harness/protocol-harness-results.md`](../harness/protocol-harness-results.md)).
The short version: the individual character checks in the v0.1 model are
real and solver-confirmed; the "flat chain starting right at entry" framing
around them is not.

## What v0.1 got right: the character-level branches

The original static read of `0x8258` described a flat if/else-if chain on
the packet's first byte(s) — `'&'`, `'G'`, `'!'`, `'S'`, `'B'`, `'W'`, `'I'`,
etc., each leading to a distinct handler. For the four checks that have
since been symbolically executed in isolation, this holds up exactly:

| Command | Check block | Handler block | Solver-derived R3 |
|---|---|---|---|
| `&` | `0x888c` | `0x8890` (`pending[5]=1`) | `0x26` |
| `G` | `0x83b2` | `0x83b6` | `0x47` |
| `!` | `0x87b2` | `0x87b6` | `0x21` |
| `S` | `0x87be` | `0x87c2` | `0x53` |

Each was checked with `mkParsedBlockCFG` (single-block execution, R3 left
symbolic, ask What4/Z3 whether the handler address is reachable, extract a
model of R3) — see
[`docs/harness/execution-model.md`](../harness/execution-model.md) for the
mechanism. All four match the ASCII values the static command inventory
assigned independently. **This part of the v0.1 model is solid and does not
need revising.**

## What v0.1 got wrong (and partly right): entry is not a flat scan, but it *does* branch by first byte

Seeding Macaw discovery at `0x8259` (the dispatcher's real entry) and
letting it run reveals a **single merged unit of ~339 blocks and 57
callees** — Macaw follows real jump-based control flow, not the human
notion of "one small function," and this dispatcher turns out to be fused
with a large amount of surrounding code via plain jumps rather than calls.

Early passes over this found a block range `0x827e`-`0x82c4` that isn't a
`CMP`+branch pair but an **indexed-lookup loop** — compute a key from the
buffer, index into a table at `0x20000180`, compare, advance — and,
without yet knowing when this loop runs relative to entry, assumed it was
simply the first thing entry does for every packet. **This assumption was
wrong.** Concrete execution
([`docs/investigations/dispatcher-loop-concrete-trace.md`](dispatcher-loop-concrete-trace.md))
found entry's *very first* real decision, at `0x8258`-`0x8266`, is:

```
r3 = buffer[0]
cmp r3, #0xF0
bne <skip the loop entirely, go to the 0xE0/ASCII-chain check instead>
```

**The loop only runs when `buffer[0] == 0xF0`** — it is v0.1's own "binary
motor/control frame" path (`0xF0`/`0xE0` in the original tree diagram),
which v0.1 got right. For `&`/`G`/`!`/`S` and every other ASCII command,
execution goes straight from `0x8266` to `0x82c6` (the `0xE0` check) and
on into the character-comparison chain — **the loop is never entered for
these commands at all.** See
[`docs/investigations/trigger-input.md`](trigger-input.md) for how
R4/R5/R6/R7 get established, and
[`docs/investigations/dispatcher-loop-callees.md`](dispatcher-loop-callees.md)
for the loop's fully-decoded internal structure (relevant to any future
`0xF0`/`0xE0` binary-frame work, not to the ASCII-command milestone).

**Revised model**: entry -> `buffer[0]` gate (`0xF0`/`0xE0` -> binary-frame
loop; anything else -> the ASCII character-comparison chain, reached via
`0x82c6`-`0x8368` and onward). v0.1's individual character checks are real
endpoints on this second path, confirmed both symbolically (table above)
and now concretely, in as few as 46 real instructions with no loop
iterations at all.

## Why this was missed originally

The v0.1 static read was done by inspecting the character-comparison blocks
directly (grepping the function's IR for `CMP` against known ASCII values)
without first walking entry-to-first-comparison instruction by instruction.
That approach correctly finds every reachable character check, but silently
assumes there's nothing structurally interesting between entry and the
first comparison — which happened to be false here. Symbolic execution
caught this because running the *whole* function from a cold, unseeded
register state exposed the loop as a non-terminating cycle (see
[`docs/harness/protocol-harness-results.md`](../harness/protocol-harness-results.md)'s
diagnosis section) — it would not have been visible from block-level
inspection alone unless someone happened to walk from entry manually.

## Current status and what's still open

- The loop's exact purpose is now understood
  ([`dispatcher-loop-callees.md`](dispatcher-loop-callees.md): a per-channel
  scan calling `0x5274`/`0x5448`) and it is **confirmed not to be the cause
  of the AutoPilot-only milestone's blocker** — it's gated on
  `buffer[0]==0xF0` and never runs for ASCII commands at all
  ([`dispatcher-loop-concrete-trace.md`](dispatcher-loop-concrete-trace.md)).
  See [`docs/project-status.md`](../project-status.md) for the current
  (revised) blocker.
- Since the loop is not on the ASCII-command path, v0.1's other character
  branches (`B`, `W`, `I`, `L`, `T`/`R`, `M`, `D`, `H`, `J`, `A`, `X`, `Y`,
  `+`) are almost certainly reached via the same `0x82c6`-`0x8368`
  character-comparison chain as `&`/`G`/`!`/`S`, not through the loop —
  each one individually confirmed reachable that way hasn't been done, but
  the loop is no longer a plausible intermediate step for any of them.
- The "important mismatches" v0.1 flagged (`MS|`, `MR|`, `MM|`, `N|`, `KK|`,
  `E1,...|`, bare `W|`, short `I9|`/`I1|` — packets the Remote transmits
  that aren't explained by the visible character chain) are **not resolved
  by this finding, but newly plausible**: if the real dispatch mechanism
  includes a table-driven lookup rather than only literal character
  compares, some of these could be reachable through that mechanism in a
  way a comparison-only static read would never surface. Worth revisiting
  once the loop itself is understood — tracked as
  [`docs/protocol/open-questions.md`](../protocol/open-questions.md) #8.

## Bottom line for anyone using the v0.1 command table

Treat individual command-letter-to-behavior mappings in
`research/autopilot_static_inventory/commands.md` and
`docs/protocol/command-inventory.md` as reliable (four are now
solver-confirmed, the rest are static-only but not contradicted by
anything found here). Do not rely on
`research/autopilot_static_inventory/parser-dispatch.md`'s tree *diagram*
or its "flat scan from entry" framing as an accurate description of control
flow — that part is superseded by this document.
