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

## What v0.1 got wrong: entry is not a flat scan starting at the top

Seeding Macaw discovery at `0x8259` (the dispatcher's real entry) and
letting it run reveals a **single merged unit of ~339 blocks and 57
callees** — Macaw follows real jump-based control flow, not the human
notion of "one small function," and this dispatcher turns out to be fused
with a large amount of surrounding code via plain jumps rather than calls.

More importantly, **entry does not go straight into a character comparison
at all.** The block range `0x827e`-`0x82c4` runs first, and its lifted IR is
not a `CMP`+branch pair — it:

1. Loads a byte from `[R5+1]`.
2. Computes an index from bytes at `[R4+6..9]`.
3. Performs an indexed load `[R7 + R0*4]`.
4. Compares the result against another loaded value, and either matches or
   advances to the next slot.

This is the shape of a **hash-table or lookup-table probe** — compute a
key, index into a table, compare, advance on mismatch — not a linear string
of character comparisons. It is not yet known what this loop is looking up
(a command-ID-to-handler table? a per-channel state slot?) or exactly how
many iterations it runs before falling through to the character-level
checks that v0.1 documented. See
[`docs/investigations/trigger-input.md`](trigger-input.md) for what's known
about how R4/R5/R6/R7 get established going into this loop.

**Revised model**: entry -> indexed-lookup loop (`0x827e`-`0x82c4`,
mechanism not fully understood) -> *then*, at some point, code resembling
v0.1's character-comparison chain. The character checks are real endpoints
reachable via the documented ASCII values; they are just not the first
thing that runs.

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

- The loop's exact purpose is not identified. Leading hypothesis (per
  [`docs/protocol/open-questions.md`](../protocol/open-questions.md) #10):
  it dispatches per-channel/per-command work by calling `0x5274`/`0x5448`
  once per iteration, and its exit condition depends on a memory write one
  of those makes — which the harness's current opaque-call approximation
  doesn't model, and which is the current blocker on the AutoPilot-only
  milestone (see [`docs/project-status.md`](../project-status.md)).
- Whether every one of v0.1's other character branches (`B`, `W`, `I`, `L`,
  `T`/`R`, `M`, `D`, `H`, `J`, `A`, `X`, `Y`, `+`) is reached *through* this
  same loop, or whether some are reached by a separate, more direct path,
  has not been checked — only `&`/`G`/`!`/`S` have been individually
  verified so far.
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
