# Protocol Harness Roadmap — connecting the RF protocol inventory to APTrace

`research/autopilot_static_inventory/` (v0.3, produced by a separate concurrent
research pass, not by the Macaw/Crucible spike documented elsewhere in
`research/notes/`) is a manual/scripted static reverse-engineering of the
bidirectional text-and-binary RF protocol between the **Remote** (mando
firmware) and **AutoPilot** firmware: the `0x8258` inbound parser dispatch
tree, the `0x9268` 18-event outbound dispatcher, and several proven
request/response transactions.

Its `open-questions.md` lists items that are, in several cases, **reachability
and symbolic-execution questions** rather than things that can be fully closed
by more manual tracing. APTrace's existing machinery (Steps 5-9, see
`macaw-cortexm-assessment.md` and `symbolic-execution-results.md`) is a direct
fit for several of them: Macaw code discovery already proves *what code is
reachable from where*, and the `SymbolicMutable`-memory + Crucible-block +
What4/Z3 technique already proven in `symbolic-execution-results.md` turns "is
X reachable, and under what input?" into a solver-checked answer instead of an
inference from static reading.

This document is the bridge: which inventory open questions map to which
APTrace capability, and in what order to attack them.

## Gap: APTrace hasn't touched the Remote (mando) firmware yet

Everything demonstrated so far (`firmware-layout.md`, discovery run logs,
`symbolic-execution-results.md`) is against `firmware_autopilot868.bin`. The
Remote-side addresses in this inventory (`0x58a8`, `0xb680`, `0xc440`, `0xba98`,
`0x10cf4`, etc.) live in `firmware_mando868.bin` / `firmware_mando915.bin`
instead. `tools/vector_scan.py` already validated the mando images' vector
tables (see `firmware-layout.md`), but full Macaw discovery + Crucible
translation has not yet been run against them. **This is M1 below** — it's a
prerequisite for anything Remote-side (the `G`/`S`/`!`/`&` request builders,
the synchronous wait/retry loops, `0x10cf4`'s async dispatcher).

## Milestones

### M1 — Point APTrace's loader at the Remote (mando) images too

Mechanically identical to what already works for AutoPilot: `buildMemory` +
`parseVectorTable` + `cfgFromAddrs` against `firmware_mando868.bin`, flash base
`0x4000` (same bootloader convention, confirmed in `firmware-layout.md`).
Success criterion: clean discovery (few/no `TranslateError`s) covering the
functions named in `functions-of-interest.md`'s "Remote firmware" table —
`0x58a8`, `0x5864`, `0xb440`, `0xb59c`, `0xb680`, `0xb79c`, `0xba98`, `0xc440`,
`0x10cf4`, etc. Any instruction-decode gaps found here are new Step 6 data
points (the Remote is presumably a different, possibly larger/different
peripheral-set application than the AutoPilot image, even though both are
ATSAMD51 per `firmware-layout.md`).

### M2 — Lift and validate the two protocol-critical AutoPilot functions

`0x8258` (inbound parser/dispatcher) and `0x9268` (outbound pending-event
dispatcher) are the hubs of the entire protocol per
`functions-of-interest.md`/`autopilot-to-remote.md`. Confirm Macaw discovers
and lifts both cleanly (extends the existing zero-failure Step 6 result,
established on the IRQ handlers, to the actual protocol-parsing code this
inventory cares about).

### M3 — Symbolic RX bytes through the AutoPilot parser (`0x8258`)

The highest-value new experiment. `rf-boundaries.md` identifies `0x8960` (LoRa
packet assembly) as the receive boundary and `0x8258` as "the cleanest
software-only injection boundary." Treat the bytes `0x8960` reads (presumably
from a real UART/SPI/LoRa MMIO peripheral register, the same pattern already
proven against `0x40002000` in `symbolic-execution-results.md`) as symbolic,
and ask What4/Z3 which command branches in `0x8258` are reachable and under
what byte sequences.

This directly answers, with proof instead of inference:

- `parser-dispatch.md`'s "important mismatches" — is `MS|`/`MR|`/`MM|`/`N|`/
  `KK|`/`E1...|`/bare `W|` genuinely unreachable through `0x8258`, or does a
  path exist that the static dispatch-tree reading missed? (`commands.csv`'s
  `MS_MR`/`MM`/`N`/`KK`/`E1_*`/`W_BARE` rows, all currently "not yet located"
  or "no top-level branch found.")
- Whether the `0xF0`/`0xE0` binary frame paths and the ASCII `|`-terminated
  path are truly mutually exclusive on the first byte, or whether some byte
  value reaches both.
- The exact byte-level grammar accepted at each branch (e.g. is `B2` really
  parser-accepted-but-never-transmitted, per `commands.csv`'s `B2` row?).

### M4 — Reachability of the dormant pending events (open-questions.md #8)

Open question #8 explicitly names this as "a good symbolic-execution/
reachability target for the harness team." `pending-events.md` found no direct
producer for events `2, 3, 8, 9, 11, 12, 14` via a static xref survey of the
`0x200025bc` base pointer, but flags that this "does not prove that no
computed-pointer write can exist." Macaw's code-discovery + Crucible symbolic
execution is exactly the tool to close this gap formally: discover the full
reachable call graph from `0x8258` (all command branches, including any
found by M3) and check whether any reachable path can write a nonzero value
to `0x200025bc + {2,3,8,9,11,12,14}`.

### M5 — Event-7 11-vs-10 field mismatch (event7-schema.md)

Symbolically trace the Remote's `0xc440` parser (once M1 makes it
discoverable) with the AutoPilot's real 11-field output as an input, to see
concretely what happens to the unconsumed 11th field — buffer leftover,
silent drop, or something that affects the *next* parsed transaction. This
replaces "the binaries alone do not establish which" (event7-schema.md's own
words) with an actual traced answer.

### M6 — Name the unresolved semantics (lower priority, may not need APTrace)

`open-questions.md` items 1-3 (name event-7's fields, the `I<channel><mode>`
numeric semantic, the `a0/a1/a2` states) are more about *linking recovered
values to human meaning* (cross-referencing the printed PDF manual's UI
labels, RAM addresses, and behavior) than about reachability — plain manual
tracing or dynamic testing against real hardware is likely more direct here
than symbolic execution. Not an APTrace priority unless M3/M4 surface new
structure that makes a symbolic approach clearly cheaper.

## Suggested order

M1 -> M2 -> M3 -> M4 in sequence (each depends on the loader/discovery step
before it); M5 and M6 can happen in parallel with M4 once M1 is done, since
they mostly concern the Remote side already unblocked by M1.
