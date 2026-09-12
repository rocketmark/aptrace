# AutoPilot/Remote Protocol — Overview

## What this covers

The AutoPilot (motion-control unit) and Remote (`mando`, the RF handset)
speak a bidirectional, mostly-ASCII, `|`-terminated command protocol over
LoRa, with two dedicated binary frame types (`0xF0`, `0xE0`) for what looks
like real-time motor control data.

**Two independent research passes produced what we know:**

1. **`research/autopilot_static_inventory/`** — a purely static
   reverse-engineering pass (reading disassembly, no execution) that mapped
   most of the command grammar, the outbound event-dispatch mechanism, and
   several proven request/response transactions. This is the primary
   source for command names, event IDs, and RAM addresses. It is versioned
   internally (v0.1 through v0.3 per individual file headers) and is a
   **derived research artifact** — detailed, valuable, but not verified by
   execution.
2. **APTrace's symbolic-execution work** (this project) — takes specific
   claims from (1) and checks them against the real, running (symbolically
   executed) firmware. Where it agrees, that's real cross-validation, not
   just repetition. Where it disagrees, (1)'s claim is corrected here, with
   the correction preserved and explained rather than silently overwritten.

**This directory (`docs/protocol/`) is the current, curated layer**: it
tells you what to trust, cites the raw inventory files for exhaustive detail,
and flags where symbolic execution has confirmed or corrected a claim.

## Files in this directory

| File | Covers |
|---|---|
| [`command-inventory.md`](command-inventory.md) | The command grammar (which ASCII strings mean what), cross-referenced against `commands.csv`/`commands.md` |
| [`bidirectional-protocol.md`](bidirectional-protocol.md) | The full request/response transaction graph |
| [`event-map.md`](event-map.md) | The AutoPilot's 18-slot outbound event-dispatch mechanism |
| [`open-questions.md`](open-questions.md) | Current, consolidated open questions (protocol-level; see [`docs/project-status.md`](../project-status.md) for harness-level blockers) |

## What's confirmed by execution, not just static reading

Only the following have been checked by actually running (symbolically
executing) the real firmware, via APTrace's Crucible/What4/Z3 pipeline:

- The AutoPilot's inbound dispatcher (flash `0x8258`) really does branch on
  the packet's first byte to reach `&`, `G`, `!`, and `S`-specific code,
  and the exact byte value required for each was solver-derived (not
  hand-fed) and matches the ASCII value the static inventory assigned:
  `&`→`0x26`, `G`→`0x47`, `!`→`0x21`, `S`→`0x53`. See
  [`docs/investigations/protocol-harness-results.md`](../investigations/protocol-harness-results.md).
- The `&` handler (`0x8890`) really does write `1` to the pending-event
  array at the event-5 slot (RAM `0x200025bc + 5`) and then returns — this
  was read directly from the lifted instruction semantics, not inferred.

**Everything else in this protocol documentation — the full command table,
the event map, the bidirectional transaction graph — comes from the static
inventory pass and has not yet been independently confirmed by execution.**
Treat it as well-reasoned but unverified until a specific claim has been
checked the way the four commands above were.

## What's been corrected

The static inventory's `protocol-pipeline.md` (v0.1) modeled the AutoPilot
dispatcher as a flat if/else-if character scan. Execution found the real
entry sequence runs through an indexed-lookup loop first, and the whole
region is much larger (~340 Macaw-discovered blocks) than a simple
dispatcher. See [`docs/investigations/protocol-pipeline.md`](../investigations/protocol-pipeline.md)
for the corrected picture. The individual character branches this model
predicted are still correct — only the "it's just a flat scan" framing
was wrong.

## Where the raw data lives

- `research/autopilot_static_inventory/commands.csv`,
  `research/autopilot_static_inventory/responses.csv`,
  `research/autopilot_static_inventory/pending-writes.csv` — the primary
  tabular data, still authoritative as *source data* (not yet superseded,
  just not yet independently verified beyond the four commands above).
- `research/autopilot_static_inventory/*.md` — the narrative research notes
  these tables were built from.
