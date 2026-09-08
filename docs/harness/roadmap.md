# Harness Roadmap (current, authoritative)

This supersedes [`docs/history/protocol-harness-roadmap-v1.md`](../history/protocol-harness-roadmap-v1.md),
which was written before any symbolic execution had been attempted against
the real dispatcher and assumed a flat-chain model later found to be
incomplete (see
[`docs/investigations/parser-dispatch.md`](../investigations/parser-dispatch.md)).
For a blow-by-blow of what changed and why, see
[`docs/harness/protocol-harness-results.md`](protocol-harness-results.md).

For the fuller "APTrace as a workbench" direction this roadmap sits inside,
see [`docs/architecture.md`](../architecture.md).

## Milestone ordering (do not skip ahead)

### M1 — AutoPilot-only `&` transaction, end to end — **COMPLETE (concrete tier)**

Closed as of 2026-09-07, at the concrete (Unicorn) evidence tier — see
[`docs/project-status.md`](../project-status.md)'s "Current milestone" for
the full status and what remains at the solver-confirmed tier (a known,
deliberately unfixed tooling gap, not a blocker). What actually resolved
this, for the record (the three steps below as originally planned turned
out not to be the right order — the non-termination was a harness bug,
not something `0x5274`/`0x5448` needed a real-CFG fix for):

1. ~~Resolve the whole-function replay's non-termination~~ — root cause
   was a harness memory-model limitation (readonly flash populated via
   solver assumptions, not folded literals), not `0x5274`/`0x5448` or a
   missing lazy-real-CFG mechanism. See
   [`docs/investigations/whole-function-trace-divergence.md`](../investigations/whole-function-trace-divergence.md).
   Deliberately left unfixed (see `docs/project-status.md`'s "Tooling
   gaps") since the milestone closed without needing it.
2. ~~Confirm a real in-memory `&` packet, run through the *unmodified*
   whole dispatcher function, sets `pending[5]`~~ — done concretely via
   Unicorn. See
   [`docs/investigations/dispatcher-loop-concrete-trace.md`](../investigations/dispatcher-loop-concrete-trace.md).
3. ~~Hook outbound transmission at `0x8c10`/`0x7f84` and verify the emitted
   bytes equal `V01R39`~~ — done concretely via Unicorn. See
   [`docs/investigations/tx-hook-verification.md`](../investigations/tx-hook-verification.md).

### M2 — Strengthen the AutoPilot-side evidence

M1 is done; this is a smaller, parallel task, not a prerequisite for M3:

4. Independently verify `G`/`!`/`S`'s handlers perform their claimed
   event-scheduling writes (currently only handler-*entry* reachability is
   solver-verified for these three).
5. Attempt the reachability question for the "dormant" events (2, 3, 8, 9,
   11, 12, 14) per [`docs/protocol/open-questions.md`](../protocol/open-questions.md)
   #9 — a natural fit once whole-function execution of the relevant call
   graph is reliable.
6. **Ground firmware analysis in the confirmed ATSAMD51J19A hardware** —
   started: real peripheral/register naming
   (`tools/svd/resolve_mmio.py`), a confirmed startup peripheral survey,
   and one fully-resolved pin fact (PB22, from a real timer ISR). See
   [`docs/investigations/samd51-peripheral-mapping.md`](../investigations/samd51-peripheral-mapping.md)
   for what's done and its own "next logical slice" (the other three
   motor channels' pin/ISR pairs; naming the TX path's real transport
   peripheral).

### M3 — Remote (`mando`) firmware — **COMPLETE (concrete tier)**

M1 is done, so this began 2026-09-08 and closed the same day. See
[`docs/investigations/mando-first-execution.md`](../investigations/mando-first-execution.md)
and [`docs/investigations/virtual-rf-link.md`](../investigations/virtual-rf-link.md)
for the full result.

6. ~~Point APTrace's loader/discovery at `firmware_mando868.bin`~~ — done:
   clean discovery, 563 functions, every named Remote function of interest
   (`0x58a8`, `0xb440`, `0xb59c`, `0xb680`, `0xba98`, `0xc440`, `0xfa10`,
   `0xfadc`, `0x10cf4`) resolved at its documented address, zero
   platform-specific harness changes needed.
7. ~~Complete the `&|` -> `V01R39` transaction from the *Remote's* side~~
   — done at the **concrete (Unicorn)** evidence tier, both halves: real
   TX construction (`0xba98` calling the real TX wrapper with a real
   `"&|\0"` literal) and real RX capture (the real byte-collection loop
   copying the AutoPilot's already-proven response into `0x200002fc`).
   **Not** done at the solver-confirmed (Crucible) tier — deliberately,
   consistent with M1's own evidence-level discipline; revisit only if a
   real use case needs it.
8. ~~Connect the two sides with an in-memory virtual RF queue~~ — done:
   `tools/unicorn/virtual_link.py` runs the complete `&|` -> `V01R39`
   round trip as one harness-driven script, hooking each side's real
   TX-wrapper argument and seeding it into the other side's real RX state
   (AutoPilot: packet buffer `0x2000232a`; Remote: ring buffer
   `0x20001773` + write pointer `0x200017d8`) — no LoRa/SPI hardware
   modeled. Built as two reusable primitives (`capture_tx_bytes`,
   `deliver_and_observe`), not a transaction-specific script — see
   `virtual-rf-link.md` for the full design and what the harness still
   substitutes for real radio behavior.

### M4 — Broader protocol reachability

9. Exercise the next protocol transaction through the virtual link built
   in M3 — `G -> #` (`0xb680`/`0xb59c`, event 17) or `S -> P...`
   (`0xc440`, event 6), per
   `research/autopilot_static_inventory/protocol-bidirectional.md`. Same
   two primitives, new addresses; `G`'s Remote-side retry loop (`0xb59c`)
   may need its own `--stub-call` treatment, not yet confirmed. Not
   started.
10. Resolve the Remote-transmitted-packets-not-in-dispatch-tree question
    (`docs/protocol/open-questions.md` #8) now that the real dispatch
    structure is better understood.
11. Resolve the event-7 11-vs-10 field mismatch by symbolically tracing the
    Remote's `0xc440` parser with the real 11-field output as input.

### M5+ — Tool-workbench integration — **done**

Ghidra and Unicorn are both integrated (see
[`docs/tooling/ghidra-backend.md`](../tooling/ghidra-backend.md) and
[`docs/tooling/unicorn-backend.md`](../tooling/unicorn-backend.md)) and
were exactly what closed M1 above — not deferred any further. See
[`docs/tooling/tool-selection.md`](../tooling/tool-selection.md) for the
current, durable guidance on when to use which tool.
