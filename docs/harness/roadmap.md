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

9. ~~Exercise the next protocol transaction through the virtual link
   built in M3~~ — `G -> #` done (`tools/unicorn/virtual_link.py g`):
   Remote's real `0xb680`/`0xb59c` request+retry, AutoPilot's real `G`
   handler concretely scheduling event 17 (not just solver-confirmed
   reachability), AutoPilot's real `0x7f84` single-byte response, and
   Remote's real `0xb59c` accepting the ack — all at the concrete tier.
   Confirmed the M3 primitives generalize (needed register seeding and a
   new byte-value TX-capture primitive, both now reusable). See
   [`docs/investigations/g-ack-roundtrip.md`](../investigations/g-ack-roundtrip.md).
   Then `S -> P...` also done (`tools/unicorn/virtual_link.py s`): both
   the short (`"P1,"`) and extended (`"P11,0,0,"`) response forms
   exercised concretely, AutoPilot's event-6 scheduling and field
   computation confirmed in one pass, and a real "don't downgrade" guard
   in the Remote's parser found by running it (a fresh device receiving
   `"P1,"` does not update its stored state). No new harness capability
   needed. See
   [`docs/investigations/s-p-roundtrip.md`](../investigations/s-p-roundtrip.md).
   **Deliberate pause here, per the task that closed `S -> P...`**: not
   continuing into `!`/`I` yet — pivoting to hardware provenance instead
   (see M6 below). `!`/`I` remain queued for whenever protocol-transaction
   work resumes.
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

### M6 — Behavior-to-hardware provenance (new, 2026-09-08)

A deliberate pivot from protocol mapping toward physical hardware:
`command/state -> internal variable/function -> timer/MMIO -> ISR/GPIO ->
MCU pin -> physical hardware behavior`. Not a replacement for M4's
remaining items — a parallel track, per
[`docs/investigations/s-p-roundtrip.md`](../investigations/s-p-roundtrip.md)'s
closing recommendation.

12. ~~Find TC0/TC1/TC2's ISR/pin pairs~~ — done: TC0-TC3 are IRQ107-110
    (`0x607c`/`0x6098`/`0x60b4`/`0x60d0`), each clearing its own MC0+OVF
    flags then reaching a shared, table-indexed GPIO-pulse helper
    (`FUN_00005898`/`FUN_0000d388`) rather than TCC1's inline toggle — a
    confirmed *mechanism*, concretely exercised on all four channels via
    `--log-mmio`, but the real per-channel pin assignment depends on a
    RAM index byte this pass found no static producer for (cold RAM
    gives the same pin for all four, an artifact, not a hardware fact).
    Also found, falling out naturally: `FUN_00005c00`/`FUN_00006260`
    write/read each TC's `CC0` (period) — the rate-control mechanism. See
    [`docs/investigations/motor-timer-survey.md`](../investigations/motor-timer-survey.md).
13. Connect `I<channel><mode>|`'s already-mapped protocol-level state
    machine (`u8[0x20001b14[channel]]`/`u8[0x200029d8[channel]]`/
    `i32[0x20002064[channel]]`, per
    `research/autopilot_static_inventory/synchronous-responses.md`) to
    the timer/pin chain (12) found — `i32[0x20002064[channel]]` is
    already confirmed to be the exact same step-position counter
    `FUN_00005898` increments, a real link found in (12), not yet
    exploited. The concrete next step per `motor-timer-survey.md`: find
    what writes the per-channel pin-index RAM bytes
    (`0x20000164`-`0x20000167`), the one gap blocking a fully confirmed
    per-channel pin. Not started.
