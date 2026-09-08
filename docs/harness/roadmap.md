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

### M1 — AutoPilot-only `&` transaction, end to end (current milestone)

Not yet complete. See [`docs/project-status.md`](../project-status.md) for
the exact blocker and next steps. In order:

1. Resolve the whole-function replay's non-termination — either implement
   lazy real-CFG execution for called functions (architecturally correct;
   see [`docs/harness/execution-model.md`](execution-model.md)), or find and
   validate a narrower fix specific to `0x5274`/`0x5448` once their real
   behavior is understood.
2. Confirm a real in-memory `&` packet, run through the *unmodified* whole
   dispatcher function, sets `pending[5]`.
3. Hook outbound transmission at `0x8c10`/`0x7f84` and verify the emitted
   bytes equal `V01R39`.

### M2 — Strengthen the AutoPilot-side evidence

Once M1 is done, before moving to the Remote firmware:

4. Independently verify `G`/`!`/`S`'s handlers perform their claimed
   event-scheduling writes (currently only handler-*entry* reachability is
   solver-verified for these three).
5. Attempt the reachability question for the "dormant" events (2, 3, 8, 9,
   11, 12, 14) per [`docs/protocol/open-questions.md`](../protocol/open-questions.md)
   #9 — a natural fit once whole-function execution of the relevant call
   graph is reliable.

### M3 — Remote (`mando`) firmware

**Do not start this until M1 is done** (explicit rule, repeated in
[`docs/project-status.md`](../project-status.md) because it has been
stated multiple times in this project's history and is easy to
accidentally skip ahead of).

Once unblocked:

6. Point APTrace's loader/discovery at `firmware_mando868.bin` — same
   mechanics as the AutoPilot image (see
   [`docs/firmware/firmware-layout.md`](../firmware/firmware-layout.md) for
   why the same flash-base/bootloader assumptions apply), but not yet
   attempted. Success criterion: clean discovery covering the Remote
   functions named in `research/autopilot_static_inventory/functions-of-interest.md`'s
   "Remote firmware" table (`0x58a8`, `0xb680`, `0xc440`, `0xba98`,
   `0x10cf4`, etc.).
7. Complete the `&|` -> `V01R39` transaction from the *Remote's* side:
   symbolically confirm the Remote's request-building and response-parsing
   code around `0xba98`.
8. Connect the two sides with an in-memory virtual RF queue (Remote TX hook
   feeds AutoPilot RX buffer and vice versa), so a single harness run
   exercises both firmwares against each other without modeling LoRa/SPI
   hardware.

### M4 — Broader protocol reachability

9. Resolve the Remote-transmitted-packets-not-in-dispatch-tree question
   (`docs/protocol/open-questions.md` #8) now that the real dispatch
   structure is better understood.
10. Resolve the event-7 11-vs-10 field mismatch by symbolically tracing the
    Remote's `0xc440` parser with the real 11-field output as input.

### M5+ — Tool-workbench integration

Deliberately deferred (see [`docs/project-status.md`](../project-status.md)'s
"explicit do-not-start-yet items") until M1-M2 are resolved or explicitly
deprioritized:

- Ghidra integration for static structure/table/MMIO naming.
- Unicorn integration for cheap concrete execution and state snapshotting
  (would directly help with the `0x5274`/`0x5448` memory-effect problem —
  concretely run them once, snapshot the RAM delta, and compare against
  what the opaque stub currently assumes).
