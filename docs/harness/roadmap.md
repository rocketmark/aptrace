# Harness Roadmap

Current, unfinished work only. For what's already proven and how the
system got here, see [`docs/project-status.md`](../project-status.md)
(authoritative) and the relevant `docs/investigations/*.md` dossier —
completed milestones are not re-narrated here.

## Done (summary only)

- **M1 — AutoPilot-only `&` transaction, end to end.** Closed at the
  concrete tier.
- **M3 — Remote (`mando`) firmware brought up, virtual RF link built.**
  Closed at the concrete tier; `capture_tx_bytes`/`deliver_and_observe`
  are the reusable primitives.
- **M4 (partial) — `G → #` and `S → P...` transactions.** Both closed at
  the concrete tier through the same virtual link.
- **M5 — Tool-workbench integration (Ghidra, Unicorn).** Done; see
  [`docs/tooling/tool-selection.md`](../tooling/tool-selection.md).
- **M6 — Behavior-to-hardware provenance.** The full pivot from protocol
  mapping to physical hardware is done: boot sequence, motor-subsystem
  unlock, motor-config persistence, `'+'`/Auto Mode, Manual Mode/limits,
  and the trigger-input investigation are all closed — see
  [`docs/project-status.md`](../project-status.md#major-established-system-facts)
  for the current-state summary and links to each dossier.

See [`docs/harness/protocol-harness-results.md`](protocol-harness-results.md)
and [`docs/harness/execution-model.md`](execution-model.md) for the harness
mechanics (calling convention, tracing, memory model) established along
the way.

## Open — protocol pipeline

1. **Exercise `!`/`I` through the virtual link.** Deliberately paused
   after `S → P...` closed, to pivot toward hardware provenance (M6).
   Never resumed. `!` currently has only solver-confirmed entry
   *reachability*, not a confirmed event-scheduling write; `I`'s dynamic,
   per-channel state was never run through `virtual_link.py`.
2. **Dormant-event reachability** (events 2, 3, 8, 9, 11, 12, 14) — per
   [`docs/protocol/open-questions.md`](../protocol/open-questions.md), a
   natural Crucible/What4 target now that whole-function execution habits
   are better understood (see the readonly-flash caveat in
   [`docs/investigations/protocol-pipeline.md`](../investigations/protocol-pipeline.md)
   before attempting a whole-function run).
3. **Event-7's 11-vs-10 field mismatch** — trace the Remote's `0xc440`
   parser with the AutoPilot's real 11-field output as input to see
   concretely what happens to the unconsumed field.
4. **Remote-transmitted-packets-not-in-the-dispatch-tree question** — not
   revisited since the dispatch structure was corrected.
5. **Name the TX path's real transport peripheral** — what populates the
   driver-object pointer `0x8c10` dispatches through. Named as a next step
   repeatedly across multiple slices; never actually identified. Check
   first whether it's the same SERCOM/DMA driver object already
   constructed and probed in
   [`docs/investigations/boot-and-hardware-bringup.md`](../investigations/boot-and-hardware-bringup.md).

## Open — trigger-input mitigation

A software mitigation (consecutive-sample debounce on the digital arm) is
designed and Unicorn-prototyped in
[`docs/investigations/trigger-input.md`](../investigations/trigger-input.md),
but nothing has been flashed to real hardware. Before any patch is real:

6. **Get physical measurements** at the trigger jack and at PB05:
   transient polarity/duration/bounce count, whether the line floats when
   disconnected, and whether the MCU-side waveform matches the jack-side
   waveform. Also measure the real main-loop period (to convert a
   poll-count debounce threshold into real time) and the minimum
   legitimate trigger pulse width.
7. **Find a verified, real flash code cave** for the mitigation trampoline
   — the current design uses a harness-only scratch page. The most
   promising unexplored option is flash beyond the current image's end,
   within the part's real 512KB; this needs either a real device flash
   dump or vendor/BOSSA documentation review, not assumed blank.
8. Once (6) and (7) are done: pick a real debounce threshold, build a real
   flashable patch, and validate it against a real device — none of this
   has been attempted yet.

## Open — hardware-bringup loose ends

9. **A second, deeper NVM-erase-loop dependency**, found while reaching
   the stable main loop, was reported but not chased (likely gated on a
   zero-valued config field rather than a documented status bit) — see
   [`docs/investigations/boot-and-hardware-bringup.md`](../investigations/boot-and-hardware-bringup.md).
10. **`'+'`'s own dispatch is still not reachable from a genuinely fresh
    boot** in a single concrete run — blocked by a real, finite (not
    looping) SERCOM device-probe cost the project's boot-recipe
    calibration doesn't yet budget for. See
    [`docs/investigations/auto-mode-and-plus-command.md`](../investigations/auto-mode-and-plus-command.md).

## Tooling gaps (not firmware blockers)

- **Readonly flash vs. plain Crucible execution**: a whole-function
  symbolic replay through a literal-pool-derived branch doesn't fold
  correctly. Root-caused, deliberately left unfixed — see
  [`docs/investigations/protocol-pipeline.md`](../investigations/protocol-pipeline.md).
  Revisit only if a real symbolic use case needs a whole-function proof
  through such a branch; the narrow fix (baking the specific literal-pool
  words that target reads) is the smallest starting point.
- **`GhidraSVD`** is still not installed as a proper extension; the
  standalone `tools/svd/resolve_mmio.py` resolver remains good enough for
  routine use — install only if that changes.

## Adding new work here

When a numbered item above closes, delete it (or fold a one-line summary
into "Done") rather than leaving a struck-through record — git history is
the record of how it closed. Add new items only for work that is
genuinely not started or not finished; do not use this file to narrate
progress on an item that's already in flight (that belongs in the
relevant investigation's own working notes until it closes).
