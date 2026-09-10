# APTrace — Project Status

**This is the single authoritative source for current project state.** If
anything elsewhere in the repo conflicts with this document, this document
wins — and if you find such a conflict, it's a bug in the docs; fix it
here. This file describes *current truth only*: what's proven, what's
open, what's next. Chronological narrative belongs in git history, not
here — do not append "previous update" logs to this file; when a slice of
work closes, fold its durable finding into the relevant section below (or
into a canonical dossier under `docs/investigations/`) and move on.

## What APTrace can do now

APTrace orchestrates four specialist tools against real, unmodified
AutoPilot/Remote (`mando`) firmware (ATSAMD51J19A, Cortex-M4F) rather than
reimplementing any of them — see [`docs/architecture.md`](architecture.md)
and [`docs/tooling/tool-selection.md`](tooling/tool-selection.md) for when
to reach for which:

| Tool | Role | Status |
|---|---|---|
| Ghidra | static RE, decompile, xrefs, tables, MMIO naming | Integrated — [`docs/tooling/ghidra-backend.md`](tooling/ghidra-backend.md) |
| Unicorn | concrete Thumb-2 execution, state capture | Integrated — [`docs/tooling/unicorn-backend.md`](tooling/unicorn-backend.md) |
| Macaw | independent CFG discovery / ARM/Thumb lifting | In use, proven |
| Crucible + What4 + Z3 | targeted symbolic reachability / input solving | In use, proven |

Demonstrated, reusable capabilities: a persistent per-firmware Ghidra
project (build once, query many times without re-analysis); a reusable
`ConcreteMachine` class with a real ARM-AAPCS direct-function-call helper
(`--call`/`--arg`), structured never-discarded failure snapshots, an
always-on bounded PC trace (`--trace-last`), and explicit state
carry-forward between runs (`RunResult.carry`); harness capabilities for
disclosed hardware/timing assumptions (`--fake-tick`, `--mmio-force-bits`/
`--mmio-clear-bits`, `--force-reg`, `--force-mem`, `--watch-mem-write`,
`--log-mmio`), each scoped and justified individually, never a general
peripheral model; a harness-driven virtual RF link
(`tools/unicorn/virtual_link.py`) connecting both firmwares' real TX/RX
paths with no radio hardware modeled; and `aptrace census`
(`tools/census/`, see [`docs/tooling/census.md`](tooling/census.md)) — a
fully mechanical, no-LLM-in-the-loop static+dynamic evidence database
(functions, basic blocks, CFG edges, RAM/MMIO accesses, vectors, pins,
Unicorn dynamic coverage) built and run against all four known firmware
images, with a deterministic query CLI and closure/warning report.
Semantic classification of the residual (uncovered functions, unresolved
indirect edges, etc.) is a later, separate phase, not yet started.

## Current milestone: the core protocol pipeline

**Status: CLOSED at the concrete (Unicorn) evidence tier**, both firmwares,
for three transactions: `&|` → `V01R39`, `G` → `#`, `S` → `P...`. Every
stage — real dispatcher, real event scheduling, real TX/RX — has been
independently demonstrated against unmodified firmware, entering at real
call sites with the firmware establishing its own state. See
[`docs/investigations/protocol-pipeline.md`](investigations/protocol-pipeline.md)
for the full evidence chain, the real dispatcher structure, and a real
tooling limitation found and explained along the way (a whole-function
Crucible replay of the dispatcher can't fold a readonly-flash-derived
branch — a harness limitation, not a firmware bug; deliberately left
unfixed since no current use case needs it).

**Not yet done**: `!`/`I` were never exercised through the virtual link —
paused deliberately to pivot toward hardware/behavior provenance (below),
not resumed since. A solver-confirmed (level-3) proof of the *whole*
dispatcher chain in one run remains blocked by the tooling limitation
above; individual pieces (e.g. the `&` character check) already have
independent level-3 confirmation.

## Major established system facts

- **Boot sequence, fully concretely reproducible**: `Reset_Handler` →
  clock/peripheral init → SERCOM/DMA driver construction → startup
  reference/input routine ("homing") → a real SPI radio-chip-ID probe
  (fails with no chip attached, taking a real infinite retry loop — not a
  timing gap) → a stable, repeating real main loop. See
  [`docs/investigations/boot-and-hardware-bringup.md`](investigations/boot-and-hardware-bringup.md)
  for the exact SVD-named completion bits modeled, the real Arduino-idiom
  function names (`main`/`setup`/`loop`), and the confirmed pin/peripheral
  map (TC0→PB10, TC1→PA08, TC2→PB12, TC3→PA10, TCC1→PB22).
- **The motor subsystem is unreachable from a cold boot without `MC4`**:
  the real main loop lives entirely inside the sketch's `setup()` and never
  returns until `MC4` clears one specific unlock byte. `MC<0-3>`/`G`/`I`
  and the AutoPilot's own boot-time `MT` Quick-Setup broadcast are all
  fully characterized, including a genuine, exhaustively-confirmed negative
  result (nothing in this firmware image ever sets one specific per-channel
  busy gate). See
  [`docs/investigations/motor-subsystem-unlock.md`](investigations/motor-subsystem-unlock.md).
- **Motor-target persistence (flash `0x12000`) is closed end to end**:
  command → dirty flag → save → real flash mutation → reboot recovery, all
  concretely demonstrated, including the real page-size register
  dependency that had to be resolved. The real protocol-native producer of
  nonzero target deltas is a previously-undocumented command, `'+'`. See
  [`docs/investigations/motor-config-persistence.md`](investigations/motor-config-persistence.md).
- **`'+'` and Auto Mode, traced end to end**: real Remote-side triggers and
  UI call sites found, with a load-bearing distinction preserved — the
  interactive Auto-Mode confirm screens are *not* the same event as the
  bulk config-push that actually arms a drivable target. A full concrete
  round trip (Remote `'+'` → AutoPilot persist → `G` → real move-commit)
  is demonstrated. See
  [`docs/investigations/auto-mode-and-plus-command.md`](investigations/auto-mode-and-plus-command.md).
- **Manual Mode's live jog is a previously-unknown binary frame family**
  (`0xF0`/`0xE0`), not any ASCII command — continuous, once per UI tick,
  not discrete. `LL1`/`LL2` ("Set Limits") are confirmed pure RAM
  bookkeeping with **no path to a real physical position anywhere in the
  firmware** — a negative result confirmed three independent ways. See
  [`docs/investigations/manual-mode-and-limits.md`](investigations/manual-mode-and-limits.md).
- **The 3.5mm trigger-input bug is fully characterized, on both of its two
  mutually-exclusive boot-time arms**: a digital arm (no debounce, no
  latch — a bouncy insertion can produce multiple accepted config-reloads)
  and a previously-unknown analog arm (boot-time-latched: a *post-boot*
  transient can't reach it, but a trigger chain already connected at
  power-up can influence the one boot-time sample that gets latched for
  the whole session). Neither arm can cause uncommanded motor motion. A
  software mitigation (consecutive-sample debounce) is designed and
  Unicorn-prototyped, but **not deployed to real firmware** — no verified
  flash code cave was found for a real trampoline. See
  [`docs/investigations/trigger-input.md`](investigations/trigger-input.md).
- **Physical hardware facts** (part numbers, board/bootloader mechanics,
  condensed manual summary): [`docs/hardware/hardware-reference.md`](hardware/hardware-reference.md).

## Current open questions

Full protocol-level list: [`docs/protocol/open-questions.md`](protocol/open-questions.md).
Headline items still unresolved:

- The real transport peripheral behind the TX path's `0x8c10` dispatch —
  named as "next" repeatedly, never actually identified.
- Dormant-event reachability (events 2, 3, 8, 9, 11, 12, 14) and the
  event-7 11-vs-10 field mismatch — both natural Crucible/What4 targets,
  neither attempted since the pivot to hardware provenance.
- Whether any Remote-transmitted packet exists outside the currently-known
  dispatch tree.
- The physical trigger-port electrical behavior (transient shape, bounce,
  minimum legitimate pulse width, real main-loop period) — needed before
  any trigger-input mitigation candidate can be called *correct* rather
  than merely *possible*. See `trigger-input.md`'s "Open / physical
  unknowns."
- A second, deeper NVM-erase-loop dependency found during hardware
  bring-up, reported but not chased (`boot-and-hardware-bringup.md`).

## Tooling limitations that still matter

- **Readonly flash vs. plain Crucible execution**: a whole-function
  symbolic replay through a literal-pool-derived branch doesn't fold
  correctly (solver assumptions ≠ concrete literals to a non-solver-
  mediated step). Deliberately unfixed; revisit only if a real symbolic
  use case needs a whole-function proof through such a branch — see
  [`docs/investigations/protocol-pipeline.md`](investigations/protocol-pipeline.md).
- **No real, verified flash code cave** has been found for a trigger-input
  mitigation trampoline; the most promising unexplored option is flash
  beyond the current image's end, within the part's real 512KB, not yet
  checked against a real device.
- **`GhidraSVD`** (the proper Ghidra SVD-loading extension) is still not
  installed — the standalone `tools/svd/resolve_mmio.py` resolver remains
  good enough for routine use; install only if that stops being true.

## Next priorities

1. Name the TX path's real transport peripheral (what populates the
   driver-object pointer `0x8c10` dispatches through).
2. Resume `!`/`I` through the virtual link, or explicitly re-scope them out.
3. Attempt dormant-event reachability and the event-7 field-mismatch
   question now that whole-function execution habits are better
   understood.
4. Get real physical measurements at the trigger jack/PB05 (see
   `trigger-input.md`) before choosing a debounce threshold or attempting
   a real flash patch.

Fuller, itemized unfinished-work tracking lives in
[`docs/harness/roadmap.md`](harness/roadmap.md) — not duplicated here.
