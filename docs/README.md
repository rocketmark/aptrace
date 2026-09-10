# APTrace Documentation

Start at [`project-status.md`](project-status.md) — it is the single
authoritative source of current project state (what's proven, what's
open, what's next) and wins over anything else here if they disagree.

## Current status

- [`project-status.md`](project-status.md) — current state, proven
  capabilities, open questions, tooling limitations, next priorities.
- [`harness/roadmap.md`](harness/roadmap.md) — unfinished work only.

## System reference

Describes current truth, not chronology:

- [`architecture.md`](architecture.md) — how APTrace orchestrates its
  specialist tools.
- [`firmware/firmware-inventory.md`](firmware/firmware-inventory.md),
  [`firmware/firmware-layout.md`](firmware/firmware-layout.md) — image
  hashes, memory layout, vector tables.
- [`hardware/hardware-reference.md`](hardware/hardware-reference.md) —
  physical board/MCU/connector facts and a condensed user-manual summary.
- [`ui/user-guide-workflows.md`](ui/user-guide-workflows.md),
  [`ui/action-command-map.md`](ui/action-command-map.md) — user-visible
  workflows and which protocol command implements which UI action.

## Protocol

- [`protocol/protocol-overview.md`](protocol/protocol-overview.md),
  [`protocol/bidirectional-protocol.md`](protocol/bidirectional-protocol.md) —
  the AutoPilot↔Remote RF protocol shape.
- [`protocol/command-inventory.md`](protocol/command-inventory.md) —
  every characterized command.
- [`protocol/event-map.md`](protocol/event-map.md) — the outbound
  pending-event table.
- [`protocol/open-questions.md`](protocol/open-questions.md) — protocol-
  level unknowns.

## Tooling

- [`tooling/tool-selection.md`](tooling/tool-selection.md) — which of
  Ghidra/Unicorn/Macaw/Crucible to reach for, and why (read before any
  firmware-analysis work — see [`../CLAUDE.md`](../CLAUDE.md)).
- [`tooling/ghidra-backend.md`](tooling/ghidra-backend.md),
  [`tooling/unicorn-backend.md`](tooling/unicorn-backend.md) — backend
  capabilities and CLI reference.
- [`harness/execution-model.md`](harness/execution-model.md),
  [`harness/protocol-harness-results.md`](harness/protocol-harness-results.md),
  [`harness/symbolic-execution-results.md`](harness/symbolic-execution-results.md) —
  harness internals and solver results.
- [`tooling/census.md`](tooling/census.md) — `aptrace census`, the
  mechanical firmware evidence database/closure report (`tools/census/`).
- [`toolchain.md`](toolchain.md) — build/toolchain setup.

## Investigations

Canonical topic dossiers under [`investigations/`](investigations/) — each
one is the final, current model plus evidence, test/repro scripts, and
open items for one area, not a chronological log:

- [`investigations/trigger-input.md`](investigations/trigger-input.md) —
  the 3.5mm trigger-input bug, both boot-time arms, mitigation design.
- [`investigations/protocol-pipeline.md`](investigations/protocol-pipeline.md) —
  the core dispatcher/TX/virtual-RF-link chain.
- [`investigations/motor-subsystem-unlock.md`](investigations/motor-subsystem-unlock.md) —
  cold-boot reachability, `MC4`/`MC`/`G`/`I`/`MT`.
- [`investigations/motor-config-persistence.md`](investigations/motor-config-persistence.md) —
  flash `0x12000` persistence round trip.
- [`investigations/auto-mode-and-plus-command.md`](investigations/auto-mode-and-plus-command.md) —
  `'+'` and Auto Mode.
- [`investigations/manual-mode-and-limits.md`](investigations/manual-mode-and-limits.md) —
  Manual Mode's binary jog frame, `LL1`/`LL2`.

**Documentation rule**: an investigation is a working notebook. When it
closes, fold the durable finding into the relevant dossier above (or start
a new one) and delete the slice file — git history is the archive, not a
second hand-maintained copy of it. See [`../CLAUDE.md`](../CLAUDE.md)'s
"Documentation discipline."
