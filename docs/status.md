# APTrace Framework Status

This document answers: **what can APTrace itself currently do?** It does not
track conclusions or open questions for any particular firmware target. Those
belong in each case's status document.

## Available capabilities

- Load raw Cortex-M firmware at a caller-supplied flash/RAM geometry and parse
  its vector table.
- Discover and normalize machine-code control flow with Macaw, including an
  APTrace semantic classification layer for ambiguous control transfers.
- Build persistent headless Ghidra projects and query disassembly,
  decompilation, references, and exported static-analysis data.
- Execute Thumb firmware concretely with Unicorn using explicit memory maps,
  hooks, state carry-forward, bounded traces, and structured failure snapshots.
- Translate bounded Macaw regions into Crucible and ask What4/Z3 reachability
  and input-model questions.
- Combine static and dynamic evidence in the census database, including CFG,
  RAM/MMIO, vector, coverage, fingerprint, reduction, and comparison data.

## Current limitations

- Cortex-M exception delivery and peripherals are modeled only through narrow,
  explicit harness mechanisms; APTrace is not a general MCU simulator.
- Function and CFG discovery remain heuristic and require cross-checking when a
  boundary is material to a conclusion.
- Symbolic execution works best for targeted, already-understood regions; whole
  firmware replay is neither its purpose nor a supported workflow.
- Case selection is currently wired explicitly by the application and some
  scripts. A plugin/provider architecture is intentionally deferred until more
  than one real case demonstrates the need.

The exact remaining integration seams and their rationale are tracked in
[`case-boundary.md`](case-boundary.md).

## Capability status versus case status

Framework implementation work is recorded here. Investigation progress,
firmware-specific blockers, addresses, hashes, and behavioral conclusions are
recorded under the applicable case—for example
[`cases/performing-rigs/status.md`](../cases/performing-rigs/status.md).
