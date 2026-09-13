# APTrace Framework Documentation

This tree documents reusable APTrace architecture, tooling, methodology, and
development. Concrete target findings and evidence belong to a case under
[`../cases/`](../cases/).

## Start here

- [`architecture.md`](architecture.md) — framework components and dependency
  direction.
- [`status.md`](status.md) — implemented framework capabilities and known
  limitations.
- [`adding-a-case.md`](adding-a-case.md) — how a target case consumes APTrace
  without leaking into framework areas.
- [`case-boundary.md`](case-boundary.md) — intentional single-case integration
  seams and deferred extraction work.
- [`toolchain.md`](toolchain.md) — build and development environment.

## Tooling and methodology

- [`tooling/tool-selection.md`](tooling/tool-selection.md) — selecting Ghidra,
  Unicorn, Macaw, or symbolic execution for a question.
- [`tooling/ghidra-backend.md`](tooling/ghidra-backend.md) — persistent Ghidra
  project integration.
- [`tooling/unicorn-backend.md`](tooling/unicorn-backend.md) — reusable concrete
  execution backend.
- [`tooling/macaw-analysis.md`](tooling/macaw-analysis.md) — Macaw discovery,
  normalization, and comparison.
- [`tooling/census.md`](tooling/census.md) — mechanical evidence database and
  reduction pipeline.
- [`tooling/compact-ram-initialization.md`](tooling/compact-ram-initialization.md)
  — scalable symbolic RAM initialization.
- [`harness/execution-model.md`](harness/execution-model.md) — reusable
  Crucible/What4/Z3 harness model.

## Cases

- [`Performing Rigs`](../cases/performing-rigs/README.md) — AutoPilot and Remote
  firmware/hardware reverse engineering. Its documentation, status, roadmap,
  experiments, and evidence are all owned by the case.
