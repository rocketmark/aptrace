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
- [`aptrace-agent-framework.md`](aptrace-agent-framework.md) — roadmap for the
  Galois-first binary map, local-model labeling, and investigation tooling.
- [`objective-bounded-investigation.md`](objective-bounded-investigation.md) —
  declared relations, operation relevance, progress tracking and the
  unresolved-relation report for focused research runs.
- [`terminal-review.md`](terminal-review.md) — the deterministic terminal
  assessment of every focused run, adversarial review by the review model,
  sequential oMLX model residency, review persistence and retry.
- [`critic-validation.md`](critic-validation.md) — deterministic validation
  of the reviewer's findings (supported, contradicted, unresolved,
  ungrounded), execution-state continuity, follow-up question proposals and
  review-package integrity.
- [`research-ledger.md`](research-ledger.md) — research ledger, adversarial
  audit, and deterministic verification.
- [`cross-engine-verification.md`](cross-engine-verification.md) — normative
  requirements for independent discovery, deterministic cross-engine
  comparison, discrepancy retention, and claim-class verification policy.
- [`work-store.md`](work-store.md) — optional Beads-backed investigation work
  items: hand-off to the ledger, reconciliation, ownership, backup.
- [`spikes/beads-work-store.md`](spikes/beads-work-store.md) — the spike that
  evaluated Beads as the work store (adopted with conditions).

## Tooling and methodology

- [`tooling/tool-selection.md`](tooling/tool-selection.md) — selecting Ghidra,
  Unicorn, Macaw, or symbolic execution for a question.
- [`tooling/ghidra-backend.md`](tooling/ghidra-backend.md) — persistent Ghidra
  project integration.
- [`tooling/pcode-forward-use.md`](tooling/pcode-forward-use.md) — forward use
  of a value over Ghidra p-code (`value_forward_use`).
- [`tooling/pcode-migration.md`](tooling/pcode-migration.md) — plan for
  retiring the Capstone-based census dataflow in favor of p-code.
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
