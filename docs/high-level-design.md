# APTrace — High-Level Design (skeleton)

**Status: skeleton.** Written by `/map-codebase` (brownfield bootstrap) on
2026-10-16 from HEAD `a6395d7`.
- *What this is:* a navigation index only.
- *What this is not:* an approved architecture. It will stay a skeleton until
  the consolidated mapping audit has been reviewed:
  - `docs/arrows/mapping-report.md`;
  - `docs/arrows/cross-segment-findings.md`.
- *Conflicts:* conflicting semantics across segments are recorded, not
  reconciled. No implementation was chosen as authoritative.

## Purpose (from CLAUDE.md, approved intent)

APTrace is a reusable, autonomous, evidence-driven firmware investigation
platform. It:
- orchestrates mature analysis engines;
- normalizes what they produce into evidence with provenance;
- decides mechanically which conclusions that evidence supports.

AutoPilot (the Performing Rigs case) is its first research case, not its
architectural target.

## Segment tree (lens: evidence pipeline)

| Group | Leaves | Sub-HLD |
|---|---|---|
| production | target-loading, structural-discovery, census, static-dataflow, symbolic-execution, concrete-execution | `docs/intent/production/production-design.md` (skeleton) |
| (root) | evidence-record | none (leaf LLD: `docs/intent/evidence-record/evidence-record-design.md`) |
| claims | claim-semantics, admission, verification, audit | `docs/intent/claims/claims-design.md` (skeleton) |
| investigation | controller, continuity, work | `docs/intent/investigation/investigation-design.md` (skeleton) |

The overlay with dependencies, status and drift is in
`docs/arrows/index.yaml`. Each leaf has three documents:
- an arrow doc: `docs/arrows/<path>.md`;
- an LLD: `docs/intent/<path>/<leaf>-design.md`;
- EARS specs: `docs/intent/<path>/<leaf>-specs.md`.

## Pending (after audit review)

- Architecture narrative, invariants and cross-cutting decisions.
- Resolution of the decision areas listed in `docs/arrows/mapping-report.md`
  §5 and §7.
