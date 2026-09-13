# Performing Rigs Case

This case reverse-engineers the Performing Rigs AutoPilot motion-control unit
and its handheld Remote (called Mando in firmware artifacts). The known images
target the Microchip ATSAMD51J19A/Cortex-M4F and include 868 MHz and 915 MHz
AutoPilot and Remote variants.

APTrace is the reusable framework used by the investigation. Everything in this
directory is case-owned: firmware and hardware facts, target geometry, protocol
and UI findings, scenarios, experiments, provenance, generated evidence, and
case status.

## Start here

- [`status.md`](status.md) — authoritative current findings and unresolved
  Performing Rigs questions.
- [`roadmap.md`](roadmap.md) — unfinished case work.
- [`docs/firmware/firmware-inventory.md`](docs/firmware/firmware-inventory.md)
  — image identities, hashes, and provenance.
- [`docs/hardware/hardware-reference.md`](docs/hardware/hardware-reference.md)
  — boards, MCU, connectors, and physical findings.
- [`docs/protocol/protocol-overview.md`](docs/protocol/protocol-overview.md) —
  protocol orientation.
- [`docs/investigations/`](docs/investigations/) — current evidence dossiers.
- [`research/`](research/) — raw, derived, generated, and run evidence.

Framework architecture and tooling documentation remain at
[`../../docs/README.md`](../../docs/README.md).

## Firmware and evidence

Canonical working copies and hashes live under `research/firmware/originals/`.
The preserved vendor update package is under
`research/firmware/vendor-package/`. Proprietary binaries, vendor tools, board
photos, Ghidra caches, and census databases are intentionally untracked; their
tracked hashes, provenance, and reproducible outputs remain beside them.

## Case code and scripts

Case-specific Haskell modules, configuration, scenarios, scripts, and tests live
under this directory. They call reusable engines at the repository root. Run
commands from the repository root unless a document says otherwise.

Read [`CLAUDE.md`](CLAUDE.md) before adding findings or experiments.
