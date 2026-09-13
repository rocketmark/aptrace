# Performing Rigs Case — Operating Rules for Claude Code

The root [`../../CLAUDE.md`](../../CLAUDE.md) rules also apply. These rules
govern work anywhere under this case.

## Case ownership

All concrete Performing Rigs, AutoPilot, Mando/Remote, firmware, hardware, PCB,
protocol, UI, motor, trigger, radio, address, hash, scenario, or experiment
material stays under `cases/performing-rigs/`.

- Put durable findings in the relevant `docs/` dossier.
- Put current investigation truth in `status.md` and unfinished priorities in
  `roadmap.md`.
- Put raw/derived evidence, firmware, provenance, generated artifacts, static
  inventories, and run output under `research/`.
- Put target geometry and registries in `config/`; case experiments and recipes
  in `scripts/`; Haskell case modules in `src/`; case tests in `test/`.
- Never add Performing Rigs findings to root `docs/` or recreate root
  `research/`.

The engine belongs to APTrace; the recipe belongs here. Move a mechanism to the
framework only when it is genuinely reusable without Performing Rigs identities
or assumptions.

## Evidence and documentation

Preserve the established evidence levels and do not strengthen conclusions
during organizational work. Disclose harness assumptions separately from
firmware-produced state. Keep provenance with moved artifacts.

An investigation dossier is a current technical record, not a session log.
When work closes, fold durable results into the appropriate dossier/status and
let git history preserve chronology.

Before analysis work, read [`status.md`](status.md), the relevant dossier, and
the framework's
[`tool-selection.md`](../../docs/tooling/tool-selection.md).
