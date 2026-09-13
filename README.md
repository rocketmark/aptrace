# APTrace

APTrace is a reusable firmware-analysis workbench for bare-metal Cortex-M
images. It combines static analysis, concrete execution, symbolic reasoning,
and repeatable evidence capture without trying to replace the specialist tools
that provide those capabilities.

The repository has two deliberately separate layers:

- **Framework and tooling** live at the repository root: the Haskell library
  and CLI, generic Ghidra and Unicorn backends, Macaw discovery, symbolic
  execution, and census machinery.
- **Analysis cases** live under [`cases/`](cases/). A case owns its firmware,
  target geometry, scenarios, research evidence, findings, and investigation
  status.

The current case is the
[`Performing Rigs AutoPilot / Remote investigation`](cases/performing-rigs/README.md).
It is a consumer of APTrace, not the definition of APTrace.

## Capabilities

- Raw Cortex-M firmware loading and vector-table discovery.
- Ghidra project creation, decompilation, cross-reference, and export tooling.
- Macaw-based independent CFG discovery and Thumb lifting.
- Unicorn-based concrete execution and state capture.
- Crucible, What4, and Z3 integration for bounded symbolic questions.
- A mechanical static/dynamic census and evidence database.

See [`docs/architecture.md`](docs/architecture.md) for how the pieces fit
together and [`docs/status.md`](docs/status.md) for current framework
capabilities and limitations.

## Repository layout

```text
aptrace/
├── app/                         generic APTrace CLI entry point
├── src/APTrace/                 reusable Haskell framework modules
├── tools/                       reusable analysis backends and utilities
├── docs/                        framework architecture and methodology
├── test/                        framework tests
└── cases/performing-rigs/       one concrete reverse-engineering case
```

The framework/case rule is simple: the engine belongs to APTrace; target
recipes and findings belong to the case. See
[`docs/adding-a-case.md`](docs/adding-a-case.md) for the repository contract.

## Quick start

The core Haskell package is built with Cabal:

```sh
cd external/macaw
git submodule update --init
cd ../..
cabal build aptrace
```

Python backend checks and the repository diagnostic are available with:

```sh
python3 tools/ghidra/test_aptrace_ghidra.py
tools/unicorn/.venv/bin/python3 tools/unicorn/test_concrete.py
tools/doctor.sh
```

Environment setup and pinned dependencies are documented in
[`docs/toolchain.md`](docs/toolchain.md). Case-specific commands, firmware
placement, and research entry points are documented by each case.

## Documentation

- [`docs/README.md`](docs/README.md) — framework documentation index.
- [`docs/status.md`](docs/status.md) — APTrace capability status.
- [`cases/performing-rigs/README.md`](cases/performing-rigs/README.md) — case
  entry point.
- [`cases/performing-rigs/status.md`](cases/performing-rigs/status.md) — current
  Performing Rigs findings and open questions.
