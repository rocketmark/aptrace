# APTrace

APTrace is a firmware reverse-engineering workbench for analyzing and
testing bare-metal Cortex-M embedded firmware, using static analysis,
concrete execution, symbolic reasoning, and repeatable protocol/hardware-
behavior fixtures. Its initial target is the bidirectional RF command
protocol between a Performing Rigs **AutoPilot** motion-control unit and
its **Remote** control (Microchip **ATSAMD51J19A** / Cortex-M4F), reverse-
engineered from raw firmware images alone, but the design is meant to
generalize to other Cortex-M firmware.

The goal throughout is evidence over inspection: claims are backed by an
actual execution or solver result, not just "I read the disassembly and
this looks right."

## What it does

APTrace is a workbench that orchestrates several purpose-built tools
rather than reimplementing what they already do well:

- **Ghidra** — static RE: decompilation, cross-references, structure/table
  recovery, MMIO/global naming.
- **Unicorn** — cheap, fast concrete Cortex-M/Thumb execution and
  memory-state snapshotting.
- **Macaw** — independent control-flow recovery and Thumb-2 lifting
  (ground truth that doesn't depend on a decompiler's heuristics).
- **Crucible + What4 + Z3** — targeted symbolic reachability and
  input-solving, once the question and code region are already understood.

On top of these, APTrace supports protocol reconstruction (request/response
wire transactions), persistence analysis (flash-backed config round trips),
MMIO/timer/GPIO hardware provenance, and cross-firmware **virtual-link**
testing — running both the AutoPilot's and Remote's real, unmodified code
against each other with no radio hardware modeled.

## Evidence model

Every finding is graded by how it was established, weakest to strongest:

1. **Static** — read from disassembly/decompilation, no execution.
2. **Concrete** — actually run (Unicorn) for one specific input/state.
3. **Solver-confirmed** — a Crucible/What4/Z3 query where the solver
   *derived* the value(s), proving a property over the symbolic input
   space, not just one chosen input.

Findings also disclose **harness assumptions** (a fabricated register/MMIO
value standing in for real hardware, e.g. an unmodeled radio chip's
response) as distinct from firmware-produced state. See
[`docs/tooling/tool-selection.md`](docs/tooling/tool-selection.md) for the
full guidance, worked examples, and when to reach for which tool.

## Repository layout

```
aptrace/
  README.md                 -- this file
  CLAUDE.md                  -- mandatory operating rules for Claude Code sessions
  docs/                      -- current, authoritative documentation (see below)
  aptrace.cabal               -- the APTrace library + CLI, as a local cabal package
  src/APTrace/                -- VectorTable, FirmwareLoader, SymbolicRunner, ProtocolHarness
  app/Main.hs                 -- CLI entry point
  tools/
    doctor.sh                 -- verifies Ghidra/Unicorn/Macaw-Crucible-What4-Z3 are usable
    ghidra/                    -- persistent-project Ghidra query interface (aptrace_ghidra.py)
    unicorn/                   -- concrete-execution backend (ConcreteMachine, virtual_link.py)
    svd/                       -- ATSAMD51J19A SVD file + MMIO address resolver
  external/macaw/              -- GaloisInc/macaw + crucible/what4/dismantle/asl-translator submodules
  research/
    firmware/originals/            -- working copies of the AutoPilot/Remote firmware images + hashes
    autopilot_static_inventory/    -- raw/derived static RE artifacts
    runs/                           -- saved tool output (Ghidra project cache, etc.), gitignored
```

Original firmware images live untouched in `Autopilot_firm/` at the repo
root (not under `research/`). Proprietary firmware binaries are not
intended to be published outside this local checkout.

## Quick start

Verified on macOS (Apple Silicon); full detail in
[`docs/toolchain.md`](docs/toolchain.md).

```sh
# Ghidra (static RE)
brew install ghidra   # pinned at 12.1.3 as of this writing

# Unicorn (concrete execution) -- project-local pinned venv
python3 -m venv tools/unicorn/.venv
tools/unicorn/.venv/bin/pip install -r tools/unicorn/requirements.txt

# Macaw/Crucible/What4/Z3 (symbolic execution)
brew install z3
sh <(curl --proto '=https' --tlsv1.2 -sSf https://get-ghcup.haskell.org)   # GHC 9.6.7 + cabal
cd external/macaw && git submodule update --init
ln -sf cabal.project.freeze.ghc-9.6.7 cabal.project.freeze
cabal build aptrace   # ~15-20 min the first time

# Verify everything is usable (does not itself run the cabal build)
tools/doctor.sh
```

## Common workflows

**Persistent Ghidra query** (imports/analyzes once, then answers repeated
queries in ~seconds, no re-analysis):

```sh
tools/ghidra/aptrace_ghidra.py build      autopilot868
tools/ghidra/aptrace_ghidra.py decompile  autopilot868 0x8258
tools/ghidra/aptrace_ghidra.py callers    autopilot868 0x6fd8
```

**Concrete protocol scenario** (both firmwares' real code, no radio
modeled):

```sh
tools/unicorn/.venv/bin/python3 tools/unicorn/virtual_link.py          # all transactions
tools/unicorn/.venv/bin/python3 tools/unicorn/virtual_link.py g        # G -> # only
```

**Test suites**:

```sh
tools/doctor.sh                              # Ghidra/Unicorn/Macaw-Crucible-What4-Z3 usable
tools/unicorn/.venv/bin/python3 tools/unicorn/test_concrete.py
python3 tools/ghidra/test_aptrace_ghidra.py
```

## Documentation

Start at [`docs/project-status.md`](docs/project-status.md) —
**authoritative current state.** [`docs/README.md`](docs/README.md) is the
full documentation index (system reference, protocol, tooling,
investigations).

## Current status

See [`docs/project-status.md`](docs/project-status.md) for the
authoritative current state and
[`docs/harness/roadmap.md`](docs/harness/roadmap.md) for active research
priorities.
