# APTrace

APTrace is a bare-metal Cortex-M firmware analysis and symbolic execution tool
built around [Macaw](https://github.com/GaloisInc/macaw),
[Crucible](https://github.com/GaloisInc/crucible), and
[What4](https://github.com/GaloisInc/what4). Its initial target is firmware for
the AutoPilot motion-control system (Microchip ATSAMD51, Cortex-M4F), but the
architecture is meant to stay general enough for other Cortex-M firmware.

This is a feasibility spike, not a product: the goal is to reuse as much of the
Galois Macaw/Crucible/What4 stack as possible rather than writing a new symbolic
execution engine. See `research/notes/macaw-cortexm-assessment.md` for the
detailed assessment and `research/notes/symbolic-execution-results.md` for the
key end-to-end demonstration.

## Status

All nine "primary goal" milestones (raw firmware loading through a
solver-produced path model on a real memory-mapped peripheral) are demonstrated
on real, unmodified AutoPilot firmware. See `research/notes/progress.md` for the
full log.

A separate research track, `research/autopilot_static_inventory/`, has statically
mapped the bidirectional RF command protocol between the AutoPilot and Remote
firmware (parser dispatch, event system, several proven request/response
transactions). `research/notes/protocol-harness-roadmap.md` maps that inventory's
open questions onto APTrace's discovery/symbolic-execution capabilities as the
next phase of work — several of them (dormant pending events, unexplained
Remote-transmitted commands) are reachability questions APTrace can answer
directly rather than by further manual tracing.

## Repository layout

```
aptrace/
  README.md
  aptrace.cabal              -- the APTrace library + CLI, as a local cabal package
  src/APTrace/
    VectorTable.hs           -- ARMv7-M vector table parser
    FirmwareLoader.hs        -- raw firmware -> Macaw Memory (no ELF)
    SymbolicRunner.hs        -- one Macaw block -> Crucible -> What4/Z3
  app/Main.hs                -- CLI: `aptrace` (discover) and `aptrace solve` (symbolic demo)
  tools/vector_scan.py       -- standalone Python vector-table scanner/validator
  external/macaw/            -- GaloisInc/macaw, with crucible/what4/semmc/dismantle/
                                 asl-translator/arm-asl-parser as git submodules;
                                 see external/macaw/cabal.project (local, not upstream)
  research/
    firmware/originals/      -- copies of the AutoPilot/Mando firmware images + SHA256SUMS.txt
    autopilot_static_inventory/  -- separate research track: static RF protocol reverse-engineering
    notes/
      progress.md                        -- chronological log: commands, findings, decisions
      firmware-layout.md                 -- MCU ID, vector table, memory map
      macaw-cortexm-assessment.md        -- can Macaw's AArch32 backend handle Cortex-M?
      symbolic-execution-results.md      -- the Steps 7-9 demonstration, in detail
      protocol-harness-roadmap.md        -- next phase: apply APTrace to the protocol inventory
      runs/                              -- saved tool output from real runs
```

Original firmware images live untouched in `Autopilot_firm/` at the repo root
(not under `research/`); `research/firmware/originals/` holds working copies plus
recorded hashes. Proprietary firmware binaries are not intended to be published
outside this local checkout.

## Environment setup

No Haskell toolchain is required to be pre-installed; here's exactly what this
project was built and run with (macOS, Apple Silicon):

```sh
# 1. GHC + cabal via GHCup
export BOOTSTRAP_HASKELL_NONINTERACTIVE=1
export BOOTSTRAP_HASKELL_INSTALL_NO_STACK=1
export BOOTSTRAP_HASKELL_GHC_VERSION=9.6.7
export BOOTSTRAP_HASKELL_ADJUST_BASHRC=P
sh <(curl --proto '=https' --tlsv1.2 -sSf https://get-ghcup.haskell.org)
source ~/.ghcup/env

# 2. Z3 (the SMT solver used by the `solve` subcommand)
brew install z3      # or any package manager; just needs to be on PATH

# 3. Macaw + its submodules (crucible, what4, semmc, dismantle, asl-translator, arm-asl-parser)
cd external/macaw
git submodule update --init
ln -sf cabal.project.freeze.ghc-9.6.7 cabal.project.freeze   # pin known-good dependency versions
# cabal.project here is NOT the upstream symlink -- it's a small local file:
#   import: cabal.project.dist
#   packages: ../../.
# which adds this repo's `aptrace` package to macaw's own package set, so the
# build reuses macaw's already-resolved/cached dependency tree.

# 4. Build (targeted -- this skips x86/PPC/RISC-V, which aptrace doesn't need)
cabal build aptrace
```

The build takes roughly 15-20 minutes on a modern machine the first time (most of
it is `macaw-aarch32` and its ASL-derived semantics packages); subsequent builds
are incremental.

## Usage

```sh
EXE=external/macaw/dist-newstyle/build/*/ghc-9.6.7/aptrace-0.1.0.0/x/aptrace/build/aptrace/aptrace

# Parse the vector table and run Macaw code discovery from every handler:
$EXE research/firmware/originals/firmware_autopilot868.bin 0x4000

# Run the Steps 7-9 symbolic-execution demonstration (hardcoded to IRQ10_Handler
# in the AutoPilot firmware family -- see research/notes/symbolic-execution-results.md):
$EXE solve research/firmware/originals/firmware_autopilot868.bin
```

The `0x4000` argument is the flash address that firmware byte 0 corresponds to
(the AutoPilot images are application-only dumps, flashed behind a 16KB
bootloader at that offset — see `research/notes/firmware-layout.md`). It defaults
to `0x4000` if omitted.

A future CLI may grow into something like `aptrace scan` / `aptrace vectors` /
`aptrace map` / `aptrace lift` / `aptrace solve` as separate, more general
subcommands; today's `aptrace [solve] FIRMWARE.bin [FLASH_BASE]` is deliberately
minimal, matching the project's "don't over-design the CLI yet" guidance for this
phase.

## Standalone vector-table scanner

`tools/vector_scan.py` is a dependency-free Python prototype that scores
candidate vector-table offsets in a raw firmware image (used to validate the
firmware layout before any Haskell code was written):

```sh
python3 tools/vector_scan.py FIRMWARE.bin --flash-base 0x4000 --ram-size 0x30000
```
