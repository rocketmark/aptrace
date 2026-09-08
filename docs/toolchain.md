# APTrace Toolchain — Build and Run

Exact environment/setup instructions, verified on macOS (Apple Silicon). No
Haskell toolchain needs to be pre-installed.

## 1. GHC + cabal via GHCup

```sh
export BOOTSTRAP_HASKELL_NONINTERACTIVE=1
export BOOTSTRAP_HASKELL_INSTALL_NO_STACK=1
export BOOTSTRAP_HASKELL_GHC_VERSION=9.6.7
export BOOTSTRAP_HASKELL_ADJUST_BASHRC=P
sh <(curl --proto '=https' --tlsv1.2 -sSf https://get-ghcup.haskell.org)
source ~/.ghcup/env
```

## 2. Z3 (the SMT solver used by `solve` and `protocol`)

```sh
brew install z3      # or any package manager; just needs to be on PATH
```

## 3. Macaw + its submodules

```sh
cd external/macaw
git submodule update --init
ln -sf cabal.project.freeze.ghc-9.6.7 cabal.project.freeze   # pin known-good dependency versions
```

`external/macaw/cabal.project` here is **not** the upstream symlink — it's a
small local file, not tracked by upstream:

```
import: cabal.project.dist
packages: ../../.
```

This adds this repo's `aptrace` package to macaw's own package set, so the
build reuses macaw's already-resolved/cached dependency tree instead of
duplicating it.

## 4. Build

```sh
cd external/macaw   # cabal.project lives here
cabal build aptrace
```

This targets just `aptrace` and its actual dependencies (macaw-aarch32,
macaw-symbolic, crucible, what4, ...) rather than `cabal build all`, which
would also build x86/PPC/RISC-V backends APTrace doesn't need.

The build takes roughly 15-20 minutes on a modern machine the first time
(most of it is `macaw-aarch32` and its ASL-derived semantics packages, plus
crucible/what4/dismantle/asl-translator); subsequent builds are incremental
and much faster.

## Usage

```sh
EXE=external/macaw/dist-newstyle/build/*/ghc-9.6.7/aptrace-0.1.0.0/x/aptrace/build/aptrace/aptrace

# Parse the vector table and run Macaw code discovery from every handler:
$EXE research/firmware/originals/firmware_autopilot868.bin 0x4000

# Symbolic-execution demonstration (IRQ10_Handler, real MMIO peripheral):
$EXE solve research/firmware/originals/firmware_autopilot868.bin

# Explore an arbitrary seeded entry point (investigation tool):
$EXE explore research/firmware/originals/firmware_autopilot868.bin 0x4000 0x8259

# Protocol-dispatcher symbolic checks (& / G / ! / S command bytes):
$EXE protocol research/firmware/originals/firmware_autopilot868.bin
```

The `0x4000` flash-base argument is the flash address that firmware byte 0
corresponds to (the AutoPilot images are application-only dumps, flashed
behind a 16KB bootloader at that offset — see
[`docs/firmware/firmware-layout.md`](firmware/firmware-layout.md)). It
defaults to `0x4000` when omitted.

A future CLI may grow into something like `aptrace scan` / `aptrace vectors`
/ `aptrace map` / `aptrace lift` / `aptrace solve` as separate, more general
subcommands; today's flat subcommand set (`aptrace [solve|explore|protocol]
FIRMWARE.bin [ARGS]`) is deliberately minimal for this phase.

## Standalone vector-table scanner

`tools/vector_scan.py` is a dependency-free Python prototype that scores
candidate vector-table offsets in a raw firmware image — used to validate
the firmware layout before any Haskell code was written, and useful on its
own for a quick look at a new image:

```sh
python3 tools/vector_scan.py FIRMWARE.bin --flash-base 0x4000 --ram-size 0x30000
```

## Known toolchain gaps

- No independent disassembler (arm-none-eabi-objdump / Capstone / Ghidra) is
  installed on the reference dev machine as of this writing — cross-
  validating Macaw's Thumb-2 decode against one of these remains an open
  item (not currently blocking; see
  [`docs/firmware/cortexm-assessment.md`](firmware/cortexm-assessment.md)).
- No Ghidra or Unicorn integration yet (planned; see
  [`docs/architecture.md`](architecture.md)).
