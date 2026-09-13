# APTrace Toolchain

APTrace uses GHC/Cabal for its Haskell library and CLI, Python for backend
orchestration, Ghidra for static analysis, Unicorn for concrete execution, and
Z3 with Macaw/Crucible/What4 for symbolic work.

## Haskell build

The local Macaw checkout provides the Cabal project that includes APTrace:

```sh
cd external/macaw
git submodule update --init
ln -sf cabal.project.freeze.ghc-9.6.7 cabal.project.freeze
cabal build aptrace
cabal test aptrace-test
```

The currently validated compiler line is GHC 9.6.7. Install Z3 separately and
ensure it is on `PATH` for solver-backed commands.

## Python and Ghidra

Create the pinned Unicorn environment with:

```sh
python3 -m venv tools/unicorn/.venv
tools/unicorn/.venv/bin/pip install -r tools/unicorn/requirements.txt
```

Install Ghidra and make `analyzeHeadless` available directly or through
`GHIDRA_HOME`. Run `tools/doctor.sh` for dependency and backend smoke checks.

Case-specific firmware paths, load addresses, commands, and historical setup
notes belong to the case. The current Performing Rigs record is preserved in
[`toolchain-case-notes.md`](../cases/performing-rigs/docs/investigations/toolchain-case-notes.md).
