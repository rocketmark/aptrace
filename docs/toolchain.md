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

## Python environments

APTrace uses two separate Python environments. Do not install one's
dependencies into the other.

| Environment | Declared by | Holds | Used for |
|---|---|---|---|
| `agent/.venv` | `agent/pyproject.toml`, `agent/uv.lock` | Python ≥ 3.12, pydantic-ai, Capstone; pytest (dev group) | the agent and `ResearchController`, ledger, agent tests, case tests that import `aptrace_agent` |
| `tools/unicorn/.venv` | `tools/unicorn/requirements.txt` | pinned `unicorn==2.1.4`, Capstone; no pytest | the concrete harness (`tools/unicorn/`), boot recipes and scenarios, and the plain-assertion scripts that exercise them |

The agent environment does not contain Unicorn. The agent runs concrete
execution as a subprocess under `tools/unicorn/.venv/bin/python3`
(`UNICORN_PYTHON` in `agent/src/aptrace_agent/structural_wiring.py`), never by
importing Unicorn into its own process.

Create them with:

```sh
(cd agent && uv sync)
python3 -m venv tools/unicorn/.venv
tools/unicorn/.venv/bin/pip install -r tools/unicorn/requirements.txt
```

Each test file names its interpreter in its docstring. Tests that execute
Unicorn are plain-assertion scripts run with `tools/unicorn/.venv/bin/python3`;
when pytest in `agent/.venv` collects them, they are reported as skipped,
with that reason. A case may provide a runner that uses the right
interpreter for each file; for Performing Rigs it is
`cases/performing-rigs/test/run_python_tests.sh`.

## Ghidra

Install Ghidra and make `analyzeHeadless` available directly or through
`GHIDRA_HOME`. Run `tools/doctor.sh` for dependency and backend smoke checks.

Case-specific firmware paths, load addresses, commands, and historical setup
notes belong to the case. The current Performing Rigs record is preserved in
[`toolchain-case-notes.md`](../cases/performing-rigs/docs/investigations/toolchain-case-notes.md).
