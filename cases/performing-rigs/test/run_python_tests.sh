#!/usr/bin/env bash
# Run the Performing Rigs Python tests, each under its declared interpreter
# (docs/toolchain.md, "Python environments"):
#
#   agent/.venv            pytest over this directory; the Unicorn scripts
#                          are skipped there (conftest.py) and run below
#   tools/unicorn/.venv    the plain-assertion Unicorn and census scripts
#
# Tests that need gitignored inputs (census DB, Ghidra cache, firmware)
# skip or fail with a message when those are absent; this script does not
# build them. The Haskell tests (Main.hs) run through `cabal test`.
#
# Exit status: 0 if every step passed, 1 otherwise.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
TEST_DIR="cases/performing-rigs/test"
AGENT_PY="$REPO_ROOT/agent/.venv/bin/python"
UNICORN_PY="$REPO_ROOT/tools/unicorn/.venv/bin/python3"

UNICORN_SCRIPTS=(
  test_concrete.py
  test_feather_m4_profile.py
  test_observe_scenarios.py
  test_indirect_dispatch.py
  test_reduce.py
  test_target_irq_count.py
)

cd "$REPO_ROOT" || exit 1
FAILED=()

for py in "$AGENT_PY" "$UNICORN_PY"; do
  if [ ! -x "$py" ]; then
    echo "missing interpreter $py -- see docs/toolchain.md" >&2
    exit 1
  fi
done

echo "== agent/.venv: pytest $TEST_DIR"
"$AGENT_PY" -m pytest -q -rs "$TEST_DIR" || FAILED+=("pytest (agent/.venv)")

for script in "${UNICORN_SCRIPTS[@]}"; do
  echo
  echo "== tools/unicorn/.venv: $script"
  "$UNICORN_PY" "$TEST_DIR/$script" || FAILED+=("$script (tools/unicorn/.venv)")
done

echo
if [ ${#FAILED[@]} -gt 0 ]; then
  printf 'FAILED: %s\n' "${FAILED[@]}"
  exit 1
fi
echo "All Performing Rigs Python test steps passed."
