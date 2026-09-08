#!/usr/bin/env bash
# APTrace doctor: verify the four analysis backends are usable.
#
# Checks (see docs/tooling/tool-selection.md for what each backend is for):
#   1. Ghidra headless analysis (static RE)
#   2. Unicorn ARM/Thumb concrete execution
#   3. Macaw/Crucible/What4/Z3 build prerequisites (symbolic execution)
#
# This does not build the aptrace cabal package itself (that takes 15-20
# minutes the first time -- see docs/toolchain.md); it only checks that the
# prerequisites for doing so are in place.
#
# Exit status: 0 if everything checked out, 1 if anything failed.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FIRMWARE="$REPO_ROOT/Autopilot_firm/firmware_autopilot868.bin"
FAILED=0

pass() { echo "  OK   $1"; }
fail() { echo "  FAIL $1"; FAILED=1; }
info() { echo "  ..   $1"; }

echo "== 1. Ghidra headless (static RE) =="
resolve_headless() {
  if command -v analyzeHeadless >/dev/null 2>&1; then
    command -v analyzeHeadless; return 0
  fi
  if [ -n "${GHIDRA_HOME:-}" ] && [ -x "${GHIDRA_HOME}/support/analyzeHeadless" ]; then
    echo "${GHIDRA_HOME}/support/analyzeHeadless"; return 0
  fi
  if command -v brew >/dev/null 2>&1; then
    local brew_prefix
    if brew_prefix="$(brew --prefix ghidra 2>/dev/null)" && \
       [ -x "${brew_prefix}/libexec/support/analyzeHeadless" ]; then
      echo "${brew_prefix}/libexec/support/analyzeHeadless"; return 0
    fi
  fi
  return 1
}
if HEADLESS="$(resolve_headless)"; then
  pass "found analyzeHeadless: $HEADLESS"
  if [ -f "$FIRMWARE" ]; then
    info "running a real headless analysis pass against firmware_autopilot868.bin (~10-30s)..."
    OUT_JSON="$(mktemp -t aptrace_ghidra_doctor.XXXX).json"
    if "$REPO_ROOT/tools/ghidra/analyze_firmware.sh" "$FIRMWARE" 0x4000 "$OUT_JSON" >/tmp/aptrace_ghidra_doctor.log 2>&1; then
      NUM_FUNCS=$(python3 -c "import json;print(len(json.load(open('$OUT_JSON'))['functions']))" 2>/dev/null || echo 0)
      if [ "${NUM_FUNCS:-0}" -gt 0 ]; then
        pass "headless analysis produced $NUM_FUNCS functions"
      else
        fail "headless analysis ran but produced no functions -- see /tmp/aptrace_ghidra_doctor.log"
      fi
      rm -f "$OUT_JSON"
    else
      fail "headless analysis failed -- see /tmp/aptrace_ghidra_doctor.log"
    fi
  else
    info "firmware not present at $FIRMWARE (proprietary, not vendored) -- skipping functional check"
  fi
else
  fail "analyzeHeadless not found. Install with: brew install ghidra"
fi

echo "== 2. Unicorn (concrete Thumb execution) =="
VENV="$REPO_ROOT/tools/unicorn/.venv"
if [ -x "$VENV/bin/python3" ]; then
  pass "found venv: $VENV"
else
  fail "no venv at $VENV -- create with: python3 -m venv tools/unicorn/.venv && tools/unicorn/.venv/bin/pip install -r tools/unicorn/requirements.txt"
fi
if [ -x "$VENV/bin/python3" ]; then
  if "$VENV/bin/python3" -c "import unicorn; assert unicorn.__version__ == '2.1.4'" >/dev/null 2>&1; then
    pass "unicorn==2.1.4 importable"
  else
    fail "unicorn package missing or wrong version in $VENV -- run: $VENV/bin/pip install -r tools/unicorn/requirements.txt"
  fi
  if [ -f "$FIRMWARE" ]; then
    RESULT=$("$VENV/bin/python3" "$REPO_ROOT/tools/unicorn/run_concrete.py" \
      --firmware "$FIRMWARE" --entry 0x888c --reg r3=0x26 \
      --stop-at 0x8890 --stop-at 0x889e 2>/tmp/aptrace_unicorn_doctor.log)
    if echo "$RESULT" | grep -q '"stop_reason": "reached stop address 0x00008890"'; then
      pass "concrete execution reproduces the solver-confirmed '&' branch (0x888c -> 0x8890)"
    else
      fail "concrete execution did not reach the expected address -- see /tmp/aptrace_unicorn_doctor.log"
    fi
  else
    info "firmware not present at $FIRMWARE -- skipping functional check"
  fi
fi

echo "== 3. Macaw/Crucible/What4/Z3 (symbolic execution) prerequisites =="
if command -v z3 >/dev/null 2>&1; then
  pass "z3 on PATH ($(z3 --version | head -1))"
else
  fail "z3 not on PATH -- install with: brew install z3"
fi
if command -v ghc >/dev/null 2>&1 && command -v cabal >/dev/null 2>&1; then
  pass "ghc/cabal on PATH ($(ghc --numeric-version), cabal $(cabal --numeric-version))"
else
  fail "ghc/cabal not on PATH -- see docs/toolchain.md's GHCup bootstrap step"
fi
if [ -f "$REPO_ROOT/external/macaw/cabal.project" ]; then
  pass "external/macaw/cabal.project present (submodules initialized)"
else
  fail "external/macaw/cabal.project missing -- see docs/toolchain.md step 3 (git submodule update --init, symlink cabal.project.freeze)"
fi

echo
if [ "$FAILED" -eq 0 ]; then
  echo "All checks passed."
else
  echo "Some checks failed -- see messages above."
fi
exit "$FAILED"
