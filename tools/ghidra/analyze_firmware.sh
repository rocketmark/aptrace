#!/usr/bin/env bash
# APTrace: run Ghidra headless static analysis against a raw Cortex-M
# firmware image and export functions/calls/data-refs/strings to JSON.
#
# See docs/tooling/tool-selection.md for why Ghidra is used for this
# (static structure recovery) rather than Macaw, and why the language is
# forced to ARM:LE:32:Cortex (Thumb-only Cortex-M processor spec -- unlike
# Macaw's more general AArch32 backend, this cannot decode A32/ARM-mode
# instructions, which makes it a useful independent check on the 0x801c
# anomaly documented in docs/investigations/trigger-input.md).
#
# Usage: tools/ghidra/analyze_firmware.sh FIRMWARE.bin [LOAD_ADDR_HEX] [OUT_JSON] [EXTRA_SEED_ADDRS]
#   LOAD_ADDR_HEX defaults to 0x4000 (the AutoPilot/Remote images' flash base).
#   OUT_JSON defaults to research/runs/ghidra/<firmware-basename>.json
#   EXTRA_SEED_ADDRS is an optional comma-separated list of additional
#     addresses to force-disassemble/create-function-at before analysis --
#     e.g. "0x8259,0x801c,0x8a35" to seed specific addresses under
#     investigation that aren't reachable from the vector table alone.
#
# Before auto-analysis, seeds Ghidra's function starts from the ARMv7-M
# vector table (APTraceSeedVectorTable.java) -- a raw BinaryLoader import
# gives Ghidra no entry points otherwise, and its own heuristics alone miss
# most real functions (see that script's header comment for what was
# actually observed without this step).
#
# Requires `analyzeHeadless` on PATH, or GHIDRA_HOME set to a Ghidra install
# root (the directory containing support/analyzeHeadless), or Ghidra
# installed via `brew install ghidra`.
set -euo pipefail

if [ $# -lt 1 ] || [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
  sed -n '2,20p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
  exit 1
fi

FIRMWARE="$1"
LOAD_ADDR="${2:-0x4000}"
BASENAME="$(basename "$FIRMWARE")"
BASENAME="${BASENAME%.bin}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT_PATH="$REPO_ROOT/tools/ghidra/scripts"
OUT_JSON="${3:-$REPO_ROOT/research/runs/ghidra/${BASENAME}.json}"
EXTRA_SEEDS="${4:-}"

resolve_headless() {
  if command -v analyzeHeadless >/dev/null 2>&1; then
    command -v analyzeHeadless
    return 0
  fi
  if [ -n "${GHIDRA_HOME:-}" ] && [ -x "${GHIDRA_HOME}/support/analyzeHeadless" ]; then
    echo "${GHIDRA_HOME}/support/analyzeHeadless"
    return 0
  fi
  if command -v brew >/dev/null 2>&1; then
    local brew_prefix
    if brew_prefix="$(brew --prefix ghidra 2>/dev/null)" && \
       [ -x "${brew_prefix}/libexec/support/analyzeHeadless" ]; then
      echo "${brew_prefix}/libexec/support/analyzeHeadless"
      return 0
    fi
  fi
  return 1
}

if ! HEADLESS="$(resolve_headless)"; then
  echo "error: could not find Ghidra's analyzeHeadless." >&2
  echo "  install it with: brew install ghidra" >&2
  echo "  or set GHIDRA_HOME to a Ghidra install root." >&2
  exit 1
fi

mkdir -p "$(dirname "$OUT_JSON")"
PROJECT_DIR="$(mktemp -d)"
trap 'rm -rf "$PROJECT_DIR"' EXIT

"$HEADLESS" "$PROJECT_DIR" aptrace_headless \
  -import "$FIRMWARE" \
  -processor "ARM:LE:32:Cortex" \
  -cspec default \
  -loader BinaryLoader \
  -loader-baseAddr "$LOAD_ADDR" \
  -scriptPath "$SCRIPT_PATH" \
  -preScript APTraceSeedVectorTable.java 56 "$EXTRA_SEEDS" \
  -postScript APTraceExportStaticAnalysis.java "$OUT_JSON" \
  -deleteProject \
  -analysisTimeoutPerFile 300

echo "Wrote $OUT_JSON"
