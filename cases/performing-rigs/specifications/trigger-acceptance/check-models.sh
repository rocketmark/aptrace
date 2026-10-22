#!/bin/sh
# Model-checker orchestration only; no controller implementation.
set -eu
trigger_jar=${TLA_TOOLS_JAR:?Set TLA_TOOLS_JAR to pinned tla2tools.jar}
trigger_java=${TLA_JAVA:-java}
trigger_root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$trigger_root"
trigger_meta=$(mktemp -d /private/tmp/aptrace-trigger-tlc.XXXXXX)
trap 'rm -rf "$trigger_meta"' EXIT HUP INT TERM
mkdir -p verification/replay
run_check() {
  trigger_cfg=$1
  trigger_module=$2
  trigger_expected=$3
  trigger_message=$4
  set +e
  "$trigger_java" -Xmx2g -cp "$trigger_jar" tlc2.TLC -workers 1 \
    -metadir "$trigger_meta/$trigger_cfg" -config "$trigger_cfg.cfg" \
    "$trigger_module.tla" > "verification/replay/$trigger_cfg.log" 2>&1
  trigger_actual=$?
  set -e
  if [ "$trigger_actual" -ne "$trigger_expected" ]; then
    printf '%s: expected exit %s, got %s\n' "$trigger_cfg" "$trigger_expected" "$trigger_actual" >&2
    exit 1
  fi
  if ! rg -F -q "$trigger_message" "verification/replay/$trigger_cfg.log"; then
    printf '%s: required checker diagnostic missing\n' "$trigger_cfg" >&2
    exit 1
  fi
  printf '%s: expected result confirmed (exit %s)\n' "$trigger_cfg" "$trigger_actual"
}
for trigger_cfg in Safety SafetyTwoEvents SafetyZeroAge Progress Cooperative; do
  run_check "$trigger_cfg" TriggerAcceptance 0 'Model checking completed. No error has been found.'
done
run_check StartupCounterexample TriggerAcceptance 12 'Invariant PendingQualified is violated'
run_check DuplicateCounterexample TriggerAcceptance 12 'Invariant UniqueStarts is violated'
run_check StopCounterexample TriggerAcceptance 12 'Invariant StoppedInvalidates is violated'
run_check UnconditionalProgressCounterexample TriggerAcceptance 13 'Temporal properties were violated'
run_check FairnessCounterexample TriggerAcceptance 13 'Temporal properties were violated'
for trigger_cfg in NoxonStartup NoxonReclassification NoxonFilterTail; do
  run_check "$trigger_cfg" NoxonWitness 12 'Invariant NewEpisodeRequired is violated'
done
