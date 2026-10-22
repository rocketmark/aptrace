#!/bin/sh
# Checker-only orchestration; no firmware execution. Run from this directory.
set -u
JAVA=${TLA_JAVA:-/opt/homebrew/opt/openjdk@21/bin/java}
JAR=${TLA_JAR:-/private/tmp/aptrace-tla-2026-10-22/tla2tools.jar}
failed=0
for spec in Correspondence:0 Startup:12 Reclassification:12 FilterTail:12 StartupTail:12 SampledRelease:12 AcceptedRelease:12 DecayedClassification:12 ShortPulse:13 UnsampledPulse:13 WrongRawGuard:12 WrongFrozenFilter:12 WrongRawAnalogGuard:12; do
 name=${spec%:*}; expected=${spec#*:}
 "$JAVA" -Xmx2g -cp "$JAR" tlc2.TLC -workers 1 -metadir "/private/tmp/aptrace-noxon-$name-$$" -config "$name.cfg" NoxonTrigger.tla > "verification/$name.log" 2>&1
 actual=$?
 case "$expected" in
  0) diagnostic='Model checking completed. No error has been found.';;
  12) diagnostic='is violated';;
  13) diagnostic='Temporal properties were violated';;
 esac
 if [ "$actual" -eq "$expected" ] && rg -q "$diagnostic" "verification/$name.log"; then
  echo "$name expected=$expected actual=$actual OK"
 else
  echo "$name expected=$expected actual=$actual FAIL"; failed=1
 fi
 done
exit "$failed"
