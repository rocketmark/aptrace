#!/bin/sh
set -u
JAVA=${TLA_JAVA:-/opt/homebrew/opt/openjdk@21/bin/java}
JAR=${TLA_JAR:-/private/tmp/aptrace-tla-2026-10-22/tla2tools.jar}
for name in DirectG ReferenceReplay; do
 "$JAVA" -DTLA-Library=../trigger-acceptance -Xmx2g -cp "$JAR" tlc2.TLC -workers 1 -metadir "/private/tmp/aptrace-comparison-$name-$$" -config "$name.cfg" "$name.tla" > "verification/$name.log" 2>&1
 actual=$?
 if [ "$actual" -ne 0 ] || ! rg -q 'Model checking completed. No error has been found.' "verification/$name.log"; then
  echo "$name expected=0 actual=$actual FAIL"; exit 1
 fi
 echo "$name expected=0 actual=$actual OK"
done
