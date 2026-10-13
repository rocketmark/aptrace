#!/bin/bash
# usage: q.sh NAME OP [args...] -> rea OP FW args... <raw-binary flags> --json, timed, into $REA_SPIKE_ROOT/out/NAME.json
: "${REA_SPIKE_ROOT:?set REA_SPIKE_ROOT}"
S=$REA_SPIKE_ROOT; FW=$S/fw/firmware_autopilot868.bin; HERE=$(cd "$(dirname "$0")" && pwd)
name=$1; op=$2; shift 2
SNAP=(); [ -n "$REA_SNAP" ] && SNAP=(--snapshot "$REA_SNAP")
/usr/bin/time -l "$HERE/rea" "$op" "$FW" "$@" --target-format raw-binary --architecture arm --entry-point 0x4000 --provider ghidra "${SNAP[@]}" --json > "$S/out/$name.json" 2> "$S/out/$name.time"
rc=$?
echo "$name op=$op rc=$rc real=$(awk '/ real /{print $1}' "$S/out/$name.time")s maxrss=$(( $(awk '/maximum resident/{print $1}' "$S/out/$name.time") / 1048576 ))MiB"
