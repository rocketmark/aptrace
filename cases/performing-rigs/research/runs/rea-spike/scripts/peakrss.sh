#!/bin/bash
# usage: peakrss.sh OUTFILE CMD... ; samples summed RSS of CMD's whole process tree every 0.2s
out=$1; shift
"$@" & root=$!
peak=0
while kill -0 $root 2>/dev/null; do
  pids=$root; frontier=$root
  while [ -n "$frontier" ]; do
    next=$(pgrep -P "$(echo $frontier | tr ' ' ',')" 2>/dev/null | tr '\n' ' ')
    pids="$pids $next"; frontier=$(echo $next)
  done
  rss=$(ps -o rss= -p "$(echo $pids | tr ' ' ',')" 2>/dev/null | awk '{s+=$1} END {print s+0}')
  [ "$rss" -gt "$peak" ] && peak=$rss
  sleep 0.2
done
wait $root; rc=$?
echo "peak_tree_rss_kib=$peak rc=$rc" | tee "$out"
