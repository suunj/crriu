#!/bin/sh
# usage: branchdiff.sh PID_A PID_B [cowmap options]
#
# What differs between two crriu branches: host memory (cowmap: CoW pages
# still shared vs diverged, guest-RAM divergence map) and the TCG
# translation cache (tbstat: TBs, flushes, invalidations, code bytes).
# For two branches forked at the same event with -n, every difference is
# caused by what each branch was fed afterwards.
W=$(dirname "$0")
A=$1; B=$2; shift 2
echo "=== branches $A / $B  ($(date '+%F %T'))"
echo
echo "--- memory (cowmap)"
"$W/cowmap" "$A" "$B" "$@"
echo
echo "--- TCG translation cache (tbstat)"
"$W/tbstat.sh" "$A" "$B"
