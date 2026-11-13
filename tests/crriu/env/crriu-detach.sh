#!/bin/sh
# usage: crriu-detach.sh TRACE LOG SEL [SEL...]
#   SEL  a console string (-u: branch off right after it appears) or one
#        event number (-e). Several strings give several branches: every
#        match but the last detaches a clone of the replay, the last match
#        detaches the replay itself.
#
# Runs rr detach as the only child of a fresh pid namespace, so nothing else
# allocates pids while the recorded tids are being reproduced. Branch K gets
# $CRRIU_BR/branch-K.stdin (FIFO) and branch-K.log as its stdio.
TRACE=$1; LOG=$2; shift 2
. "$(dirname "$0")/common.sh"

# Turn each SEL into "-u SEL" or "-e SEL", keeping spaces inside SEL intact.
n=$#; i=0
while [ $i -lt $n ]; do
  s=$1; shift
  case "$s" in
    ''|*[!0-9]*) set -- "$@" -u "$s" ;;
    *)           set -- "$@" -e "$s" ;;
  esac
  i=$((i + 1))
done

exec unshare -pf --mount-proc sh -c '
  RR=$1; BR=$2; CWD=$3; TRACE=$4; LOG=$5; shift 5
  "$RR" detach -o "$BR" -c "$CWD" "$@" "$TRACE" >"$LOG" 2>&1 </dev/null &
  wait
' sh "$CRRIU_RR" "$CRRIU_BR" "$CRRIU_CWD" "$TRACE" "$LOG" "$@"
