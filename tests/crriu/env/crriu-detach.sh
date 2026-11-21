#!/bin/sh
# usage: crriu-detach.sh TRACE LOG TARGET...
#   TARGET: EVENT (right after that frame) or SYM[:N] (N-th entry of SYM)
#   CRRIU_OPTS: extra rr detach options, e.g. "-y 100000 -m 3 -n 2"
# Runs rr detach in its own pid namespace. PID 1 there reaps rr, writes its
# exit status to $CRRIU_BR/rr.status, then stays alive so handed-off branches
# survive rr. This script (the unshare parent) is recorded in
# $CRRIU_BR/ns.pid; killing it kills the namespace (--kill-child).
set -e
. "$(dirname "$0")/common.sh"
TRACE=$1; LOG=$2; shift 2
[ $# -ge 1 ] || { echo "usage: $0 TRACE LOG TARGET..." >&2; exit 2; }
args=""
for t; do args="$args -r $t"; done
mkdir -p "$CRRIU_BR"
rm -f "$CRRIU_BR/rr.status"
echo $$ > "$CRRIU_BR/ns.pid"
exec unshare -pf --kill-child --mount-proc sh -c '
  RR=$1; BR=$2; CWD=$3; TRACE=$4; LOG=$5; shift 5
  "$RR" detach -o "$BR" -c "$CWD" $CRRIU_OPTS "$@" "$TRACE" >"$LOG" 2>&1 </dev/null &
  wait $!
  echo $? > "$BR/rr.status"
  exec sleep infinity
' sh "$CRRIU_RR" "$CRRIU_BR" "$CRRIU_CWD" "$TRACE" "$LOG" $args
