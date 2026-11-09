#!/bin/sh
# usage: crriu-detach.sh TRACE SEL LOG
#   SEL  event number (-e) or a console string (-u: detach right after it appears)
#
# Runs rr detach as the only child of a fresh pid namespace, so nothing else
# allocates pids while the recorded tids are being reproduced. The tracee's
# stdin is a FIFO opened read-write, so input can be fed to it after restore.
TRACE=$1; SEL=$2; LOG=$3
. "$(dirname "$0")/common.sh"
case "$SEL" in
  ''|*[!0-9]*) OPT="-u" ;;
  *) OPT="-e" ;;
esac
exec unshare -pf --mount-proc sh -c '
  "$5" detach "$1" "$2" -c "$6" "$3" >"$4" 2>&1 0<>"$7" &
  wait
' sh "$OPT" "$SEL" "$TRACE" "$LOG" "$CRRIU_RR" "$CRRIU_CWD" "$CRRIU_STDIN"
