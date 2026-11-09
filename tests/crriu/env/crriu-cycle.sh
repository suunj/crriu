#!/bin/sh
# usage: [INJECT='text'] crriu-cycle.sh TRACE SEL NSPID
#   NSPID  the recorded pid (rr ps TRACE), which is also the pid inside the namespace
#
# detach -> criu dump -> kill the original -> criu restore in a new namespace
# -> SIGCONT -> optionally write INJECT to the tracee's stdin. Prints the tail
# of the tracee's output.
set -e
TRACE=$1; SEL=$2; NSPID=$3
. "$(dirname "$0")/common.sh"
LOG=$CRRIU_LOG; IMG=$CRRIU_IMG
W=$(dirname "$0")

# Host pid of the most recent stopped tracee (rr renames tracees to "rr:<comm>").
find_tracee() { ps -eo pid,stat,comm | awk '$2 ~ /^T/ && $3 ~ /^rr:/ {print $1}' | tail -1; }

# Leftovers from an earlier cycle would compete for the stdin FIFO.
pkill -f 'bin/rr detach' 2>/dev/null || true
pkill -KILL -x 'rr:.*' 2>/dev/null || true
pkill -f 'criu restore' 2>/dev/null || true
sleep 1
rm -f "$LOG"
"$W/crriu-detach.sh" "$TRACE" "$SEL" "$LOG" &
while ! grep -qsE 'detached pid|FATAL|ERROR' "$LOG"; do sleep 2; done
grep -q 'detached pid' "$LOG" || { grep -E 'FATAL|ERROR' "$LOG"; exit 1; }
grep 'detached pid' "$LOG"

QPID=$(find_tracee); echo "host pid of detached tracee: $QPID"
rm -rf "$IMG"; mkdir "$IMG"
nsenter -t "$QPID" -p -m criu dump -t "$NSPID" -D "$IMG" --shell-job --ext-unix-sk --leave-stopped -v4 -o dump.log
echo "dump ok"

kill -9 "$QPID"; sleep 1
unshare -pf --mount-proc criu restore -D "$IMG" --shell-job --ext-unix-sk -v4 -o restore.log &
sleep 3
RPID=$(find_tracee); echo "host pid of restored tracee: $RPID"
kill -CONT "$RPID"
sleep 3
if [ -n "$INJECT" ]; then printf '%s\n' "$INJECT" > "$CRRIU_STDIN"; fi
sleep "${INJECT_WAIT:-8}"
sleep 5
tail -c 1500 "$LOG"
