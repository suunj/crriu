#!/bin/sh
# usage: [RESTORE=K] [INJECT='text'] crriu-cycle.sh TRACE SEL [SEL...]
#
# One replay, N branches: detach at every SEL, criu dump each branch into
# $CRRIU_IMG/K, tear the replay down, then restore branch RESTORE (default:
# the last one) and optionally feed INJECT to its stdin. Any branch can be
# restored again later with crriu-restore.sh K.
set -e
TRACE=$1; shift
. "$(dirname "$0")/common.sh"
LOG=$CRRIU_LOG; IMG=$CRRIU_IMG; BR=$CRRIU_BR
W=$(dirname "$0")
N=$#

# Leftovers from an earlier cycle would hold pids and FIFOs. Only ours:
# the pid namespaces we created (unshare --kill-child takes everything
# inside down with them).
for f in "$BR/ns.pid" "$IMG"/*/restore.pid; do
  [ -f "$f" ] && kill -KILL "$(cat "$f")" 2>/dev/null || true
done
sleep 1
rm -f "$LOG"; rm -rf "$IMG"; mkdir -p "$IMG"
rm -f "$BR"/branch-*

"$W/crriu-detach.sh" "$TRACE" "$LOG" "$@" >/dev/null 2>&1 </dev/null &
while :; do
  if grep -qsE 'FATAL|ERROR' "$LOG"; then grep -E 'FATAL|ERROR' "$LOG"; exit 1; fi
  if [ -f "$BR/rr.status" ]; then echo "rr detach exited early: status $(cat "$BR/rr.status")"; tail -5 "$LOG"; exit 1; fi
  c=$(grep -c "detached pid" "$LOG" 2>/dev/null || true); [ "${c:-0}" -ge "$N" ] && break
  sleep 2
done
grep 'detached pid' "$LOG"

# rr itself is a member of the namespace; nsenter through it. Find it via
# our own namespace: unshare (ns.pid) -> sh (its PID 1) -> rr.
NSINIT=$(pgrep -P "$(cat "$BR/ns.pid")")
RRHOST=$(pgrep -P "$NSINIT" -x rr)
echo "rr host pid: $RRHOST"

k=0
grep 'detached pid' "$LOG" | while read -r _ _ nspid _; do
  k=$((k + 1))
  mkdir -p "$IMG/$k"
  nsenter -t "$RRHOST" -p -m criu dump -t "$nspid" -D "$IMG/$k" \
    --shell-job --ext-unix-sk --leave-stopped -v4 -o dump.log
  echo "branch $k (ns pid $nspid): dump ok -> $IMG/$k"
done

# Everything is on disk now; free the pids: killing the unshare parent
# kills the namespace's PID 1 (--kill-child) and with it rr, checkpoints
# and the dumped branches.
kill -KILL "$(cat "$BR/ns.pid")" 2>/dev/null || true   # unshare ignores SIGTERM; --kill-child does the rest
sleep 1

exec "$W/crriu-restore.sh" "${RESTORE:-$N}"
