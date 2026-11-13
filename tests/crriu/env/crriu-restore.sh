#!/bin/sh
# usage: [INJECT='text'] [INJECT_WAIT=sec] crriu-restore.sh K
#
# criu restore branch K (dumped by crriu-cycle.sh) in a fresh pid namespace,
# SIGCONT it, optionally write INJECT to branch-K.stdin, print the tail of
# branch-K.log. Several branches can be restored side by side: each has its
# own namespace, FIFO and log.
set -e
K=$1
. "$(dirname "$0")/common.sh"
IMG=$CRRIU_IMG/$K; BR=$CRRIU_BR
[ -d "$IMG" ] || { echo "no images for branch $K in $IMG" >&2; exit 1; }

unshare -pf --mount-proc criu restore -D "$IMG" --shell-job --ext-unix-sk -v4 -o restore.log \
  >"$IMG/restore.out" 2>&1 </dev/null &
sleep 3
# Newest stopped tracee is ours.
RPID=$(ps -eo pid,stat,comm --sort=etimes | awk '$2 ~ /^T/ && $3 ~ /^rr:qemu/ {print $1; exit}')
[ -n "$RPID" ] || { echo "restore failed, see $IMG/restore.log" >&2; exit 1; }
echo "branch $K restored: host pid $RPID"
kill -CONT "$RPID"; echo "continued; waiting $((3 + ${INJECT_WAIT:-8}))s for output"
sleep 3
if [ -n "$INJECT" ]; then printf '%s\n' "$INJECT" > "$BR/branch-$K.stdin"; fi
sleep "${INJECT_WAIT:-8}"
tail -c 1500 "$BR/branch-$K.log"
