#!/bin/sh
# usage: tbstat.sh PID [PID2]
#
# TCG translation-cache statistics of a (stopped or running) QEMU process,
# read with gdb from QEMU's own data structures -- no QEMU changes, no
# monitor needed. With two pids prints both and the difference, which for
# two crriu branches forked from the same event is exactly what the
# branches' different inputs caused.
#
#   tb_flush_count        whole-cache flushes (tb_ctx)
#   tb_invalidate_count   TBs thrown away by tb_phys_invalidate (SMC, page
#                         writes, mprotect, ...)
#   nb_tbs                live TBs                       (tcg_nb_tbs())
#   code_size             bytes of generated host code   (tcg_code_size())
#   code_capacity         size of the code buffer        (tcg_code_capacity())
#
# The three function calls run inside the target, on one thread, with the
# others held; the counters are plain reads. A process that was stopped (T)
# is stopped again afterwards.
#
# Symbols: the tracee's text mapping is used as symbol file (rr replays from
# a byte copy of the binary, which keeps the symbols) and its load base is
# taken from /proc/PID/maps. Override with TBSTAT_SYM=/path/to/qemu-system-*.

one() {
  pid=$1
  [ -d /proc/$pid ] || { echo "no such pid $pid" >&2; return 1; }
  was_stopped=$(awk '$1=="State:" && $2 ~ /^[Tt]/ {print 1}' /proc/$pid/status)

  # Text mapping: executable, file-backed, name contains "qemu".
  sym=${TBSTAT_SYM:-$(awk '$2 ~ /x/ && $6 ~ /qemu/ {print $6; exit}' /proc/$pid/maps)}
  [ -n "$sym" ] || { echo "pid $pid: can't find qemu text mapping" >&2; return 1; }
  mapname=$(awk '$2 ~ /x/ && $6 ~ /qemu/ {print $6; exit}' /proc/$pid/maps)
  base=$(awk -v f="$mapname" '$6==f && $3=="00000000" {sub(/-.*/,"",$1); print "0x"$1; exit}' /proc/$pid/maps)
  [ -n "$base" ] || { echo "pid $pid: can't find load base of $mapname" >&2; return 1; }

  out=$(gdb -q -batch -p "$pid" \
    -ex 'set pagination off' -ex 'set confirm off' \
    -ex "add-symbol-file $sym -o $base" \
    -ex 'set scheduler-locking on' \
    -ex 'handle SIGSTOP nostop noprint nopass' \
    -ex 'printf "tb_flush_count %u\n", tb_ctx.tb_flush_count' \
    -ex 'printf "tb_invalidate_count %u\n", tb_ctx.tb_phys_invalidate_count' \
    -ex 'printf "nb_tbs %lu\n", (unsigned long)tcg_nb_tbs()' \
    -ex 'printf "code_size %lu\n", (unsigned long)tcg_code_size()' \
    -ex 'printf "code_capacity %lu\n", (unsigned long)tcg_code_capacity()' \
    -ex 'detach' 2>&1)
  [ -n "$TBSTAT_DEBUG" ] && echo "$out" >&2
  [ -n "$was_stopped" ] && kill -STOP "$pid" 2>/dev/null

  echo "$out" | grep -E '^(tb_flush_count|tb_invalidate_count|nb_tbs|code_size|code_capacity) ' || {
    echo "pid $pid: gdb failed:" >&2; echo "$out" | tail -5 >&2; return 1; }
}

[ $# -ge 1 ] || { echo "usage: $0 PID [PID2]" >&2; exit 2; }

a=$(one "$1") || exit 1
if [ $# -eq 1 ]; then
  echo "$a" | awk '{printf "%-20s %12s\n", $1, $2}'
  exit 0
fi
b=$(one "$2") || exit 1

printf '%-20s %14s %14s %14s\n' stat "pid $1" "pid $2" "B-A"
echo "$a" | while read -r k va; do
  vb=$(echo "$b" | awk -v k="$k" '$1==k {print $2}')
  printf '%-20s %14s %14s %+14d\n' "$k" "$va" "$vb" "$((vb - va))"
done
