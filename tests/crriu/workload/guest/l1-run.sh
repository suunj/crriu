#!/bin/sh
# usage: l1-run.sh 'command' [wait_seconds]   -> boots L1 natively, runs the command at the shell, prints the tail
CMD=$1; WAIT=${2:-90}
cd /home/suunj/dev/debug/work/rv
pkill -KILL -f 'qemu-system-riscv64 -M virt' 2>/dev/null; pkill -KILL -x 'rr:qemu-system-' 2>/dev/null; pkill -f 'bin/rr detach' 2>/dev/null; sleep 1
rm -f trixie-overlay.qcow2 && qemu-img create -q -f qcow2 -b /home/suunj/dev/kernel/riscv/image/trixie.img -F raw trixie-overlay.qcow2
rm -f /tmp/l1-run.log; dd if=/tmp/qemu-stdin iflag=nonblock of=/dev/null 2>/dev/null   # drain stale input
./${L1:-trixie-qemu.sh} 0<>/tmp/qemu-stdin >/tmp/l1-run.log 2>&1 &
while ! grep -qs 'job control turned off' /tmp/l1-run.log; do sleep 5; done; sleep 5
printf '%s\n' "$CMD" > /tmp/qemu-stdin
sleep "$WAIT"
sed -n '/job control turned off/,$p' /tmp/l1-run.log | tail -c 2500
