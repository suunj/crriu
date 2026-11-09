#!/bin/sh
exec qemu-system-riscv64 -M virt -accel tcg -icount shift=3,sleep=off -nographic -monitor none -no-reboot -m 256 -smp 1 \
  -kernel /home/suunj/dev/debug/work/linux-rv/arch/riscv/boot/Image -initrd /home/suunj/dev/debug/work/rv/pmu/initrd.gz \
  -append 'console=ttyS0 panic=1' "$@"
