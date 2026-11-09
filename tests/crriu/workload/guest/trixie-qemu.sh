#!/bin/sh
# crriu용 trixie guest. 평소 명령에서 TCG/icount, smp 1, 1G, nic none, overlay disk로 바꾼 것.
exec qemu-system-riscv64 -M virt,aia=aplic-imsic -cpu rv64,h=true,sscofpmf=true -smp 4 -m 4G -nographic -monitor none \
  -accel tcg -icount shift=3,sleep=off \
  -kernel /home/suunj/dev/kernel/riscv/abit-fix/arch/riscv/boot/Image \
  -append "root=/dev/vda rw console=ttyS0 earlycon selinux=0 net.ifnames=0 init=/bin/sh" \
  -drive file=/home/suunj/dev/debug/work/rv/trixie-overlay.qcow2,format=qcow2,if=none,id=hd0 \
  -device virtio-blk-device,drive=hd0 -nic none "$@"
