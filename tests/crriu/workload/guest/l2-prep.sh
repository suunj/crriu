#!/bin/sh
# Build kvmtool (lkvm) for riscv64, put it and the tiny L2 kernel + pmuloop
# initrd into the trixie image, then boot L1 natively and start L2 to check
# that pmuloop runs inside the nested VM. Log: /tmp/l2-prep.log
set -x
TC=/home/suunj/dev/riscv64-lp64d--glibc--stable-2024.05-1/bin/riscv64-buildroot-linux-gnu-
W=/home/suunj/dev/debug/work
cd $W/rv
# 1. libfdt (static) from dtc
[ -d dtc ] || git clone --depth 1 https://git.kernel.org/pub/scm/utils/dtc/dtc.git
make -C dtc libfdt CC=${TC}gcc AR=${TC}ar NO_PYTHON=1 NO_YAML=1 NO_VALGRIND=1 2>&1 | tail -2
ls -l dtc/libfdt/libfdt.a || exit 1
# 2. kvmtool, static
[ -d kvmtool ] || git clone --depth 1 https://git.kernel.org/pub/scm/linux/kernel/git/will/kvmtool.git
CFLAGS="-I$W/rv/dtc/libfdt" LDFLAGS="-static -L$W/rv/dtc/libfdt" \
  make -C kvmtool ARCH=riscv CROSS_COMPILE=$TC LIBFDT_DIR=$W/rv/dtc/libfdt -j$(nproc) 2>&1 | tail -3
[ -x kvmtool/lkvm ] || exit 1
# 3. into the image: lkvm, L2 kernel, pmuloop initrd
mount -o loop /home/suunj/dev/kernel/riscv/image/trixie.img /mnt/trixie || exit 1
cp kvmtool/lkvm /mnt/trixie/root/lkvm
cp $W/linux-rv/arch/riscv/boot/Image /mnt/trixie/root/l2-Image
cp $W/rv/pmu/initrd.gz /mnt/trixie/root/l2-pmu-initrd.gz
ls -l /mnt/trixie/root/; umount /mnt/trixie
# 4. native L1 boot, start L2 with pmuloop as init
rm -f trixie-overlay.qcow2* && qemu-img create -q -f qcow2 -b /home/suunj/dev/kernel/riscv/image/trixie.img -F raw trixie-overlay.qcow2 && cp trixie-overlay.qcow2 trixie-overlay.qcow2.pristine
pkill -KILL -f 'qemu-system-riscv64 -M virt'; sleep 1
rm -f /tmp/l2-native.log
./trixie-qemu.sh 0<>/tmp/qemu-stdin >/tmp/l2-native.log 2>&1 &
while ! grep -qs 'job control turned off' /tmp/l2-native.log; do sleep 5; done; sleep 5
echo '/root/lkvm run -c 1 -m 128 --console serial -k /root/l2-Image -i /root/l2-pmu-initrd.gz -p "console=ttyS0 panic=1" 2>&1; echo L2RC=$?' > /tmp/qemu-stdin
for i in $(seq 1 60); do grep -qs 'L2RC=' /tmp/l2-native.log && break; sleep 10; done
grep -E 'pmu |L2RC=|lkvm|Error|rror' /tmp/l2-native.log | head -30
pkill -KILL -f 'qemu-system-riscv64 -M virt'
echo "L2 PREP DONE"
