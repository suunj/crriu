#!/usr/bin/env python3
"""Decode -d dumps of CPURISCVState taken at riscv_cpu_do_interrupt():
one line per trap: hit#, cause, pc/sepc symbol, syscall name/args.

usage: trapseq.py DUMPDIR NAME --layout env-layout.txt [--map System.map]
"""
import os, re, sys, struct, argparse
ap = argparse.ArgumentParser()
ap.add_argument("dir"); ap.add_argument("name")
ap.add_argument("--layout", required=True); ap.add_argument("--map")
a = ap.parse_args()

off = {}
fre = re.compile(r"/\*\s*(\d+)(?::\s*\d+)?\s*\|\s*(\d+)\s*\*/\s*(.*?)\s*;")
for line in open(a.layout):
    m = fre.search(line)
    if not m or "{" in m.group(3): continue
    nm = re.sub(r"\[.*", "", m.group(3).split()[-1]).lstrip("*")
    off.setdefault(nm, (int(m.group(1)), int(m.group(2))))
def u64(b, name, idx=0):
    o, _ = off[name]; return struct.unpack_from("<Q", b, o + 8 * idx)[0]

syms = []
if a.map:
    for line in open(a.map):
        p = line.split()
        if len(p) >= 3 and p[1] in "tTwW": syms.append((int(p[0], 16), p[2]))
    syms.sort()
def sym(addr):
    if not syms or addr < syms[0][0]: return "%#x" % addr
    lo, hi = 0, len(syms)
    while hi - lo > 1:
        mid = (lo + hi) // 2
        if syms[mid][0] <= addr: lo = mid
        else: hi = mid
    return "%s+%#x" % (syms[lo][1], addr - syms[lo][0])

SYSCALL = {17:"getcwd",23:"dup",25:"fcntl",29:"ioctl",35:"unlinkat",48:"faccessat",49:"chdir",
  56:"openat",57:"close",59:"pipe2",61:"getdents64",62:"lseek",63:"read",64:"write",66:"writev",
  72:"pselect6",73:"ppoll",78:"readlinkat",79:"fstatat",80:"fstat",88:"utimensat",93:"exit",
  94:"exit_group",96:"set_tid_address",98:"futex",99:"set_robust_list",113:"clock_gettime",
  129:"kill",131:"tgkill",134:"rt_sigaction",135:"rt_sigprocmask",139:"rt_sigreturn",
  160:"uname",172:"getpid",173:"getppid",174:"getuid",175:"geteuid",176:"getgid",177:"getegid",
  178:"gettid",214:"brk",215:"munmap",220:"clone",221:"execve",222:"mmap",226:"mprotect",
  233:"madvise",260:"wait4",261:"prlimit64",278:"getrandom",291:"statx",435:"clone3"}
CAUSE = {0:"insn misaligned",1:"insn fault",2:"illegal insn",3:"breakpoint",4:"load misaligned",
  5:"load fault",6:"store misaligned",7:"store fault",8:"ecall U",9:"ecall S",11:"ecall M",
  12:"insn page fault",13:"load page fault",15:"store page fault",20:"insn guest-page fault",
  21:"load guest-page fault",23:"store guest-page fault"}

pat = re.compile(r"^%s\.(.+)\.(\d+)\.bin$" % re.escape(a.name))
files = sorted((int(m.group(2)), f) for f in os.listdir(a.dir) for m in [pat.match(f)] if m)
for n, f in files:
    b = open(os.path.join(a.dir, f), "rb").read()
    pc = u64(b, "pc"); priv = struct.unpack_from("<B", b, off["priv"][0])[0]
    a7 = u64(b, "gpr", 17); a0 = u64(b, "gpr", 10); a1 = u64(b, "gpr", 11); a2 = u64(b, "gpr", 12)
    # do_interrupt is entered before the cause CSRs are written; the cause is
    # cs->exception_index, dumped separately as "excp" at the same hit.
    where = "U" if priv == 0 else ("S" if priv == 1 else "M")
    ef = os.path.join(a.dir, f.replace(a.name + ".", "excp.", 1))
    cause = struct.unpack("<i", open(ef, "rb").read(4))[0] if os.path.exists(ef) else -1
    if cause & (1 << 31):
        what = "interrupt %d" % (cause & 0x7fffffff)
    elif cause in (8, 9) and priv == 0:
        what = "syscall %s(%#x, %#x, %#x)" % (SYSCALL.get(a7, "nr%d" % a7), a0, a1, a2)
    else:
        what = CAUSE.get(cause, "cause %d" % cause)
    print("#%-6d %s %-44s pc=%s" % (n, where, what, sym(pc) if priv else "%#x" % pc))
