/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "hpobs/ptrace_target.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#include "hpobs/log.h"

using namespace std;

namespace hpobs {

static const long kTraceOptions = PTRACE_O_TRACEEXEC | PTRACE_O_EXITKILL;

PtraceTarget::PtraceTarget(pid_t pid) : pid_(pid) {}

PtraceTarget::~PtraceTarget() {
  if (exited_) {
    return;
  }
  for (const auto& kv : bps_) {
    poke_byte(kv.first, kv.second);
  }
  ptrace(PTRACE_DETACH, pid_, nullptr, nullptr);
}

unique_ptr<PtraceTarget> PtraceTarget::spawn(char* const argv[]) {
  pid_t pid = fork();
  if (pid < 0) {
    logf("fork: %s", strerror(errno));
    return nullptr;
  }
  if (pid == 0) {
    if (ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) < 0) {
      _exit(127);
    }
    execvp(argv[0], argv);
    fprintf(stderr, "%s: exec %s: %s\n", log_prefix(), argv[0], strerror(errno));
    _exit(127);
  }
  int status;
  if (waitpid(pid, &status, 0) < 0 || !WIFSTOPPED(status)) {
    logf("%s did not stop after exec", argv[0]);
    return nullptr;
  }
  unique_ptr<PtraceTarget> t(new PtraceTarget(pid));
  ptrace(PTRACE_SETOPTIONS, pid, nullptr, (void*)kTraceOptions);
  return t;
}

unique_ptr<PtraceTarget> PtraceTarget::attach(pid_t pid) {
  if (ptrace(PTRACE_ATTACH, pid, nullptr, nullptr) < 0) {
    logf("attach %d: %s", pid, strerror(errno));
    return nullptr;
  }
  int status;
  if (waitpid(pid, &status, 0) < 0 || !WIFSTOPPED(status)) {
    logf("%d did not stop after attach", pid);
    return nullptr;
  }
  unique_ptr<PtraceTarget> t(new PtraceTarget(pid));
  ptrace(PTRACE_SETOPTIONS, pid, nullptr, (void*)kTraceOptions);
  return t;
}

void PtraceTarget::hide_breakpoints(uint64_t addr, void* buf, size_t len) const {
  for (const auto& kv : bps_) {
    if (kv.first >= addr && kv.first < addr + len) {
      ((uint8_t*)buf)[kv.first - addr] = kv.second;
    }
  }
}

bool PtraceTarget::read(uint64_t addr, void* buf, size_t len) {
  if (exited_) {
    return false;
  }
  struct iovec local = {buf, len};
  struct iovec remote = {(void*)addr, len};
  ssize_t n = process_vm_readv(pid_, &local, 1, &remote, 1, 0);
  if (n != (ssize_t)len) {
    // Fall back to /proc/pid/mem for pages process_vm_readv refuses.
    char path[64];
    snprintf(path, sizeof path, "/proc/%d/mem", pid_);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
      return false;
    }
    n = pread(fd, buf, len, addr);
    close(fd);
    if (n != (ssize_t)len) {
      return false;
    }
  }
  hide_breakpoints(addr, buf, len);
  return true;
}

Regs PtraceTarget::regs() {
  Regs r = {};
  if (exited_) {
    return r;
  }
  struct user_regs_struct u;
  if (ptrace(PTRACE_GETREGS, pid_, nullptr, &u) < 0) {
    return r;
  }
  r.gpr[Regs::RAX] = u.rax;
  r.gpr[Regs::RDX] = u.rdx;
  r.gpr[Regs::RCX] = u.rcx;
  r.gpr[Regs::RBX] = u.rbx;
  r.gpr[Regs::RSI] = u.rsi;
  r.gpr[Regs::RDI] = u.rdi;
  r.gpr[Regs::RBP] = u.rbp;
  r.gpr[Regs::RSP] = u.rsp;
  r.gpr[Regs::R8] = u.r8;
  r.gpr[Regs::R9] = u.r9;
  r.gpr[Regs::R10] = u.r10;
  r.gpr[Regs::R11] = u.r11;
  r.gpr[Regs::R12] = u.r12;
  r.gpr[Regs::R13] = u.r13;
  r.gpr[Regs::R14] = u.r14;
  r.gpr[Regs::R15] = u.r15;
  r.gpr[Regs::RIP] = u.rip;
  r.fs_base = u.fs_base;
  r.gs_base = u.gs_base;
  return r;
}

void PtraceTarget::set_ip(uint64_t ip) {
  struct user_regs_struct u;
  if (ptrace(PTRACE_GETREGS, pid_, nullptr, &u) < 0) {
    return;
  }
  u.rip = ip;
  ptrace(PTRACE_SETREGS, pid_, nullptr, &u);
}

vector<Mapping> PtraceTarget::maps() {
  vector<Mapping> out;
  char path[64];
  snprintf(path, sizeof path, "/proc/%d/maps", pid_);
  FILE* f = fopen(path, "r");
  if (!f) {
    return out;
  }
  char line[4096];
  while (fgets(line, sizeof line, f)) {
    uint64_t start, end, off;
    char perms[8];
    unsigned dmaj, dmin;
    unsigned long ino;
    int consumed = 0;
    if (sscanf(line, "%" SCNx64 "-%" SCNx64 " %7s %" SCNx64 " %x:%x %lu%n", &start, &end, perms,
               &off, &dmaj, &dmin, &ino, &consumed) < 7) {
      continue;
    }
    const char* p = line + consumed;
    while (*p == ' ') {
      p++;
    }
    string fsname(p);
    while (!fsname.empty() && (fsname.back() == '\n' || fsname.back() == ' ')) {
      fsname.pop_back();
    }
    int prot = (perms[0] == 'r' ? PROT_READ : 0) | (perms[1] == 'w' ? PROT_WRITE : 0) |
               (perms[2] == 'x' ? PROT_EXEC : 0);
    out.push_back({start, end, prot, off, fsname});
  }
  fclose(f);
  return out;
}

uint64_t PtraceTarget::address_space_id() {
  return generation_;
}

bool PtraceTarget::peek_byte(uint64_t addr, uint8_t* byte) {
  uint64_t word_addr = addr & ~7ULL;
  errno = 0;
  long word = ptrace(PTRACE_PEEKTEXT, pid_, (void*)word_addr, nullptr);
  if (word == -1 && errno) {
    return false;
  }
  *byte = ((uint8_t*)&word)[addr - word_addr];
  return true;
}

bool PtraceTarget::poke_byte(uint64_t addr, uint8_t byte) {
  uint64_t word_addr = addr & ~7ULL;
  errno = 0;
  long word = ptrace(PTRACE_PEEKTEXT, pid_, (void*)word_addr, nullptr);
  if (word == -1 && errno) {
    return false;
  }
  ((uint8_t*)&word)[addr - word_addr] = byte;
  return ptrace(PTRACE_POKETEXT, pid_, (void*)word_addr, (void*)word) == 0;
}

bool PtraceTarget::add_breakpoint(uint64_t addr) {
  if (exited_ || bps_.count(addr)) {
    return false;
  }
  uint8_t orig;
  if (!peek_byte(addr, &orig) || !poke_byte(addr, 0xCC)) {
    return false;
  }
  bps_[addr] = orig;
  return true;
}

void PtraceTarget::remove_breakpoint(uint64_t addr) {
  auto it = bps_.find(addr);
  if (it == bps_.end()) {
    return;
  }
  if (!exited_) {
    poke_byte(addr, it->second);
  }
  bps_.erase(it);
}

PtraceTarget::Stop PtraceTarget::wait_stop() {
  int status;
  while (waitpid(pid_, &status, 0) < 0) {
    if (errno != EINTR) {
      exited_ = true;
      return {StopKind::Exited, 0, -1};
    }
  }
  if (WIFEXITED(status)) {
    exited_ = true;
    exit_code_ = WEXITSTATUS(status);
    return {StopKind::Exited, 0, exit_code_};
  }
  if (WIFSIGNALED(status)) {
    exited_ = true;
    exit_code_ = -WTERMSIG(status);
    return {StopKind::Exited, 0, exit_code_};
  }
  int sig = WSTOPSIG(status);
  if (sig == SIGTRAP && (status >> 16) == PTRACE_EVENT_EXEC) {
    generation_++;
    bps_.clear();  // the old image is gone
    return {StopKind::Exec, 0, 0};
  }
  if (sig == SIGTRAP) {
    // A single-step trap is TRAP_TRACE; an int3 we planted is SI_KERNEL
    // with ip just past it. Telling them apart by si_code matters: after
    // stepping a one-byte instruction at a breakpoint, ip-1 is that
    // breakpoint too.
    siginfo_t si;
    bool stepped = ptrace(PTRACE_GETSIGINFO, pid_, nullptr, &si) == 0 && si.si_code == TRAP_TRACE;
    uint64_t ip = regs().ip();
    if (!stepped && ip && bps_.count(ip - 1)) {
      set_ip(ip - 1);
      return {StopKind::Breakpoint, ip - 1, 0};
    }
    return {StopKind::Signal, 0, SIGTRAP};  // single-step or other trap
  }
  pending_signal_ = sig;
  return {StopKind::Signal, 0, sig};
}

bool PtraceTarget::step_over_breakpoint() {
  uint64_t ip = regs().ip();
  auto it = bps_.find(ip);
  if (it == bps_.end()) {
    return true;
  }
  uint8_t orig = it->second;
  poke_byte(ip, orig);
  int sig = pending_signal_;
  pending_signal_ = 0;
  if (ptrace(PTRACE_SINGLESTEP, pid_, nullptr, (void*)(uintptr_t)sig) < 0) {
    return false;
  }
  Stop s = wait_stop();
  if (s.kind == StopKind::Exited) {
    return false;
  }
  if (bps_.count(ip)) {  // still wanted (not removed by exec)
    poke_byte(ip, 0xCC);
  }
  return true;
}

StepStatus PtraceTarget::step() {
  if (exited_) {
    return StepStatus::Exited;
  }
  if (bps_.count(regs().ip())) {
    return step_over_breakpoint() ? StepStatus::Stopped : StepStatus::Exited;
  }
  int sig = pending_signal_;
  pending_signal_ = 0;
  if (ptrace(PTRACE_SINGLESTEP, pid_, nullptr, (void*)(uintptr_t)sig) < 0) {
    exited_ = true;
    return StepStatus::Exited;
  }
  Stop s = wait_stop();
  return s.kind == StopKind::Exited ? StepStatus::Exited : StepStatus::Stopped;
}

PtraceTarget::Stop PtraceTarget::cont() {
  if (exited_) {
    return {StopKind::Exited, 0, exit_code_};
  }
  if (bps_.count(regs().ip()) && !step_over_breakpoint()) {
    return {StopKind::Exited, 0, exit_code_};
  }
  int sig = pending_signal_;
  pending_signal_ = 0;
  if (ptrace(PTRACE_CONT, pid_, nullptr, (void*)(uintptr_t)sig) < 0) {
    exited_ = true;
    return {StopKind::Exited, 0, -1};
  }
  return wait_stop();
}

}  // namespace hpobs
