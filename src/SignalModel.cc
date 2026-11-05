/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */
#include "SignalModel.h"

#include <signal.h>

#include "AutoRemoteSyscalls.h"
#include "Event.h"
#include "Task.h"
#include "TraceFrame.h"
#include "kernel_abi.h"
#include "log.h"

using namespace std;

namespace rr {

void SignalModel::observe(const TraceFrame& frame, Task* t) {
  if ((int64_t)frame.time() == last_time) return;
  last_time = frame.time();

  const Event& ev = frame.event();
  if (!ev.is_syscall_event()) return;
  const SyscallEvent& sc = ev.Syscall();
  if (sc.state != EXITING_SYSCALL) return;

  SupportedArch arch = sc.arch();
  const Registers& r = frame.regs();
  int no = sc.number;
  long ret = r.syscall_result_signed();
  long a0 = r.arg1_signed(), a1 = r.arg2_signed();

  if (no == syscall_number_for_rt_sigprocmask(arch)) {
    if (ret == 0 && a1) {
      uint64_t set = t->read_mem(remote_ptr<uint64_t>(a1));
      uint64_t& cur = blocked[t->rec_tid];
      switch ((int)a0) {
        case SIG_BLOCK:   cur |= set;  break;
        case SIG_UNBLOCK: cur &= ~set; break;
        case SIG_SETMASK: cur = set;   break;
      }
    }
  } else if (no == syscall_number_for_rt_sigaction(arch)) {
    if (ret == 0 && a1 && a0 > 0 && a0 < 65) {
      // x86-64 struct kernel_sigaction: handler, flags, restorer, mask
      Action& a = actions[a0];
      a.handler  = t->read_mem(remote_ptr<uint64_t>(a1));
      a.flags    = t->read_mem(remote_ptr<uint64_t>(a1 + 8));
      a.restorer = t->read_mem(remote_ptr<uint64_t>(a1 + 16));
      a.mask     = t->read_mem(remote_ptr<uint64_t>(a1 + 24));
      a.set = true;
    }
  }
}

bool SignalModel::materialize(Task* t) {
  SupportedArch arch = t->arch();
  AutoRemoteSyscalls remote(t);
  bool ok = true;

  auto it = blocked.find(t->rec_tid);
  if (it != blocked.end()) {
    AutoRestoreMem m(remote, &it->second, sizeof(uint64_t));
    long r = remote.syscall(syscall_number_for_rt_sigprocmask(arch),
                            SIG_SETMASK, m.get().as_int(), 0, 8);
    if (r != 0) { LOG(error) << "rt_sigprocmask -> " << r; ok = false; }
  }

  if (t->tid == t->real_tgid()) {
    for (int sig = 1; sig < 65; ++sig) {
      if (!actions[sig].set) continue;
      uint64_t ka[4] = { actions[sig].handler, actions[sig].flags,
                         actions[sig].restorer, actions[sig].mask };
      AutoRestoreMem m(remote, ka, sizeof ka);
      long r = remote.syscall(syscall_number_for_rt_sigaction(arch),
                              sig, m.get().as_int(), 0, 8);
      if (r != 0) { LOG(error) << "rt_sigaction(" << sig << ") -> " << r; ok = false; }
    }
  }
  return ok;
}

} // namespace rr
