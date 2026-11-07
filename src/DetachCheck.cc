#include "DetachCheck.h"
#include "Task.h"
#include "TraceFrame.h"
#include "kernel_abi.h"
#include "kernel_metadata.h"
#include "log.h"
using namespace std;
namespace rr {

void DetachCheck::observe(const TraceFrame& frame, Task* t) {
  if (!frame.event().is_syscall_event()) return;
  const auto& ev = frame.event().Syscall();
  last[t->rec_tid] = { ev.number, ev.state == EXITING_SYSCALL, (int64_t)frame.time(),
                       (long)frame.regs().arg1_signed() };
}

// Syscalls whose EXITING state leaves nothing in the kernel that the models
// don't already recreate, or that replay executes for real anyway.
static bool exit_effect_covered(int no, SupportedArch a) {
  return
    // FdModel
    is_open_syscall(no,a) || is_openat_syscall(no,a) || is_close_syscall(no,a) ||
    is_dup_syscall(no,a) || is_dup2_syscall(no,a) || is_dup3_syscall(no,a) ||
    is_lseek_syscall(no,a) || is_read_syscall(no,a) || is_write_syscall(no,a) ||
    is_chdir_syscall(no,a) || is_eventfd2_syscall(no,a) || is_signalfd4_syscall(no,a) ||
    is_epoll_create1_syscall(no,a) || is_epoll_ctl_syscall(no,a) ||
    // SignalModel
    is_rt_sigprocmask_syscall(no,a) || is_rt_sigaction_syscall(no,a) ||
    // executed for real during replay
    is_mmap_syscall(no,a) || is_munmap_syscall(no,a) || is_mprotect_syscall(no,a) ||
    is_brk_syscall(no,a) || is_madvise_syscall(no,a) || is_mremap_syscall(no,a) ||
    // no persistent kernel state
    is_futex_syscall(no,a) || is_nanosleep_syscall(no,a) || is_clock_nanosleep_syscall(no,a) ||
    is_ppoll_syscall(no,a) || is_poll_syscall(no,a) || is_epoll_wait_syscall(no,a) ||
    is_epoll_pwait_syscall(no,a) || is_sched_yield_syscall(no,a) ||
    is_clock_gettime_syscall(no,a) || is_gettimeofday_syscall(no,a) ||
    is_getpid_syscall(no,a) || is_gettid_syscall(no,a) || is_getrandom_syscall(no,a) ||
    is_rt_sigreturn_syscall(no,a) || is_set_robust_list_syscall(no,a) ||
    is_fstat_syscall(no,a) || is_stat_syscall(no,a) || is_fstatat_syscall(no,a) ||
    is_statx_syscall(no,a) || is_access_syscall(no,a) || is_readlink_syscall(no,a) ||
    is_uname_syscall(no,a) || is_getrlimit_syscall(no,a) || is_prlimit64_syscall(no,a);
}

// Writes to stdout/stderr are echoed by the replay session itself.
static bool stdio_write(int no, long fd, SupportedArch a) {
  return (fd == 1 || fd == 2) &&
         (is_write_syscall(no,a) || is_writev_syscall(no,a) || is_pwritev_syscall(no,a));
}

vector<string> DetachCheck::run(const vector<Task*>& tasks, const FdModel& model) {
  vector<string> out;
  for (Task* t : tasks) {
    auto it = last.find(t->rec_tid);
    if (it != last.end() && it->second.exiting &&
      !exit_effect_covered(it->second.number, t->arch()) &&
      !stdio_write(it->second.number, it->second.fd, t->arch())) {
      out.push_back("tid " + to_string(t->rec_tid) + ": kernel effect of " +
                    syscall_name(it->second.number, t->arch()) + " (event " +
                    to_string(it->second.time) + ") is not reflected");
    }
    for (const auto& kv : model.fds(t)) {
      if (kv.second->type == FdModel::OpenFile::UNSUPPORTED) {
        out.push_back("tid " + to_string(t->rec_tid) + ": fd " + to_string(kv.first) +
                      " from " + kv.second->origin + " cannot be recreated");
      }
    }
  }
  return out;
}
}
