/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "DetachHandOff.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <set>
#include <vector>

#include "AddressSpace.h"
#include "AutoRemoteSyscalls.h"
#include "RrTaskTarget.h"
#include "hpobs/symbols.h"
#include "FdTable.h"
#include "ReplayTask.h"
#include "core.h"
#include "log.h"
#include "preload/preload_interface.h"
#include "rr/rr.h"

using namespace std;

namespace rr {

// An executable mapping of a file on disk: the only kind rr patches code in.
static bool is_exec_file_mapping(const KernelMapping& km) {
  return (km.prot() & PROT_EXEC) && !km.fsname().empty() &&
         km.fsname()[0] == '/';
}

// rr patches code in the tracee while it replays (syscall buffering hooks and
// the like). Put back the bytes of the files the code was mapped from, so
// the branch runs the program's own code.
static void restore_patched_code(Task* t) {
  for (const auto& m : t->vm()->maps()) {
    const KernelMapping& km = m.map;

    if (!is_exec_file_mapping(km)) {
      continue;
    }
    ScopedFd fd(km.fsname().c_str(), O_RDONLY);
    if (!fd.is_open()) {
      continue;
    }

    std::vector<uint8_t> file(km.size());
    ssize_t n = pread(fd, file.data(), file.size(), km.file_offset_bytes());
    if (n <= 0) {
      continue;
    }
    std::vector<uint8_t> mem(n);
    t->read_bytes_helper(km.start().cast<uint8_t>(), n, mem.data());
    for (ssize_t i = 0; i < n;) {
      if (mem[i] == file[i]) {
        ++i;
        continue;
      }
      ssize_t j = i;
      while (j < n && mem[j] != file[j]) {
        ++j;
      }
      t->write_bytes_helper(km.start().cast<uint8_t>() + i, j - i, &file[i]);

      LOG(debug) << "restored " << (j - i) << " patched bytes at "
                 << HEX(km.start().as_int() + i) << " in " << km.fsname();
      i = j;
    }
  }
}

bool open_branch_stdio(const string& dir, size_t k, FdModel& model,
                       ScopedFd& in, ScopedFd& out, string& stdio_note) {
  if (dir.empty()) {
    return true;
  }
  char base[PATH_MAX];
  snprintf(base, sizeof base, "%s/branch-%zu", dir.c_str(), k);
  string fifo = string(base) + ".stdin", log = string(base) + ".log";

  struct stat st;
  if (stat(fifo.c_str(), &st) < 0 || !S_ISFIFO(st.st_mode)) {
    unlink(fifo.c_str());
    if (mkfifo(fifo.c_str(), 0600) < 0) {
      fprintf(stderr, "rr detach: mkfifo %s: %s\n", fifo.c_str(), strerror(errno));
      return false;
    }
  }
  in = ScopedFd(open(fifo.c_str(), O_RDWR | O_CLOEXEC));
  out = ScopedFd(open(log.c_str(), O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644));
  if (!in.is_open() || !out.is_open()) {
    fprintf(stderr, "rr detach: can't open %s: %s\n", base, strerror(errno));
    return false;
  }
  model.set_stdio_target(0, &in);
  model.set_stdio_target(1, &out);
  model.set_stdio_target(2, &out);
  stdio_note = string(" stdio ") + base;
  return true;
}

// CRRIU_TRACE: a few addresses whose first bytes are shown at hand-off.
struct TraceSpot {
  const char* name;
  uintptr_t addr;
};

int hand_off(ReplaySession& session, ReplayModels& m, bool strict,
             FrameTime stopped_at, const char* tag) {
  detach_init_logging();
  // 2. Collect tasks.
  vector<Task*> tasks;
  for (auto& it : session.tasks()) {
    tasks.push_back(it.second);
  }

  if (tasks.empty()) {
    fprintf(stderr, "rr detach: no tasks to detach\n");
    return 1;
  }

  pid_t real_pid = tasks[0]->tid;

  for (const string& f : m.check.run(tasks, m.fd)) {
    fprintf(stderr, "rr detach: %s%s\n", strict ? "" : "warning: ", f.c_str());
    if (strict) {
      return 1;
    }
  }

  m.fd.forget_materialized();

  // 3. Close rr-internal FDs once per shared file table.
  std::set<FdTable*> done_tables;
  int close_failures = 0;

  std::set<const void*> restored_tables;

  // Restore working directories before recreating file descriptors.
  for (Task* t : tasks) {
    if (!m.fd.apply_cwd(t)) {
      fprintf(stderr,
              "rr detach: failed to restore cwd for tid=%d\n",
              t->rec_tid);
      return 1;
    }
  }

  for (Task* t : tasks) {
    const void* table_id = m.fd.table_id(t);

    if (!restored_tables.insert(table_id).second) {
      continue;
    }

    if (!m.fd.materialize(t)) {
      fprintf(stderr,
              "rr detach: failed to recreate fds for tid=%d\n",
              t->rec_tid);
      return 1;
    }
  }

  for (Task* t : tasks) {
    if (!m.sigs.materialize(t)) {
      fprintf(stderr, "rr detach: failed to restore signal state\n");
      return 1;
    }
  }

  for (Task* t : tasks) {
    FdTable* table = t->fd_table().get();
    if (!done_tables.insert(table).second) {
      continue;
    }

    vector<int> rr_fds;
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/fd", t->tid);

    DIR* d = opendir(path);
    if (!d) {
      FATAL() << "Can't read " << path;
    }

    while (dirent* e = readdir(d)) {
      if (e->d_name[0] == '.') {
        continue;
      }

      int fd = atoi(e->d_name);
      if (table->is_rr_fd(fd) || fd == RR_MAGIC_SAVE_DATA_FD) {
        rr_fds.push_back(fd);
      }
    }
    closedir(d);

    Registers before = t->regs();

    {
      AutoRemoteSyscalls remote(t);
      for (int fd : rr_fds) {
        long ret = remote.syscall(
            syscall_number_for_close(t->arch()), fd);

        if (ret < 0) {
          fprintf(stderr, "tid %d: close(%d) failed: %s\n",
                  t->tid, fd, strerror(-ret));
          close_failures++;
        } else {
          LOG(debug) << "tid " << t->tid << ": closed rr fd " << fd;
        }
      }
    }

    DEBUG_ASSERT(t->regs().ip() == before.ip() &&
                 t->regs().sp() == before.sp());
  }

  if (close_failures) {
    fprintf(stderr,
            "rr detach: %d rr fd(s) could not be closed\n",
            close_failures);
    return 1;
  }

  // 4. Restore registers and detach all tasks.
  std::set<AddressSpace*> unpatched;
  for (Task* t : tasks) {
    t->set_in_diversion(true);

    if (unpatched.insert(t->vm().get()).second) {
      restore_patched_code(t);
    }
    t->write_mem(remote_ptr<unsigned char>(RR_PAGE_IN_REPLAY_FLAG), (unsigned char)0);

    t->reenable_cpuid_tsc();

    // Replay never lets a syscall actually execute, but the tracee may be
    // parked in a syscall-entry stop; clearing orig_rax stops the kernel
    // from treating the detach as a syscall return (which would clobber rax).
    Registers regs = t->regs();
    if (regs.syscall_result_signed() == -ENOSYS && regs.original_syscallno() >= 0) {

      regs.set_syscall_result(regs.original_syscallno());
      regs.set_ip(regs.ip() - 2);   // x86-64 `syscall` is 2 bytes

      LOG(debug) << "tid " << t->tid << ": rewound to re-execute syscall "
                 << regs.original_syscallno();
    }
    regs.set_original_syscallno(-1);
    t->set_regs(regs);

    bool flushed = t->flush_regs();
    LOG(debug) << "tid " << t->tid << ": flushed=" << flushed
               << " ip=" << t->ip();
  }

  // CRRIU_TRACE: exactly what is handed off (after the register fix-ups
  // above), to compare with a debugger attached to the branch.
  if (detach_trace_enabled()) {
    static hpobs::SymbolMaps symbols;
    for (Task* t : tasks) {
      const Registers& r = t->regs();
      RrTaskTarget tgt(session, t);
      symbols.build(tgt);
      fprintf(stderr, "handoff tid %d rec_tid %d ip %#lx (%s) sp %#lx arg1 %#lx arg2 %#lx arg3 %#lx\n",
              t->tid, t->rec_tid, (unsigned long)r.ip().register_value(),
              symbols.lookup(tgt, r.ip().register_value()).c_str(), (unsigned long)r.sp().as_int(),
              (unsigned long)r.arg1(), (unsigned long)r.arg2(), (unsigned long)r.arg3());

      const TraceSpot spots[] = {
        { "ip", r.ip().register_value() },
        { "sp", r.sp().as_int() },
        { "arg2", r.arg2() },
      };

      for (const TraceSpot& spot : spots) {
        uint8_t b[16];
        bool ok = true;
        t->read_bytes_helper(remote_ptr<void>(spot.addr), sizeof b, b, &ok);
        fprintf(stderr, "  mem[%s=%#lx]:", spot.name, (unsigned long)spot.addr);
        if (!ok) {
            fprintf(stderr, " unreadable\n");
            continue;
        }
        for (uint8_t x : b) {
          fprintf(stderr, " %02x", x);
        }
        fprintf(stderr, "\n");
      }
    }
  }

  // 4b. Release all tasks, stopped.
  for (Task* t : tasks) {
    errno = 0;
    long r = t->fallible_ptrace(
        PTRACE_DETACH, nullptr, (void*)(uintptr_t)SIGSTOP);

    LOG(debug) << "detach tid " << t->tid << ": ret=" << r;

    if (r < 0) {
      fprintf(stderr, "rr detach: failed to detach tid %d\n", t->tid);
      return 1;
    }
  }

  session.forget_tasks();

  printf("detached pid %d after event %lld (%zu threads)%s\n",
          real_pid, (long long)stopped_at, tasks.size(), tag);
  fflush(stdout);
  return 0;
}

} // namespace rr
