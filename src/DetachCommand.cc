/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include <dirent.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <set>

#include "AutoRemoteSyscalls.h"
#include "Command.h"
#include "FdModel.h"
#include "FdTable.h"
#include "ReplaySession.h"
#include "ReplayTask.h"
#include "rr/rr.h"
#include "core.h"
#include "log.h"
#include "main.h"

using namespace std;

namespace rr {

class DetachCommand : public Command {
public:
  virtual int run(vector<string>& args) override;

protected:
  DetachCommand(const char* name, const char* help) : Command(name, help) {}
  static DetachCommand singleton;
};

DetachCommand DetachCommand::singleton(
    "detach",
    " rr detach [OPTION]... [<trace-dir>]\n"
    "  Replay to a given event, then detach from all tracees, leaving\n"
    "  them SIGSTOPped so another tracer (e.g. CRIU) can seize them.\n"
    "  -e, --event=<EVENT>        event number to stop and detach at\n");

struct DetachFlags {
  FrameTime event;
  string cwd;
  DetachFlags() : event(0) {}
};

static bool parse_detach_arg(vector<string>& args, DetachFlags& flags) {
  if (parse_global_option(args)) {
    return true;
  }
  static const OptionSpec options[] = {
    { 'c', "cwd", HAS_PARAMETER },
    { 'e', "event", HAS_PARAMETER },
  };
  ParsedOption opt;
  if (!Command::parse_option(args, options, &opt)) {
    return false;
  }
  switch (opt.short_name) {
    case 'c':
      flags.cwd = opt.value;
      break;
    case 'e':
      if (!opt.verify_valid_int(1, INT64_MAX)) {
        return false;
      }
      flags.event = opt.int_value;
      break;
    default:
      DEBUG_ASSERT(0 && "Unknown option");
  }
  return true;
}

static int detach(const string& trace_dir, const DetachFlags& flags) {
  ReplaySession::Flags session_flags;
  ReplaySession::shr_ptr session =
      ReplaySession::create(trace_dir, session_flags);

  //FdModel model(session->trace_reader().initial_cwd());
  string cwd = flags.cwd;
  if (!cwd.empty() && cwd[0] != '/') {
    fprintf(stderr,
            "rr detach: --cwd requires an absolute path\n");
    return 1;
 }

  if (cwd.empty()) {
    char link[64], buf[PATH_MAX];
    snprintf(link, sizeof link, "/proc/%d/cwd", session->current_task()->tid);
    ssize_t n = readlink(link, buf, sizeof buf - 1);

    if (n < 0) {
      fprintf(stderr, "rr detach: can't read tracee cwd: %s\n", strerror(errno)); return 1;
    }
    cwd.assign(buf, n);
    fprintf(stderr, "rr detach: assuming recording cwd %s; pass --cwd if different\n", cwd.c_str());
  }
  FdModel model(cwd);

  // 1. Replay until event `flags.event` has been fully replayed, i.e. the
  //    trace reader has moved past it.
  while (session->trace_reader().time() <= flags.event) {
    auto result = session->replay_step(RUN_CONTINUE);
    if (result.status == REPLAY_EXITED) {
      fprintf(stderr, "rr detach: trace ended before event %lld\n",
              (long long)flags.event);
      return 1;
    }
    Task* cur = session->current_task();
    if (cur)
      model.observe(session->current_trace_frame(), cur);
  }

  // 모델 덤프 (검증용)
  for (auto& kv : model.fds())
    fprintf(stderr, "fd %d -> %s flags=%#x off=%lld\n", kv.first,
            kv.second->path.c_str(), kv.second->flags, (long long)kv.second->offset);

  // 2. Collect tasks.
  vector<Task*> tasks;
  for (auto& it : session->tasks()) {
    tasks.push_back(it.second);
  }

  if (tasks.empty()) {
    fprintf(stderr, "rr detach: no tasks to detach\n");
    return 1;
  }

  pid_t real_pid = tasks[0]->tid;

  // 3. Close rr-internal FDs once per shared file table.
  std::set<FdTable*> done_tables;
  int close_failures = 0;

  for (Task* t : tasks) {
    FdTable* table = t->fd_table().get();
    if (!done_tables.insert(table).second)
      continue;

    vector<int> rr_fds;
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/fd", t->tid);

    DIR* d = opendir(path);
    if (!d)
      FATAL() << "Can't read " << path;

    while (dirent* e = readdir(d)) {
      if (e->d_name[0] == '.')
        continue;

      int fd = atoi(e->d_name);
      if (table->is_rr_fd(fd) || fd == RR_MAGIC_SAVE_DATA_FD)
        rr_fds.push_back(fd);
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
          fprintf(stderr, "tid %d: closed rr fd %d\n",
                  t->tid, fd);
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

  // Reconstruct the tracee's modeled file descriptors before detach.
  for (Task* t : tasks) {
    if (!model.apply_cwd(t) || !model.materialize(t)) {
      fprintf(stderr, "rr detach: failed to recreate fds\n");
      return 1;
    }
    break;   // one shared fd table for now; TODO per-FdTable like step 3
  }

  // 4. Restore registers and detach all tasks.
  for (Task* t : tasks) {
    t->reenable_cpuid_tsc();

    // Replay never lets a syscall actually execute, but the tracee may be
    // parked in a syscall-entry stop; clearing orig_rax stops the kernel
    // from treating the detach as a syscall return (which would clobber rax).
    Registers regs = t->regs();
    regs.set_original_syscallno(-1);
    t->set_regs(regs);

    fprintf(stderr, "tid %d logical rax=%llx orig=%llx\n", t->tid,
            (unsigned long long)regs.syscall_result(),
            (unsigned long long)regs.original_syscallno());

    bool flushed = t->flush_regs();
    fprintf(stderr, "tid %d flush=%d ip=%p\n",
            t->tid, flushed,
            (void*)t->ip().register_value());

    errno = 0;
    long r = t->fallible_ptrace(
        PTRACE_DETACH, nullptr, (void*)(uintptr_t)SIGSTOP);

    fprintf(stderr, "detach tid %d: ret=%ld errno=%d (%s)\n",
            t->tid, r, errno, strerror(errno));

    if (r < 0) {
      fprintf(stderr, "rr detach: failed to detach tid %d\n", t->tid);
      return 1;
    }
  }

  printf("detached pid %d after event %lld (%zu threads)\n",
       real_pid, (long long)flags.event, tasks.size());
  fflush(stdout);

  // 5. Keep rr alive until the tracees are handed off.
  while (true) {
    pause();
  }

  return 0;
}

int DetachCommand::run(vector<string>& args) {
  DetachFlags flags;
  while (parse_detach_arg(args, flags)) {
  }
  if (!flags.event) {
    print_help(stderr);
    return 1;
  }
  string trace_dir;
  if (!parse_optional_trace_dir(args, &trace_dir)) {
    print_help(stderr);
    return 1;
  }
  assert_prerequisites();
  return detach(trace_dir, flags);
}

} // namespace rr
