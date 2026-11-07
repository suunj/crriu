/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include <dirent.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <set>
#include <fstream>

#include "AutoRemoteSyscalls.h"
#include "Command.h"
#include "FdModel.h"
#include "FdTable.h"
#include "SignalModel.h"
#include "DetachCheck.h"
#include "ReplaySession.h"
#include "ReplayTask.h"
#include "AddressSpace.h"
#include "rr/rr.h"
#include "preload/preload_interface.h"
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
  bool strict;
  string until_output;
  DetachFlags() : event(0), strict(false) {}
};

static bool parse_detach_arg(vector<string>& args, DetachFlags& flags) {
  if (parse_global_option(args)) {
    return true;
  }
  static const OptionSpec options[] = {
    { 'c', "cwd", HAS_PARAMETER },
    { 's', "strict", NO_PARAMETER },
    { 'e', "event", HAS_PARAMETER },
    { 'u', "until-output", HAS_PARAMETER },
  };
  ParsedOption opt;
  if (!Command::parse_option(args, options, &opt)) {
    return false;
  }
  switch (opt.short_name) {
    case 'c':
      flags.cwd = opt.value;
      break;
    case 's':
      flags.strict = true;
      break;
    case 'e':
      if (!opt.verify_valid_int(1, INT64_MAX)) {
        return false;
      }
      flags.event = opt.int_value;
      break;
    case 'u':
      flags.until_output = opt.value;
      break;
    default:
      DEBUG_ASSERT(0 && "Unknown option");
  }
  return true;
}

static void restore_patched_code(Task* t) {
  for (const auto& m : t->vm()->maps()) {
    const KernelMapping& km = m.map;

    if (!(km.prot() & PROT_EXEC) || km.fsname().empty() || km.fsname()[0] != '/') {
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

static int detach(const string& trace_dir, const DetachFlags& flags) {
  ReplaySession::Flags session_flags;
  session_flags.preserve_thread_groups = true;
  // Echo recorded stdout/stderr writes during replay so that console output
  // up to the detach point ends up where the tracee's stdio points.
  session_flags.redirect_stdio = true;
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
  model.init_task(session->current_task());

  session->on_task_cloned =
    [&](Task* parent, Task* child, int flags) {
      model.fork_task(parent, child, flags);
    };

  SignalModel sigs;
  DetachCheck check;

  // 1. Replay until event `flags.event` has been fully replayed, i.e. the
  //    trace reader has moved past it.
  FrameTime stop_at = flags.event;
  string seen;
  bool hit = false;

  if (!flags.until_output.empty()) {
    stop_at = INT64_MAX;
    session->on_stdio_output = [&](int, const vector<uint8_t>& b) {
      if (hit)
        return;

      seen.append(b.begin(), b.end());

      if (seen.find(flags.until_output) != string::npos)
        hit = true;
      if (seen.size() > 65536)
        seen.erase(0, seen.size() - 32768);
    };
  }

  FrameTime stopped_at = 0;
  while (session->trace_reader().time() <= stop_at) {
    // current_trace_frame() is the frame about to be replayed; feed it to
    // the models now so they stay exactly in step with what has run.
    if (Task* cur = session->current_task()) {
      model.observe(session->current_trace_frame(), cur);
      sigs.observe(session->current_trace_frame(), cur);
      check.observe(session->current_trace_frame(), cur);
    }
    auto result = session->replay_step(RUN_CONTINUE);
    if (result.status == REPLAY_EXITED) {
      fprintf(stderr, "rr detach: trace ended before %s\n",
              hit || flags.until_output.empty() ? "the target event" : "the output appeared");

      return 1;
    }
    // The reader has moved on to the next frame; the one just replayed is
    // the frame before it.
    stopped_at = session->trace_reader().time() - 1;
    if (hit)
      break;
  }

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

  // 2b. Is this state safe to hand to the kernel?
  for (const string& f : check.run(tasks, model)) {
    fprintf(stderr, "rr detach: %s%s\n", flags.strict ? "" : "warning: ", f.c_str());
    if (flags.strict) return 1;
  }

  // 3. Close rr-internal FDs once per shared file table.
  std::set<FdTable*> done_tables;
  int close_failures = 0;

  std::set<const void*> restored_tables;

  // Restore working directories before recreating file descriptors.
  for (Task* t : tasks) {
    if (!model.apply_cwd(t)) {
      fprintf(stderr,
              "rr detach: failed to restore cwd for tid=%d\n",
              t->rec_tid);
      return 1;
    }
  }

  for (Task* t : tasks) {
    const void* table_id = model.table_id(t);

    if (!restored_tables.insert(table_id).second)
      continue;

    if (!model.materialize(t)) {
      fprintf(stderr,
              "rr detach: failed to recreate fds for tid=%d\n",
              t->rec_tid);
      return 1;
    }
  }

  for (Task* t : tasks) {
    if (!sigs.materialize(t)) {
      fprintf(stderr, "rr detach: failed to restore signal state\n");
      return 1;
    }
  }

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

  printf("detached pid %d after event %lld (%zu threads)\n",
       real_pid, (long long)stopped_at, tasks.size());
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
  if (!flags.event && flags.until_output.empty()) {
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
