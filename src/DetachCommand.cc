/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include <signal.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "Command.h"
#include "ReplaySession.h"
#include "ReplayTask.h"
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
  DetachFlags() : event(0) {}
};

static bool parse_detach_arg(vector<string>& args, DetachFlags& flags) {
  if (parse_global_option(args)) {
    return true;
  }
  static const OptionSpec options[] = {
    { 'e', "event", HAS_PARAMETER },
  };
  ParsedOption opt;
  if (!Command::parse_option(args, options, &opt)) {
    return false;
  }
  switch (opt.short_name) {
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

  // 1. Replay until we reach the target event.
  while (session->trace_reader().time() < flags.event) {
    auto result = session->replay_step(RUN_CONTINUE);
    if (result.status == REPLAY_EXITED) {
      fprintf(stderr, "rr detach: trace ended before event %lld\n",
              (long long)flags.event);
      return 1;
    }
  }
  FrameTime reached = session->trace_reader().time();

  // 2. Collect tasks.
  vector<Task*> tasks;
  for (auto& it : session->tasks()) {
    tasks.push_back(it.second);
  }
  pid_t real_pid = tasks[0]->tid;

  for (Task* t : tasks) {
    t->reenable_cpuid_tsc();
    // rr parks the real PC inside rr_page during syscall emulation and keeps
    // the logical registers cached. Push the cached state into the kernel.
    t->set_regs(t->regs());
    bool flushed = t->flush_regs();
    fprintf(stderr, "tid %d flush=%d ip=%p\n", t->tid, flushed,
            (void*)t->ip().register_value());
    errno = 0;
    long r = t->fallible_ptrace(PTRACE_DETACH, nullptr, (void*)(uintptr_t)SIGSTOP);
    fprintf(stderr, "detach tid %d: ret=%ld errno=%d (%s)\n",
            t->tid, r, errno, strerror(errno));
  }


  printf("detached pid %d at event %lld (%zu threads)\n",
         real_pid, (long long)reached, tasks.size());
  fflush(stdout);

  // 3. Stay alive: if rr exits, the tracees (our children) may be reaped.
  // TODO: find a cleaner hand-off (reparenting or not destroying the session).
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
