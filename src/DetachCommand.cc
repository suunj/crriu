/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <algorithm>
#include <string>
#include <vector>

#include "Command.h"
#include "DetachCheckpointStore.h"
#include "DetachHandOff.h"
#include "DetachModels.h"
#include "DetachReplay.h"
#include "DetachTarget.h"
#include "ReplaySession.h"
#include "ReplayTask.h"
#include "ScopedFd.h"
#include "core.h"
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
    " rr detach [OPTION]... -r TARGET... [<trace-dir>]\n"
    "  Replay to each TARGET and hand off a copy of the replayed processes\n"
    "  there, SIGSTOPped, as an independent branch: no longer traced, with\n"
    "  the recorded fds and signal state recreated. TARGET is an event\n"
    "  number (branch right after that frame) or SYM[:N] (the N-th entry of\n"
    "  function SYM, default 1). Targets behind the replay are served from\n"
    "  the checkpoint cache; rr stays alive holding it until SIGTERM/SIGINT.\n"
    "  -r, --resume-to=TARGET     branch here (repeatable)\n"
    "  -n, --clones=N             branches per target (default 1)\n"
    "  -o, --output-dir=DIR       per-branch stdio: DIR/branch-K.stdin (FIFO)\n"
    "                             and DIR/branch-K.log\n"
    "  -c, --cwd=DIR              cwd of the recording (default: current)\n"
    "  -s, --strict               refuse to branch where state can't be restored\n"
    "  -k, --checkpoint=EVENT     also keep a checkpoint at EVENT\n"
    "  -y, --cache-every=N        checkpoint every N events while replaying\n"
    "  -m, --cache-max=N          checkpoints kept besides the base (default 4)\n"
    "  -e, --exits                also stop where each watched call returns:\n"
    "                             log the return value, dump NAME.SYM.N.exit.bin\n"
    "  -f, --from=EVENT           replay natively (no breakpoints, no hit counting)\n"
    "                             until trace event EVENT, then start watching\n"
    "  -x, --access=SYM[:EVERY]   single-step every EVERY-th call of SYM to its\n"
    "                             return, logging each memory read/write to\n"
    "                             DIR/access.SYM.N.txt (needs capstone)\n"
    "  -d, --dump-mem=NAME:ADDR:LEN[:EVERY[:FROM]]\n"
    "                             at every EVERY-th hit of any watched SYM,\n"
    "                             dump LEN bytes at ADDR to\n"
    "                             DIR/NAME.SYM.<hit>.bin (DIR from -o)\n"
    "  CRRIU_TRACE=1 logs every replayed frame (event, ticks, rip symbol,\n"
    "  syscall result).\n");

struct DetachFlags {
  string cwd;
  bool strict;
  string output_dir;
  int clones;
  string checkpoint;            // -k
  vector<string> resume_to;     // -r
  FrameTime cache_every;
  size_t cache_max;
  vector<string> dumps;         // -d
  bool exits;                   // -e
  vector<string> access;        // -x
  long from_event = 0;          // -f
  DetachFlags() : strict(false), clones(1), cache_every(0), cache_max(4), exits(false) {}
};

static bool parse_detach_arg(vector<string>& args, DetachFlags& flags) {
  if (parse_global_option(args)) {
    return true;
  }
  static const OptionSpec options[] = {
    { 'c', "cwd", HAS_PARAMETER },
    { 's', "strict", NO_PARAMETER },
    { 'o', "output-dir", HAS_PARAMETER },
    { 'n', "clones", HAS_PARAMETER },
    { 'k', "checkpoint", HAS_PARAMETER },
    { 'r', "resume-to", HAS_PARAMETER },
    { 'y', "cache-every", HAS_PARAMETER },
    { 'm', "cache-max", HAS_PARAMETER },
    { 'd', "dump-mem", HAS_PARAMETER },
    { 'e', "exits", NO_PARAMETER },
    { 'x', "access", HAS_PARAMETER },
    { 'f', "from", HAS_PARAMETER }
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
    case 'o':
      flags.output_dir = opt.value;
      break;
    case 'n':
      flags.clones = opt.int_value;
      break;
    case 'k':
      flags.checkpoint = opt.value;
      break;
    case 'r':
      flags.resume_to.push_back(opt.value);
      break;
    case 'y':
      if (!opt.verify_valid_int(1, INT64_MAX))
          return false;
      flags.cache_every = opt.int_value;
      break;
    case 'm':
      if (!opt.verify_valid_int(1, 1024))
          return false;
      flags.cache_max = opt.int_value;
      break;
    case 'd':
      flags.dumps.push_back(opt.value);
      break;
    case 'e':
      flags.exits = true;
      break;
    case 'x':
      flags.access.push_back(opt.value);
      break;
    case 'f':
      flags.from_event = strtol(opt.value.c_str(), nullptr, 10);
      break;
    default:
      DEBUG_ASSERT(0 && "Unknown option");
  }
  return true;
}

static volatile sig_atomic_t stop_requested;
static void on_stop(int) { stop_requested = 1; }

// Stay alive until SIGTERM/SIGINT: cached checkpoints are our tracees and
// die with us, handed-off branches are on their own.
static void wait_for_stop() {
  struct sigaction sa = {};
  sa.sa_handler = on_stop;
  sigaction(SIGTERM, &sa, nullptr);
  sigaction(SIGINT, &sa, nullptr);
  sigset_t block, old;
  sigemptyset(&block);
  sigaddset(&block, SIGTERM);
  sigaddset(&block, SIGINT);
  sigprocmask(SIG_BLOCK, &block, &old);
  while (!stop_requested) {
    sigsuspend(&old);
  }
  sigprocmask(SIG_SETMASK, &old, nullptr);
  fprintf(stderr, "rr detach: exiting; branches stay, checkpoints are killed\n");
}

// Clone `src` (a checkpoint or the live replay) with its models, replay the
// clone on to `target` if that is still ahead, hand it off as branch
// `branch_no`.
static int branch_from(ReplaySession& src, const ReplayModels& models,
                       const Target& target, const DetachFlags& flags,
                       size_t branch_no, const char* how) {
  ReplaySession::shr_ptr b = src.clone();
  ReplayModels m = models.snapshot();          // counting continues from here
  FrameTime at = src.trace_reader().time() - 1;
  bool ahead = target.by_event() ? target.event > at
                                 : m.hits_of(target.symbol) < target.hit;
  if (ahead) {
    at = run_until(*b, m, target, nullptr, 0);
    if (at < 0) {
      fprintf(stderr, "rr detach: trace ended before '%s'\n", target.text.c_str());
      return 1;
    }
  }
  ScopedFd bin, bout;
  string stdio_note;
  if (!open_branch_stdio(flags.output_dir, branch_no, m.fd, bin, bout, stdio_note))
    return 1;
  char tag[PATH_MAX + 96];
  snprintf(tag, sizeof tag, " [branch %zu: '%s' %s]%s", branch_no, target.text.c_str(), how,
           stdio_note.c_str());
  int rc = hand_off(*b, m, flags.strict, at, tag);   // hand_off ends with forget_tasks()
  m.fd.clear_stdio_targets();
  return rc;
}

static int detach_cached(ReplaySession::shr_ptr session, ReplayModels& live,
                         const DetachFlags& flags) {
  CheckpointStore store(flags.cache_max);
  Watch& watch = live.watch;

  vector<Target> targets;
  for (const string& spec : flags.dumps)
      watch.dumps.push_back(parse_dump(spec));
  watch.dump_dir = flags.output_dir.empty() ? "crriu-dumps" : flags.output_dir;
  watch.track_exits = flags.exits;
  watch.from_event = flags.from_event;
  for (const string& spec : flags.access) {
    size_t colon = spec.rfind(':');
    string sym = colon == string::npos ? spec : spec.substr(0, colon);
    long every = colon == string::npos ? 1 : strtol(spec.c_str() + colon + 1, nullptr, 10);
    watch.access_every[sym] = every < 1 ? 1 : every;
    watch.symbols.push_back(sym);
  }

  Target ckpt;
  if (!flags.checkpoint.empty()) {
    ckpt = parse_target(flags.checkpoint);
    if (!ckpt.by_event())
        watch.symbols.push_back(ckpt.symbol);
  }
  for (const string& spec : flags.resume_to) {
    targets.push_back(parse_target(spec));
    if (!targets.back().by_event()) watch.symbols.push_back(targets.back().symbol);
  }
  store.set_pending(targets);
  std::sort(watch.symbols.begin(), watch.symbols.end());
  watch.symbols.erase(std::unique(watch.symbols.begin(), watch.symbols.end()),
                      watch.symbols.end());

  // Base checkpoint: first clone-safe point after the recorded program
  // exec'd. Every "behind" request can at worst start from here.
  session->on_task_cloned = [&](Task* p, Task* c, int f) { live.fd.fork_task(p, c, f); };
  while (!(session->done_initial_exec() && session->can_clone())) {
    if (Task* cur = session->current_task())
      live.observe(session->current_trace_frame(), cur);
    if (session->replay_step(RUN_CONTINUE).status == REPLAY_EXITED) {
      fprintf(stderr, "rr detach: trace ended before the program exec'd\n");
      return 1;
    }
  }
  store.take(*session, live, session->trace_reader().time() - 1);

  // -k TARGET: an explicit checkpoint (frame targets only; a function entry
  // is mid-frame and cannot be cloned).
  if (!flags.checkpoint.empty()) {
    if (!ckpt.by_event()) {
      fprintf(stderr, "rr detach: -k takes an event number\n");
      return 1;
    }
    FrameTime at = run_until(*session, live, ckpt, &store, flags.cache_every);
    if (at < 0) {
      fprintf(stderr, "rr detach: trace ended before the checkpoint\n");
      return 1;
    }
    store.take(*session, live, at);
  }

  size_t branch_no = 1;
  for (const Target& t : targets) {
    FrameTime pos = session->trace_reader().time() - 1;
    bool behind = t.by_event() ? t.event <= pos : live.hits_of(t.symbol) >= t.hit;
    ReplaySession* src = session.get();
    const ReplayModels* models = &live;
    char how[64] = "from the replay";

    if (behind) {
      Checkpoint* c = store.nearest_before(t);
      if (!c) {
        fprintf(stderr, "rr detach: '%s' is before the base checkpoint\n", t.text.c_str());
        return 1;
      }
      src = c->session.get();
      models = &c->models;
      snprintf(how, sizeof how, "from checkpoint %lld", (long long)c->time);
    } else {
      FrameTime at = run_until(*session, live, t, &store, flags.cache_every);
      if (at < 0) {
        fprintf(stderr, "rr detach: trace ended before '%s'\n", t.text.c_str());
        return 1;
      }
      if (t.by_event())                       // a function entry is mid-frame
        store.take(*session, live, at);
    }
    for (int k = 0; k < flags.clones; k++, branch_no++) {
      int rc = branch_from(*src, *models, t, flags, branch_no, how);
      if (rc)
        return rc;
    }
    store.pop_pending();
  }

  fprintf(stderr, "rr detach: %zu branch(es); %zu checkpoint(s) kept:\n", branch_no - 1, store.size());
  store.list(stderr);
  wait_for_stop();
  return 0;
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
  ReplayModels live{ FdModel(cwd), SignalModel(), DetachCheck(), Watch() };
  live.fd.init_task(session->current_task());
  session->on_task_cloned = [&](Task* parent, Task* child, int flags) {
    live.fd.fork_task(parent, child, flags);
  };

  return detach_cached(session, live, flags);
}

int DetachCommand::run(vector<string>& args) {
  DetachFlags flags;
  while (parse_detach_arg(args, flags)) {
  }
  if (flags.checkpoint.empty() && flags.resume_to.empty()) {
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
