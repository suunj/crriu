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
#include "ElfReader.h"
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
  string break_at;
  string output_dir;
  int clones;
  string checkpoint;            // -C
  vector<string> resume_to;     // -R
  DetachFlags() : event(0), strict(false), clones(1) {}
};

static bool parse_detach_arg(vector<string>& args, DetachFlags& flags) {
  if (parse_global_option(args)) {
    return true;
  }
  static const OptionSpec options[] = {
    { 'c', "cwd", HAS_PARAMETER },
    { 's', "strict", NO_PARAMETER },
    { 'e', "event", HAS_PARAMETER },
    { 'b', "break-at", HAS_PARAMETER },
    { 'o', "output-dir", HAS_PARAMETER },
    { 'n', "clones", HAS_PARAMETER },
    { 'k', "checkpoint", HAS_PARAMETER },
    { 'r', "resume-to", HAS_PARAMETER }
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
    case 'b':
      flags.break_at = opt.value;
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

static bool open_branch_stdio(const string& dir, size_t k, FdModel& model,
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

static FrameTime run_until(ReplaySession& s, FdModel& model, SignalModel& sigs,
                           DetachCheck& check, const string& target) {
  bool by_event = !target.empty() &&
                  target.find_first_not_of("0123456789") == string::npos;
  FrameTime event = by_event ? strtoll(target.c_str(), nullptr, 10) : 0;

  string seen;
  bool hit = false;
  s.on_stdio_output = nullptr;
  if (!by_event) {
    s.on_stdio_output = [&](int, const vector<uint8_t>& b) {
      if (hit)
        return;
      seen.append(b.begin(), b.end());
      if (seen.find(target) != string::npos)
        hit = true;
      if (seen.size() > 65536)
        seen.erase(0, seen.size() - 32768);
    };
  }
  s.on_task_cloned = [&](Task* parent, Task* child, int flags) {
    model.fork_task(parent, child, flags);
  };

  FrameTime stopped_at = -1;
  while (true) {
    if (Task* cur = s.current_task()) {
      model.observe(s.current_trace_frame(), cur);
      sigs.observe(s.current_trace_frame(), cur);
      check.observe(s.current_trace_frame(), cur);
    }
    auto result = s.replay_step(RUN_CONTINUE);
    if (result.status == REPLAY_EXITED) {
      stopped_at = -1;
      break;
    }
    stopped_at = s.trace_reader().time() - 1;
    if (by_event)
      hit = s.trace_reader().time() > event;
    if (hit && s.can_clone())
      break;
  }
  // The callbacks capture locals of this frame.
  s.on_stdio_output = nullptr;
  s.on_task_cloned = nullptr;
  return stopped_at;
}

static remote_code_ptr resolve_break(Task* t, const string& spec, string& where) {
  if (spec.compare(0, 2, "0x") == 0) {
    where = spec;
    return remote_code_ptr(strtoull(spec.c_str(), nullptr, 16));
  }
  for (const auto& m : t->vm()->maps()) {
    const KernelMapping& km = m.map;
    if (!(km.prot() & PROT_EXEC) || km.fsname().empty() || km.fsname()[0] != '/')
      continue;
    ScopedFd fd(km.fsname().c_str(), O_RDONLY);
    if (!fd.is_open())
      continue;
    ElfFileReader reader(fd);
    SymbolTable syms = reader.read_symbols(".symtab", ".strtab");
    for (size_t i = 0; i < syms.size(); i++) {
      if (!syms.is_name(i, spec.c_str()) || !syms.addr(i))
        continue;
      // load base: the mapping of this file at file offset 0
      uintptr_t base = 0;
      for (const auto& m2 : t->vm()->maps()) {
        if (m2.map.fsname() == km.fsname() && m2.map.file_offset_bytes() == 0) {
          base = m2.map.start().as_int();
          break;
        }
      }
      uintptr_t addr = syms.addr(i);
      if (addr < base)                 // PIE: symbol value is an offset
        addr += base;
      char buf[32];
      snprintf(buf, sizeof buf, " @ %#lx", (unsigned long)addr);
      where = spec + buf + " in " + km.fsname();
      return remote_code_ptr(addr);
    }
  }
  return remote_code_ptr();
}

static int hand_off(ReplaySession& session, FdModel& model, SignalModel& sigs,
                    DetachCheck& check, const DetachFlags& flags,
                    FrameTime stopped_at, const char* tag) {
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

  for (const string& f : check.run(tasks, model)) {
    fprintf(stderr, "rr detach: %s%s\n", flags.strict ? "" : "warning: ", f.c_str());
    if (flags.strict) return 1;
  }

  model.forget_materialized();

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


  printf("detached pid %d after event %lld (%zu threads)%s\n",
          real_pid, (long long)stopped_at, tasks.size(), tag);
  fflush(stdout);
  return 0;
}

static int detach_from_checkpoint(ReplaySession::shr_ptr session, FdModel& model,
                                  SignalModel& sigs, DetachCheck& check,
                                  const DetachFlags& flags) {
  FrameTime at = run_until(*session, model, sigs, check, flags.checkpoint);
  if (at < 0) {
    fprintf(stderr, "rr detach: trace ended before the checkpoint\n");
    return 1;
  }

  // The checkpoint: a session clone plus the models as they were here.
  ReplaySession::shr_ptr ckpt = session->clone();
  FdModel ckpt_model = model.snapshot();
  SignalModel ckpt_sigs = sigs;
  DetachCheck ckpt_check = check;
  printf("checkpoint at event %lld\n", (long long)at);
  fflush(stdout);

  vector<ReplaySession::shr_ptr> branches;
  // Models of handed-off branches must outlive hand_off; keep them here.
  vector<unique_ptr<FdModel>> branch_models;

  size_t branch_no = 1;
  for (const string& target : flags.resume_to) {
    ReplaySession::shr_ptr b = ckpt->clone();
    branches.push_back(b);
    branch_models.push_back(unique_ptr<FdModel>(new FdModel(ckpt_model.snapshot())));
    FdModel& bm = *branch_models.back();
    SignalModel bs = ckpt_sigs;
    DetachCheck bc = ckpt_check;

    FrameTime stopped_at = run_until(*b, bm, bs, bc, target);
    if (stopped_at < 0) {
      fprintf(stderr, "rr detach: trace ended before '%s'\n", target.c_str());
      return 1;
    }

    ScopedFd bin, bout;
    string stdio_note;
    if (!open_branch_stdio(flags.output_dir, branch_no, bm, bin, bout, stdio_note))
      return 1;
    char tag[PATH_MAX + 64];
    snprintf(tag, sizeof tag, " [branch %zu: resumed %lld -> '%s']%s", branch_no,
             (long long)at, target.c_str(), stdio_note.c_str());
    int rc = hand_off(*b, bm, bs, bc, flags, stopped_at, tag);
    bm.clear_stdio_targets();
    if (rc)
      return rc;
    branch_no++;
  }

  // ckpt and session stay alive (and stopped) until we are killed.
  while (true) {
    pause();
  }
  return 0;
}

// A branch that is handed off right away does not replay on, so ticks
// slop in the current frame (which can_clone() refuses) does not matter;
// only frames where tasks are going away are off limits.
static bool can_branch_now(ReplaySession& s) {
  if (!s.current_task() || !s.done_initial_exec())
    return false;
  switch (s.current_trace_frame().event().type()) {
    case EV_EXIT:
    case EV_SYSCALLBUF_RESET:
    case EV_TRACE_TERMINATION:
      return false;
    default:
      return true;
  }
}

static int detach_at_function(ReplaySession::shr_ptr session, FdModel& model,
                              SignalModel& sigs, DetachCheck& check,
                              const DetachFlags& flags) {
  string spec = flags.break_at;
  long first_hit = 1;
  size_t colon = spec.rfind(':');
  if (colon != string::npos && colon > 2) {        // "0x..:N" / "sym:N", not "::"
    first_hit = strtol(spec.c_str() + colon + 1, nullptr, 10);
    spec.erase(colon);
    if (first_hit < 1) first_hit = 1;
  }

  // The replay starts in rr's exec stub; the symbol becomes visible once
  // the recorded program has exec'd, i.e. the task's address space changed.
  remote_code_ptr addr;
  string where;
  AddressSpace* tried_vm = nullptr;
  auto try_resolve = [&]() {
      Task* t = session->current_task();
      if (!t || t->vm().get() == tried_vm)
          return false;
      tried_vm = t->vm().get();
      addr = resolve_break(t, spec, where);
      return !addr.is_null();
  };
  session->on_task_cloned = [&](Task* parent, Task* child, int f) {
    model.fork_task(parent, child, f);
  };
  while (!try_resolve()) {
    if (Task* cur = session->current_task()) {
      model.observe(session->current_trace_frame(), cur);
      sigs.observe(session->current_trace_frame(), cur);
      check.observe(session->current_trace_frame(), cur);
    }
    auto r = session->replay_step(RUN_CONTINUE);
    if (r.status == REPLAY_EXITED) {
        fprintf(stderr, "rr detach: can't resolve '%s' in any executable the trace ran\n", spec.c_str());
        return 1;
    }
  }
  fprintf(stderr, "rr detach: break at %s\n", where.c_str());

  vector<ReplaySession::shr_ptr> clones;
  long hits = 0;
  size_t branch_no = 1;
  int branches_left = flags.clones;            // the replay itself is the last one
  FrameTime stopped_at = 0;

  bool warned = false;
  while (true) {
      Task* cur = session->current_task();
      if (cur) {
          model.observe(session->current_trace_frame(), cur);
          sigs.observe(session->current_trace_frame(), cur);
          check.observe(session->current_trace_frame(), cur);
      }
      // Arm for this step only: rr remaps segments as it replays (exec,
      // mmap), which would wipe a permanently installed int3, and a clone
      // taken while it is armed would carry the int3 into the branch.
      AddressSpace::shr_ptr vm = cur ? cur->vm() : nullptr;
      bool armed = vm && vm->add_breakpoint(addr, BKPT_USER);
      if (!armed && !warned) {
          //fprintf(stderr, "rr detach: warning: can't arm breakpoint at %s yet\n", where.c_str());
          fprintf(stderr, "rr detach: warning: can't arm breakpoint at %s yet (cur tid %d, vm %p, first_running_task %p)\n",
                  where.c_str(), cur ? cur->tid : -1, (void*)vm.get(),
                  vm ? (void*)vm->first_running_task() : nullptr);
          warned = true;
      }
      auto result = session->replay_step(RUN_CONTINUE);
      if (armed)
          vm->remove_breakpoint(addr, BKPT_USER);
      if (result.status == REPLAY_EXITED) {
          fprintf(stderr, "rr detach: trace ended after %ld hit(s) of %s\n", hits, spec.c_str());
          return 1;
      }
      stopped_at = session->trace_reader().time() - 1;
      if (!result.break_status.breakpoint_hit)
          continue;

      Task* hit_task = result.break_status.task_context.task;
      hits++;
      bool take = hits >= first_hit && can_branch_now(*session);
      can_branch_now(*session);
      if (take && branches_left > 1) {
          ReplaySession::shr_ptr clone = session->clone();   // no int3 in memory now
          clones.push_back(clone);
          size_t branch = branch_no++;
          ScopedFd bin, bout;
          string stdio_note;
          if (!open_branch_stdio(flags.output_dir, branch, model, bin, bout, stdio_note))
              return 1;
          char tag[PATH_MAX + 64];
          snprintf(tag, sizeof tag, " [branch %zu: %s hit #%ld, tid %d]%s", branch, spec.c_str(),
                  hits, hit_task ? hit_task->rec_tid : 0, stdio_note.c_str());
          int rc = hand_off(*clone, model, sigs, check, flags, stopped_at, tag);
          model.clear_stdio_targets();
          if (rc)
              return rc;
          branches_left--;
      } else if (take) {
          break;                                   // last branch: the replay itself
      }

      // Step off the breakpoint address (it is disarmed right now).
      auto step = session->replay_step(RUN_SINGLESTEP);
      if (step.status == REPLAY_EXITED) {
          fprintf(stderr, "rr detach: trace ended while stepping over %s\n", spec.c_str());
          return 1;
      }
  }
  // (breakpoint is already disarmed here)

  {
    ScopedFd bin, bout;
    string stdio_note;
    if (!open_branch_stdio(flags.output_dir, branch_no, model, bin, bout, stdio_note))
      return 1;
    char tag[PATH_MAX + 64];
    snprintf(tag, sizeof tag, " [%s hit #%ld]%s", spec.c_str(), hits, stdio_note.c_str());
    int rc = hand_off(*session, model, sigs, check, flags, stopped_at, tag);
    model.clear_stdio_targets();
    if (rc)
      return rc;
  }
  while (true) {
    pause();
  }
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
  FdModel model(cwd);
  model.init_task(session->current_task());

  session->on_task_cloned =
    [&](Task* parent, Task* child, int flags) {
        model.fork_task(parent, child, flags);
    };

  SignalModel sigs;
  DetachCheck check;

  if (!flags.checkpoint.empty()) {
    return detach_from_checkpoint(session, model, sigs, check, flags);
  }
  if (!flags.break_at.empty()) {
    return detach_at_function(session, model, sigs, check, flags);
  }

  // -e EVENT: replay to the event and hand the replay itself off.
  FrameTime stopped_at = run_until(*session, model, sigs, check, std::to_string(flags.event));
  if (stopped_at < 0) {
    fprintf(stderr, "rr detach: trace ended before event %lld\n", (long long)flags.event);
    return 1;
  }
  {
    ScopedFd bin, bout;
    string stdio_note;
    if (!open_branch_stdio(flags.output_dir, 1, model, bin, bout, stdio_note))
      return 1;
    int rc = hand_off(*session, model, sigs, check, flags, stopped_at, stdio_note.c_str());
    model.clear_stdio_targets();
    if (rc)
      return rc;
  }

  // Keep rr alive until the tracees are handed off.
  while (true) {
    pause();
  }
  return 0;
}

int DetachCommand::run(vector<string>& args) {
  DetachFlags flags;
  while (parse_detach_arg(args, flags)) {
  }
  if (!flags.event && flags.checkpoint.empty() && flags.break_at.empty()) {
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
