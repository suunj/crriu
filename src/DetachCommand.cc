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
  string cwd;
  bool strict;
  string output_dir;
  int clones;
  string checkpoint;            // -C
  vector<string> resume_to;     // -R
  FrameTime cache_every;
  size_t cache_max;
  DetachFlags() : strict(false), clones(1), cache_every(0), cache_max(4) {}
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
    { 'm', "cache-max", HAS_PARAMETER }
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

// A live checkpoint: a stopped clone of the replay plus the models as they
// were there. `time` is the last frame the clone has fully replayed
// (trace_reader().time() - 1 at clone time); a branch taken from it is
// replayed on from frame time+1.
struct Checkpoint {
  FrameTime time;
  ReplaySession::shr_ptr session;
  FdModel fd;
  SignalModel sigs;
  DetachCheck check;
  std::map<string, long> hits;     // function entries seen so far (Watch::hits)
  uint64_t last_used;
};

class CheckpointStore {
public:
  explicit CheckpointStore(size_t max) : max_(max ? max : 1) {}

  // Clone `s` here. Caller guarantees s.can_clone(). Duplicates are ignored.
  // The earliest entry is the base and is never evicted; beyond it `max`
  // entries are kept, least recently used evicted first.
  bool take(ReplaySession& s, const FdModel& fd, const SignalModel& sigs,
            const DetachCheck& check, const std::map<string, long>& hits,
            FrameTime time) {
    if (by_time_.count(time)) {
      return false;
    }
    Checkpoint c{ time, s.clone(), fd.snapshot(), sigs, check, hits, ++tick_ };
    by_time_.emplace(time, std::move(c));
    fprintf(stderr, "rr detach: checkpoint at event %lld (%zu cached)\n",
            (long long)time, by_time_.size());
    evict();
    return true;
  }

  // Latest checkpoint from which `t` is still ahead: by frame, the last one
  // at or before t.event; by function, the last one that has seen fewer
  // than t.hit entries of t.symbol. nullptr if even the base is too late.
  Checkpoint* nearest_before(const struct Target& t);

  size_t size() const { return by_time_.size(); }

  void list(FILE* f) const {
    for (const auto& kv : by_time_) {
      fprintf(f, "  checkpoint event %lld pid %d%s\n", (long long)kv.first,
              kv.second.session->tasks().begin()->second->tid,
              &kv == &*by_time_.begin() ? " (base)" : "");
    }
  }

private:
  void evict() {
    while (by_time_.size() > max_ + 1) {
      auto victim = by_time_.end();
      for (auto it = std::next(by_time_.begin()); it != by_time_.end(); ++it) {
        if (victim == by_time_.end() || it->second.last_used < victim->second.last_used) {
          victim = it;
        }
      }
      fprintf(stderr, "rr detach: evicting checkpoint at event %lld\n",
              (long long)victim->first);
      by_time_.erase(victim);             // ~ReplaySession: tasks killed, emufs freed
    }
  }

  std::map<FrameTime, Checkpoint> by_time_;
  size_t max_;
  uint64_t tick_ = 0;
};

/* Address -> "symbol+off" for the exec mappings of one address space.
 * Built once per AddressSpace (rebuilt after exec), used only for logging. */
struct SymbolMap {
  remote_ptr<void> start, end;      // exec mapping this map covers
  uintptr_t base;                   // start of the file-offset-0 mapping
  bool relative;                    // PIE/.so: symbol values are offsets from base
  map<uintptr_t, string> by_addr;   // symbol value -> name

  string lookup(remote_code_ptr ip) const {
    uintptr_t v = ip.register_value() - (relative ? base : 0);
    auto it = by_addr.upper_bound(v);
    if (it == by_addr.begin()) return "?";
    --it;
    char buf[32];
    snprintf(buf, sizeof buf, "+%#lx", (unsigned long)(v - it->first));
    return it->second + buf;
  }
};

struct SymbolMaps {
  AddressSpace* built_for = nullptr;
  vector<SymbolMap> maps;

  void build(Task* t, bool force = false) {
    if (t->vm().get() == built_for && !force) return;
    maps.clear();
    for (const auto& m : t->vm()->maps()) {
      const KernelMapping& km = m.map;
      if (!(km.prot() & PROT_EXEC) || km.fsname().empty() || km.fsname()[0] != '/')
        continue;
      ScopedFd fd(km.fsname().c_str(), O_RDONLY);
      if (!fd.is_open()) continue;
      ElfFileReader reader(fd);
      SymbolTable syms = reader.read_symbols(".symtab", ".strtab");
      SymbolMap sm{km.start(), km.end(), 0, false, {}};
      for (const auto& m2 : t->vm()->maps())
        if (m2.map.fsname() == km.fsname() && m2.map.file_offset_bytes() == 0) {
          sm.base = m2.map.start().as_int();
          break;
        }
      uintptr_t highest = 0;
      for (size_t i = 0; i < syms.size(); i++) {
        const char* n = syms.name(i);
        if (!syms.addr(i) || !n || !*n) continue;
        sm.by_addr.emplace(syms.addr(i), n);
        highest = max(highest, syms.addr(i));
      }
      sm.relative = highest < sm.base;          // same rule as resolve_break
      maps.push_back(std::move(sm));
    }
    built_for = t->vm().get();
  }
  const SymbolMap* map_for(remote_code_ptr ip) const {
    remote_ptr<void> p = ip.to_data_ptr<void>();
    for (const auto& m : maps)
      if (p >= m.start && p < m.end) return &m;
    return nullptr;
  }
  // Mappings come and go (dlopen, ld.so loading libc); on a miss rebuild once.
  string lookup(Task* t, remote_code_ptr ip) {
    const SymbolMap* m = map_for(ip);
    if (!m) {
      build(t, true);
      m = map_for(ip);
    }
    return m ? m->lookup(ip) : "?";
  }
};

static bool trace_frames = getenv("CRRIU_TRACE") != nullptr;

static bool frame_allows_branch(ReplaySession& s) {
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

static remote_code_ptr resolve_break(Task* t, const string& spec, string& location) {
  if (spec.compare(0, 2, "0x") == 0) {
    location = spec;
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
      location = spec + buf + " in " + km.fsname();
      return remote_code_ptr(addr);
    }
  }
  return remote_code_ptr();
}

// Where a branch is taken: right after frame `event`, or at the `hit`-th
// entry of function `symbol`.
struct Target {
  string text;
  FrameTime event = 0;
  string symbol;
  long hit = 1;
  bool by_event() const { return event > 0; }
};

static Target parse_target(const string& spec) {
  Target t;
  t.text = spec;
  if (!spec.empty() && spec.find_first_not_of("0123456789") == string::npos) {
    t.event = strtoll(spec.c_str(), nullptr, 10);
    return t;
  }
  size_t colon = spec.rfind(':');
  if (colon != string::npos && colon > 2) {        // "sym:N" / "0x..:N", not "::"
    t.hit = strtol(spec.c_str() + colon + 1, nullptr, 10);
    if (t.hit < 1) t.hit = 1;
    t.symbol = spec.substr(0, colon);
  } else {
    t.symbol = spec;
  }
  return t;
}

// Function entries watched while replaying. Every function named on the
// command line is armed for the whole replay so that `hits` is exact at
// every frame; checkpoints save a copy and branches resume counting from it.
struct Watch {
  vector<string> symbols;
  map<string, long> hits;
  map<string, remote_code_ptr> addr;     // resolved in `resolved_for`
  AddressSpace* resolved_for = nullptr;
  size_t resolved_maps = 0;              // mapping count at last resolve

  void resolve(Task* t) {
    size_t nmaps = 0;
    for (const auto& m : t->vm()->maps()) { (void)m; nmaps++; }
    bool incomplete = addr.size() < symbols.size();
    if (t->vm().get() == resolved_for && !(incomplete && nmaps != resolved_maps))
      return;
    resolved_for = t->vm().get();
    resolved_maps = nmaps;
    for (const string& sym : symbols) {
      if (addr.count(sym) && !incomplete) continue;
      string location;
      remote_code_ptr a = resolve_break(t, sym, location);
      if (a.is_null()) continue;
      if (!addr.count(sym) || addr[sym] != a)
        fprintf(stderr, "rr detach: break at %s\n", location.c_str());
      addr[sym] = a;
    }
  }
  bool arm(AddressSpace& vm) {
    bool any = false;
    for (const auto& kv : addr) any |= vm.add_breakpoint(kv.second, BKPT_USER);
    return any;
  }
  void disarm(AddressSpace& vm) {
    for (const auto& kv : addr) vm.remove_breakpoint(kv.second, BKPT_USER);
  }
  const string* symbol_at(remote_code_ptr ip) const {
    for (const auto& kv : addr) if (kv.second == ip) return &kv.first;
    return nullptr;
  }
};

Checkpoint* CheckpointStore::nearest_before(const Target& t) {
  Checkpoint* best = nullptr;
  for (auto& kv : by_time_) {
    Checkpoint& c = kv.second;
    bool ok;
    if (t.by_event()) {
      ok = c.time <= t.event;
    } else {
      auto h = c.hits.find(t.symbol);
      ok = (h == c.hits.end() ? 0 : h->second) < t.hit;
    }
    if (ok) best = &c;
  }
  if (best) best->last_used = ++tick_;
  return best;
}

// Replay `s` until `target`. Returns the last completed frame (-1 if the
// trace ended first). With `store`, clones a checkpoint every `every` frames.
static FrameTime run_until(ReplaySession& s, FdModel& model, SignalModel& sigs,
                           DetachCheck& check, Watch& watch, const Target& target,
                           CheckpointStore* store, FrameTime every) {
  s.on_task_cloned = [&](Task* parent, Task* child, int flags) {
    model.fork_task(parent, child, flags);
  };
  FrameTime next_ckpt = every ? ((s.trace_reader().time() / every) + 1) * every : 0;
  FrameTime stopped_at = -1;
  while (true) {
    Task* cur = s.current_task();
    if (cur) {
      model.observe(s.current_trace_frame(), cur);
      sigs.observe(s.current_trace_frame(), cur);
      check.observe(s.current_trace_frame(), cur);
    }
    // For CRRIU_TRACE: the frame about to be replayed, and its symbol map
    // (resolved now, while the task that will execute it is current).
    string pending_sym;
    TraceFrame pending;
    FrameTime before = s.trace_reader().time();
    if (trace_frames && cur) {
      static SymbolMaps symbols;
      pending = s.current_trace_frame();
      pending_sym = symbols.lookup(cur, pending.regs().ip());
    }
    // Arm for this step only: rr remaps segments as it replays (exec, mmap),
    // which would wipe a permanently installed int3, and a clone taken while
    // armed would carry the int3 into the branch.
    AddressSpace::shr_ptr vm = cur ? cur->vm() : nullptr;
    bool armed = false;
    if (vm && s.done_initial_exec() && !watch.symbols.empty()) {
      watch.resolve(cur);
      armed = watch.arm(*vm);
    }
    auto result = s.replay_step(RUN_CONTINUE);
    if (armed)
      watch.disarm(*vm);
    if (trace_frames && s.trace_reader().time() > before) {   // frame completed
      string ret;
      if (pending.event().is_syscall_event() &&
          pending.event().Syscall().state == EXITING_SYSCALL) {
        long r = (long)pending.regs().syscall_result_signed();
        char buf[48];
        if (r < 0 && r > -4096)
          snprintf(buf, sizeof buf, " = -%s", errno_name(-r).c_str());
        else
          snprintf(buf, sizeof buf, " = %ld", r);
        ret = buf;
      }
      fprintf(stderr, "frame %lld tid %d %-36s ticks %lld rip %s%s\n",
              (long long)(s.trace_reader().time() - 1), pending.tid(),
              pending.event().str().c_str(), (long long)pending.ticks(),
              pending_sym.c_str(), ret.c_str());
    }
    if (result.status == REPLAY_EXITED) {
      stopped_at = -1;
      break;
    }
    stopped_at = s.trace_reader().time() - 1;

    if (result.break_status.breakpoint_hit) {
      Task* t = result.break_status.task_context.task;
      const string* sym = t ? watch.symbol_at(t->ip()) : nullptr;
      if (sym) {
        long n = ++watch.hits[*sym];
        if (trace_frames)
          fprintf(stderr, "hit %s #%ld tid %d after frame %lld\n", sym->c_str(), n,
                  t->rec_tid, (long long)stopped_at);
        if (!target.by_event() && *sym == target.symbol && n >= target.hit &&
            frame_allows_branch(s))
          break;
      }
      // Step off the breakpoint address (disarmed right now).
      if (s.replay_step(RUN_SINGLESTEP).status == REPLAY_EXITED) {
        stopped_at = -1;
        break;
      }
      continue;                                    // mid-frame: no checkpoint
    }
    if (store && every && stopped_at >= next_ckpt && s.can_clone()) {
      store->take(s, model, sigs, check, watch.hits, stopped_at);
      next_ckpt = (stopped_at / every + 1) * every;
    }
    if (target.by_event() && s.trace_reader().time() > target.event && s.can_clone())
      break;
  }
  s.on_task_cloned = nullptr;
  return stopped_at;
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

  session.forget_tasks();

  printf("detached pid %d after event %lld (%zu threads)%s\n",
          real_pid, (long long)stopped_at, tasks.size(), tag);
  fflush(stdout);
  return 0;
}



// A branch that is handed off right away does not replay on, so ticks
// slop in the current frame (which can_clone() refuses) does not matter;
// only frames where tasks are going away are off limits.


// Clone `src` (a checkpoint or the live replay), replay the clone on to
// `target` if asked, hand it off as branch `branch_no`.
static int branch_from(ReplaySession& src, const FdModel& fd, const SignalModel& sigs,
                       const DetachCheck& check, const Watch& watch,
                       const std::map<string, long>& hits, const Target& target,
                       bool replay_on, const DetachFlags& flags, size_t branch_no,
                       const char* how) {
  ReplaySession::shr_ptr b = src.clone();
  FdModel bm = fd.snapshot();
  SignalModel bs = sigs;
  DetachCheck bc = check;
  Watch bw;
  bw.symbols = watch.symbols;
  bw.hits = hits;                       // counting continues from the checkpoint
  FrameTime at = src.trace_reader().time() - 1;
  if (replay_on) {
    at = run_until(*b, bm, bs, bc, bw, target, nullptr, 0);
    if (at < 0) {
      fprintf(stderr, "rr detach: trace ended before '%s'\n", target.text.c_str());
      return 1;
    }
  }
  ScopedFd bin, bout;
  string stdio_note;
  if (!open_branch_stdio(flags.output_dir, branch_no, bm, bin, bout, stdio_note))
    return 1;
  char tag[PATH_MAX + 96];
  snprintf(tag, sizeof tag, " [branch %zu: '%s' %s]%s", branch_no, target.text.c_str(), how,
           stdio_note.c_str());
  int rc = hand_off(*b, bm, bs, bc, flags, at, tag);   // hand_off ends with forget_tasks()
  bm.clear_stdio_targets();
  return rc;
}

static int detach_cached(ReplaySession::shr_ptr session, FdModel& model,
                         SignalModel& sigs, DetachCheck& check,
                         const DetachFlags& flags) {
  CheckpointStore store(flags.cache_max);

  vector<Target> targets;
  Watch watch;
  Target ckpt;
  if (!flags.checkpoint.empty()) {
    ckpt = parse_target(flags.checkpoint);
    if (!ckpt.by_event()) watch.symbols.push_back(ckpt.symbol);
  }
  for (const string& spec : flags.resume_to) {
    targets.push_back(parse_target(spec));
    if (!targets.back().by_event()) watch.symbols.push_back(targets.back().symbol);
  }
  std::sort(watch.symbols.begin(), watch.symbols.end());
  watch.symbols.erase(std::unique(watch.symbols.begin(), watch.symbols.end()),
                      watch.symbols.end());

  // Base checkpoint: first clone-safe point after the recorded program
  // exec'd. Every "behind" request can at worst start from here.
  session->on_task_cloned = [&](Task* p, Task* c, int f) { model.fork_task(p, c, f); };
  while (!(session->done_initial_exec() && session->can_clone())) {
    if (Task* cur = session->current_task()) {
      model.observe(session->current_trace_frame(), cur);
      sigs.observe(session->current_trace_frame(), cur);
      check.observe(session->current_trace_frame(), cur);
    }
    if (session->replay_step(RUN_CONTINUE).status == REPLAY_EXITED) {
      fprintf(stderr, "rr detach: trace ended before the program exec'd\n");
      return 1;
    }
  }
  store.take(*session, model, sigs, check, watch.hits, session->trace_reader().time() - 1);

  // -k TARGET: an explicit checkpoint (frame targets only; a function entry
  // is mid-frame and cannot be cloned).
  if (!flags.checkpoint.empty()) {
    if (!ckpt.by_event()) {
      fprintf(stderr, "rr detach: -k takes an event number\n");
      return 1;
    }
    FrameTime at = run_until(*session, model, sigs, check, watch, ckpt, &store, flags.cache_every);
    if (at < 0) {
      fprintf(stderr, "rr detach: trace ended before the checkpoint\n");
      return 1;
    }
    store.take(*session, model, sigs, check, watch.hits, at);
  }

  size_t branch_no = 1;
  for (const Target& t : targets) {
    FrameTime pos = session->trace_reader().time() - 1;
    bool behind = t.by_event() ? t.event <= pos : watch.hits[t.symbol] >= t.hit;
    ReplaySession* src = session.get();
    const FdModel* fd = &model;
    const SignalModel* sg = &sigs;
    const DetachCheck* ck = &check;
    const std::map<string, long>* hits = &watch.hits;
    bool replay_on = false;
    char how[64] = "from the replay";
    if (behind) {
      Checkpoint* c = store.nearest_before(t);
      if (!c) {
        fprintf(stderr, "rr detach: '%s' is before the base checkpoint\n", t.text.c_str());
        return 1;
      }
      src = c->session.get(); fd = &c->fd; sg = &c->sigs; ck = &c->check; hits = &c->hits;
      replay_on = t.by_event() ? t.event > c->time : true;
      snprintf(how, sizeof how, "from checkpoint %lld", (long long)c->time);
    } else {
      FrameTime at = run_until(*session, model, sigs, check, watch, t, &store, flags.cache_every);
      if (at < 0) {
        fprintf(stderr, "rr detach: trace ended before '%s'\n", t.text.c_str());
        return 1;
      }
      if (t.by_event())                       // a function entry is mid-frame
        store.take(*session, model, sigs, check, watch.hits, at);
    }
    for (int k = 0; k < flags.clones; k++, branch_no++) {
      int rc = branch_from(*src, *fd, *sg, *ck, watch, *hits, t, replay_on, flags, branch_no, how);
      if (rc)
        return rc;
    }
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
  FdModel model(cwd);
  model.init_task(session->current_task());

  session->on_task_cloned =
    [&](Task* parent, Task* child, int flags) {
        model.fork_task(parent, child, flags);
    };

  SignalModel sigs;
  DetachCheck check;

  return detach_cached(session, model, sigs, check, flags);
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
