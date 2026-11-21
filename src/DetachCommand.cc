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
#ifdef HAVE_CAPSTONE
#include <capstone/capstone.h>
#endif

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

static remote_code_ptr resolve_break(Task* t, const string& spec, string& location);

// Function entries watched while replaying. Every function named on the
// command line is armed for the whole replay so that `hits` is exact at
// every frame; checkpoints save a copy and branches resume counting from it.
// -D NAME:ADDR:LEN[:EVERY]: a memory range to snapshot at symbol hits, so
// that successive snapshots can be diffed to see what the program itself
// changed between two hits (rr records only what the kernel wrote).
struct Dump {
  string name;
  uintptr_t addr;
  size_t len;
  long every;
  long from = 1;        // first hit to dump
};

static Dump parse_dump(const string& spec) {
  Dump d;
  d.every = 1;
  size_t a = spec.find(':');
  size_t b = a == string::npos ? a : spec.find(':', a + 1);

  if (a == string::npos || b == string::npos) {
    fprintf(stderr, "rr detach: -d expects NAME:ADDR:LEN[:EVERY], got '%s'\n", spec.c_str());
    exit(1);
  }
  d.name = spec.substr(0, a);
  d.addr = strtoull(spec.c_str() + a + 1, nullptr, 0);
  size_t c = spec.find(':', b + 1);
  d.len = strtoull(spec.substr(b + 1, c == string::npos ? string::npos : c - b - 1).c_str(), nullptr, 0);

  if (c != string::npos) {
    d.every = strtol(spec.c_str() + c + 1, nullptr, 0);
    size_t e = spec.find(':', c + 1);
    if (e != string::npos)
        d.from = strtol(spec.c_str() + e + 1, nullptr, 0);
  }
  if (d.every < 1)
      d.every = 1;

  return d;
}

// With -e: a call we are inside of, waiting for it to return.
struct PendingReturn {
  remote_code_ptr ret;          // return address, read from [sp] at entry
  remote_ptr<void> sp;          // sp after the return, to tell recursion apart
  pid_t tid;
  string sym;
  long n;
};

struct Watch {
  vector<string> symbols;
  map<string, long> hits;
  vector<Dump> dumps;
  string dump_dir;
  long dumped = 0;
  bool track_exits = false;
  vector<PendingReturn> pending;
  map<string, long> access_every;        // -x: symbol -> EVERY
  FrameTime from_event = 0;              // -f: no breakpoints before this event

  void dump(Task* t, const string& sym, long n, const char* phase = "") {
    if (dumps.empty())
        return;
    for (const Dump& d : dumps) {
      if (n < d.from || n % d.every)
          continue;
      if (!dumped)
          mkdir(dump_dir.c_str(), 0755);
      vector<uint8_t> buf(d.len);
      bool ok = true;
      t->read_bytes_helper(remote_ptr<void>(d.addr), d.len, buf.data(), &ok);
      if (!ok) {
        fprintf(stderr, "rr detach: dump %s: can't read %zu bytes at %#lx\n",
                d.name.c_str(), d.len, (unsigned long)d.addr);
        continue;
      }
      char path[PATH_MAX];
      snprintf(path, sizeof path, "%s/%s.%s.%ld%s.bin", dump_dir.c_str(),
               d.name.c_str(), sym.c_str(), n, phase);
      FILE* f = fopen(path, "wb");
      if (!f) {
          perror(path);
          continue;
      }
      fwrite(buf.data(), 1, buf.size(), f);
      fclose(f);
      dumped++;
    }
  }
  map<string, remote_code_ptr> addr;     // resolved in `resolved_for`
  AddressSpace* resolved_for = nullptr;
  size_t resolved_maps = 0;              // mapping count at last resolve

  void resolve(Task* t) {
    size_t nmaps = 0;
    for (const auto& m : t->vm()->maps()) {
        (void)m;
        nmaps++;
    }
    bool incomplete = addr.size() < symbols.size();
    if (t->vm().get() == resolved_for && !(incomplete && nmaps != resolved_maps))
      return;
    resolved_for = t->vm().get();
    resolved_maps = nmaps;
    for (const string& sym : symbols) {
      if (addr.count(sym) && !incomplete)
          continue;
      string location;
      remote_code_ptr a = resolve_break(t, sym, location);

      if (a.is_null())
          continue;
      if (!addr.count(sym) || addr[sym] != a)
        fprintf(stderr, "rr detach: break at %s\n", location.c_str());
      addr[sym] = a;
    }
  }
  bool arm(AddressSpace& vm) {
    bool any = false;
    for (const auto& kv : addr)
        any |= vm.add_breakpoint(kv.second, BKPT_USER);
    for (const auto& p : pending)
        any |= vm.add_breakpoint(p.ret, BKPT_USER);
    return any;
  }
  void disarm(AddressSpace& vm) {
    for (const auto& kv : addr)
        vm.remove_breakpoint(kv.second, BKPT_USER);
    for (const auto& p : pending)
        vm.remove_breakpoint(p.ret, BKPT_USER);
  }
  // At an entry hit: remember where this call will return to.
  void expect_return(Task* t, const string& sym, long n) {
    remote_ptr<void> sp = t->regs().sp();
    uint64_t ra = t->read_mem(sp.cast<uint64_t>());
    pending.push_back({ remote_code_ptr(ra), sp + 8, t->rec_tid, sym, n });
  }
  // Is this stop the return of a pending call? Pops and returns it if so.
  bool take_return(Task* t, PendingReturn* out) {
    for (auto it = pending.begin(); it != pending.end(); ++it) {
      if (it->ret == t->ip() && it->tid == t->rec_tid && it->sp == t->regs().sp()) {
        *out = *it;
        pending.erase(it);
        return true;
      }
    }
    return false;
  }
  const string* symbol_at(remote_code_ptr ip) const {
    for (const auto& kv : addr)
        if (kv.second == ip)
            return &kv.first;
    return nullptr;
  }
};


// Everything a replay point carries besides the ReplaySession itself: the
// models of kernel state recreated at hand-off (fds, signals, checks) and the
// watched functions with their hit counts. A checkpoint keeps a snapshot; a
// branch starts from one and keeps counting.
struct ReplayModels {
  FdModel fd;
  SignalModel sigs;
  DetachCheck check;
  Watch watch;

  ReplayModels snapshot() const {
    return ReplayModels{ fd.snapshot(), sigs, check, watch };
  }
  void observe(const TraceFrame& frame, Task* t) {
    fd.observe(frame, t);
    sigs.observe(frame, t);
    check.observe(frame, t);
  }
  long hits_of(const string& sym) const {
    auto h = watch.hits.find(sym);
    return h == watch.hits.end() ? 0 : h->second;
  }
};

// A live checkpoint: a stopped clone of the replay plus the models as they
// were there. `time` is the last frame the clone has fully replayed
// (trace_reader().time() - 1 at clone time); a branch taken from it is
// replayed on from frame time+1.
struct Checkpoint {
  FrameTime time;
  ReplaySession::shr_ptr session;
  ReplayModels models;
  uint64_t last_used;
};

class CheckpointStore {
public:
  explicit CheckpointStore(size_t max) : max_(max ? max : 1) {}

  // Clone `s` here. Caller guarantees s.can_clone(). Duplicates are ignored.
  // The earliest entry is the base and is never evicted; beyond it `max`
  // entries are kept, least recently used evicted first.
  // Targets not yet branched. A pending target that is already behind the
  // replay can only be served from its nearest checkpoint, so evict() keeps
  // that one.
  void set_pending(const vector<Target>& targets) { pending_ = targets; }
  void pop_pending() { if (!pending_.empty()) pending_.erase(pending_.begin()); }

  bool take(ReplaySession& s, const ReplayModels& m, FrameTime time) {
    if (by_time_.count(time)) {
      return false;
    }
    Checkpoint c{ time, s.clone(), m.snapshot(), ++tick_ };
    by_time_.emplace(time, std::move(c));
    fprintf(stderr, "rr detach: checkpoint at event %lld (%zu cached)\n",
            (long long)time, by_time_.size());
    evict(time, m.watch.hits);
    return true;
  }

  // Latest checkpoint from which `t` is still ahead: by frame, the last one
  // at or before t.event; by function, the last one that has seen fewer
  // than t.hit entries of t.symbol. nullptr if even the base is too late.
  Checkpoint* nearest_before(const Target& t) {
    Checkpoint* c = find_before(t);
    if (c) c->last_used = ++tick_;
    return c;
  }

  size_t size() const { return by_time_.size(); }

  void list(FILE* f) const {
    for (const auto& kv : by_time_) {
      fprintf(f, "  checkpoint event %lld pid %d%s\n", (long long)kv.first,
              kv.second.session->tasks().begin()->second->tid,
              &kv == &*by_time_.begin() ? " (base)" : "");
    }
  }

private:
  Checkpoint* find_before(const Target& t) {
    Checkpoint* best = nullptr;
    for (auto& kv : by_time_) {
      Checkpoint& c = kv.second;
      bool ok;
      if (t.by_event()) {
        ok = c.time <= t.event;
      } else {
        ok = c.models.hits_of(t.symbol) < t.hit;
      }
      if (ok) best = &c;
    }
    return best;
  }

  // Checkpoints a pending, already-passed target will start from.
  std::set<FrameTime> pinned(FrameTime pos, const std::map<string, long>& hits) {
    std::set<FrameTime> keep;
    for (const Target& t : pending_) {
      auto h = hits.find(t.symbol);
      bool behind = t.by_event() ? t.event <= pos
                                 : (h == hits.end() ? 0 : h->second) >= t.hit;
      if (!behind)
          continue;
      if (Checkpoint* c = find_before(t))
          keep.insert(c->time);
    }
    return keep;
  }

  void evict(FrameTime pos, const std::map<string, long>& hits) {
    std::set<FrameTime> keep = pinned(pos, hits);
    while (by_time_.size() > max_ + 1) {
      auto victim = by_time_.end();
      for (auto it = std::next(by_time_.begin()); it != by_time_.end(); ++it) {
        if (keep.count(it->first))
            continue;
        if (victim == by_time_.end() || it->second.last_used < victim->second.last_used) {
          victim = it;
        }
      }
      if (victim == by_time_.end())
          break;     // everything left is pinned
      fprintf(stderr, "rr detach: evicting checkpoint at event %lld\n",
              (long long)victim->first);
      by_time_.erase(victim);             // ~ReplaySession: tasks killed, emufs freed
    }
  }

  std::map<FrameTime, Checkpoint> by_time_;
  vector<Target> pending_;
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

    if (it == by_addr.begin())
        return "?";
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

    if (t->vm().get() == built_for && !force)
        return;
    maps.clear();
    for (const auto& m : t->vm()->maps()) {
      const KernelMapping& km = m.map;
      if (!(km.prot() & PROT_EXEC) || km.fsname().empty() || km.fsname()[0] != '/')
        continue;
      ScopedFd fd(km.fsname().c_str(), O_RDONLY);
      if (!fd.is_open())
          continue;

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
        if (!syms.addr(i) || !n || !*n)
            continue;
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
      if (p >= m.start && p < m.end)
          return &m;
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


// -x: single-step one call of `sym` (hit `n`) from its entry to its return,
// decoding each instruction to log the memory it reads and writes. Follows
// into callees, so the log is the call's dynamic dependency set. Returns
// false if the trace ended first.
#ifdef HAVE_CAPSTONE
static uint64_t reg_value(const NativeArch::user_regs_struct& u, x86_reg r, uint64_t next_ip) {
  switch (r) {
    case X86_REG_RAX: return u.rax;  case X86_REG_EAX: return (uint32_t)u.rax;
    case X86_REG_RBX: return u.rbx;  case X86_REG_EBX: return (uint32_t)u.rbx;
    case X86_REG_RCX: return u.rcx;  case X86_REG_ECX: return (uint32_t)u.rcx;
    case X86_REG_RDX: return u.rdx;  case X86_REG_EDX: return (uint32_t)u.rdx;
    case X86_REG_RSI: return u.rsi;  case X86_REG_ESI: return (uint32_t)u.rsi;
    case X86_REG_RDI: return u.rdi;  case X86_REG_EDI: return (uint32_t)u.rdi;
    case X86_REG_RBP: return u.rbp;  case X86_REG_EBP: return (uint32_t)u.rbp;
    case X86_REG_RSP: return u.rsp;  case X86_REG_ESP: return (uint32_t)u.rsp;
    case X86_REG_R8:  return u.r8;   case X86_REG_R8D:  return (uint32_t)u.r8;
    case X86_REG_R9:  return u.r9;   case X86_REG_R9D:  return (uint32_t)u.r9;
    case X86_REG_R10: return u.r10;  case X86_REG_R10D: return (uint32_t)u.r10;
    case X86_REG_R11: return u.r11;  case X86_REG_R11D: return (uint32_t)u.r11;
    case X86_REG_R12: return u.r12;  case X86_REG_R12D: return (uint32_t)u.r12;
    case X86_REG_R13: return u.r13;  case X86_REG_R13D: return (uint32_t)u.r13;
    case X86_REG_R14: return u.r14;  case X86_REG_R14D: return (uint32_t)u.r14;
    case X86_REG_R15: return u.r15;  case X86_REG_R15D: return (uint32_t)u.r15;
    case X86_REG_RIP: return next_ip;
    case X86_REG_INVALID: return 0;
    default: return 0;
  }
}

static bool trace_access(ReplaySession& s, const string& sym, long n, const string& dir) {
  static csh cs = 0;
  if (!cs) {
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &cs) != CS_ERR_OK) {
      fprintf(stderr, "rr detach: capstone init failed\n");
      exit(1);
    }
    cs_option(cs, CS_OPT_DETAIL, CS_OPT_ON);
  }
  Task* t = s.current_task();
  remote_ptr<void> sp0 = t->regs().sp();
  uint64_t ret = t->read_mem(sp0.cast<uint64_t>());
  mkdir(dir.c_str(), 0755);
  char path[PATH_MAX];
  snprintf(path, sizeof path, "%s/access.%s.%ld.txt", dir.c_str(), sym.c_str(), n);
  FILE* f = fopen(path, "w");
  if (!f) { perror(path); exit(1); }
  fprintf(f, "# %s hit %ld tid %d entry sp %#lx ret %#lx\n# ip rw addr size value insn\n",
          sym.c_str(), n, t->rec_tid, (unsigned long)sp0.as_int(), (unsigned long)ret);

  const long limit = 2000000;
  long steps = 0;
  bool ok_end = true;
  for (; steps < limit; steps++) {
    t = s.current_task();
    if (!t) { ok_end = false; break; }
    uint64_t ip = t->ip().register_value();
    if (ip == ret && t->regs().sp() == sp0 + 8)
      break;                                            // back in the caller
    NativeArch::user_regs_struct u = t->regs().get_ptrace();
    uint8_t code[16];
    bool rd = true;
    t->read_bytes_helper(remote_ptr<void>(ip), sizeof code, code, &rd);
    cs_insn* insn = nullptr;
    size_t cnt = rd ? cs_disasm(cs, code, sizeof code, ip, 1, &insn) : 0;
    if (cnt == 1) {
      uint64_t next_ip = ip + insn->size;
      const cs_x86& x = insn->detail->x86;
      // Reads are logged with the value before the step; writes are queued
      // and logged with the value after it.
      auto hex_at = [&](uint64_t addr, unsigned size, string* out) {
        unsigned n = size > 64 ? 64 : size;
        uint8_t buf[64];
        bool ok = true;
        t->read_bytes_helper(remote_ptr<void>(addr), n, buf, &ok);
        if (!ok) { *out = "?"; return; }
        char h[3];
        for (unsigned i = 0; i < n; i++) { snprintf(h, sizeof h, "%02x", buf[i]); *out += h; }
        if (n < size) *out += "..";
      };
      struct Pending { char rw; uint64_t addr; unsigned size; string text; };
      vector<Pending> writes;
      auto log = [&](char rw, uint64_t addr, unsigned size) {
        string text = string(insn->mnemonic) + " " + insn->op_str;
        if (rw == 'W') { writes.push_back({rw, addr, size, text}); return; }
        string v; hex_at(addr, size, &v);
        fprintf(f, "%#lx %c %#lx %u %s %s\n", (unsigned long)ip, rw, (unsigned long)addr,
                size, v.c_str(), text.c_str());
      };
      for (uint8_t i = 0; i < x.op_count; i++) {
        const cs_x86_op& op = x.operands[i];
        if (op.type != X86_OP_MEM) continue;
        if (insn->id == X86_INS_LEA || insn->id == X86_INS_NOP) continue;
        uint64_t addr = (uint64_t)op.mem.disp;
        addr += reg_value(u, (x86_reg)op.mem.base, next_ip);
        addr += reg_value(u, (x86_reg)op.mem.index, next_ip) * (op.mem.scale ? op.mem.scale : 1);
        if (op.mem.segment == X86_REG_FS) addr += u.fs_base;
        if (op.mem.segment == X86_REG_GS) addr += u.gs_base;
        if (op.access & CS_AC_READ)  log('R', addr, op.size);
        if (op.access & CS_AC_WRITE) log('W', addr, op.size);
        if (!(op.access & (CS_AC_READ | CS_AC_WRITE))) log('?', addr, op.size);
      }
      // Implicit stack / string accesses that have no memory operand.
      switch (insn->id) {
        case X86_INS_PUSH: case X86_INS_CALL: log('W', u.rsp - 8, 8); break;
        case X86_INS_POP:  case X86_INS_RET:  log('R', u.rsp, 8); break;
        case X86_INS_LEAVE: log('R', u.rbp, 8); break;
        case X86_INS_MOVSB: case X86_INS_MOVSW: case X86_INS_MOVSD: case X86_INS_MOVSQ:
        case X86_INS_STOSB: case X86_INS_STOSW: case X86_INS_STOSD: case X86_INS_STOSQ:
        case X86_INS_LODSB: case X86_INS_LODSW: case X86_INS_LODSD: case X86_INS_LODSQ:
        case X86_INS_CMPSB: case X86_INS_CMPSW: case X86_INS_CMPSD: case X86_INS_CMPSQ: {
          unsigned esz = 1;
          switch (insn->id) {
            case X86_INS_MOVSW: case X86_INS_STOSW: case X86_INS_LODSW: case X86_INS_CMPSW: esz = 2; break;
            case X86_INS_MOVSD: case X86_INS_STOSD: case X86_INS_LODSD: case X86_INS_CMPSD: esz = 4; break;
            case X86_INS_MOVSQ: case X86_INS_STOSQ: case X86_INS_LODSQ: case X86_INS_CMPSQ: esz = 8; break;
            default: break;
          }
          bool rep = x.prefix[0] == X86_PREFIX_REP || x.prefix[0] == X86_PREFIX_REPNE;
          uint64_t bytes = esz * (rep ? (u.rcx ? u.rcx : 1) : 1);
          if (bytes > (1u << 20)) bytes = 1u << 20;
          bool src = insn->id <= X86_INS_MOVSQ ? true : false;   // movs: rsi read, rdi write
          switch (insn->id) {
            case X86_INS_MOVSB: case X86_INS_MOVSW: case X86_INS_MOVSD: case X86_INS_MOVSQ:
              log('R', u.rsi, bytes); log('W', u.rdi, bytes); break;
            case X86_INS_STOSB: case X86_INS_STOSW: case X86_INS_STOSD: case X86_INS_STOSQ:
              log('W', u.rdi, bytes); break;
            case X86_INS_LODSB: case X86_INS_LODSW: case X86_INS_LODSD: case X86_INS_LODSQ:
              log('R', u.rsi, bytes); break;
            default:
              log('R', u.rsi, bytes); log('R', u.rdi, bytes); break;
          }
          (void)src;
          break;
        }
        default: break;
      }
      cs_free(insn, cnt);
      if (s.replay_step(RUN_SINGLESTEP).status == REPLAY_EXITED) { ok_end = false; break; }
      t = s.current_task();
      for (const Pending& w : writes) {
        string v;
        if (t) hex_at(w.addr, w.size, &v); else v = "?";
        fprintf(f, "%#lx W %#lx %u %s %s\n", (unsigned long)ip, (unsigned long)w.addr,
                w.size, v.c_str(), w.text.c_str());
      }
      continue;
    } else {
      fprintf(f, "%#lx ? 0 0 - (undecodable)\n", (unsigned long)ip);
    }
    if (s.replay_step(RUN_SINGLESTEP).status == REPLAY_EXITED) { ok_end = false; break; }
  }
  fprintf(f, "# %ld instructions%s\n", steps, steps >= limit ? " (limit reached)" : "");
  fclose(f);
  if (trace_frames)
    fprintf(stderr, "access %s #%ld: %ld instructions -> %s\n", sym.c_str(), n, steps, path);
  return ok_end;
}
#else
static bool trace_access(ReplaySession&, const string&, long, const string&) {
  fprintf(stderr, "rr detach: -x needs capstone (rebuild with capstone-devel installed)\n");
  exit(1);
}
#endif

// Replay `s` until `target`. Returns the last completed frame (-1 if the
// trace ended first). With `store`, clones a checkpoint every `every` frames.
static FrameTime run_until(ReplaySession& s, ReplayModels& m, const Target& target,
                           CheckpointStore* store, FrameTime every) {
  s.on_task_cloned = [&](Task* parent, Task* child, int flags) {
    m.fd.fork_task(parent, child, flags);
  };
  FrameTime next_ckpt = every ? ((s.trace_reader().time() / every) + 1) * every : 0;
  FrameTime stopped_at = -1;
  while (true) {
    Task* cur = s.current_task();
    if (cur) {
      m.observe(s.current_trace_frame(), cur);
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
    if (vm && s.done_initial_exec() && !m.watch.symbols.empty() &&
        before >= m.watch.from_event) {
      m.watch.resolve(cur);
      armed = m.watch.arm(*vm);
    }
    auto result = s.replay_step(RUN_CONTINUE);
    if (armed)
      m.watch.disarm(*vm);
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
      const string* sym = t ? m.watch.symbol_at(t->ip()) : nullptr;

      PendingReturn pr;
      if (sym) {
        long n = ++m.watch.hits[*sym];
        m.watch.dump(t, *sym, n);
        if (m.watch.track_exits)
          m.watch.expect_return(t, *sym, n);
        if (trace_frames)
        {
          NativeArch::user_regs_struct u = t->regs().get_ptrace();
          uint64_t st[4] = { 0, 0, 0, 0 };       // [sp]=return addr, then stack args
          bool ok = true;
          t->read_bytes_helper(remote_ptr<void>(u.rsp), sizeof st, st, &ok);
          fprintf(stderr, "hit %s #%ld tid %d after frame %lld"
                  " rdi %#lx rsi %#lx rdx %#lx rcx %#lx r8 %#lx r9 %#lx"
                  " ra %#lx s1 %#lx s2 %#lx s3 %#lx\n",
                  sym->c_str(), n, t->rec_tid, (long long)stopped_at,
                  (unsigned long)u.rdi, (unsigned long)u.rsi, (unsigned long)u.rdx,
                  (unsigned long)u.rcx, (unsigned long)u.r8, (unsigned long)u.r9,
                  (unsigned long)st[0], (unsigned long)st[1], (unsigned long)st[2],
                  (unsigned long)st[3]);
        }
        if (!target.by_event() && *sym == target.symbol && n >= target.hit &&
            frame_allows_branch(s))
          break;
        auto ae = m.watch.access_every.find(*sym);
        if (ae != m.watch.access_every.end() && n % ae->second == 0) {
          if (!trace_access(s, *sym, n, m.watch.dump_dir)) {
            stopped_at = -1;
            break;
          }
          stopped_at = s.trace_reader().time() - 1;
          Task* cur = s.current_task();
          if (cur && m.watch.take_return(cur, &pr)) {     // we stepped onto the return
            if (trace_frames)
              fprintf(stderr, "ret %s #%ld tid %d rax %#lx after frame %lld\n",
                      pr.sym.c_str(), pr.n, cur->rec_tid,
                      (unsigned long)cur->regs().ax(), (long long)stopped_at);
            m.watch.dump(cur, pr.sym, pr.n, ".exit");
          }
          continue;                                   // already off the breakpoint
        }
      } else if (t && m.watch.take_return(t, &pr)) {
        if (trace_frames)
          fprintf(stderr, "ret %s #%ld tid %d rax %#lx after frame %lld\n",
                  pr.sym.c_str(), pr.n, t->rec_tid,
                  (unsigned long)t->regs().ax(), (long long)stopped_at);
        m.watch.dump(t, pr.sym, pr.n, ".exit");
      }
      // Step off the breakpoint address (disarmed right now).
      if (s.replay_step(RUN_SINGLESTEP).status == REPLAY_EXITED) {
        stopped_at = -1;
        break;
      }
      continue;                                    // mid-frame: no checkpoint
    }
    if (store && every && stopped_at >= next_ckpt && s.can_clone()) {
      store->take(s, m, stopped_at);
      next_ckpt = (stopped_at / every + 1) * every;
    }
    if (target.by_event() && s.trace_reader().time() > target.event && s.can_clone())
      break;
  }
  s.on_task_cloned = nullptr;
  return stopped_at;
}

static int hand_off(ReplaySession& session, ReplayModels& m, const DetachFlags& flags,
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

  for (const string& f : m.check.run(tasks, m.fd)) {
    fprintf(stderr, "rr detach: %s%s\n", flags.strict ? "" : "warning: ", f.c_str());
    if (flags.strict)
        return 1;
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

    if (!restored_tables.insert(table_id).second)
      continue;

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

  // CRRIU_TRACE: exactly what is handed off (after the register fix-ups
  // above), to compare with a debugger attached to the branch.
  if (trace_frames) {
    static SymbolMaps symbols;
    for (Task* t : tasks) {
      const Registers& r = t->regs();
      symbols.build(t);
      fprintf(stderr, "handoff tid %d rec_tid %d ip %#lx (%s) sp %#lx arg1 %#lx arg2 %#lx arg3 %#lx\n",
              t->tid, t->rec_tid, (unsigned long)r.ip().register_value(),
              symbols.lookup(t, r.ip()).c_str(), (unsigned long)r.sp().as_int(),
              (unsigned long)r.arg1(), (unsigned long)r.arg2(), (unsigned long)r.arg3());

      const struct { const char* name; uintptr_t addr; } spots[] = {
        { "ip", r.ip().register_value() }, { "sp", r.sp().as_int() }, { "arg2", r.arg2() } };

      for (const auto& spot : spots) {
        uint8_t b[16];
        bool ok = true;
        t->read_bytes_helper(remote_ptr<void>(spot.addr), sizeof b, b, &ok);
        fprintf(stderr, "  mem[%s=%#lx]:", spot.name, (unsigned long)spot.addr);
        if (!ok) {
            fprintf(stderr, " unreadable\n");
            continue;
        }
        for (uint8_t x : b)
            fprintf(stderr, " %02x", x);
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

// Clone `src` (a checkpoint or the live replay), replay the clone on to
// `target` if asked, hand it off as branch `branch_no`.
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
  int rc = hand_off(*b, m, flags, at, tag);   // hand_off ends with forget_tasks()
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
