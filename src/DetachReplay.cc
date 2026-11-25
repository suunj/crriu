/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "DetachReplay.h"

#include <inttypes.h>
#include <stdio.h>

#include "ReplayTask.h"
#include "RrTaskTarget.h"
#include "hpobs/access_trace.h"
#include "hpobs/symbols.h"
#include "kernel_metadata.h"

using namespace std;

namespace rr {

// Can the replay be handed off at the frame it is on?
static bool frame_allows_branch(ReplaySession& s) {
  if (!s.current_task() || !s.done_initial_exec()) {
    return false;
  }
  switch (s.current_trace_frame().event().type()) {
    case EV_EXIT:
    case EV_SYSCALLBUF_RESET:
    case EV_TRACE_TERMINATION:
      return false;
    default:
      return true;
  }
}

// A watched call (-e) has returned in `t`: log it and take the ".exit" dumps.
static void report_return(hpobs::Watch& watch, hpobs::Target& t,
                          const hpobs::PendingReturn& pr, FrameTime stopped_at) {
  if (detach_trace_enabled()) {
    fprintf(stderr, "ret %s #%" PRId64 " tid %d rax %#" PRIx64 " after frame %lld\n",
            pr.sym.c_str(), pr.n, t.tid(), t.regs().ax(), (long long)stopped_at);
  }
  watch.dump(t, pr.sym, pr.n, ".exit");
}

// CRRIU_TRACE: a completed frame, with the syscall result when it has one.
static void report_frame(const TraceFrame& frame, FrameTime time, const string& sym) {
  string ret;
  if (frame.event().is_syscall_event() &&
      frame.event().Syscall().state == EXITING_SYSCALL) {
    long r = (long)frame.regs().syscall_result_signed();
    char buf[48];
    if (r < 0 && r > -4096) {
      snprintf(buf, sizeof buf, " = -%s", errno_name(-r).c_str());
    } else {
      snprintf(buf, sizeof buf, " = %ld", r);
    }
    ret = buf;
  }
  fprintf(stderr, "frame %lld tid %d %-36s ticks %lld rip %s%s\n", (long long)time,
          frame.tid(), frame.event().str().c_str(), (long long)frame.ticks(),
          sym.c_str(), ret.c_str());
}

// CRRIU_TRACE: a watched entry with its register and first stack arguments.
static void report_hit(hpobs::Target& t, const string& sym, int64_t n, FrameTime stopped_at) {
  hpobs::Regs u = t.regs();
  uint64_t st[4] = { 0, 0, 0, 0 };       // [sp]=return addr, then stack args
  t.read(u.sp(), st, sizeof st);
  fprintf(stderr,
          "hit %s #%" PRId64 " tid %d after frame %lld"
          " rdi %#" PRIx64 " rsi %#" PRIx64 " rdx %#" PRIx64
          " rcx %#" PRIx64 " r8 %#" PRIx64 " r9 %#" PRIx64
          " ra %#" PRIx64 " s1 %#" PRIx64 " s2 %#" PRIx64 " s3 %#" PRIx64 "\n",
          sym.c_str(), n, t.tid(), (long long)stopped_at, u.arg(0), u.arg(1), u.arg(2),
          u.arg(3), u.arg(4), u.arg(5), st[0], st[1], st[2], st[3]);
}

FrameTime run_until(ReplaySession& s, ReplayModels& m, const Target& target,
                    CheckpointStore* store, FrameTime every) {
  detach_init_logging();
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
    // The task about to be stepped. Holds its address space across the
    // step so the breakpoints can be removed even if the task goes away.
    RrTaskTarget tgt(s, cur);
    // For CRRIU_TRACE: the frame about to be replayed, and its symbol map
    // (resolved now, while the task that will execute it is current).
    string pending_sym;
    TraceFrame pending;
    FrameTime before = s.trace_reader().time();
    if (detach_trace_enabled() && cur) {
      static hpobs::SymbolMaps symbols;
      pending = s.current_trace_frame();
      pending_sym = symbols.lookup(tgt, pending.regs().ip().register_value());
    }
    // Arm for this step only: rr remaps segments as it replays (exec, mmap),
    // which would wipe a permanently installed int3, and a clone taken while
    // armed would carry the int3 into the branch.
    bool armed = false;
    if (cur && s.done_initial_exec() && !m.watch.symbols.empty() &&
        before >= m.watch.from_event) {
      m.watch.resolve(tgt);
      armed = m.watch.arm(tgt);
    }
    auto result = s.replay_step(RUN_CONTINUE);
    if (armed) {
      m.watch.disarm(tgt);
    }
    if (detach_trace_enabled() && s.trace_reader().time() > before) {   // frame completed
      report_frame(pending, s.trace_reader().time() - 1, pending_sym);
    }
    if (result.status == REPLAY_EXITED) {
      stopped_at = -1;
      break;
    }
    stopped_at = s.trace_reader().time() - 1;

    if (result.break_status.breakpoint_hit) {
      Task* t = result.break_status.task_context.task;
      RrTaskTarget bt(s, t);
      const string* sym = t ? m.watch.symbol_at(bt.regs().ip()) : nullptr;

      hpobs::PendingReturn pr;
      if (sym) {
        int64_t n = m.watch.record_hit(*sym);
        m.watch.dump(bt, *sym, n);
        if (m.watch.track_exits) {
          m.watch.expect_return(bt, *sym, n);
        }
        if (detach_trace_enabled()) {
          report_hit(bt, *sym, n, stopped_at);
        }
        if (!target.by_event() && *sym == target.symbol && n >= target.hit &&
            frame_allows_branch(s)) {
          break;
        }
        auto ae = m.watch.access_every.find(*sym);
        if (ae != m.watch.access_every.end() && n % ae->second == 0) {
          int64_t steps = 0;
          string path;
          bool ok = hpobs::trace_access(bt, *sym, n, m.watch.dump_dir, &steps, &path);
          if (detach_trace_enabled()) {
            fprintf(stderr, "access %s #%" PRId64 ": %" PRId64 " instructions -> %s\n",
                    sym->c_str(), n, steps, path.c_str());
          }
          if (!ok) {
            stopped_at = -1;
            break;
          }
          stopped_at = s.trace_reader().time() - 1;
          Task* cur2 = s.current_task();
          RrTaskTarget ct(s, cur2);
          if (cur2 && m.watch.take_return(ct, &pr)) {    // we stepped onto the return
            report_return(m.watch, ct, pr, stopped_at);
          }
          continue;                                   // already off the breakpoint
        }
      } else if (t && m.watch.take_return(bt, &pr)) {
        report_return(m.watch, bt, pr, stopped_at);
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
    if (target.by_event() && s.trace_reader().time() > target.event && s.can_clone()) {
      break;
    }
  }
  s.on_task_cloned = nullptr;
  return stopped_at;
}

} // namespace rr
