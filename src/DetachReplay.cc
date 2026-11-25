/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "DetachReplay.h"

#include <stdio.h>

#include "DetachAccessTrace.h"
#include "DetachSymbols.h"
#include "ReplayTask.h"
#include "RrTaskTarget.h"
#include "kernel_metadata.h"

using namespace std;

namespace rr {

// Can the replay be handed off at the frame it is on?
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

// A watched call (-e) has returned in `t`: log it and take the ".exit" dumps.
static void report_return(Watch& watch, obs::Target& t, const PendingReturn& pr,
                          FrameTime stopped_at) {
  if (detach_trace_enabled())
    fprintf(stderr, "ret %s #%ld tid %d rax %#lx after frame %lld\n",
            pr.sym.c_str(), pr.n, t.tid(),
            (unsigned long)t.regs().ax(), (long long)stopped_at);
  watch.dump(t, pr.sym, pr.n, ".exit");
}

FrameTime run_until(ReplaySession& s, ReplayModels& m, const Target& target,
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
    // The task about to be stepped. Holds its address space across the
    // step so the breakpoints can be removed even if the task goes away.
    RrTaskTarget tgt(s, cur);
    // For CRRIU_TRACE: the frame about to be replayed, and its symbol map
    // (resolved now, while the task that will execute it is current).
    string pending_sym;
    TraceFrame pending;
    FrameTime before = s.trace_reader().time();
    if (detach_trace_enabled() && cur) {
      static SymbolMaps symbols;
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
    if (armed)
      m.watch.disarm(tgt);
    if (detach_trace_enabled() && s.trace_reader().time() > before) {   // frame completed
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
      RrTaskTarget bt(s, t);
      const string* sym = t ? m.watch.symbol_at(bt.regs().ip()) : nullptr;

      PendingReturn pr;
      if (sym) {
        long n = ++m.watch.hits[*sym];
        m.watch.dump(bt, *sym, n);
        if (m.watch.track_exits)
          m.watch.expect_return(bt, *sym, n);
        if (detach_trace_enabled())
        {
          obs::Regs u = bt.regs();
          uint64_t st[4] = { 0, 0, 0, 0 };       // [sp]=return addr, then stack args
          bt.read(u.sp(), st, sizeof st);
          fprintf(stderr, "hit %s #%ld tid %d after frame %lld"
                  " rdi %#lx rsi %#lx rdx %#lx rcx %#lx r8 %#lx r9 %#lx"
                  " ra %#lx s1 %#lx s2 %#lx s3 %#lx\n",
                  sym->c_str(), n, bt.tid(), (long long)stopped_at,
                  (unsigned long)u.arg(0), (unsigned long)u.arg(1), (unsigned long)u.arg(2),
                  (unsigned long)u.arg(3), (unsigned long)u.arg(4), (unsigned long)u.arg(5),
                  (unsigned long)st[0], (unsigned long)st[1], (unsigned long)st[2],
                  (unsigned long)st[3]);
        }
        if (!target.by_event() && *sym == target.symbol && n >= target.hit &&
            frame_allows_branch(s))
          break;
        auto ae = m.watch.access_every.find(*sym);
        if (ae != m.watch.access_every.end() && n % ae->second == 0) {
          long steps = 0;
          string path;
          bool ok = trace_access(bt, *sym, n, m.watch.dump_dir, &steps, &path);
          if (detach_trace_enabled())
            fprintf(stderr, "access %s #%ld: %ld instructions -> %s\n",
                    sym->c_str(), n, steps, path.c_str());
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
    if (target.by_event() && s.trace_reader().time() > target.event && s.can_clone())
      break;
  }
  s.on_task_cloned = nullptr;
  return stopped_at;
}

} // namespace rr
