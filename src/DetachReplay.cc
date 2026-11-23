/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "DetachReplay.h"

#include <stdio.h>

#include "AddressSpace.h"
#include "DetachAccessTrace.h"
#include "DetachSymbols.h"
#include "ReplayTask.h"
#include "kernel_abi.h"
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
static void report_return(Watch& watch, Task* t, const PendingReturn& pr,
                          FrameTime stopped_at) {
  if (detach_trace_enabled())
    fprintf(stderr, "ret %s #%ld tid %d rax %#lx after frame %lld\n",
            pr.sym.c_str(), pr.n, t->rec_tid,
            (unsigned long)t->regs().ax(), (long long)stopped_at);
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
    // For CRRIU_TRACE: the frame about to be replayed, and its symbol map
    // (resolved now, while the task that will execute it is current).
    string pending_sym;
    TraceFrame pending;
    FrameTime before = s.trace_reader().time();
    if (detach_trace_enabled() && cur) {
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
      const string* sym = t ? m.watch.symbol_at(t->ip()) : nullptr;

      PendingReturn pr;
      if (sym) {
        long n = ++m.watch.hits[*sym];
        m.watch.dump(t, *sym, n);
        if (m.watch.track_exits)
          m.watch.expect_return(t, *sym, n);
        if (detach_trace_enabled())
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
            report_return(m.watch, cur, pr, stopped_at);
          }
          continue;                                   // already off the breakpoint
        }
      } else if (t && m.watch.take_return(t, &pr)) {
        report_return(m.watch, t, pr, stopped_at);
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
