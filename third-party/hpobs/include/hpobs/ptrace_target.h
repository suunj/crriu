/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef HPOBS_PTRACE_TARGET_H_
#define HPOBS_PTRACE_TARGET_H_

#include <sys/types.h>

#include <map>
#include <memory>

#include "hpobs/target.h"

namespace hpobs {

// Target over a single-threaded process traced with ptrace. Breakpoints are
// int3 patches; stepping or continuing from a breakpoint address lifts the
// patch for one instruction. Threads created by the tracee are not
// followed (PTRACE_O_TRACECLONE is not set).
class PtraceTarget : public Target {
public:
  // fork+exec `argv` under ptrace; returns it stopped right after the exec.
  static std::unique_ptr<PtraceTarget> spawn(char* const argv[]);
  // Attach to a running process; returns it stopped.
  static std::unique_ptr<PtraceTarget> attach(pid_t pid);
  ~PtraceTarget() override;

  enum class StopKind { Breakpoint, Signal, Exec, Exited };
  struct Stop {
    StopKind kind;
    uint64_t addr;  // Breakpoint: its address (ip already rewound to it)
    int code;       // Signal: signo; Exited: exit status or -signo
  };
  // Run until a breakpoint, a signal, an exec or exit. A signal stop is
  // reported once and the signal delivered on the next cont()/step().
  Stop cont();
  bool exited() const { return exited_; }
  int exit_code() const { return exit_code_; }

  pid_t tid() const override { return pid_; }
  bool read(uint64_t addr, void* buf, size_t len) override;
  Regs regs() override;
  std::vector<Mapping> maps() override;
  uint64_t address_space_id() override;
  bool add_breakpoint(uint64_t addr) override;
  void remove_breakpoint(uint64_t addr) override;
  StepStatus step() override;

private:
  explicit PtraceTarget(pid_t pid);
  bool poke_byte(uint64_t addr, uint8_t byte);
  bool peek_byte(uint64_t addr, uint8_t* byte);
  void set_ip(uint64_t ip);
  // Put the original bytes back where our int3 patches fall inside buf.
  void hide_breakpoints(uint64_t addr, void* buf, size_t len) const;
  Stop wait_stop();
  bool step_over_breakpoint();  // if ip is on one of ours: lift, step, replant

  pid_t pid_;
  std::map<uint64_t, uint8_t> bps_;  // address -> original byte
  int pending_signal_ = 0;
  bool exited_ = false;
  int exit_code_ = 0;
  uint64_t generation_ = 1;  // bumped on exec
};

}  // namespace hpobs

#endif /* HPOBS_PTRACE_TARGET_H_ */
