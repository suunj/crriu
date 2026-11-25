/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_RR_TASK_TARGET_H_
#define RR_RR_TASK_TARGET_H_

#include "AddressSpace.h"
#include "ReplaySession.h"
#include "hpobs/target.h"

namespace rr {

class Task;

// hpobs::Target over a task of a replay session. Breakpoints go to the
// address space captured at construction, so they can still be removed
// after the task is gone; step() replays one instruction and then follows
// the session's current task, which may differ from the one stepped.
class RrTaskTarget : public hpobs::Target {
public:
  RrTaskTarget(ReplaySession& s, Task* t);

  Task* task() const { return t_; }

  pid_t tid() const override;
  bool read(uint64_t addr, void* buf, size_t len) override;
  hpobs::Regs regs() override;
  std::vector<hpobs::Mapping> maps() override;
  uint64_t address_space_id() override;
  bool add_breakpoint(uint64_t addr) override;
  void remove_breakpoint(uint64_t addr) override;
  hpobs::StepStatus step() override;

private:
  ReplaySession& s_;
  Task* t_;
  AddressSpace::shr_ptr vm_;
};

} // namespace rr

#endif /* RR_RR_TASK_TARGET_H_ */
