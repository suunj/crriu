/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "RrTaskTarget.h"

#include "ReplayTask.h"
#include "Task.h"
#include "kernel_abi.h"

using namespace std;

namespace rr {

RrTaskTarget::RrTaskTarget(ReplaySession& s, Task* t)
    : s_(s), t_(t), vm_(t ? t->vm() : nullptr) {}

pid_t RrTaskTarget::tid() const { return t_ ? t_->rec_tid : 0; }

bool RrTaskTarget::read(uint64_t addr, void* buf, size_t len) {
  if (!t_) {
    return false;
  }
  bool ok = true;
  t_->read_bytes_helper(remote_ptr<void>(addr), len, buf, &ok);
  return ok;
}

hpobs::Regs RrTaskTarget::regs() {
  hpobs::Regs r = {};
  if (!t_) {
    return r;
  }
  NativeArch::user_regs_struct u = t_->regs().get_ptrace();
  r.gpr[hpobs::Regs::RAX] = u.rax;
  r.gpr[hpobs::Regs::RDX] = u.rdx;
  r.gpr[hpobs::Regs::RCX] = u.rcx;
  r.gpr[hpobs::Regs::RBX] = u.rbx;
  r.gpr[hpobs::Regs::RSI] = u.rsi;
  r.gpr[hpobs::Regs::RDI] = u.rdi;
  r.gpr[hpobs::Regs::RBP] = u.rbp;
  r.gpr[hpobs::Regs::RSP] = u.rsp;
  r.gpr[hpobs::Regs::R8] = u.r8;
  r.gpr[hpobs::Regs::R9] = u.r9;
  r.gpr[hpobs::Regs::R10] = u.r10;
  r.gpr[hpobs::Regs::R11] = u.r11;
  r.gpr[hpobs::Regs::R12] = u.r12;
  r.gpr[hpobs::Regs::R13] = u.r13;
  r.gpr[hpobs::Regs::R14] = u.r14;
  r.gpr[hpobs::Regs::R15] = u.r15;
  r.gpr[hpobs::Regs::RIP] = u.rip;
  r.fs_base = u.fs_base;
  r.gs_base = u.gs_base;
  return r;
}

vector<hpobs::Mapping> RrTaskTarget::maps() {
  vector<hpobs::Mapping> out;
  AddressSpace* vm = t_ ? t_->vm().get() : vm_.get();
  if (!vm) {
    return out;
  }
  for (const auto& m : vm->maps()) {
    const KernelMapping& km = m.map;
    out.push_back({ km.start().as_int(), km.end().as_int(), km.prot(),
                    km.file_offset_bytes(), km.fsname() });
  }
  return out;
}

// An AddressSpace is unique while it lives and a replay never reuses one
// for another image, so its identity serves as the id.
uint64_t RrTaskTarget::address_space_id() {
  AddressSpace* vm = t_ ? t_->vm().get() : vm_.get();
  return reinterpret_cast<uintptr_t>(vm);
}

bool RrTaskTarget::add_breakpoint(uint64_t addr) {
  return vm_ && vm_->add_breakpoint(remote_code_ptr(addr), BKPT_USER);
}

void RrTaskTarget::remove_breakpoint(uint64_t addr) {
  if (vm_) {
    vm_->remove_breakpoint(remote_code_ptr(addr), BKPT_USER);
  }
}

hpobs::StepStatus RrTaskTarget::step() {
  auto result = s_.replay_step(RUN_SINGLESTEP);
  t_ = s_.current_task();
  if (result.status == REPLAY_EXITED || !t_) {
    return hpobs::StepStatus::Exited;
  }
  return hpobs::StepStatus::Stopped;
}

} // namespace rr
