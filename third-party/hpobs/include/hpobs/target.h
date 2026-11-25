/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef HPOBS_TARGET_H_
#define HPOBS_TARGET_H_

#include <stdint.h>
#include <sys/mman.h>
#include <sys/types.h>

#include <string>
#include <vector>

namespace hpobs {

// One mapping of the target's address space.
struct Mapping {
  uint64_t start;
  uint64_t end;
  int prot;              // PROT_* bits
  uint64_t file_offset;  // of `start` within fsname
  std::string fsname;    // empty when anonymous

  // An executable mapping of a file on disk: the only kind symbols are
  // looked up in.
  bool exec_file() const { return (prot & PROT_EXEC) && !fsname.empty() && fsname[0] == '/'; }
};

// General-purpose registers in x86-64 DWARF numbering, which gdb and the
// remote protocol use too: 0 rax 1 rdx 2 rcx 3 rbx 4 rsi 5 rdi 6 rbp 7 rsp
// 8-15 r8-r15 16 rip.
struct Regs {
  enum { RAX, RDX, RCX, RBX, RSI, RDI, RBP, RSP, R8, R9, R10, R11, R12, R13, R14, R15, RIP, NGPR };
  uint64_t gpr[NGPR];
  uint64_t fs_base;
  uint64_t gs_base;

  uint64_t ip() const { return gpr[RIP]; }
  uint64_t sp() const { return gpr[RSP]; }
  uint64_t ax() const { return gpr[RAX]; }
  // SysV integer argument i (0-5): rdi rsi rdx rcx r8 r9.
  uint64_t arg(int i) const {
    static const int order[6] = {RDI, RSI, RDX, RCX, R8, R9};
    return gpr[order[i]];
  }
};

enum class StepStatus { Stopped, Exited };

// A stopped thread we can observe and nudge: read its memory and registers,
// list its mappings, plant breakpoints and single-step it. This is all the
// symbol, watch and access-trace code needs. A ptrace'd process, a task of
// an rr replay and a gdb remote stub can all implement it.
class Target {
public:
  virtual ~Target() = default;

  virtual pid_t tid() const = 0;

  // False if any byte of [addr, addr+len) is unreadable.
  virtual bool read(uint64_t addr, void* buf, size_t len) = 0;
  virtual Regs regs() = 0;
  virtual std::vector<Mapping> maps() = 0;

  // Identifies the address space: symbols resolved under one id stay valid
  // while the id stays the same. Changes on exec.
  virtual uint64_t address_space_id() = 0;

  // Software breakpoints. add_breakpoint returns true if one was installed.
  virtual bool add_breakpoint(uint64_t addr) = 0;
  virtual void remove_breakpoint(uint64_t addr) = 0;

  // Execute one instruction. After Exited there is no thread to observe.
  virtual StepStatus step() = 0;
};

}  // namespace hpobs

#endif /* HPOBS_TARGET_H_ */
