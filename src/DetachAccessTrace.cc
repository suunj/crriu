/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "DetachAccessTrace.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>

#include <vector>

#include "DetachSymbols.h"
#include "ReplaySession.h"
#include "ReplayTask.h"
#include "kernel_abi.h"
#ifdef HAVE_CAPSTONE
#include <capstone/capstone.h>
#endif

using namespace std;

namespace rr {

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

bool trace_access(ReplaySession& s, const string& sym, long n, const string& dir) {
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
  if (detach_trace_enabled())
    fprintf(stderr, "access %s #%ld: %ld instructions -> %s\n", sym.c_str(), n, steps, path);
  return ok_end;
}
#else
bool trace_access(ReplaySession&, const string&, long, const string&) {
  fprintf(stderr, "rr detach: -x needs capstone (rebuild with capstone-devel installed)\n");
  exit(1);
}
#endif

} // namespace rr
