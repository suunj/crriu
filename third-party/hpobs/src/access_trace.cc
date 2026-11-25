/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "hpobs/access_trace.h"

#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include <vector>

#include "hpobs/log.h"

#ifdef HAVE_CAPSTONE
#include <capstone/capstone.h>
#endif

using namespace std;

namespace hpobs {

bool trace_access_supported() {
#ifdef HAVE_CAPSTONE
  return true;
#else
  return false;
#endif
}

#ifdef HAVE_CAPSTONE

// Capstone register -> our DWARF-numbered slot. `low32` picks the 32-bit
// alias (eax for rax, ...).
struct RegSlot {
  x86_reg reg;
  int slot;
  bool low32;
};

static const RegSlot kRegSlots[] = {
    {X86_REG_RAX, Regs::RAX, false}, {X86_REG_EAX, Regs::RAX, true},
    {X86_REG_RDX, Regs::RDX, false}, {X86_REG_EDX, Regs::RDX, true},
    {X86_REG_RCX, Regs::RCX, false}, {X86_REG_ECX, Regs::RCX, true},
    {X86_REG_RBX, Regs::RBX, false}, {X86_REG_EBX, Regs::RBX, true},
    {X86_REG_RSI, Regs::RSI, false}, {X86_REG_ESI, Regs::RSI, true},
    {X86_REG_RDI, Regs::RDI, false}, {X86_REG_EDI, Regs::RDI, true},
    {X86_REG_RBP, Regs::RBP, false}, {X86_REG_EBP, Regs::RBP, true},
    {X86_REG_RSP, Regs::RSP, false}, {X86_REG_ESP, Regs::RSP, true},
    {X86_REG_R8, Regs::R8, false},   {X86_REG_R8D, Regs::R8, true},
    {X86_REG_R9, Regs::R9, false},   {X86_REG_R9D, Regs::R9, true},
    {X86_REG_R10, Regs::R10, false}, {X86_REG_R10D, Regs::R10, true},
    {X86_REG_R11, Regs::R11, false}, {X86_REG_R11D, Regs::R11, true},
    {X86_REG_R12, Regs::R12, false}, {X86_REG_R12D, Regs::R12, true},
    {X86_REG_R13, Regs::R13, false}, {X86_REG_R13D, Regs::R13, true},
    {X86_REG_R14, Regs::R14, false}, {X86_REG_R14D, Regs::R14, true},
    {X86_REG_R15, Regs::R15, false}, {X86_REG_R15D, Regs::R15, true},
};

// Value of `reg` in `r`; rip-relative operands use the address of the next
// instruction. Unknown registers (segment bases are handled by the caller,
// vector registers never form addresses) read as 0.
static uint64_t reg_value(const Regs& r, x86_reg reg, uint64_t next_ip) {
  if (reg == X86_REG_RIP) {
    return next_ip;
  }
  for (const RegSlot& s : kRegSlots) {
    if (s.reg == reg) {
      return s.low32 ? (uint32_t)r.gpr[s.slot] : r.gpr[s.slot];
    }
  }
  return 0;
}

// String instructions have no memory operand in the decoder's view; they
// read [rsi] and/or write or read [rdi], `size` bytes per element.
struct StringOp {
  unsigned id;
  unsigned size;
  bool reads_rsi;
  bool reads_rdi;
  bool writes_rdi;
};

static const StringOp kStringOps[] = {
    {X86_INS_MOVSB, 1, true, false, true},  {X86_INS_MOVSW, 2, true, false, true},
    {X86_INS_MOVSD, 4, true, false, true},  {X86_INS_MOVSQ, 8, true, false, true},
    {X86_INS_STOSB, 1, false, false, true}, {X86_INS_STOSW, 2, false, false, true},
    {X86_INS_STOSD, 4, false, false, true}, {X86_INS_STOSQ, 8, false, false, true},
    {X86_INS_LODSB, 1, true, false, false}, {X86_INS_LODSW, 2, true, false, false},
    {X86_INS_LODSD, 4, true, false, false}, {X86_INS_LODSQ, 8, true, false, false},
    {X86_INS_CMPSB, 1, true, true, false},  {X86_INS_CMPSW, 2, true, true, false},
    {X86_INS_CMPSD, 4, true, true, false},  {X86_INS_CMPSQ, 8, true, true, false},
};

static const StringOp* string_op(unsigned id) {
  for (const StringOp& op : kStringOps) {
    if (op.id == id) {
      return &op;
    }
  }
  return nullptr;
}

// Bound on instructions followed in one call, so a runaway or very long
// call does not single-step forever.
static const int64_t kMaxTraceSteps = 2000000;
// Bound on the bytes attributed to one rep-prefixed string instruction.
static const uint64_t kMaxStringOpBytes = 1u << 20;
// Bytes of a memory operand shown in the log before truncating with "..".
static const unsigned kMaxHexBytes = 64;

namespace {

// The process-wide capstone handle, opened on first use and closed at exit.
class Disassembler {
public:
  static csh handle() {
    static Disassembler d;
    return d.cs_;
  }

private:
  Disassembler() {
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &cs_) != CS_ERR_OK) {
      cs_ = 0;
      return;
    }
    cs_option(cs_, CS_OPT_DETAIL, CS_OPT_ON);
  }
  ~Disassembler() {
    if (cs_) {
      cs_close(&cs_);
    }
  }
  csh cs_ = 0;
};

}  // namespace

namespace {

// One call being traced: the log file and the helpers that write to it.
class AccessLog {
public:
  AccessLog(Target& t, FILE* f) : t_(t), f_(f) {}

  // Log every memory access of `insn`, executed with registers `u` at `ip`.
  // Reads are written now with the value before the step; writes are
  // queued for flush_writes() so they carry the value after it.
  void record(const cs_insn* insn, const Regs& u, uint64_t ip) {
    ip_ = ip;
    text_ = string(insn->mnemonic) + " " + insn->op_str;
    writes_.clear();

    uint64_t next_ip = ip + insn->size;
    const cs_x86& x = insn->detail->x86;
    for (uint8_t i = 0; i < x.op_count; i++) {
      const cs_x86_op& op = x.operands[i];
      if (op.type != X86_OP_MEM) {
        continue;
      }
      if (insn->id == X86_INS_LEA || insn->id == X86_INS_NOP) {
        continue;  // address formed, memory untouched
      }
      uint64_t addr = (uint64_t)op.mem.disp;
      addr += reg_value(u, (x86_reg)op.mem.base, next_ip);
      addr += reg_value(u, (x86_reg)op.mem.index, next_ip) * (op.mem.scale ? op.mem.scale : 1);
      if (op.mem.segment == X86_REG_FS) {
        addr += u.fs_base;
      }
      if (op.mem.segment == X86_REG_GS) {
        addr += u.gs_base;
      }
      if (op.access & CS_AC_READ) {
        log('R', addr, op.size);
      }
      if (op.access & CS_AC_WRITE) {
        log('W', addr, op.size);
      }
      if (!(op.access & (CS_AC_READ | CS_AC_WRITE))) {
        log('?', addr, op.size);
      }
    }

    // Implicit stack and string accesses that have no memory operand.
    uint64_t rsp = u.gpr[Regs::RSP];
    switch (insn->id) {
      case X86_INS_PUSH:
      case X86_INS_CALL:
        log('W', rsp - 8, 8);
        break;
      case X86_INS_POP:
      case X86_INS_RET:
        log('R', rsp, 8);
        break;
      case X86_INS_LEAVE:
        log('R', u.gpr[Regs::RBP], 8);
        break;
      default:
        break;
    }
    if (const StringOp* sop = string_op(insn->id)) {
      bool rep = x.prefix[0] == X86_PREFIX_REP || x.prefix[0] == X86_PREFIX_REPNE;
      uint64_t count = rep ? (u.gpr[Regs::RCX] ? u.gpr[Regs::RCX] : 1) : 1;
      uint64_t bytes = sop->size * count;
      if (bytes > kMaxStringOpBytes) {
        bytes = kMaxStringOpBytes;
      }
      if (sop->reads_rsi) {
        log('R', u.gpr[Regs::RSI], bytes);
      }
      if (sop->reads_rdi) {
        log('R', u.gpr[Regs::RDI], bytes);
      }
      if (sop->writes_rdi) {
        log('W', u.gpr[Regs::RDI], bytes);
      }
    }
  }

  // After the step: write the queued writes with their new values.
  void flush_writes() {
    for (const Pending& w : writes_) {
      string v = hex_at(w.addr, w.size);
      fprintf(f_, "%#" PRIx64 " W %#" PRIx64 " %u %s %s\n", ip_, w.addr, w.size, v.c_str(),
              text_.c_str());
    }
    writes_.clear();
  }

  void undecodable(uint64_t ip) { fprintf(f_, "%#" PRIx64 " ? 0 0 - (undecodable)\n", ip); }

private:
  struct Pending {
    uint64_t addr;
    unsigned size;
  };

  void log(char rw, uint64_t addr, unsigned size) {
    if (rw == 'W') {
      writes_.push_back({addr, size});
      return;
    }
    string v = hex_at(addr, size);
    fprintf(f_, "%#" PRIx64 " %c %#" PRIx64 " %u %s %s\n", ip_, rw, addr, size, v.c_str(),
            text_.c_str());
  }

  // Up to kMaxHexBytes at `addr` as hex, ".." if truncated, "?" if unreadable.
  string hex_at(uint64_t addr, unsigned size) {
    unsigned n = size > kMaxHexBytes ? kMaxHexBytes : size;
    uint8_t buf[kMaxHexBytes];
    if (!t_.read(addr, buf, n)) {
      return "?";
    }
    string out;
    char h[3];
    for (unsigned i = 0; i < n; i++) {
      snprintf(h, sizeof h, "%02x", buf[i]);
      out += h;
    }
    if (n < size) {
      out += "..";
    }
    return out;
  }

  Target& t_;
  FILE* f_;
  uint64_t ip_ = 0;
  string text_;
  vector<Pending> writes_;
};

}  // namespace

bool trace_access(Target& t, const string& sym, int64_t n, const string& dir, int64_t* steps_out,
                  string* path_out) {
  csh cs = Disassembler::handle();
  if (!cs) {
    logf("capstone init failed");
    return false;
  }

  uint64_t sp0 = t.regs().sp();
  uint64_t ret = 0;
  if (!t.read(sp0, &ret, sizeof ret)) {
    logf("%s: can't read the return address at sp %#" PRIx64, sym.c_str(), sp0);
    return false;
  }

  if (mkdir(dir.c_str(), 0755) < 0 && errno != EEXIST) {
    logf("mkdir %s: %s", dir.c_str(), strerror(errno));
    return false;
  }
  char path[PATH_MAX];
  snprintf(path, sizeof path, "%s/access.%s.%" PRId64 ".txt", dir.c_str(), sym.c_str(), n);
  FILE* f = fopen(path, "w");
  if (!f) {
    logf("%s: %s", path, strerror(errno));
    return false;
  }
  fprintf(f,
          "# %s hit %" PRId64 " tid %d entry sp %#" PRIx64 " ret %#" PRIx64
          "\n# ip rw addr size value insn\n",
          sym.c_str(), n, t.tid(), sp0, ret);

  AccessLog alog(t, f);
  int64_t steps = 0;
  bool ok_end = true;
  for (; steps < kMaxTraceSteps; steps++) {
    Regs u = t.regs();
    uint64_t ip = u.ip();
    if (ip == ret && u.sp() == sp0 + 8) {
      break;  // back in the caller
    }
    uint8_t code[16];
    bool readable = t.read(ip, code, sizeof code);
    cs_insn* insn = nullptr;
    size_t cnt = readable ? cs_disasm(cs, code, sizeof code, ip, 1, &insn) : 0;
    if (cnt == 1) {
      alog.record(insn, u, ip);
      cs_free(insn, cnt);
    } else {
      alog.undecodable(ip);
    }
    if (t.step() == StepStatus::Exited) {
      ok_end = false;
      break;
    }
    alog.flush_writes();
  }
  fprintf(f, "# %" PRId64 " instructions%s\n", steps,
          steps >= kMaxTraceSteps ? " (limit reached)" : "");
  fclose(f);
  if (steps_out) {
    *steps_out = steps;
  }
  if (path_out) {
    *path_out = path;
  }
  return ok_end;
}

#else

bool trace_access(Target&, const string&, int64_t, const string&, int64_t*, string*) {
  logf("access tracing needs capstone (rebuild with capstone-devel installed)");
  return false;
}

#endif

}  // namespace hpobs
