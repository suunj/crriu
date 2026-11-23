/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "DetachWatch.h"

#include <limits.h>
#include <stdio.h>
#include <sys/stat.h>

#include "AddressSpace.h"
#include "DetachSymbols.h"
#include "Task.h"

using namespace std;

namespace rr {

void Watch::dump(Task* t, const string& sym, long n, const char* phase) {
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

void Watch::resolve(Task* t) {
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

bool Watch::arm(AddressSpace& vm) {
  bool any = false;
  for (const auto& kv : addr)
      any |= vm.add_breakpoint(kv.second, BKPT_USER);
  for (const auto& p : pending)
      any |= vm.add_breakpoint(p.ret, BKPT_USER);
  return any;
}

void Watch::disarm(AddressSpace& vm) {
  for (const auto& kv : addr)
      vm.remove_breakpoint(kv.second, BKPT_USER);
  for (const auto& p : pending)
      vm.remove_breakpoint(p.ret, BKPT_USER);
}

void Watch::expect_return(Task* t, const string& sym, long n) {
  remote_ptr<void> sp = t->regs().sp();
  uint64_t ra = t->read_mem(sp.cast<uint64_t>());
  pending.push_back({ remote_code_ptr(ra), sp + 8, t->rec_tid, sym, n });
}

bool Watch::take_return(Task* t, PendingReturn* out) {
  for (auto it = pending.begin(); it != pending.end(); ++it) {
    if (it->ret == t->ip() && it->tid == t->rec_tid && it->sp == t->regs().sp()) {
      *out = *it;
      pending.erase(it);
      return true;
    }
  }
  return false;
}

const string* Watch::symbol_at(remote_code_ptr ip) const {
  for (const auto& kv : addr)
      if (kv.second == ip)
          return &kv.first;
  return nullptr;
}

} // namespace rr
