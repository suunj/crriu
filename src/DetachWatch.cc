/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "DetachWatch.h"

#include <limits.h>
#include <stdio.h>
#include <sys/stat.h>

#include "DetachSymbols.h"

using namespace std;

namespace rr {

void Watch::dump(obs::Target& t, const string& sym, long n, const char* phase) {
  if (dumps.empty())
      return;
  for (const Dump& d : dumps) {
    if (n < d.from || n % d.every)
        continue;
    if (!dumped)
        mkdir(dump_dir.c_str(), 0755);
    vector<uint8_t> buf(d.len);
    if (!t.read(d.addr, buf.data(), d.len)) {
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

void Watch::resolve(obs::Target& t) {
  size_t nmaps = t.maps().size();
  bool incomplete = addr.size() < symbols.size();
  if (t.address_space_id() == resolved_for && !(incomplete && nmaps != resolved_maps))
    return;
  resolved_for = t.address_space_id();
  resolved_maps = nmaps;
  for (const string& sym : symbols) {
    if (addr.count(sym) && !incomplete)
        continue;
    string location;
    uint64_t a = resolve_break(t, sym, location);

    if (!a)
        continue;
    if (!addr.count(sym) || addr[sym] != a)
      fprintf(stderr, "rr detach: break at %s\n", location.c_str());
    addr[sym] = a;
  }
}

bool Watch::arm(obs::Target& t) {
  bool any = false;
  for (const auto& kv : addr)
      any |= t.add_breakpoint(kv.second);
  for (const auto& p : pending)
      any |= t.add_breakpoint(p.ret);
  return any;
}

void Watch::disarm(obs::Target& t) {
  for (const auto& kv : addr)
      t.remove_breakpoint(kv.second);
  for (const auto& p : pending)
      t.remove_breakpoint(p.ret);
}

void Watch::expect_return(obs::Target& t, const string& sym, long n) {
  obs::Regs r = t.regs();
  uint64_t ra = 0;
  t.read(r.sp(), &ra, sizeof ra);
  pending.push_back({ ra, r.sp() + 8, t.tid(), sym, n });
}

bool Watch::take_return(obs::Target& t, PendingReturn* out) {
  obs::Regs r = t.regs();
  for (auto it = pending.begin(); it != pending.end(); ++it) {
    if (it->ret == r.ip() && it->tid == t.tid() && it->sp == r.sp()) {
      *out = *it;
      pending.erase(it);
      return true;
    }
  }
  return false;
}

const string* Watch::symbol_at(uint64_t ip) const {
  for (const auto& kv : addr)
      if (kv.second == ip)
          return &kv.first;
  return nullptr;
}

} // namespace rr
