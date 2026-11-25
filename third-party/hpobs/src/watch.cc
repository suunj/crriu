/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "hpobs/watch.h"

#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "hpobs/log.h"
#include "hpobs/symbols.h"

using namespace std;

namespace hpobs {

bool parse_dump(const string& spec, Dump* out) {
  Dump d;
  size_t a = spec.find(':');
  size_t b = a == string::npos ? a : spec.find(':', a + 1);
  if (a == string::npos || b == string::npos) {
    logf("dump spec expects NAME:ADDR:LEN[:EVERY[:FROM]], got '%s'", spec.c_str());
    return false;
  }
  d.name = spec.substr(0, a);
  d.addr = strtoull(spec.c_str() + a + 1, nullptr, 0);
  size_t c = spec.find(':', b + 1);
  d.len = strtoull(spec.substr(b + 1, c == string::npos ? string::npos : c - b - 1).c_str(),
                   nullptr, 0);
  if (c != string::npos) {
    d.every = strtoll(spec.c_str() + c + 1, nullptr, 0);
    size_t e = spec.find(':', c + 1);
    if (e != string::npos) {
      d.from = strtoll(spec.c_str() + e + 1, nullptr, 0);
    }
  }
  if (d.every < 1) {
    d.every = 1;
  }
  *out = d;
  return true;
}

void Watch::add_symbol(const string& sym) {
  for (const string& s : symbols) {
    if (s == sym) {
      return;
    }
  }
  symbols.push_back(sym);
}

int64_t Watch::hits_of(const string& sym) const {
  auto h = hits_.find(sym);
  return h == hits_.end() ? 0 : h->second;
}

void Watch::dump(Target& t, const string& sym, int64_t n, const char* phase) {
  if (dumps.empty()) {
    return;
  }
  for (const Dump& d : dumps) {
    if (n < d.from || n % d.every) {
      continue;
    }
    if (!dumped_ && mkdir(dump_dir.c_str(), 0755) < 0 && errno != EEXIST) {
      logf("mkdir %s: %s", dump_dir.c_str(), strerror(errno));
      return;
    }
    vector<uint8_t> buf(d.len);
    if (!t.read(d.addr, buf.data(), d.len)) {
      logf("dump %s: can't read %zu bytes at %#" PRIx64, d.name.c_str(), d.len, d.addr);
      continue;
    }
    char path[PATH_MAX];
    snprintf(path, sizeof path, "%s/%s.%s.%" PRId64 "%s.bin", dump_dir.c_str(), d.name.c_str(),
             sym.c_str(), n, phase);
    FILE* f = fopen(path, "wb");
    if (!f) {
      perror(path);
      continue;
    }
    fwrite(buf.data(), 1, buf.size(), f);
    fclose(f);
    dumped_++;
  }
}

void Watch::resolve(Target& t) {
  size_t nmaps = t.maps().size();
  bool incomplete = addr_.size() < symbols.size();
  if (t.address_space_id() == resolved_for_ && !(incomplete && nmaps != resolved_maps_)) {
    return;
  }
  resolved_for_ = t.address_space_id();
  resolved_maps_ = nmaps;
  for (const string& sym : symbols) {
    if (addr_.count(sym) && !incomplete) {
      continue;
    }
    string location;
    uint64_t a = resolve_break(t, sym, location);
    if (!a) {
      continue;
    }
    if (!addr_.count(sym) || addr_[sym] != a) {
      logf("break at %s", location.c_str());
    }
    addr_[sym] = a;
  }
}

bool Watch::arm(Target& t) {
  bool any = false;
  for (const auto& kv : addr_) {
    any |= t.add_breakpoint(kv.second);
  }
  for (const auto& p : pending_) {
    any |= t.add_breakpoint(p.ret);
  }
  return any;
}

void Watch::disarm(Target& t) {
  for (const auto& kv : addr_) {
    t.remove_breakpoint(kv.second);
  }
  for (const auto& p : pending_) {
    t.remove_breakpoint(p.ret);
  }
}

bool Watch::expect_return(Target& t, const string& sym, int64_t n) {
  Regs r = t.regs();
  uint64_t ra = 0;
  if (!t.read(r.sp(), &ra, sizeof ra)) {
    logf("%s: can't read the return address at sp %#" PRIx64, sym.c_str(), r.sp());
    return false;
  }
  pending_.push_back({ra, r.sp() + 8, t.tid(), sym, n});
  return true;
}

bool Watch::take_return(Target& t, PendingReturn* out) {
  Regs r = t.regs();
  for (auto it = pending_.begin(); it != pending_.end(); ++it) {
    if (it->ret == r.ip() && it->tid == t.tid() && it->sp == r.sp()) {
      *out = *it;
      pending_.erase(it);
      return true;
    }
  }
  return false;
}

const string* Watch::symbol_at(uint64_t ip) const {
  for (const auto& kv : addr_) {
    if (kv.second == ip) {
      return &kv.first;
    }
  }
  return nullptr;
}

}  // namespace hpobs
