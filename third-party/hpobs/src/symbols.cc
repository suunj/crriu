/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "hpobs/symbols.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>

#include <algorithm>

#include "hpobs/elf.h"

using namespace std;

namespace hpobs {

uint64_t load_base(Target& t, const string& fsname) {
  for (const Mapping& m : t.maps()) {
    if (m.fsname == fsname && m.file_offset == 0) {
      return m.start;
    }
  }
  return 0;
}

uint64_t resolve_break(Target& t, const string& spec, string& location) {
  if (spec.compare(0, 2, "0x") == 0) {
    location = spec;
    return strtoull(spec.c_str(), nullptr, 16);
  }
  for (const Mapping& m : t.maps()) {
    if (!m.exec_file()) {
      continue;
    }
    for (const ElfSymbol& s : read_elf_symbols(m.fsname)) {
      if (s.name != spec) {
        continue;
      }
      uint64_t base = load_base(t, m.fsname);
      uint64_t addr = s.value;
      if (addr < base) {  // PIE: symbol value is an offset
        addr += base;
      }
      char buf[32];
      snprintf(buf, sizeof buf, " @ %#" PRIx64, addr);
      location = spec + buf + " in " + m.fsname;
      return addr;
    }
  }
  return 0;
}

string SymbolMap::lookup(uint64_t ip) const {
  uint64_t v = ip - (relative ? base : 0);
  auto it = by_addr.upper_bound(v);

  if (it == by_addr.begin()) {
    return "?";
  }
  --it;
  char buf[32];
  snprintf(buf, sizeof buf, "+%#" PRIx64, v - it->first);

  return it->second + buf;
}

void SymbolMaps::build(Target& t, bool force) {
  if (t.address_space_id() == built_for && !force) {
    return;
  }
  maps.clear();
  for (const Mapping& m : t.maps()) {
    if (!m.exec_file()) {
      continue;
    }
    vector<ElfSymbol> syms = read_elf_symbols(m.fsname);
    if (syms.empty()) {
      continue;
    }
    SymbolMap sm{m.start, m.end, load_base(t, m.fsname), false, {}};

    uint64_t highest = 0;
    for (const ElfSymbol& s : syms) {
      sm.by_addr.emplace(s.value, s.name);
      highest = max(highest, s.value);
    }
    sm.relative = highest < sm.base;  // same rule as resolve_break
    maps.push_back(std::move(sm));
  }
  built_for = t.address_space_id();
}

const SymbolMap* SymbolMaps::map_for(uint64_t ip) const {
  for (const auto& m : maps) {
    if (ip >= m.start && ip < m.end) {
      return &m;
    }
  }
  return nullptr;
}

string SymbolMaps::lookup(Target& t, uint64_t ip) {
  const SymbolMap* m = map_for(ip);
  if (!m) {
    build(t, true);
    m = map_for(ip);
  }
  return m ? m->lookup(ip) : "?";
}

}  // namespace hpobs
