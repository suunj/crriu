/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "DetachSymbols.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>

#include <algorithm>

#include "ElfReader.h"
#include "ScopedFd.h"

using namespace std;

namespace rr {

uint64_t load_base(obs::Target& t, const string& fsname) {
  for (const obs::Mapping& m : t.maps()) {
    if (m.fsname == fsname && m.file_offset == 0) {
      return m.start;
    }
  }
  return 0;
}

uint64_t resolve_break(obs::Target& t, const string& spec, string& location) {
  if (spec.compare(0, 2, "0x") == 0) {
    location = spec;
    return strtoull(spec.c_str(), nullptr, 16);
  }
  for (const obs::Mapping& m : t.maps()) {
    if (!m.exec_file())
      continue;
    ScopedFd fd(m.fsname.c_str(), O_RDONLY);
    if (!fd.is_open())
      continue;
    ElfFileReader reader(fd);
    SymbolTable syms = reader.read_symbols(".symtab", ".strtab");
    for (size_t i = 0; i < syms.size(); i++) {
      if (!syms.is_name(i, spec.c_str()) || !syms.addr(i))
        continue;
      uint64_t base = load_base(t, m.fsname);
      uint64_t addr = syms.addr(i);
      if (addr < base)                 // PIE: symbol value is an offset
        addr += base;
      char buf[32];
      snprintf(buf, sizeof buf, " @ %#lx", (unsigned long)addr);
      location = spec + buf + " in " + m.fsname;
      return addr;
    }
  }
  return 0;
}

string SymbolMap::lookup(uint64_t ip) const {
  uint64_t v = ip - (relative ? base : 0);
  auto it = by_addr.upper_bound(v);

  if (it == by_addr.begin())
      return "?";
  --it;
  char buf[32];
  snprintf(buf, sizeof buf, "+%#lx", (unsigned long)(v - it->first));

  return it->second + buf;
}

void SymbolMaps::build(obs::Target& t, bool force) {
  if (t.address_space_id() == built_for && !force)
      return;
  maps.clear();
  for (const obs::Mapping& m : t.maps()) {
    if (!m.exec_file())
      continue;
    ScopedFd fd(m.fsname.c_str(), O_RDONLY);
    if (!fd.is_open())
        continue;

    ElfFileReader reader(fd);
    SymbolTable syms = reader.read_symbols(".symtab", ".strtab");
    SymbolMap sm{ m.start, m.end, load_base(t, m.fsname), false, {} };

    uint64_t highest = 0;
    for (size_t i = 0; i < syms.size(); i++) {
      const char* n = syms.name(i);
      if (!syms.addr(i) || !n || !*n)
          continue;
      sm.by_addr.emplace(syms.addr(i), n);
      highest = max<uint64_t>(highest, syms.addr(i));
    }
    sm.relative = highest < sm.base;          // same rule as resolve_break
    maps.push_back(std::move(sm));
  }
  built_for = t.address_space_id();
}

const SymbolMap* SymbolMaps::map_for(uint64_t ip) const {
  for (const auto& m : maps)
    if (ip >= m.start && ip < m.end)
        return &m;
  return nullptr;
}

string SymbolMaps::lookup(obs::Target& t, uint64_t ip) {
  const SymbolMap* m = map_for(ip);
  if (!m) {
    build(t, true);
    m = map_for(ip);
  }
  return m ? m->lookup(ip) : "?";
}

} // namespace rr
