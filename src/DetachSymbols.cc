/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "DetachSymbols.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>

#include <algorithm>

#include "AddressSpace.h"
#include "ElfReader.h"
#include "ScopedFd.h"
#include "Task.h"

using namespace std;

namespace rr {

bool detach_trace_enabled() {
  static bool enabled = getenv("CRRIU_TRACE") != nullptr;
  return enabled;
}

bool is_exec_file_mapping(const KernelMapping& km) {
  return (km.prot() & PROT_EXEC) && !km.fsname().empty() &&
         km.fsname()[0] == '/';
}

uintptr_t load_base(Task* t, const string& fsname) {
  for (const auto& m : t->vm()->maps()) {
    if (m.map.fsname() == fsname && m.map.file_offset_bytes() == 0) {
      return m.map.start().as_int();
    }
  }
  return 0;
}

remote_code_ptr resolve_break(Task* t, const string& spec, string& location) {
  if (spec.compare(0, 2, "0x") == 0) {
    location = spec;
    return remote_code_ptr(strtoull(spec.c_str(), nullptr, 16));
  }
  for (const auto& m : t->vm()->maps()) {
    const KernelMapping& km = m.map;
    if (!is_exec_file_mapping(km))
      continue;
    ScopedFd fd(km.fsname().c_str(), O_RDONLY);
    if (!fd.is_open())
      continue;
    ElfFileReader reader(fd);
    SymbolTable syms = reader.read_symbols(".symtab", ".strtab");
    for (size_t i = 0; i < syms.size(); i++) {
      if (!syms.is_name(i, spec.c_str()) || !syms.addr(i))
        continue;
      uintptr_t base = load_base(t, km.fsname());
      uintptr_t addr = syms.addr(i);
      if (addr < base)                 // PIE: symbol value is an offset
        addr += base;
      char buf[32];
      snprintf(buf, sizeof buf, " @ %#lx", (unsigned long)addr);
      location = spec + buf + " in " + km.fsname();
      return remote_code_ptr(addr);
    }
  }
  return remote_code_ptr();
}

string SymbolMap::lookup(remote_code_ptr ip) const {
  uintptr_t v = ip.register_value() - (relative ? base : 0);
  auto it = by_addr.upper_bound(v);

  if (it == by_addr.begin())
      return "?";
  --it;
  char buf[32];
  snprintf(buf, sizeof buf, "+%#lx", (unsigned long)(v - it->first));

  return it->second + buf;
}

void SymbolMaps::build(Task* t, bool force) {
  if (t->vm().get() == built_for && !force)
      return;
  maps.clear();
  for (const auto& m : t->vm()->maps()) {
    const KernelMapping& km = m.map;
    if (!is_exec_file_mapping(km))
      continue;
    ScopedFd fd(km.fsname().c_str(), O_RDONLY);
    if (!fd.is_open())
        continue;

    ElfFileReader reader(fd);
    SymbolTable syms = reader.read_symbols(".symtab", ".strtab");
    SymbolMap sm{km.start(), km.end(), load_base(t, km.fsname()), false, {}};

    uintptr_t highest = 0;
    for (size_t i = 0; i < syms.size(); i++) {
      const char* n = syms.name(i);
      if (!syms.addr(i) || !n || !*n)
          continue;
      sm.by_addr.emplace(syms.addr(i), n);
      highest = max(highest, syms.addr(i));
    }
    sm.relative = highest < sm.base;          // same rule as resolve_break
    maps.push_back(std::move(sm));
  }
  built_for = t->vm().get();
}

const SymbolMap* SymbolMaps::map_for(remote_code_ptr ip) const {
  remote_ptr<void> p = ip.to_data_ptr<void>();
  for (const auto& m : maps)
    if (p >= m.start && p < m.end)
        return &m;
  return nullptr;
}

string SymbolMaps::lookup(Task* t, remote_code_ptr ip) {
  const SymbolMap* m = map_for(ip);
  if (!m) {
    build(t, true);
    m = map_for(ip);
  }
  return m ? m->lookup(ip) : "?";
}

} // namespace rr
