/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_DETACH_SYMBOLS_H_
#define RR_DETACH_SYMBOLS_H_

#include <stdint.h>

#include <map>
#include <string>
#include <vector>

#include "remote_code_ptr.h"
#include "remote_ptr.h"

namespace rr {

class AddressSpace;
class KernelMapping;
class Task;

/* True when CRRIU_TRACE is set: `rr detach` logs every replayed frame,
 * watched-function hit and hand-off to stderr. */
bool detach_trace_enabled();

/* An executable mapping of a file on disk: the only mappings symbols are
 * looked up in, and the only ones rr patches code in. */
bool is_exec_file_mapping(const KernelMapping& km);

/* Load base of `fsname` in t's address space: the start of its mapping at
 * file offset 0, or 0 if there is none. */
uintptr_t load_base(Task* t, const std::string& fsname);

/* Resolve `spec` ("0x<addr>" or a .symtab function name) to an address in
 * t's address space. `location` gets a printable description. Returns a null
 * pointer if the symbol is not (yet) mapped. */
remote_code_ptr resolve_break(Task* t, const std::string& spec,
                              std::string& location);

/* Address -> "symbol+off" for the exec mappings of one address space.
 * Built once per AddressSpace (rebuilt after exec), used only for logging. */
struct SymbolMap {
  remote_ptr<void> start, end;      // exec mapping this map covers
  uintptr_t base;                   // start of the file-offset-0 mapping
  bool relative;                    // PIE/.so: symbol values are offsets from base
  std::map<uintptr_t, std::string> by_addr; // symbol value -> name

  std::string lookup(remote_code_ptr ip) const;
};

struct SymbolMaps {
  AddressSpace* built_for = nullptr;
  std::vector<SymbolMap> maps;

  void build(Task* t, bool force = false);
  const SymbolMap* map_for(remote_code_ptr ip) const;
  // Mappings come and go (dlopen, ld.so loading libc); on a miss rebuild once.
  std::string lookup(Task* t, remote_code_ptr ip);
};

} // namespace rr

#endif /* RR_DETACH_SYMBOLS_H_ */
