/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_DETACH_SYMBOLS_H_
#define RR_DETACH_SYMBOLS_H_

#include <stdint.h>

#include <map>
#include <string>
#include <vector>

#include "ObserveTarget.h"

namespace rr {

/* Load base of `fsname` in the target's address space: the start of its
 * mapping at file offset 0, or 0 if there is none. */
uint64_t load_base(obs::Target& t, const std::string& fsname);

/* Resolve `spec` ("0x<addr>" or a .symtab function name) to an address in
 * the target's address space. `location` gets a printable description.
 * Returns 0 if the symbol is not (yet) mapped. */
uint64_t resolve_break(obs::Target& t, const std::string& spec,
                       std::string& location);

/* Address -> "symbol+off" for the exec mappings of one address space.
 * Built once per address space (rebuilt after exec), used only for logging. */
struct SymbolMap {
  uint64_t start, end;              // exec mapping this map covers
  uint64_t base;                    // start of the file-offset-0 mapping
  bool relative;                    // PIE/.so: symbol values are offsets from base
  std::map<uint64_t, std::string> by_addr; // symbol value -> name

  std::string lookup(uint64_t ip) const;
};

struct SymbolMaps {
  const void* built_for = nullptr;
  std::vector<SymbolMap> maps;

  void build(obs::Target& t, bool force = false);
  const SymbolMap* map_for(uint64_t ip) const;
  // Mappings come and go (dlopen, ld.so loading libc); on a miss rebuild once.
  std::string lookup(obs::Target& t, uint64_t ip);
};

} // namespace rr

#endif /* RR_DETACH_SYMBOLS_H_ */
