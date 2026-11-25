/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef HPOBS_ELF_H_
#define HPOBS_ELF_H_

#include <stdint.h>

#include <string>
#include <vector>

namespace hpobs {

struct ElfSymbol {
  std::string name;
  uint64_t value;
};

// The .symtab entries of `path` that have a name and a non-zero value, in
// file order. Empty if the file is not a 64-bit ELF or has no .symtab.
std::vector<ElfSymbol> read_elf_symbols(const std::string& path);

}  // namespace hpobs

#endif /* HPOBS_ELF_H_ */
