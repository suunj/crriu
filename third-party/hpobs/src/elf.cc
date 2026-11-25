/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "hpobs/elf.h"

#include <elf.h>
#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

using namespace std;

namespace hpobs {

vector<ElfSymbol> read_elf_symbols(const string& path) {
  vector<ElfSymbol> out;
  int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    return out;
  }
  struct stat st;
  if (fstat(fd, &st) < 0 || st.st_size < (off_t)sizeof(Elf64_Ehdr)) {
    close(fd);
    return out;
  }
  size_t size = st.st_size;
  const uint8_t* base = (const uint8_t*)mmap(nullptr, size, PROT_READ, MAP_PRIVATE, fd, 0);
  close(fd);
  if (base == MAP_FAILED) {
    return out;
  }
  const Elf64_Ehdr* eh = (const Elf64_Ehdr*)base;
  if (memcmp(eh->e_ident, ELFMAG, SELFMAG) != 0 || eh->e_ident[EI_CLASS] != ELFCLASS64 ||
      eh->e_shoff == 0 || eh->e_shentsize != sizeof(Elf64_Shdr) ||
      eh->e_shoff + (uint64_t)eh->e_shnum * sizeof(Elf64_Shdr) > size) {
    munmap((void*)base, size);
    return out;
  }
  const Elf64_Shdr* sh = (const Elf64_Shdr*)(base + eh->e_shoff);
  for (unsigned i = 0; i < eh->e_shnum; i++) {
    if (sh[i].sh_type != SHT_SYMTAB || sh[i].sh_link >= eh->e_shnum) {
      continue;
    }
    const Elf64_Shdr& strs = sh[sh[i].sh_link];
    if (sh[i].sh_offset + sh[i].sh_size > size || strs.sh_offset + strs.sh_size > size) {
      continue;
    }
    const Elf64_Sym* sym = (const Elf64_Sym*)(base + sh[i].sh_offset);
    size_t n = sh[i].sh_size / sizeof(Elf64_Sym);
    const char* strtab = (const char*)(base + strs.sh_offset);
    for (size_t k = 0; k < n; k++) {
      if (!sym[k].st_value || sym[k].st_name >= strs.sh_size) {
        continue;
      }
      const char* name = strtab + sym[k].st_name;
      if (!*name) {
        continue;
      }
      out.push_back({name, sym[k].st_value});
    }
    break;  // one .symtab per file
  }
  munmap((void*)base, size);
  return out;
}

}  // namespace hpobs
