/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef HPOBS_ACCESS_TRACE_H_
#define HPOBS_ACCESS_TRACE_H_

#include <stdint.h>

#include <string>

#include "hpobs/target.h"

namespace hpobs {

// Single-step one call of `sym` (hit `n`) from its entry to its return,
// decoding each instruction to log the memory it reads and writes to
// `dir`/access.SYM.N.txt. Follows into callees, so the log is the call's
// dynamic dependency set. `t` must be stopped at the function's entry with
// no breakpoints armed; on return it is stopped at the return address (or
// wherever the target ended). `steps` gets the instruction count and
// `path` the log file. Returns false, with a message logged, if the target
// exited first, the entry could not be read, or this build has no
// disassembler (see trace_access_supported()). x86-64 only.
bool trace_access(Target& t, const std::string& sym, int64_t n, const std::string& dir,
                  int64_t* steps, std::string* path);

// True when this build can decode instructions (capstone was available).
bool trace_access_supported();

}  // namespace hpobs

#endif /* HPOBS_ACCESS_TRACE_H_ */
