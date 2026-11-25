/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_DETACH_ACCESS_TRACE_H_
#define RR_DETACH_ACCESS_TRACE_H_

#include <string>

#include "ObserveTarget.h"

namespace rr {

// -x: single-step one call of `sym` (hit `n`) from its entry to its return,
// decoding each instruction to log the memory it reads and writes to
// `dir`/access.SYM.N.txt. Follows into callees, so the log is the call's
// dynamic dependency set. `t` must be stopped at the function's entry; on
// return it is stopped at the return address (or wherever the target
// ended). `steps` gets the instruction count and `path` the log file.
// Returns false if the target exited first. Exits with an error message
// when rr was built without capstone.
bool trace_access(obs::Target& t, const std::string& sym, long n,
                  const std::string& dir, long* steps, std::string* path);

} // namespace rr

#endif /* RR_DETACH_ACCESS_TRACE_H_ */
