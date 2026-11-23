/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_DETACH_ACCESS_TRACE_H_
#define RR_DETACH_ACCESS_TRACE_H_

#include <string>

namespace rr {

class ReplaySession;

// -x: single-step one call of `sym` (hit `n`) from its entry to its return,
// decoding each instruction to log the memory it reads and writes to
// `dir`/access.SYM.N.txt. Follows into callees, so the log is the call's
// dynamic dependency set. Returns false if the trace ended first. Exits with
// an error message when rr was built without capstone.
bool trace_access(ReplaySession& s, const std::string& sym, long n,
                  const std::string& dir);

} // namespace rr

#endif /* RR_DETACH_ACCESS_TRACE_H_ */
