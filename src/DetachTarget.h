/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_DETACH_TARGET_H_
#define RR_DETACH_TARGET_H_

#include <string>

#include "TraceFrame.h"

namespace rr {

// Where a branch is taken: right after frame `event`, or at the `hit`-th
// entry of function `symbol`.
struct Target {
  std::string text;
  FrameTime event = 0;
  std::string symbol;
  long hit = 1;
  bool by_event() const { return event > 0; }
};

// EVENT or SYM[:N].
Target parse_target(const std::string& spec);

} // namespace rr

#endif /* RR_DETACH_TARGET_H_ */
