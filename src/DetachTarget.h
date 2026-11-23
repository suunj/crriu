/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_DETACH_TARGET_H_
#define RR_DETACH_TARGET_H_

#include <stddef.h>
#include <stdint.h>

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

// -d NAME:ADDR:LEN[:EVERY[:FROM]]: a memory range to snapshot at symbol hits,
// so that successive snapshots can be diffed to see what the program itself
// changed between two hits (rr records only what the kernel wrote).
struct Dump {
  std::string name;
  uintptr_t addr;
  size_t len;
  long every;
  long from = 1; // first hit to dump
};

// Exits with an error message if `spec` is malformed.
Dump parse_dump(const std::string& spec);

} // namespace rr

#endif /* RR_DETACH_TARGET_H_ */
