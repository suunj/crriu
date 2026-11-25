/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_DETACH_WATCH_H_
#define RR_DETACH_WATCH_H_

#include <stdint.h>
#include <sys/types.h>

#include <map>
#include <string>
#include <vector>

#include "DetachTarget.h"
#include "ObserveTarget.h"
#include "TraceFrame.h"

namespace rr {

// With -e: a call we are inside of, waiting for it to return.
struct PendingReturn {
  uint64_t ret;                 // return address, read from [sp] at entry
  uint64_t sp;                  // sp after the return, to tell recursion apart
  pid_t tid;
  std::string sym;
  long n;
};

// Function entries watched while replaying. Every function named on the
// command line is armed for the whole replay so that `hits` is exact at
// every frame; checkpoints save a copy and branches resume counting from it.
struct Watch {
  std::vector<std::string> symbols;
  std::map<std::string, long> hits;
  std::vector<Dump> dumps;
  std::string dump_dir;
  long dumped = 0;
  bool track_exits = false;
  std::vector<PendingReturn> pending;
  std::map<std::string, long> access_every; // -x: symbol -> EVERY
  FrameTime from_event = 0;                 // -f: no breakpoints before this event

  std::map<std::string, uint64_t> addr;     // resolved in `resolved_for`
  const void* resolved_for = nullptr;
  size_t resolved_maps = 0;                 // mapping count at last resolve

  // Write every -d range due at hit `n` of `sym` to
  // dump_dir/NAME.SYM.<n><phase>.bin.
  void dump(obs::Target& t, const std::string& sym, long n,
            const char* phase = "");

  // (Re)resolve `symbols` in the target's address space if it changed
  // since last time.
  void resolve(obs::Target& t);

  // Install / remove breakpoints at the resolved entries and pending
  // returns. arm() returns true if anything was installed.
  bool arm(obs::Target& t);
  void disarm(obs::Target& t);

  // At an entry hit: remember where this call will return to.
  void expect_return(obs::Target& t, const std::string& sym, long n);
  // Is this stop the return of a pending call? Pops and returns it if so.
  bool take_return(obs::Target& t, PendingReturn* out);

  // The watched symbol whose entry is at `ip`, or nullptr.
  const std::string* symbol_at(uint64_t ip) const;
};

} // namespace rr

#endif /* RR_DETACH_WATCH_H_ */
