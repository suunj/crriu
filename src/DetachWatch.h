/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_DETACH_WATCH_H_
#define RR_DETACH_WATCH_H_

#include <sys/types.h>

#include <map>
#include <string>
#include <vector>

#include "DetachTarget.h"
#include "TraceFrame.h"
#include "remote_code_ptr.h"
#include "remote_ptr.h"

namespace rr {

class AddressSpace;
class Task;

// With -e: a call we are inside of, waiting for it to return.
struct PendingReturn {
  remote_code_ptr ret;          // return address, read from [sp] at entry
  remote_ptr<void> sp;          // sp after the return, to tell recursion apart
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

  std::map<std::string, remote_code_ptr> addr; // resolved in `resolved_for`
  AddressSpace* resolved_for = nullptr;
  size_t resolved_maps = 0;                    // mapping count at last resolve

  // Write every -d range due at hit `n` of `sym` to
  // dump_dir/NAME.SYM.<n><phase>.bin.
  void dump(Task* t, const std::string& sym, long n, const char* phase = "");

  // (Re)resolve `symbols` in t's address space if it changed since last time.
  void resolve(Task* t);

  // Install / remove breakpoints at the resolved entries and pending
  // returns. arm() returns true if anything was installed.
  bool arm(AddressSpace& vm);
  void disarm(AddressSpace& vm);

  // At an entry hit: remember where this call will return to.
  void expect_return(Task* t, const std::string& sym, long n);
  // Is this stop the return of a pending call? Pops and returns it if so.
  bool take_return(Task* t, PendingReturn* out);

  // The watched symbol whose entry is at `ip`, or nullptr.
  const std::string* symbol_at(remote_code_ptr ip) const;
};

} // namespace rr

#endif /* RR_DETACH_WATCH_H_ */
