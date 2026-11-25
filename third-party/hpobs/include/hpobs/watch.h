/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef HPOBS_WATCH_H_
#define HPOBS_WATCH_H_

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include <map>
#include <string>
#include <vector>

#include "hpobs/target.h"

namespace hpobs {

// NAME:ADDR:LEN[:EVERY[:FROM]]: a memory range to snapshot at symbol hits,
// so that successive snapshots can be diffed to see what the program
// itself changed between two hits.
struct Dump {
  std::string name;
  uint64_t addr = 0;
  size_t len = 0;
  int64_t every = 1;
  int64_t from = 1;  // first hit to dump
};

// Parses a dump spec into *out. Logs and returns false if malformed.
bool parse_dump(const std::string& spec, Dump* out);

// A call we are inside of, waiting for it to return.
struct PendingReturn {
  uint64_t ret;  // return address, read from [sp] at entry
  uint64_t sp;   // sp after the return, to tell recursion apart
  pid_t tid;
  std::string sym;
  int64_t n;
};

// Function entries watched while the target runs. Every symbol is armed
// whenever the target is let run, so hit counts are exact at every stop;
// a host that snapshots state copies the Watch and resumes counting from
// it. The public fields are configuration; the counting and resolution
// state behind them is reached through the methods.
class Watch {
public:
  std::vector<std::string> symbols;
  std::vector<Dump> dumps;
  std::string dump_dir;
  bool track_exits = false;
  std::map<std::string, int64_t> access_every;  // symbol -> trace every N-th call
  int64_t from_event = 0;                       // host-defined time before which nothing is armed

  // Add `sym` to `symbols` unless it is there already.
  void add_symbol(const std::string& sym);

  // Hit counting.
  int64_t record_hit(const std::string& sym) { return ++hits_[sym]; }
  int64_t hits_of(const std::string& sym) const;
  const std::map<std::string, int64_t>& hits() const { return hits_; }

  // Write every dump range due at hit `n` of `sym` to
  // dump_dir/NAME.SYM.<n><phase>.bin.
  void dump(Target& t, const std::string& sym, int64_t n, const char* phase = "");

  // (Re)resolve `symbols` in the target's address space if it changed
  // since last time.
  void resolve(Target& t);
  bool resolved(const std::string& sym) const { return addr_.count(sym) != 0; }

  // Install / remove breakpoints at the resolved entries and pending
  // returns. arm() returns true if anything was installed.
  bool arm(Target& t);
  void disarm(Target& t);

  // At an entry hit: remember where this call will return to. Returns
  // false if the return address could not be read.
  bool expect_return(Target& t, const std::string& sym, int64_t n);
  // Is this stop the return of a pending call? Pops and returns it if so.
  bool take_return(Target& t, PendingReturn* out);

  // The watched symbol whose entry is at `ip`, or nullptr.
  const std::string* symbol_at(uint64_t ip) const;

private:
  std::map<std::string, int64_t> hits_;
  std::vector<PendingReturn> pending_;
  std::map<std::string, uint64_t> addr_;  // resolved under address space `resolved_for_`
  uint64_t resolved_for_ = 0;
  size_t resolved_maps_ = 0;  // mapping count at last resolve
  int64_t dumped_ = 0;
};

}  // namespace hpobs

#endif /* HPOBS_WATCH_H_ */
