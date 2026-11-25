/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_DETACH_CHECKPOINT_STORE_H_
#define RR_DETACH_CHECKPOINT_STORE_H_

#include <stdint.h>
#include <stdio.h>

#include <map>
#include <set>
#include <string>
#include <vector>

#include "DetachModels.h"
#include "DetachTarget.h"
#include "ReplaySession.h"

namespace rr {

// A live checkpoint: a stopped clone of the replay plus the models as they
// were there. `time` is the last frame the clone has fully replayed
// (trace_reader().time() - 1 at clone time); a branch taken from it is
// replayed on from frame time+1.
struct Checkpoint {
  FrameTime time;
  ReplaySession::shr_ptr session;
  ReplayModels models;
  uint64_t last_used;
};

// The checkpoints `rr detach` keeps while replaying. The earliest entry is
// the base and is never evicted; beyond it `max` entries are kept, least
// recently used evicted first.
class CheckpointStore {
public:
  explicit CheckpointStore(size_t max) : max_(max ? max : 1) {}

  // Targets not yet branched. A pending target that is already behind the
  // replay can only be served from its nearest checkpoint, so evict() keeps
  // that one.
  void set_pending(const std::vector<Target>& targets) { pending_ = targets; }
  void pop_pending() {
    if (!pending_.empty()) {
      pending_.erase(pending_.begin());
    }
  }

  // Clone `s` here. Caller guarantees s.can_clone(). Duplicates are ignored.
  bool take(ReplaySession& s, const ReplayModels& m, FrameTime time);

  // Latest checkpoint from which `t` is still ahead: by frame, the last one
  // at or before t.event; by function, the last one that has seen fewer
  // than t.hit entries of t.symbol. nullptr if even the base is too late.
  Checkpoint* nearest_before(const Target& t);

  size_t size() const { return by_time_.size(); }

  void list(FILE* f) const;

private:
  Checkpoint* find_before(const Target& t);

  // Checkpoints a pending, already-passed target will start from.
  std::set<FrameTime> pinned(FrameTime pos,
                             const std::map<std::string, int64_t>& hits);

  void evict(FrameTime pos, const std::map<std::string, int64_t>& hits);

  std::map<FrameTime, Checkpoint> by_time_;
  std::vector<Target> pending_;
  size_t max_;
  uint64_t tick_ = 0;
};

} // namespace rr

#endif /* RR_DETACH_CHECKPOINT_STORE_H_ */
