/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "DetachCheckpointStore.h"

#include <iterator>
#include <utility>

#include "Task.h"

using namespace std;

namespace rr {

bool CheckpointStore::take(ReplaySession& s, const ReplayModels& m, FrameTime time) {
  if (by_time_.count(time)) {
    return false;
  }
  Checkpoint c{ time, s.clone(), m.snapshot(), ++tick_ };
  by_time_.emplace(time, std::move(c));
  fprintf(stderr, "rr detach: checkpoint at event %lld (%zu cached)\n",
          (long long)time, by_time_.size());
  evict(time, m.watch.hits());
  return true;
}

Checkpoint* CheckpointStore::nearest_before(const Target& t) {
  Checkpoint* c = find_before(t);
  if (c) c->last_used = ++tick_;
  return c;
}

void CheckpointStore::list(FILE* f) const {
  for (const auto& kv : by_time_) {
    fprintf(f, "  checkpoint event %lld pid %d%s\n", (long long)kv.first,
            kv.second.session->tasks().begin()->second->tid,
            &kv == &*by_time_.begin() ? " (base)" : "");
  }
}

Checkpoint* CheckpointStore::find_before(const Target& t) {
  Checkpoint* best = nullptr;
  for (auto& kv : by_time_) {
    Checkpoint& c = kv.second;
    bool ok;
    if (t.by_event()) {
      ok = c.time <= t.event;
    } else {
      ok = c.models.hits_of(t.symbol) < t.hit;
    }
    if (ok) best = &c;
  }
  return best;
}

set<FrameTime> CheckpointStore::pinned(FrameTime pos, const map<string, int64_t>& hits) {
  set<FrameTime> keep;
  for (const Target& t : pending_) {
    auto h = hits.find(t.symbol);
    bool behind = t.by_event() ? t.event <= pos
                               : (h == hits.end() ? 0 : h->second) >= t.hit;
    if (!behind) {
      continue;
    }
    if (Checkpoint* c = find_before(t)) {
      keep.insert(c->time);
    }
  }
  return keep;
}

void CheckpointStore::evict(FrameTime pos, const map<string, int64_t>& hits) {
  set<FrameTime> keep = pinned(pos, hits);
  while (by_time_.size() > max_ + 1) {
    auto victim = by_time_.end();
    for (auto it = std::next(by_time_.begin()); it != by_time_.end(); ++it) {
      if (keep.count(it->first)) {
        continue;
      }
      if (victim == by_time_.end() || it->second.last_used < victim->second.last_used) {
        victim = it;
      }
    }
    if (victim == by_time_.end()) {
      break;     // everything left is pinned
    }
    fprintf(stderr, "rr detach: evicting checkpoint at event %lld\n",
            (long long)victim->first);
    by_time_.erase(victim);             // ~ReplaySession: tasks killed, emufs freed
  }
}

} // namespace rr
