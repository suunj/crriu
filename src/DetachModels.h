/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_DETACH_MODELS_H_
#define RR_DETACH_MODELS_H_

#include <stdlib.h>

#include <string>

#include "DetachCheck.h"
#include "FdModel.h"
#include "SignalModel.h"
#include "hpobs/log.h"
#include "hpobs/watch.h"

namespace rr {

class Task;
class TraceFrame;

/* True when CRRIU_TRACE is set: `rr detach` logs every replayed frame,
 * watched-function hit and hand-off to stderr. */
inline bool detach_trace_enabled() {
  static bool enabled = getenv("CRRIU_TRACE") != nullptr;
  return enabled;
}

/* Make hpobs log as "rr detach: ...". Idempotent; called from the entry
 * points that use hpobs. */
inline void detach_init_logging() {
  static bool done = false;
  if (!done) {
    hpobs::set_log_prefix("rr detach");
    done = true;
  }
}

// Everything a replay point carries besides the ReplaySession itself: the
// models of kernel state recreated at hand-off (fds, signals, checks) and the
// watched functions with their hit counts. A checkpoint keeps a snapshot; a
// branch starts from one and keeps counting.
struct ReplayModels {
  FdModel fd;
  SignalModel sigs;
  DetachCheck check;
  hpobs::Watch watch;

  ReplayModels snapshot() const {
    return ReplayModels{ fd.snapshot(), sigs, check, watch };
  }
  void observe(const TraceFrame& frame, Task* t) {
    fd.observe(frame, t);
    sigs.observe(frame, t);
    check.observe(frame, t);
  }
  int64_t hits_of(const std::string& sym) const { return watch.hits_of(sym); }
};

} // namespace rr

#endif /* RR_DETACH_MODELS_H_ */
