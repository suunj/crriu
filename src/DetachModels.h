/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_DETACH_MODELS_H_
#define RR_DETACH_MODELS_H_

#include <string>

#include "DetachCheck.h"
#include "DetachWatch.h"
#include "FdModel.h"
#include "SignalModel.h"

namespace rr {

class Task;
class TraceFrame;

// Everything a replay point carries besides the ReplaySession itself: the
// models of kernel state recreated at hand-off (fds, signals, checks) and the
// watched functions with their hit counts. A checkpoint keeps a snapshot; a
// branch starts from one and keeps counting.
struct ReplayModels {
  FdModel fd;
  SignalModel sigs;
  DetachCheck check;
  Watch watch;

  ReplayModels snapshot() const {
    return ReplayModels{ fd.snapshot(), sigs, check, watch };
  }
  void observe(const TraceFrame& frame, Task* t) {
    fd.observe(frame, t);
    sigs.observe(frame, t);
    check.observe(frame, t);
  }
  long hits_of(const std::string& sym) const {
    auto h = watch.hits.find(sym);
    return h == watch.hits.end() ? 0 : h->second;
  }
};

} // namespace rr

#endif /* RR_DETACH_MODELS_H_ */
