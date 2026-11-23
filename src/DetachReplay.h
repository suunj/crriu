/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_DETACH_REPLAY_H_
#define RR_DETACH_REPLAY_H_

#include "DetachCheckpointStore.h"
#include "DetachModels.h"
#include "DetachTarget.h"
#include "ReplaySession.h"

namespace rr {

// Replay `s` until `target`. Returns the last completed frame (-1 if the
// trace ended first). With `store`, clones a checkpoint every `every` frames.
FrameTime run_until(ReplaySession& s, ReplayModels& m, const Target& target,
                    CheckpointStore* store, FrameTime every);

} // namespace rr

#endif /* RR_DETACH_REPLAY_H_ */
