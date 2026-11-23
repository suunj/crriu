/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_DETACH_HAND_OFF_H_
#define RR_DETACH_HAND_OFF_H_

#include <stddef.h>

#include <string>

#include "DetachModels.h"
#include "ReplaySession.h"
#include "ScopedFd.h"

namespace rr {

// Point branch `k`'s stdio at `dir`/branch-K.stdin (a FIFO, created if
// needed) and `dir`/branch-K.log: opens both into `in`/`out` and registers
// them with `model`, which must not outlive them. `stdio_note` gets a text
// for the "detached" line. No-op if `dir` is empty. Returns false on error.
bool open_branch_stdio(const std::string& dir, size_t k, FdModel& model,
                       ScopedFd& in, ScopedFd& out, std::string& stdio_note);

// Turn every task of `session` into an ordinary, untraced, SIGSTOPped
// process: recreate the modelled fds, cwd and signal state, close rr's own
// fds, undo rr's code patches, fix up registers and PTRACE_DETACH. With
// `strict`, refuse (instead of warning) where DetachCheck finds state that
// can't be restored. `stopped_at` and `tag` are only printed. Returns the
// process exit code: 0 on success, after which `session` has no tasks.
int hand_off(ReplaySession& session, ReplayModels& m, bool strict,
             FrameTime stopped_at, const char* tag);

} // namespace rr

#endif /* RR_DETACH_HAND_OFF_H_ */
