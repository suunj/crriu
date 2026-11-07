/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "StdioMonitor.h"

#include "Flags.h"
#include "ReplaySession.h"
#include "ReplayTask.h"
#include "Session.h"
#include "log.h"
#include "util.h"

namespace rr {

Switchable StdioMonitor::will_write(Task* t) {
  if (t->session().mark_stdio()) {
    char buf[256];
    snprintf(buf, sizeof(buf) - 1, "[rr %d %" PRId64 "]", t->tgid(), t->trace_time());
    write_all(original_fd, buf, strlen(buf));
  }

  return PREVENT_SWITCH;
}

void StdioMonitor::did_write(Task* t, const std::vector<Range>& ranges,
                             LazyOffset&) {
  ReplaySession* replay_session = t->session().as_replay();
  if (!replay_session) {
    return;
  }
  bool echo = replay_session->echo_stdio();
  if (!echo && !replay_session->on_stdio_output) {
    return;
  }
  for (auto& r : ranges) {
    auto bytes = t->read_mem(r.data.cast<uint8_t>(), r.length);
    if (echo) {
      write_all(original_fd, bytes.data(), bytes.size());
    }
    if (replay_session->on_stdio_output) {
      replay_session->on_stdio_output(original_fd, bytes);
    }
  }
}

} // namespace rr
