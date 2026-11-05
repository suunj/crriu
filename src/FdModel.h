/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */
#ifndef RR_FD_MODEL_H_
#define RR_FD_MODEL_H_

#include <map>
#include <memory>
#include <cstdint>
#include <string>

namespace rr {

class Task;
class TraceFrame;

/**
 * Reconstructs the tracee's fd table from the syscalls seen during replay.
 * Replay never performs open/dup/close for real, so at detach time the
 * kernel fd table is empty except for inherited stdio; this model lets us
 * recreate it inside the tracee before handing it off.
 *
 * Open file descriptions (what dup shares) are modelled as shared_ptr so
 * fds created by dup/dup2/F_DUPFD share one offset.
 */
class FdModel {
public:
  struct OpenFile;
  using OpenFilePtr = std::shared_ptr<OpenFile>;

  struct EpollMember {
    int registered_fd;
    OpenFilePtr file;
    uint32_t events;
    uint64_t data;
  };

  struct OpenFile {
    enum Type {
      REGULAR,
      EVENTFD,
      SIGNALFD,
      EPOLL
    };
    Type type = REGULAR;

    std::string path;   // absolute
    int flags = 0;          // as passed to open
    int64_t offset = 0;
    uint64_t counter = 0;  // EVENTFD
    uint64_t sigmask = 0;  // SIGNALFD

    std::map<int, EpollMember> epoll_members;
  };

  explicit FdModel(const std::string& initial_cwd) : cwd(initial_cwd) {}

  /** Call after each replay step with the frame that was just replayed. */
  void observe(const TraceFrame& frame, Task* t);

  /**
   * Recreate the modelled fds inside `t` using remote syscalls. Must be
   * called while `t` is still traced. Returns false if anything failed.
   */
  bool materialize(Task* t);

  /** Set the tracee's cwd to the modelled one (initial + observed chdirs). */
  bool apply_cwd(Task* t);

  const std::map<int, OpenFilePtr>& fds() const { return table; }

private:
  std::string resolve(Task* t, int dirfd, uintptr_t path_ptr);

  std::string cwd;
  std::map<int, OpenFilePtr> table;
  int64_t last_time = 0;
};

} // namespace rr
#endif
