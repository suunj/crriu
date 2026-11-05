#ifndef RR_SIGNAL_MODEL_H_
#define RR_SIGNAL_MODEL_H_
#include <cstdint>
#include <map>
#include <sys/types.h>
namespace rr {
class Task; class TraceFrame;

/**
 * Tracks signal state replay never applies to the kernel: per-thread
 * blocked masks (rt_sigprocmask) and the process-wide handler table
 * (rt_sigaction). Reapplied inside the tracee before detaching.
 */
class SignalModel {
public:
  void observe(const TraceFrame& frame, Task* t);
  bool materialize(Task* t);
private:
  struct Action { uint64_t handler = 0, flags = 0, restorer = 0, mask = 0; bool set = false; };
  std::map<pid_t, uint64_t> blocked;   // rec_tid -> sigmask
  Action actions[65];
  int64_t last_time = -1;
};
}
#endif
