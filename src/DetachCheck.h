#ifndef RR_DETACH_CHECK_H_
#define RR_DETACH_CHECK_H_
#include <map>
#include <string>
#include <vector>
#include "FdModel.h"
namespace rr {
class Task; class TraceFrame;

/**
 * Decides whether the state reached at the detach event can be handed to
 * the kernel. Replay reproduces what the program saw, not what the kernel
 * did; this reports the places where the two are known to differ.
 */
class DetachCheck {
public:
  void observe(const TraceFrame& frame, Task* t);
  // Returns the findings; empty means detach is believed safe.
  std::vector<std::string> run(const std::vector<Task*>& tasks, const FdModel& model);
private:
  struct LastSyscall { int number; bool exiting; int64_t time; };
  std::map<pid_t, LastSyscall> last;   // keyed by rec_tid
};
}
#endif
