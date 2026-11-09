/* init for the tiny guest: print cycles, instructions and time once a second.
 * Values must stay monotonic across a crriu restore. */
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <sys/syscall.h>
#include <linux/perf_event.h>
static int open_counter(unsigned config) {
  struct perf_event_attr a; memset(&a, 0, sizeof a);
  a.type = PERF_TYPE_HARDWARE; a.size = sizeof a; a.config = config;
  a.disabled = 0;
  int fd = syscall(SYS_perf_event_open, &a, 0, -1, -1, 0);
  return fd >= 0 ? fd : -errno;
}
int main(void) {
  int cyc = open_counter(PERF_COUNT_HW_CPU_CYCLES);
  int ins = open_counter(PERF_COUNT_HW_INSTRUCTIONS);
  for (int i = 1; i <= 20; i++) {
    unsigned long long c = 0, n = 0; struct timespec ts;
    if (cyc >= 0) read(cyc, &c, sizeof c);
    if (ins >= 0) read(ins, &n, sizeof n);
    clock_gettime(CLOCK_MONOTONIC, &ts);
    char b[128]; int len = snprintf(b, sizeof b, "pmu %d cycles=%llu instr=%llu mono=%ld.%03ld fd=%d,%d\n",
                                    i, c, n, (long)ts.tv_sec, ts.tv_nsec / 1000000, cyc, ins);
    write(1, b, len);
    struct timespec s = {1, 0}; nanosleep(&s, 0);
  }
  return 0;
}
