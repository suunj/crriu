#define _GNU_SOURCE
/* init for the tiny guest: sample cycles with a fixed period, count overflow
 * signals, and print counter value + overflow count once a second. Across a
 * crriu restore the overflow rate must stay the same and no sample may be
 * lost or duplicated. */
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <linux/perf_event.h>
static volatile unsigned long overflows;
static void on_sigio(int sig) { (void)sig; overflows++; }
int main(void) {
  struct perf_event_attr a; memset(&a, 0, sizeof a);
  a.type = PERF_TYPE_HARDWARE; a.size = sizeof a; a.config = PERF_COUNT_HW_CPU_CYCLES;
  a.sample_period = 20000; a.wakeup_events = 1; a.disabled = 1;
  int fd = syscall(SYS_perf_event_open, &a, 0, -1, -1, 0);
  if (fd < 0) { char b[64]; int n = snprintf(b, sizeof b, "pmuovf open failed errno=%d\n", errno); write(1, b, n); for(;;) pause(); }
  signal(SIGIO, on_sigio);
  fcntl(fd, F_SETFL, O_ASYNC); fcntl(fd, F_SETSIG, SIGIO); fcntl(fd, F_SETOWN, getpid());
  ioctl(fd, PERF_EVENT_IOC_REFRESH, 1000000);   /* arm: deliver SIGIO on each overflow */
  for (int i = 1; i <= 20; i++) {
    unsigned long long c = 0; struct timespec ts;
    read(fd, &c, sizeof c); clock_gettime(CLOCK_MONOTONIC, &ts);
    char b[128]; int n = snprintf(b, sizeof b, "pmuovf %d cycles=%llu overflows=%lu mono=%ld.%03ld\n",
                                  i, c, overflows, (long)ts.tv_sec, ts.tv_nsec / 1000000);
    write(1, b, n);
    volatile unsigned long x = 0; for (unsigned long k = 0; k < 2000000; k++) x += k;  /* burn cycles */
    struct timespec s = {0, 300000000}; nanosleep(&s, 0);
  }
  return 0;
}
