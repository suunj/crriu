#define _GNU_SOURCE
/* init for the tiny guest: two sampling events (cycles, instructions) plus a
 * plain counting event, all live at once. Exercises multi-counter snapshot
 * handling: a batch STOP that reports ALREADY_STOPPED (one event throttled)
 * must still yield valid values for the others, the SBI implementation must
 * not clobber another counter's snapshot slot, and no read may go backwards.
 * The ring buffers are drained each iteration so sample counts keep going. */
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <linux/perf_event.h>

struct ev { int fd; struct perf_event_mmap_page *mp; unsigned long long prev, head; const char *name; };
static struct ev evs[3] = { {0,0,0,0,"cyc"}, {0,0,0,0,"ins"}, {0,0,0,0,"ins2"} };

static int open_ev(struct ev *e, unsigned cfg, unsigned long period) {
  struct perf_event_attr a; memset(&a, 0, sizeof a);
  a.type = PERF_TYPE_HARDWARE; a.size = sizeof a; a.config = cfg;
  a.sample_period = period; a.disabled = 1; a.exclude_kernel = 1;
  e->fd = syscall(SYS_perf_event_open, &a, 0, -1, -1, 0);
  if (e->fd < 0) return -errno;
  if (period) {
    e->mp = mmap(0, 2 * 4096, PROT_READ | PROT_WRITE, MAP_SHARED, e->fd, 0);
    if (e->mp == MAP_FAILED) return -errno;
  }
  return 0;
}

int main(void) {
  int r[3];
  r[0] = open_ev(&evs[0], PERF_COUNT_HW_CPU_CYCLES, 20000);
  r[1] = open_ev(&evs[1], PERF_COUNT_HW_INSTRUCTIONS, 30000);
  r[2] = open_ev(&evs[2], PERF_COUNT_HW_INSTRUCTIONS, 0);
  if (r[0] || r[1] || r[2]) { char b[96]; int n = snprintf(b, sizeof b, "pmuovf2 open failed %d %d %d\n", r[0], r[1], r[2]); write(1, b, n); for (;;) pause(); }
  for (int k = 0; k < 3; k++) ioctl(evs[k].fd, PERF_EVENT_IOC_ENABLE, 0);
  unsigned long backwards = 0;
  for (int it = 1; it <= 20; it++) {
    unsigned long long v[3]; struct timespec ts; const char *flag = "";
    for (int k = 0; k < 3; k++) {
      read(evs[k].fd, &v[k], sizeof v[k]);
      if (v[k] < evs[k].prev) { backwards++; flag = " BACKWARDS"; }
      evs[k].prev = v[k];
      if (evs[k].mp) { evs[k].head = evs[k].mp->data_head; __sync_synchronize(); evs[k].mp->data_tail = evs[k].head; }
    }
    clock_gettime(CLOCK_MONOTONIC, &ts);
    char b[224];
    int n = snprintf(b, sizeof b, "pmuovf2 %d cyc=%llu ins=%llu ins2=%llu csamp=%llu isamp=%llu mono=%ld.%03ld%s\n",
                     it, v[0], v[1], v[2], evs[0].head / 8, evs[1].head / 8,
                     (long)ts.tv_sec, ts.tv_nsec / 1000000, flag);
    write(1, b, n);
    volatile unsigned long x = 0; for (unsigned long k = 0; k < 2000000; k++) x += k;  /* burn */
    struct timespec s = {0, 300000000}; nanosleep(&s, 0);
  }
  char b[64]; int n = snprintf(b, sizeof b, "pmuovf2 done backwards=%lu\n", backwards); write(1, b, n);
  return 0;
}
