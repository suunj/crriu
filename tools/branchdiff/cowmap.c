/*
 * cowmap - how much memory do two forked processes still share?
 *
 * Walks /proc/A/maps and, for every mapping that exists at the same address
 * in B, compares the physical frame behind each virtual page in both
 * processes (/proc/PID/pagemap, needs root for PFNs):
 *
 *   shared    same PFN in A and B          -> still one copy (CoW intact)
 *   diverged  both present, different PFN  -> one side wrote it
 *   A-only / B-only  present in one        -> touched after the fork, or
 *                                             swapped/dropped on the other
 *   absent    in neither                   -> never faulted (free)
 *
 * The largest anonymous mapping is taken to be QEMU's guest RAM and gets a
 * divergence histogram so you can see *where* in guest memory the branches
 * differ.  Also prints Rss/Pss from smaps_rollup for both pids.
 *
 *   gcc -O2 -o cowmap cowmap.c
 *   sudo ./cowmap PID_A PID_B [-m MIN_MB] [-b BUCKETS]
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#define PM_PRESENT   (1ULL << 63)
#define PM_SWAP      (1ULL << 62)
#define PM_PFN_MASK  ((1ULL << 55) - 1)

struct map {
  uint64_t start, end;
  char perms[5];
  char name[256];
};

struct counts {
  uint64_t shared, diverged, a_only, b_only, absent;
};

static long page_size;
static int min_mb = 1;
static int buckets = 64;

static int read_maps(pid_t pid, struct map **out) {
  char path[64];
  snprintf(path, sizeof path, "/proc/%d/maps", pid);
  FILE *f = fopen(path, "r");
  if (!f) { perror(path); return -1; }
  int n = 0, cap = 256;
  struct map *m = malloc(cap * sizeof *m);
  char line[512];
  while (fgets(line, sizeof line, f)) {
    if (n == cap) m = realloc(m, (cap *= 2) * sizeof *m);
    struct map *e = &m[n];
    e->name[0] = 0;
    unsigned long long s, en;
    if (sscanf(line, "%llx-%llx %4s %*s %*s %*s %255[^\n]", &s, &en, e->perms, e->name) < 3)
      continue;
    e->start = s; e->end = en;
    n++;
  }
  fclose(f);
  *out = m;
  return n;
}

static const struct map *find_same(const struct map *ms, int n, const struct map *a) {
  for (int i = 0; i < n; i++)
    if (ms[i].start == a->start && ms[i].end == a->end) return &ms[i];
  return NULL;
}

static int read_pagemap(int fd, uint64_t start, uint64_t npages, uint64_t *buf) {
  off_t off = (start / page_size) * 8;
  size_t want = npages * 8, got = 0;
  while (got < want) {
    ssize_t r = pread(fd, (char *)buf + got, want - got, off + got);
    if (r <= 0) return -1;
    got += r;
  }
  return 0;
}

static void add(struct counts *c, const struct counts *d) {
  c->shared += d->shared; c->diverged += d->diverged;
  c->a_only += d->a_only; c->b_only += d->b_only; c->absent += d->absent;
}

static void print_counts(const char *label, const struct counts *c) {
  double mb = page_size / 1048576.0;
  uint64_t present = c->shared + c->diverged + c->a_only + c->b_only;
  printf("%-28s shared %8.1f MiB  diverged %8.1f MiB  A-only %7.1f  B-only %7.1f  absent %8.1f",
         label, c->shared * mb, c->diverged * mb, c->a_only * mb, c->b_only * mb, c->absent * mb);
  if (present)
    printf("   [%5.1f%% of present still shared]", 100.0 * c->shared / present);
  printf("\n");
}

static void print_rollup(pid_t pid) {
  char path[64], line[256];
  snprintf(path, sizeof path, "/proc/%d/smaps_rollup", pid);
  FILE *f = fopen(path, "r");
  if (!f) return;
  printf("pid %d:", pid);
  while (fgets(line, sizeof line, f)) {
    if (!strncmp(line, "Rss:", 4) || !strncmp(line, "Pss:", 4) ||
        !strncmp(line, "Shared_Dirty:", 13) || !strncmp(line, "Private_Dirty:", 14)) {
      char k[32]; unsigned long v;
      sscanf(line, "%31s %lu", k, &v);
      printf("  %s %.1f MiB", k, v / 1024.0);
    }
  }
  printf("\n");
  fclose(f);
}

int main(int argc, char **argv) {
  if (argc < 3) {
    fprintf(stderr, "usage: %s PID_A PID_B [-m MIN_MB] [-b BUCKETS]\n", argv[0]);
    return 2;
  }
  pid_t a = atoi(argv[1]), b = atoi(argv[2]);
  for (int i = 3; i + 1 < argc; i += 2) {
    if (!strcmp(argv[i], "-m")) min_mb = atoi(argv[i + 1]);
    else if (!strcmp(argv[i], "-b")) buckets = atoi(argv[i + 1]);
  }
  page_size = sysconf(_SC_PAGESIZE);

  struct map *ma, *mb;
  int na = read_maps(a, &ma), nb = read_maps(b, &mb);
  if (na < 0 || nb < 0) return 1;

  char pa[64], pb[64];
  snprintf(pa, sizeof pa, "/proc/%d/pagemap", a);
  snprintf(pb, sizeof pb, "/proc/%d/pagemap", b);
  int fa = open(pa, O_RDONLY), fb = open(pb, O_RDONLY);
  if (fa < 0 || fb < 0) { perror("pagemap"); return 1; }
  if (geteuid() != 0)
    fprintf(stderr, "warning: not root, PFNs read as 0 -> everything present looks 'shared'\n");

  print_rollup(a);
  print_rollup(b);
  printf("\n");

  struct counts total = {0};
  int biggest = -1;
  uint64_t biggest_size = 0;
  for (int i = 0; i < na; i++) {
    const struct map *m = &ma[i];
    if (!find_same(mb, nb, m)) continue;
    uint64_t size = m->end - m->start;
    if (!m->name[0] && m->perms[1] == 'w' && size > biggest_size) {
      biggest_size = size; biggest = i;
    }
  }

  for (int i = 0; i < na; i++) {
    const struct map *m = &ma[i];
    if (!find_same(mb, nb, m)) continue;
    uint64_t npages = (m->end - m->start) / page_size;
    uint64_t *ea = malloc(npages * 8), *eb = malloc(npages * 8);
    if (read_pagemap(fa, m->start, npages, ea) < 0 || read_pagemap(fb, m->start, npages, eb) < 0) {
      free(ea); free(eb); continue;
    }
    struct counts c = {0};
    uint64_t *hist = NULL;
    uint64_t per_bucket = 0;
    if (i == biggest) {
      hist = calloc(buckets, sizeof *hist);
      per_bucket = (npages + buckets - 1) / buckets;
    }
    for (uint64_t p = 0; p < npages; p++) {
      int pa_ = !!(ea[p] & PM_PRESENT), pb_ = !!(eb[p] & PM_PRESENT);
      int div = 0;
      if (pa_ && pb_) {
        if ((ea[p] & PM_PFN_MASK) == (eb[p] & PM_PFN_MASK)) c.shared++;
        else { c.diverged++; div = 1; }
      } else if (pa_) { c.a_only++; div = 1; }
      else if (pb_) { c.b_only++; div = 1; }
      else c.absent++;
      if (hist && div) hist[p / per_bucket]++;
    }
    add(&total, &c);
    if ((m->end - m->start) >= (uint64_t)min_mb << 20) {
      char label[64];
      snprintf(label, sizeof label, "%012lx %s %s", (unsigned long)m->start, m->perms,
               m->name[0] ? m->name : "[anon]");
      label[28] = 0;
      print_counts(label, &c);
    }
    if (hist) {
      printf("\n  guest RAM candidate %lx-%lx (%.0f MiB), divergence per %.1f MiB bucket"
             " (pages touched on either side since fork):\n",
             (unsigned long)m->start, (unsigned long)m->end,
             (m->end - m->start) / 1048576.0, per_bucket * page_size / 1048576.0);
      uint64_t maxh = 1;
      for (int k = 0; k < buckets; k++) if (hist[k] > maxh) maxh = hist[k];
      for (int k = 0; k < buckets; k++) {
        uint64_t off = (uint64_t)k * per_bucket * page_size;
        int bar = (int)(40.0 * hist[k] / maxh);
        printf("  +%6.0f MiB %6.1f MiB |%-40.*s|\n", off / 1048576.0,
               hist[k] * page_size / 1048576.0, bar,
               "########################################");
      }
      printf("\n");
      free(hist);
    }
    free(ea); free(eb);
  }
  print_counts("TOTAL (common mappings)", &total);
  return 0;
}
