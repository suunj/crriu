/* memdiff: compare resident memory content of two Linux processes.
 * Usage: memdiff PID_A PID_B START END [-b BUCKETS]
 * Addresses are hexadecimal (with or without 0x). Run as root/CAP_SYS_PTRACE.
 * For consistent results, stop all threads of both processes first.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>
#include <sys/types.h>
#include <unistd.h>

#define PRESENT (1ULL << 63)
#define SWAPPED (1ULL << 62)

enum kind { SAME, DIFFERENT, A_ONLY, B_ONLY, ABSENT, UNREADABLE, N_KINDS };
static const char *names[] = {"same-content", "different-content", "A-only", "B-only", "absent", "unreadable"};

static int pagemap_entry(int fd, uint64_t va, size_t ps, uint64_t *entry) {
    off_t off = (off_t)((va / ps) * sizeof(uint64_t));
    ssize_t n = pread(fd, entry, sizeof(*entry), off);
    return n == (ssize_t)sizeof(*entry) ? 0 : -1;
}
static int read_page(pid_t pid, uint64_t va, void *buf, size_t ps) {
    struct iovec local = { .iov_base = buf, .iov_len = ps };
    struct iovec remote = { .iov_base = (void *)(uintptr_t)va, .iov_len = ps };
    return process_vm_readv(pid, &local, 1, &remote, 1, 0) == (ssize_t)ps ? 0 : -1;
}
static void usage(const char *prog) {
    fprintf(stderr, "usage: %s PID_A PID_B START_HEX END_HEX [-b BUCKETS]\n", prog);
}
static int parse_pid(const char *s, pid_t *out) {
    char *end; errno = 0;
    long v = strtol(s, &end, 10);
    if (errno || *end || v <= 0 || v > INT32_MAX) return -1;
    *out = (pid_t)v;
    return 0;
}
static int parse_addr(const char *s, uint64_t *out) {
    char *end; errno = 0;
    unsigned long long v = strtoull(s, &end, 16);
    if (errno || *end || end == s || s[0] == '-') return -1;
    *out = (uint64_t)v;
    return 0;
}
int main(int argc, char **argv) {
    if (argc != 5 && argc != 7) { usage(argv[0]); return 2; }
    pid_t a, b; uint64_t start, end;
    if (parse_pid(argv[1], &a) || parse_pid(argv[2], &b) ||
        parse_addr(argv[3], &start) || parse_addr(argv[4], &end)) {
        usage(argv[0]); return 2;
    }
    long lps = sysconf(_SC_PAGESIZE);
    if (lps <= 0) { perror("sysconf"); return 1; }
    size_t ps = (size_t)lps;
    if (end <= start || start % ps || end % ps) {
        fprintf(stderr, "range must be nonempty and page-aligned\n"); return 2;
    }
    size_t buckets = 32;
    if (argc == 7) {
        if (strcmp(argv[5], "-b")) { usage(argv[0]); return 2; }
        char *tail; errno = 0; unsigned long v = strtoul(argv[6], &tail, 10);
        if (errno || *tail || v == 0 || v > 4096) { usage(argv[0]); return 2; }
        buckets = v;
    }
    char path[80];
    snprintf(path, sizeof(path), "/proc/%ld/pagemap", (long)a);
    int fa = open(path, O_RDONLY | O_CLOEXEC);
    if (fa < 0) { perror(path); return 1; }
    snprintf(path, sizeof(path), "/proc/%ld/pagemap", (long)b);
    int fb = open(path, O_RDONLY | O_CLOEXEC);
    if (fb < 0) { perror(path); close(fa); return 1; }
    void *ba = malloc(ps), *bb = malloc(ps);
    uint64_t (*hist)[N_KINDS] = calloc(buckets, sizeof(*hist));
    if (!ba || !bb || !hist) { perror("malloc"); return 1; }
    uint64_t counts[N_KINDS] = {0};
    uint64_t npages = (end - start) / ps;
    for (uint64_t p = 0; p < npages; p++) {
        uint64_t va = start + p * ps, ea, eb;
        enum kind k;
        if (pagemap_entry(fa, va, ps, &ea) || pagemap_entry(fb, va, ps, &eb)) {
            k = UNREADABLE;
        } else {
            int pa = !!(ea & PRESENT), pb = !!(eb & PRESENT);
            if (pa && pb) {
                if (read_page(a, va, ba, ps) || read_page(b, va, bb, ps))
                    k = UNREADABLE;
                else k = memcmp(ba, bb, ps) == 0 ? SAME : DIFFERENT;
            } else if (pa) k = A_ONLY;
            else if (pb) k = B_ONLY;
            else k = ABSENT; /* includes swapped pages; not compared */
        }
        counts[k]++;
        size_t bucket = (size_t)(((__uint128_t)p * buckets) / npages);
        hist[bucket][k]++;
    }
    printf("memdiff pidA=%ld pidB=%ld range=%#" PRIx64 "-%#" PRIx64
           " (%.1f MiB), page=%zu bytes\n", (long)a, (long)b,
           start, end, (double)(end - start) / 1048576.0, ps);
    for (int k = 0; k < N_KINDS; k++)
        printf("%-19s %10" PRIu64 " pages  %10.2f MiB\n", names[k],
               counts[k], (double)counts[k] * ps / 1048576.0);
    uint64_t compared = counts[SAME] + counts[DIFFERENT];
    if (compared)
        printf("different among compared: %.4f%% (%" PRIu64 "/%" PRIu64 " pages)\n",
               100.0 * counts[DIFFERENT] / compared, counts[DIFFERENT], compared);
    printf("\nBucket offsets (different-content; A-only; B-only; unreadable), MiB:\n");
    for (size_t i = 0; i < buckets; i++) {
        uint64_t first = (uint64_t)(((__uint128_t)i * npages + buckets - 1) / buckets);
        printf("+%8.1f: %8.3f  %8.3f  %8.3f  %8.3f\n",
               (double)first * ps / 1048576.0,
               (double)hist[i][DIFFERENT] * ps / 1048576.0,
               (double)hist[i][A_ONLY] * ps / 1048576.0,
               (double)hist[i][B_ONLY] * ps / 1048576.0,
               (double)hist[i][UNREADABLE] * ps / 1048576.0);
    }
    if (counts[UNREADABLE])
        fprintf(stderr, "warning: unreadable pages; check ptrace permissions and mapped ranges\n");
    if (counts[ABSENT])
        fprintf(stderr, "note: absent includes non-present/swapped pages; contents were not compared\n");
    free(hist); free(ba); free(bb); close(fa); close(fb);
    return counts[UNREADABLE] ? 3 : 0;
}

