#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/eventfd.h>
int main(void) {
    int efd = eventfd(5, EFD_NONBLOCK | EFD_CLOEXEC);
    uint64_t v = 3; write(efd, &v, 8);          /* counter = 8 */
    printf("ready efd=%d\n", efd); fflush(stdout);
    sleep(3);                                   /* T */
    uint64_t got = 0; int n = read(efd, &got, 8);
    printf("after: read n=%d value=%llu (expect 8)\n", n, (unsigned long long)got);
    return 0;
}
