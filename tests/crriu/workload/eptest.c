#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
int main(void) {
    int ep = epoll_create1(EPOLL_CLOEXEC);
    int e1 = eventfd(0, 0), e2 = eventfd(0, 0);
    struct epoll_event ev = { .events = EPOLLIN, .data.u64 = 0x1111 };
    epoll_ctl(ep, EPOLL_CTL_ADD, e1, &ev);
    ev.data.u64 = 0x2222; epoll_ctl(ep, EPOLL_CTL_ADD, e2, &ev);
    printf("ready ep=%d e1=%d e2=%d\n", ep, e1, e2); fflush(stdout);
    sleep(3);
    uint64_t v = 1; write(e2, &v, 8);
    struct epoll_event out; int n = epoll_wait(ep, &out, 1, 1000);
    printf("after: n=%d data=%#llx (expect 1, 0x2222)\n", n, (unsigned long long)out.data.u64);
    return 0;
}
