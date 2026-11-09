#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/signalfd.h>
int main(void) {
    sigset_t m; sigemptyset(&m); sigaddset(&m, SIGUSR1); sigprocmask(SIG_BLOCK, &m, 0);
    int sfd = signalfd(-1, &m, SFD_CLOEXEC);
    printf("ready sfd=%d\n", sfd); fflush(stdout);
    sleep(3);                                     /* T */
    kill(getpid(), SIGUSR1);
    struct signalfd_siginfo si; int n = read(sfd, &si, sizeof si);
    printf("after: read n=%d signo=%d (expect %d)\n", n, si.ssi_signo, SIGUSR1);
    return 0;
}
