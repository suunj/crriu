// fdtest_append.c
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

int main(void)
{
    int fd = open("append.txt", O_WRONLY | O_CREAT | O_TRUNC | O_APPEND, 0644);
    if (fd < 0) {
        perror("open");
        return 1;
    }

    if (write(fd, "hello", 5) != 5) {
        perror("write");
        return 1;
    }

    printf("ready fd=%d\n", fd);
    fflush(stdout);

    sleep(10);

    printf("offset=%ld\n", (long)lseek(fd, 0, SEEK_CUR));
    close(fd);
    return 0;
}
