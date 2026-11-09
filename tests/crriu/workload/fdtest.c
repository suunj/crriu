#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(void) {
    char buf[256];

    int a = open("f1.txt", O_RDONLY);
    int b = open("f2.txt", O_RDONLY);
    int c = dup(a);
    int d = open("f3.txt", O_WRONLY | O_APPEND);

    read(a, buf, 50);
    read(b, buf, 120);
    write(d, "hello\n", 6);

    lseek(c, 200, SEEK_SET);

    // Replace b's open file description with d's.
    dup2(d, b);

    // Create another independent description of f1.txt.
    int e = open("f1.txt", O_RDONLY);
    lseek(e, 100, SEEK_SET);

    printf("ready a=%d b=%d c=%d d=%d e=%d\n",
           a, b, c, d, e);
    fflush(stdout);

    sleep(3); // Stop replay here.

    // Verify shared offsets after restore.
    printf("a offset=%lld\n", (long long)lseek(a, 0, SEEK_CUR));
    printf("c offset=%lld\n", (long long)lseek(c, 0, SEEK_CUR));
    printf("e offset=%lld\n", (long long)lseek(e, 0, SEEK_CUR));

    // Verify that a and c share an offset.
    read(a, buf, 20);
    printf("c offset after read(a)=%lld\n",
           (long long)lseek(c, 0, SEEK_CUR));

    // Verify that b and d share an open file description.
    printf("b offset=%lld\n", (long long)lseek(b, 0, SEEK_CUR));
    printf("d offset=%lld\n", (long long)lseek(d, 0, SEEK_CUR));

    write(b, "world\n", 6);

    int f = open("f2.txt", O_RDONLY);
    printf("relative open after restore: %s\n", f >= 0 ? "ok" : "FAILED");

    return 0;
}
