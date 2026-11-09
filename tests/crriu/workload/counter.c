#include <stdio.h>
#include <unistd.h>
int main(void) {
    for (int i = 0; ; i++) { printf("%d\n", i); fflush(stdout); usleep(300000); }
}
