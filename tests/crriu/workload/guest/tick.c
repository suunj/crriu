#include <unistd.h>
#include <stdio.h>
#include <time.h>
int main(void) {
  for (int i = 1; i <= 14; i++) {
    char b[32]; int n = snprintf(b, sizeof b, "guest tick %d\n", i);
    write(1, b, n);
    struct timespec ts = {1, 0}; nanosleep(&ts, 0);
  }
  return 0;   /* init exits → panic=1 → reboot → -no-reboot → QEMU exit */
}
