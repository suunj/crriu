/* Test program: foo() is called N times; bar() recurses. */
#include <stdio.h>
#include <stdlib.h>

volatile long sink[16];

__attribute__((noinline)) long foo(long i) {
  sink[i & 15] = i * 3;
  return i + 1;
}

__attribute__((noinline)) long bar(long d) {
  if (d == 0)
    return 1;
  return bar(d - 1) + 1;
}

int main(int argc, char** argv) {
  long n = argc > 1 ? atol(argv[1]) : 5;
  long acc = 0;
  for (long i = 0; i < n; i++)
    acc += foo(i);
  acc += bar(3);
  printf("acc=%ld sink=%p\n", acc, (void*)sink);
  return (int)(acc & 0x7f);
}
