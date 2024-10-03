/*
 * The sample program is used to generate test.bin.
 */

#include <stdio.h>

static
unsigned int fibonacci(unsigned int n) {
  if (n <= 1)
    return n;
  return fibonacci(n - 1) + fibonacci(n - 2);
}

int
main() {
  int i;
  printf("calculate fibonacci(n); n = ");
  scanf("%d", &i);

  printf("fibonacci(%d) = %d\n", i, fibonacci(i));
  return 0;
}
