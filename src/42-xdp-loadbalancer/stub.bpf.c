#include <bpf/bpf.h>

#define SEC(NAME) __attribute__((section(NAME), used))
SEC(".xdp")

int main () {
  return XDP_PASS;
}
