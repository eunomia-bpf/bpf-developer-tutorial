#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC(".xdp")
int main () {
  return XDP_PASS;
}
