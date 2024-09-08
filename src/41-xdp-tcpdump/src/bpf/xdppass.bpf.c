#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_pass(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	int pkt_sz = data_end - data;

	bpf_printk("packet size: %d", pkt_sz);
	return XDP_PASS;
}

char __license[] SEC("license") = "GPL";
