// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "tcp_quarantine.h"

#define AF_INET 2
#define TCP_ESTABLISHED 1

char LICENSE[] SEC("license") = "GPL";

const volatile __u32 target_addr;
const volatile __u16 target_port;
const volatile bool apply;

struct quarantine_stats stats;

extern int bpf_sock_destroy(struct sock_common *sock) __ksym;

SEC("iter/tcp")
int quarantine_tcp(struct bpf_iter__tcp *ctx)
{
	struct sock_common *sk = ctx->sk_common;
	__u32 dst_addr;
	__u16 dst_port;
	__u16 family;
	__u8 state;
	int err;

	if (!sk)
		return 0;

	stats.scanned++;
	family = BPF_CORE_READ(sk, skc_family);
	state = BPF_CORE_READ(sk, skc_state);
	if (family != AF_INET || state != TCP_ESTABLISHED)
		return 0;

	stats.established++;
	dst_addr = BPF_CORE_READ(sk, skc_daddr);
	dst_port = BPF_CORE_READ(sk, skc_dport);
	if (dst_addr != target_addr || dst_port != bpf_htons(target_port))
		return 0;

	stats.matched++;
	if (!apply)
		return 0;

	err = bpf_sock_destroy(sk);
	if (err)
		stats.failed++;
	else
		stats.destroyed++;

	return 0;
}
