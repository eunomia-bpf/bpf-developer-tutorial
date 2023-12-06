#include "bpf_sockmap.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("sockops")
int bpf_sockops_handler(struct bpf_sock_ops *skops){
    u32 family, op;

	family = skops->family;
	op = skops->op;
	if (op != BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB
        && op != BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB) {
        return BPF_OK;
    }

    if(skops->remote_ip4 != LOCALHOST_IPV4 || skops->local_ip4!= LOCALHOST_IPV4) {
        return BPF_OK;
    }

	struct sock_key key = {
        .dip = skops->remote_ip4,
        .sip = skops->local_ip4,
        .sport = bpf_htonl(skops->local_port),  /* convert to network byte order */
        .dport = skops->remote_port,
        .family = skops->family,
    };

	bpf_printk(">>> new connection: OP:%d, PORT:%d --> %d\n", op, bpf_ntohl(key.sport), bpf_ntohl(key.dport));

	bpf_sock_hash_update(skops, &sock_ops_map, &key, BPF_NOEXIST);
    return BPF_OK;
}