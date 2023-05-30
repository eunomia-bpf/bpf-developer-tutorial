#include <linux/bpf.h>
#include <linux/bpf_common.h>
#include <sys/socket.h>

#include "bpf_sockops.h"

static inline void bpf_sock_ops_ipv4(struct bpf_sock_ops *skops)
{
	struct sock_key key = {};
	sk_extract4_key(skops, &key);
	if (key.dip4 == 16777343 || key.sip4 == 16777343 ) {
		if (key.dport == 4135 || key.sport == 4135) {
			int ret = sock_hash_update(skops, &sock_ops_map, &key, BPF_NOEXIST);
			printk("<<< ipv4 op = %d, port %d --> %d\n", skops->op, key.sport, key.dport);
			if (ret != 0)
				printk("*** FAILED %d ***\n", ret);
		}
	}
}

static inline void bpf_sock_ops_ipv6(struct bpf_sock_ops *skops)
{
        if (skops->remote_ip4)
                bpf_sock_ops_ipv4(skops);
}


__section("sockops")
int bpf_sockmap(struct bpf_sock_ops *skops)
{
	__u32 family, op;

	family = skops->family;
	op = skops->op;

	//printk("<<< op %d, port = %d --> %d\n", op, skops->local_port, skops->remote_port);
	switch (op) {
        case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
        case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
		if (family == AF_INET6)
                        bpf_sock_ops_ipv6(skops);
                else if (family == AF_INET)
                        bpf_sock_ops_ipv4(skops);
                break;
        default:
                break;
        }
	return 0;
}

BPF_LICENSE("GPL");
int _version __section("version") = 1;
