#include <linux/types.h>
#include <linux/swab.h>

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
# define __bpf_ntohs(x)                 __builtin_bswap16(x)
# define __bpf_htons(x)                 __builtin_bswap16(x)
# define __bpf_constant_ntohs(x)        ___constant_swab16(x)
# define __bpf_constant_htons(x)        ___constant_swab16(x)
# define __bpf_ntohl(x)                 __builtin_bswap32(x)
# define __bpf_htonl(x)                 __builtin_bswap32(x)
# define __bpf_constant_ntohl(x)        ___constant_swab32(x)
# define __bpf_constant_htonl(x)        ___constant_swab32(x)
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
# define __bpf_ntohs(x)                 (x)
# define __bpf_htons(x)                 (x)
# define __bpf_constant_ntohs(x)        (x)
# define __bpf_constant_htons(x)        (x)
# define __bpf_ntohl(x)                 (x)
# define __bpf_htonl(x)                 (x)
# define __bpf_constant_ntohl(x)        (x)
# define __bpf_constant_htonl(x)        (x)
#else
# error "Fix your compiler's __BYTE_ORDER__?!"
#endif

#define bpf_htons(x)                            \
        (__builtin_constant_p(x) ?              \
         __bpf_constant_htons(x) : __bpf_htons(x))
#define bpf_ntohs(x)                            \
        (__builtin_constant_p(x) ?              \
         __bpf_constant_ntohs(x) : __bpf_ntohs(x))
#define bpf_htonl(x)                            \
        (__builtin_constant_p(x) ?              \
         __bpf_constant_htonl(x) : __bpf_htonl(x))
#define bpf_ntohl(x)                            \
        (__builtin_constant_p(x) ?              \
         __bpf_constant_ntohl(x) : __bpf_ntohl(x))

/** Section helper macros. */

#ifndef __section
# define __section(NAME)						\
	__attribute__((section(NAME), used))
#endif

#ifndef __section_tail
# define __section_tail(ID, KEY)					\
	__section(__stringify(ID) "/" __stringify(KEY))
#endif

#ifndef __section_cls_entry
# define __section_cls_entry						\
	__section("classifier")
#endif

#ifndef __section_act_entry
# define __section_act_entry						\
	__section("action")
#endif

#ifndef __section_license
# define __section_license						\
	__section("license")
#endif

#ifndef __section_maps
# define __section_maps							\
	__section("maps")
#endif

/** Declaration helper macros. */

#ifndef BPF_LICENSE
# define BPF_LICENSE(NAME)						\
	char ____license[] __section_license = NAME
#endif

#ifndef BPF_FUNC
# define BPF_FUNC(NAME, ...)              \
   (*NAME)(__VA_ARGS__) = (void *)BPF_FUNC_##NAME
#endif

static int BPF_FUNC(sock_hash_update, struct bpf_sock_ops *skops, void *map, void *key, uint64_t flags);
static int BPF_FUNC(msg_redirect_hash, struct sk_msg_md *md, void *map, void *key, uint64_t flags);
static void BPF_FUNC(trace_printk, const char *fmt, int fmt_size, ...);

#ifndef printk
# define printk(fmt, ...)                                      \
    ({                                                         \
        char ____fmt[] = fmt;                                  \
        trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); \
    })
#endif


struct bpf_map_def {
	__u32 type;
	__u32 key_size;
	__u32 value_size;
	__u32 max_entries;
	__u32 map_flags;
};

union v6addr {
        struct {
                __u32 p1;
                __u32 p2;
                __u32 p3;
                __u32 p4;
        };
        __u8 addr[16];
};

struct sock_key {
	union {
		struct {
			__u32		sip4;
			__u32		pad1;
			__u32		pad2;
			__u32		pad3;
		};
		union v6addr	sip6;
	};
	union {
		struct {
			__u32		dip4;
			__u32		pad4;
			__u32		pad5;
			__u32		pad6;
		};
		union v6addr	dip6;
	};
	__u8 family;
	__u8 pad7;
	__u16 pad8;
	__u32 sport;
	__u32 dport;
} __attribute__((packed));

struct bpf_map_def __section_maps sock_ops_map = {
	.type           = BPF_MAP_TYPE_SOCKHASH,
	.key_size       = sizeof(struct sock_key),
	.value_size     = sizeof(int),
	.max_entries    = 65535,
	.map_flags      = 0,
};

static inline void sk_extract4_key(struct bpf_sock_ops *ops,
				   struct sock_key *key)
{
	key->dip4 = ops->remote_ip4;
	key->sip4 = ops->local_ip4;
	key->family = 1;

	key->sport = (bpf_htonl(ops->local_port) >> 16);
	key->dport = ops->remote_port >> 16;
}

static inline void sk_msg_extract4_key(struct sk_msg_md *msg,
				       struct sock_key *key)
{
	key->sip4 = msg->remote_ip4;
	key->dip4 = msg->local_ip4;
	key->family = 1;

	key->dport = (bpf_htonl(msg->local_port) >> 16);
	key->sport = msg->remote_port >> 16;
}
