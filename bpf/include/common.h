#ifndef NIE_BPF_COMMON_H
#define NIE_BPF_COMMON_H

#include <linux/types.h>

#define NIE_MODE_ENFORCE 0
#define NIE_MODE_AUDIT 1

#define NIE_REASON_NOT_ALLOWED 1
#define NIE_REASON_EXPIRED 2

#define NIE_CIDR_PROTOCOL_TCP 1
#define NIE_CIDR_PROTOCOL_UDP 2
#define NIE_CIDR_PROTOCOL_ICMP 4
#define NIE_CIDR_PROTOCOL_ANY 0xff

struct allow_key {
	__u8 addr[4];
	__u16 dport;
	__u16 pad;
};

struct allow_value {
	__u64 expires_at_mono_ns;
};

struct cidr_key {
	__u32 prefixlen;
	__u8 addr[4];
};

struct cidr_value {
	__u8 protocol_mask;
	__u8 pad[3];
};

struct event {
	__u32 dst_ipv4;
	__u32 reason;
	__u32 action;
	__u8 protocol;
	__u8 pad0;
	__u16 dport;
};

#endif /* NIE_BPF_COMMON_H */
