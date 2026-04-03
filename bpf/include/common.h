#ifndef NIE_BPF_COMMON_H
#define NIE_BPF_COMMON_H

#include <linux/types.h>

#define NIE_MODE_ENFORCE 0
#define NIE_MODE_AUDIT 1

#define NIE_REASON_NOT_ALLOWED 1
#define NIE_REASON_EXPIRED 2

struct allow_key {
	__u8 addr[4];
};

struct allow_value {
	__u64 expires_at_mono_ns;
};

struct event {
	__u32 dst_ipv4;
	__u32 reason;
	__u32 action;
};

#endif /* NIE_BPF_COMMON_H */
