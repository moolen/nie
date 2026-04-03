#ifndef NIE_BPF_COMMON_H
#define NIE_BPF_COMMON_H

#include <linux/types.h>

struct allow_key {
	__u8 addr[4];
};

struct allow_val {
	__u64 expires_at_unix;
};

#endif /* NIE_BPF_COMMON_H */

