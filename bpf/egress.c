#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "common.h"

const volatile __u32 cfg_bypass_mark = 0;
const volatile __u32 cfg_mode = NIE_MODE_ENFORCE;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__type(key, struct allow_key);
	__type(value, struct allow_value);
} allow_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24); /* 16 MiB */
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} events SEC(".maps");

static __always_inline __u64 now_unix_seconds(void)
{
	/* NOTE: CLOCK_TAI is close to Unix time but differs by leap seconds. */
	return bpf_ktime_get_tai_ns() / 1000000000ULL;
}

static __always_inline int parse_ipv4_dst(struct __sk_buff *skb, __u32 *dst_ipv4)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return -1;
	if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
		return -1;

	struct iphdr *ip = (void *)eth + sizeof(*eth);
	if ((void *)(ip + 1) > data_end)
		return -1;
	if (ip->version != 4)
		return -1;
	if (ip->ihl < 5)
		return -1;
	if ((void *)ip + (ip->ihl * 4) > data_end)
		return -1;

	*dst_ipv4 = ip->daddr;
	return 0;
}

static __always_inline void emit_event(__u32 dst_ipv4, __u32 reason, __u32 action)
{
	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return;

	e->dst_ipv4 = dst_ipv4;
	e->reason = reason;
	e->action = action;
	bpf_ringbuf_submit(e, 0);
}

SEC("classifier/egress")
int nie_egress(struct __sk_buff *skb)
{
	if (cfg_bypass_mark != 0 && skb->mark == cfg_bypass_mark)
		return TC_ACT_OK;

	__u32 dst_ipv4 = 0;
	if (parse_ipv4_dst(skb, &dst_ipv4) != 0)
		return TC_ACT_OK;

	struct allow_key key = {};
	__builtin_memcpy(key.addr, &dst_ipv4, sizeof(dst_ipv4));

	struct allow_value *val = bpf_map_lookup_elem(&allow_map, &key);
	__u64 now = now_unix_seconds();
	if (val && val->expires_at_unix > now)
		return TC_ACT_OK;

	__u32 reason = val ? NIE_REASON_EXPIRED : NIE_REASON_NOT_ALLOWED;
	__u32 action = (cfg_mode == NIE_MODE_ENFORCE) ? TC_ACT_SHOT : TC_ACT_OK;
	emit_event(dst_ipv4, reason, action);
	return action;
}

char LICENSE[] SEC("license") = "GPL";

