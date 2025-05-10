// SPDX-License-Identifier: GPL-2.0-only
// SPDX-FileCopyrightText: 2025 Thibaut Varène <hacks@slashdirt.org>

#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/pkt_cls.h>
#include <asm/rwonce.h>
#include <bpf/bpf_helpers.h>

#define USPOTBPF_F_ACCT_UL	(1U << 0)
#define USPOTBPF_F_ACCT_DL	(1U << 1)

struct uspotbpf_cdata {
	uint8_t flags;
	uint64_t packets_in;
	uint64_t bytes_in;
	uint64_t packets_out;
	uint64_t bytes_out;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, ETH_ALEN);
	__type(value, struct uspotbpf_cdata);
	__uint(max_entries, 10000);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} m_clients SEC(".maps");


static __always_inline void *skb_ptr(struct __sk_buff *skb, __u32 len)
{
	void *ptr = (void *)(long)READ_ONCE(skb->data);
	void *end = (void *)(long)(skb->data_end);

	if (ptr + len >= end)
		return NULL;

	return ptr;
}

static __always_inline struct ethhdr *skb_get_ethhdr(struct __sk_buff *skb)
{
	struct ethhdr *eth;
	int len = sizeof(*eth);

	if (len > skb->len)
		return NULL;

	if (bpf_skb_pull_data(skb, len))
		return NULL;

	eth = skb_ptr(skb, len);
	return eth;
}


SEC("tc/ingress")
int uspotbpf_acct_i(struct __sk_buff *skb)
{
	struct uspotbpf_cdata *cdata;
	struct ethhdr *eth;

	eth = skb_get_ethhdr(skb);
	if (!eth)
		goto out;

	cdata = bpf_map_lookup_elem(&m_clients, eth->h_source);
	if (cdata && (cdata->flags & USPOTBPF_F_ACCT_UL)) {
		__sync_fetch_and_add(&cdata->packets_in, 1);
		__sync_fetch_and_add(&cdata->bytes_in, skb->len);
	}
out:
	return TC_ACT_UNSPEC;
}

SEC("tc/egress")
int uspotbpf_acct_o(struct __sk_buff *skb)
{
	struct uspotbpf_cdata *cdata;
	struct ethhdr *eth;

	eth = skb_get_ethhdr(skb);
	if (!eth)
		goto out;

	cdata = bpf_map_lookup_elem(&m_clients, eth->h_dest);
	if (cdata && (cdata->flags & USPOTBPF_F_ACCT_DL)) {
		__sync_fetch_and_add(&cdata->packets_out, 1);
		__sync_fetch_and_add(&cdata->bytes_out, skb->len);
	}
out:
	return TC_ACT_UNSPEC;
}

char _license[] SEC("license") = "GPL";
