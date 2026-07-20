// SPDX-FileCopyrightText: 2026 Wesley Mason (1stvamp)
// SPDX-License-Identifier: GPL-2.0
// Assayist tap/virtio-net capture gadget: host-side, per-interface, low cost.
//
// Each Firecracker microVM owns a tap, so the interface index is a reliable
// per-guest key at density (unlike block, where completion context hides the
// guest). Counting happens at XDP (RX) and tc egress (TX) with a shared
// per-ifindex map, so one program set covers thousands of taps.
//
// Direction is stated from the tap's point of view:
//   tap RX  = packets the host receives on the tap = guest egress (guest sent)
//   tap TX  = packets the host transmits on the tap = guest ingress (to guest)
// The loader labels series tap_rx_* / tap_tx_*; map to guest direction per above.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "net.h"

char LICENSE[] SEC("license") = "GPL";

#ifndef TC_ACT_OK
#define TC_ACT_OK 0
#endif
#ifndef XDP_PASS
#define XDP_PASS 2
#endif

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384); // taps (per-guest); bounded by guest count
	__type(key, __u32);         // ifindex
	__type(value, struct if_stat);
} stats SEC(".maps");

// Explicit size bucketing, unrolled. Mirrors the bounds in net.h.
static __always_inline int size_bucket(__u64 len)
{
	if (len <= 64)   return 0;
	if (len <= 128)  return 1;
	if (len <= 256)  return 2;
	if (len <= 512)  return 3;
	if (len <= 1024) return 4;
	if (len <= 1500) return 5;
	if (len <= 9000) return 6;
	return 7;
}

static __always_inline struct if_stat *stat_for(__u32 ifindex)
{
	struct if_stat *s = bpf_map_lookup_elem(&stats, &ifindex);
	if (s)
		return s;
	struct if_stat zero = {};
	bpf_map_update_elem(&stats, &ifindex, &zero, BPF_NOEXIST);
	return bpf_map_lookup_elem(&stats, &ifindex);
}

SEC("xdp")
int tap_rx(struct xdp_md *ctx)
{
	__u64 len = (__u64)(ctx->data_end - ctx->data);
	struct if_stat *s = stat_for(ctx->ingress_ifindex);
	if (!s)
		return XDP_PASS;

	__sync_fetch_and_add(&s->rx_packets, 1);
	__sync_fetch_and_add(&s->rx_bytes, len);
	__sync_fetch_and_add(&s->rx_size[size_bucket(len)], 1);
	return XDP_PASS;
}

SEC("tc")
int tap_tx(struct __sk_buff *skb)
{
	__u64 len = skb->len;
	struct if_stat *s = stat_for(skb->ifindex);
	if (!s)
		return TC_ACT_OK;

	__sync_fetch_and_add(&s->tx_packets, 1);
	__sync_fetch_and_add(&s->tx_bytes, len);
	__sync_fetch_and_add(&s->tx_size[size_bucket(len)], 1);
	return TC_ACT_OK;
}
