// SPDX-License-Identifier: GPL-2.0
// Assayist block-IO capture gadget: host-side, in-kernel aggregation.
//
// Measures block request service latency (issue -> complete) per device, split
// read vs write, as in-kernel log2 histograms, plus a byte counter per device
// for throughput. This is biolatency's measurement, wired to the Assayist
// contract and kept aggregation-in-kernel so nothing streams per request.
//
// Keyed by device, not by guest. Completion runs in softirq/IRQ context where
// the current task is not the guest, so cgroup-at-completion would be wrong.
// Per-guest block attribution needs syscall-level tracing in the VMM thread and
// is a separate gadget; see README.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "block.h"

char LICENSE[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536); // in-flight requests
	__type(key, struct rq_key);
	__type(value, struct rq_start);
} inflight SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024); // devices * 2 (read/write). Bounded, small.
	__type(key, struct blk_key);
	__type(value, struct blk_stat);
} stats SEC(".maps");

static __always_inline __u64 log2_u64(__u64 v)
{
	__u64 shift, r;
	r     = (v > 0xFFFFFFFFULL) << 5; v >>= r;
	shift = (v > 0xFFFFULL)     << 4; v >>= shift; r |= shift;
	shift = (v > 0xFFULL)       << 3; v >>= shift; r |= shift;
	shift = (v > 0xFULL)        << 2; v >>= shift; r |= shift;
	shift = (v > 0x3ULL)        << 1; v >>= shift; r |= shift;
	r |= (v >> 1);
	return r;
}

SEC("tracepoint/block/block_rq_issue")
int handle_issue(struct trace_event_raw_block_rq *ctx)
{
	struct rq_key k = {};
	struct rq_start s = {};
	char rwbs[8] = {};

	k.dev = BPF_CORE_READ(ctx, dev);
	k.sector = BPF_CORE_READ(ctx, sector);

	s.ts = bpf_ktime_get_ns();
	s.bytes = BPF_CORE_READ(ctx, bytes);

	// rwbs[0]: 'R' read, 'W' write, 'F' flush, 'D' discard. Treat non-read
	// as write for the read/write split (flush/discard are write-side work).
	bpf_core_read(rwbs, sizeof(rwbs), &ctx->rwbs);
	s.is_write = (rwbs[0] != 'R') ? 1 : 0;

	bpf_map_update_elem(&inflight, &k, &s, BPF_ANY);
	return 0;
}

SEC("tracepoint/block/block_rq_complete")
int handle_complete(struct trace_event_raw_block_rq_completion *ctx)
{
	struct rq_key k = {};
	struct rq_start *s;
	struct blk_key bk = {};
	struct blk_stat *st;
	__u64 delta, slot;

	k.dev = BPF_CORE_READ(ctx, dev);
	k.sector = BPF_CORE_READ(ctx, sector);

	s = bpf_map_lookup_elem(&inflight, &k);
	if (!s)
		return 0;

	delta = bpf_ktime_get_ns() - s->ts;

	bk.dev = k.dev;
	bk.is_write = s->is_write;

	st = bpf_map_lookup_elem(&stats, &bk);
	if (!st) {
		struct blk_stat zero = {};
		bpf_map_update_elem(&stats, &bk, &zero, BPF_NOEXIST);
		st = bpf_map_lookup_elem(&stats, &bk);
		if (!st) {
			bpf_map_delete_elem(&inflight, &k);
			return 0;
		}
	}

	slot = log2_u64(delta);
	if (slot >= MAX_SLOTS)
		slot = MAX_SLOTS - 1;

	__sync_fetch_and_add(&st->slots[slot], 1);
	__sync_fetch_and_add(&st->bytes, s->bytes);
	bpf_map_delete_elem(&inflight, &k);
	return 0;
}
