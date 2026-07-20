/* SPDX-FileCopyrightText: 2026 Wesley Mason (1stvamp)
/* SPDX-License-Identifier: GPL-2.0 */
/* Shared types for the block-IO capture gadget. */
#ifndef __ASSAYIST_BLOCK_H
#define __ASSAYIST_BLOCK_H

/* Latency histogram resolution. The gadget aggregates log-linear: each
 * power-of-two octave is split into SUBSLOTS linear sub-buckets, so the tail
 * (p99) has finer resolution than a plain 40-slot log2 histogram while keeping
 * the same wide dynamic range. Userspace collapses the sub-buckets back to
 * MAX_OCTAVES log2 slots for the default output, or emits all MAX_SLOTS as an
 * explicit histogram under --hires (see block/src/main.rs). */
#define SUBSLOTS 4
#define MAX_OCTAVES 40
#define MAX_SLOTS (MAX_OCTAVES * SUBSLOTS)

/* In-flight request key. dev+sector identifies a request across the
 * issue->complete pair without needing a stable request pointer (which the
 * tracepoints do not expose portably). Collisions on an identical in-flight
 * (dev, sector) are rare and acceptable for a latency histogram. */
struct rq_key {
	__u32 dev;
	__u32 _pad;
	__u64 sector;
};

/* Stashed at issue, consumed at complete. */
struct rq_start {
	__u64 ts;
	__u64 bytes;
	__u8  is_write;
	__u8  _pad[7];
};

/* Output key: per device, split read vs write. */
struct blk_key {
	__u32 dev;
	__u8  is_write;
	__u8  _pad[3];
};

/* Output value: latency histogram plus a byte counter for throughput. */
struct blk_stat {
	__u32 slots[MAX_SLOTS];
	__u64 bytes;
};

#endif /* __ASSAYIST_BLOCK_H */
