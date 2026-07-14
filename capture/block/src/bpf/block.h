/* SPDX-License-Identifier: GPL-2.0 */
/* Shared types for the block-IO capture gadget. */
#ifndef __ASSAYIST_BLOCK_H
#define __ASSAYIST_BLOCK_H

#define MAX_SLOTS 40

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
