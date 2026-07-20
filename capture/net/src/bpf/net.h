/* SPDX-FileCopyrightText: 2026 Wesley Mason (1stvamp)
/* SPDX-License-Identifier: GPL-2.0 */
/* Shared types for the tap/virtio-net capture gadget. */
#ifndef __ASSAYIST_NET_H
#define __ASSAYIST_NET_H

/* Explicit packet-size histogram. Upper bounds (bytes):
 *   64, 128, 256, 512, 1024, 1500, 9000
 * giving 8 buckets (7 bounds + one overflow). Kept in sync with the loader,
 * which emits these same bounds as explicit_bounds. */
#define SIZE_BUCKETS 8

struct if_stat {
	__u64 rx_packets;
	__u64 rx_bytes;
	__u64 tx_packets;
	__u64 tx_bytes;
	__u32 rx_size[SIZE_BUCKETS];
	__u32 tx_size[SIZE_BUCKETS];
};

#endif /* __ASSAYIST_NET_H */
