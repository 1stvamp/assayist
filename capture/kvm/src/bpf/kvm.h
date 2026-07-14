/* SPDX-License-Identifier: GPL-2.0 */
/* Shared types between the eBPF object and the userspace loader. */
#ifndef __ASSAYIST_KVM_H
#define __ASSAYIST_KVM_H

/* log2 histogram slots. slot i counts values in [2^i, 2^(i+1)) nanoseconds.
 * 40 slots reaches ~2^40 ns (~1099 s), well past any exit-handling latency. */
#define MAX_SLOTS 40

/* Key for the per-(guest, exit-reason) latency histogram.
 * cgroup_id is 0 in singleton mode (aggregate across guests). */
struct hist_key {
	__u64 cgroup_id;
	__u32 exit_reason;
	__u32 _pad;
};

struct hist {
	__u32 slots[MAX_SLOTS];
};

/* Per-vCPU-thread state, stashed at kvm_exit, consumed at kvm_entry. */
struct exit_state {
	__u64 ts;
	__u64 cgroup_id;
	__u32 exit_reason;
	__u32 _pad;
};

#endif /* __ASSAYIST_KVM_H */
