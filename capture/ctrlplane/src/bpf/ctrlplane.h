/* SPDX-License-Identifier: GPL-2.0 */
/* Shared types for the control-plane capture gadget. */
#ifndef __ASSAYIST_CTRLPLANE_H
#define __ASSAYIST_CTRLPLANE_H

#define MAX_SLOTS 40

struct hist {
	__u32 slots[MAX_SLOTS];
};

/* Per-CPU record of which cgroup is currently on the CPU and since when, so a
 * sched_switch can attribute the just-ended slice to the outgoing task. */
struct oncpu {
	__u64 ts;
	__u64 cgroup_id;
};

#endif /* __ASSAYIST_CTRLPLANE_H */
