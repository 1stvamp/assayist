// SPDX-FileCopyrightText: 2026 Wesley Mason (1stvamp)
// SPDX-License-Identifier: GPL-2.0
// Assayist control-plane capture gadget: host-side scheduler-treatment signal.
//
// Measures, per cgroup, how the control-plane processes (kube-scheduler,
// controllers, kube-apiserver pods) are treated by the host CPU scheduler:
//   - run-queue latency: wakeup -> actually on-CPU (the contention signal)
//   - on-CPU time: how much CPU the component is actually getting
//
// This is deliberately NOT app-level scheduling/reconcile latency. Those live
// in userspace Go and would need uprobes, which the contract bans on hot paths
// and which are unsafe on Go (stack moves break uretprobe). App-level latency
// enters Assayist via OTLP import from the components' own Prometheus metrics.
// This gadget supplies the host-side "why": was the scheduler starved?
//
// All tp_btf (~15 ns), all aggregated in-kernel. sched_switch fires on every
// context switch system-wide, so the self-metrics matter here; keep the cgroup
// allow-list narrow and the window short.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "ctrlplane.h"

char LICENSE[] SEC("license") = "GPL";

// When true, only cgroups present in `allowed` are recorded. When false,
// everything is recorded (high cardinality and cost; narrow use only).
const volatile bool filter_enabled = false;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 262144);
	__type(key, __u32);   // pid
	__type(value, __u64); // wakeup timestamp
} wakeup_ts SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u64);          // cgroup id
	__type(value, struct hist);  // run-queue latency
} runq SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u64);   // cgroup id
	__type(value, __u64); // accumulated on-CPU ns
} oncpu_ns SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct oncpu);
} oncpu_cur SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u64);  // cgroup id
	__type(value, __u8);
} allowed SEC(".maps");

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

// cgroup id on the default (v2) hierarchy, matching bpf_get_current_cgroup_id.
static __always_inline __u64 task_cgid(struct task_struct *task)
{
	return BPF_CORE_READ(task, cgroups, dfl_cgrp, kn, id);
}

static __always_inline bool allowed_cg(__u64 cgid)
{
	if (!filter_enabled)
		return true;
	return bpf_map_lookup_elem(&allowed, &cgid) != NULL;
}

static __always_inline void record_wakeup(struct task_struct *p)
{
	__u64 cgid = task_cgid(p);
	if (!allowed_cg(cgid))
		return;
	__u32 pid = BPF_CORE_READ(p, pid);
	__u64 ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&wakeup_ts, &pid, &ts, BPF_ANY);
}

SEC("tp_btf/sched_wakeup")
int BPF_PROG(on_wakeup, struct task_struct *p)
{
	record_wakeup(p);
	return 0;
}

SEC("tp_btf/sched_wakeup_new")
int BPF_PROG(on_wakeup_new, struct task_struct *p)
{
	record_wakeup(p);
	return 0;
}

// Only the first three args are declared; sched_switch grew a prev_state arg in
// later kernels, which BPF_PROG safely ignores by position.
SEC("tp_btf/sched_switch")
int BPF_PROG(on_switch, bool preempt, struct task_struct *prev, struct task_struct *next)
{
	__u64 now = bpf_ktime_get_ns();
	__u32 zero = 0;

	// Attribute the slice that just ended to whoever was on-CPU.
	struct oncpu *cur = bpf_map_lookup_elem(&oncpu_cur, &zero);
	if (cur && cur->ts) {
		__u64 delta = now - cur->ts;
		__u64 *acc = bpf_map_lookup_elem(&oncpu_ns, &cur->cgroup_id);
		if (acc)
			__sync_fetch_and_add(acc, delta);
		else
			bpf_map_update_elem(&oncpu_ns, &cur->cgroup_id, &delta, BPF_NOEXIST);
	}

	// Run-queue latency for the task coming on-CPU.
	__u64 ncg = task_cgid(next);
	bool ok = allowed_cg(ncg);
	if (ok) {
		__u32 npid = BPF_CORE_READ(next, pid);
		__u64 *tsp = bpf_map_lookup_elem(&wakeup_ts, &npid);
		if (tsp) {
			__u64 d = now - *tsp;
			struct hist *h = bpf_map_lookup_elem(&runq, &ncg);
			if (!h) {
				struct hist z = {};
				bpf_map_update_elem(&runq, &ncg, &z, BPF_NOEXIST);
				h = bpf_map_lookup_elem(&runq, &ncg);
			}
			if (h) {
				__u64 slot = log2_u64(d);
				if (slot >= MAX_SLOTS)
					slot = MAX_SLOTS - 1;
				__sync_fetch_and_add(&h->slots[slot], 1);
			}
			bpf_map_delete_elem(&wakeup_ts, &npid);
		}
	}

	// Set the new on-CPU record (only track allowed cgroups).
	if (cur) {
		struct oncpu n = {};
		if (ok) {
			n.ts = now;
			n.cgroup_id = ncg;
		}
		*cur = n;
	}
	return 0;
}
