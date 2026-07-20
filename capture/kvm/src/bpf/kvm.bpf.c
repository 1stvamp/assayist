// SPDX-FileCopyrightText: 2026 Wesley Mason (1stvamp)
// SPDX-License-Identifier: GPL-2.0
// Assayist KVM capture gadget: host-side, agentless, in-kernel aggregation.
//
// Measures exit-handling latency per exit reason: the time a vCPU thread spends
// out of the guest between kvm_exit and the following kvm_entry. That interval
// is host/VMM work (the thing you actually want to see when a guest stalls),
// and it is visible with no in-guest agent, so it works the same for a full VM,
// a Firecracker microVM, or a unikernel guest.
//
// Everything is aggregated in-kernel into log2 histograms. Nothing streams
// per-event to userspace. That is the whole low-observer-effect story: the hot
// path is two map ops on exit and a lookup-plus-increment on entry.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "kvm.h"

char LICENSE[] SEC("license") = "GPL";

// Set by the loader before load(). When true, histograms are keyed by cgroup id
// (per-guest, the density case). When false, cgroup id is 0 and reasons
// aggregate across all guests (the common single-target case).
const volatile bool per_guest = false;

// vCPU-thread state stashed at exit, keyed by thread id (tids are globally
// unique, so this disambiguates vCPUs across every guest on the host).
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 131072); // covers ~10k guests * several vCPUs each
	__type(key, __u32);
	__type(value, struct exit_state);
} exit_start SEC(".maps");

// The output: per-(guest, reason) latency histograms. max_entries is the
// cardinality budget; the loader sets it to reasons * max_guests.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 262144);
	__type(key, struct hist_key);
	__type(value, struct hist);
} hists SEC(".maps");

// Branchless integer log2 floor. No loop, so the verifier is happy and the
// cost is a handful of instructions. slot == floor(log2(delta)) is exactly the
// contract's log2 bucket index (bucket i == [2^i, 2^(i+1))).
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

// kvm_exit carries exit_reason as a formatted tracepoint field. We read it via
// CO-RE off trace_event_raw_kvm_exit so libbpf relocates the offset per kernel.
// This is the one place we depend on a KVM tracepoint field layout, so it is
// the one place the compatibility matrix has to be checked per kernel.
SEC("tracepoint/kvm/kvm_exit")
int handle_kvm_exit(struct trace_event_raw_kvm_exit *ctx)
{
	__u32 tid = (__u32)bpf_get_current_pid_tgid();
	struct exit_state st = {};

	st.ts = bpf_ktime_get_ns();
	st.exit_reason = BPF_CORE_READ(ctx, exit_reason);
	st.cgroup_id = per_guest ? bpf_get_current_cgroup_id() : 0;

	bpf_map_update_elem(&exit_start, &tid, &st, BPF_ANY);
	return 0;
}

// kvm_entry reads no formatted fields at all (we key on the current tid), so it
// is maximally portable across kernels and needs no compatibility entry.
SEC("tracepoint/kvm/kvm_entry")
int handle_kvm_entry(void *ctx)
{
	__u32 tid = (__u32)bpf_get_current_pid_tgid();
	struct exit_state *st;
	struct hist_key hk = {};
	struct hist *h;
	__u64 delta, slot;

	st = bpf_map_lookup_elem(&exit_start, &tid);
	if (!st)
		return 0; // entry without a matching recorded exit; skip

	delta = bpf_ktime_get_ns() - st->ts;

	hk.cgroup_id = st->cgroup_id;
	hk.exit_reason = st->exit_reason;

	h = bpf_map_lookup_elem(&hists, &hk);
	if (!h) {
		struct hist zero = {};
		bpf_map_update_elem(&hists, &hk, &zero, BPF_NOEXIST);
		h = bpf_map_lookup_elem(&hists, &hk);
		if (!h) {
			// Map full (cardinality budget hit). Drop the sample and
			// clear state; the loader reports overflow from the map's
			// fullness, see README.
			bpf_map_delete_elem(&exit_start, &tid);
			return 0;
		}
	}

	slot = log2_u64(delta);
	if (slot >= MAX_SLOTS)
		slot = MAX_SLOTS - 1;

	__sync_fetch_and_add(&h->slots[slot], 1);
	bpf_map_delete_elem(&exit_start, &tid);
	return 0;
}
