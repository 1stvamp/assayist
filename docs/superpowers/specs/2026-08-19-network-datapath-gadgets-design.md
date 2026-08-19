<!--
SPDX-FileCopyrightText: 2026 Wesley Mason (1stvamp)
SPDX-License-Identifier: Apache-2.0
-->

# Network datapath gadgets: design

Status: draft, for review. Scope: the whole programme, decomposed into sub-projects. Each numbered sub-project below gets its own spec, plan, and implementation cycle later; this document fixes the shared decisions (contract shape, attribution model, build order, structure) so the pieces fit.

## The question this answers

At what VM count does each candidate network backend (tap, netkit, AF_XDP copy, AF_XDP zero-copy) stop being viable, and what breaks first. Secondary: what actually happens to in-flight traffic across a Firecracker Pause/Resume cycle, measured rather than assumed.

The existing `capture/net` gadget measures latency through one VM's virtio-net/tap datapath. This programme is about cost per VM at scale, and about behaviour during lifecycle transitions, neither of which that gadget covers. We do not build a packet generator: we instrument the kernel around existing load generation (fio/wrk-style workloads already in the harness).

## Constraints that shape everything

- The core workspace, orchestrator included, must build on any host with no kernel BTF (`cargo build` / `cargo test` in CI, no clang, no bpftool). So the orchestrator cannot link libbpf or own a BPF map. All BPF lives in `capture/*`, built on a BTF host. This is why the attribution map has a capture-side owner and the orchestrator drives it over a control channel.
- Only the tap arm runs against unmodified Firecracker. netkit and both AF_XDP arms need a Firecracker VMM patch that does not exist upstream, so they are named as future sub-projects gated on that patch and are not specced to implementation depth here. Phase 0 is tap-only.
- eBPF gadgets build and validate on a BTF+KVM host with clang + bpftool; `vmlinux.h` is generated per host and gitignored. The userspace parts (attribution-map control channel, resource sampler, orchestrator pause/resume hook, contract changes) build and test on any host.
- Verify every kernel symbol with `bpftrace -l` on the target kernel before writing a loader. Several tracepoints and fentry targets differ across kernel versions; the spec names them, the plan pins them per host.

## Contract changes (additive, v0)

All additive, matching the v0 discipline (new optional fields and enum values as gadgets reveal needed vocabulary; nothing retyped or removed).

1. `MetricSeries.labels`: optional `{ string: Scalar }` map. Carries the attribution dimensions a single `key` string cannot: `vm_id`, `lifecycle_state`, `backend`. `additionalProperties` on `MetricSeries` stays `false`, so `labels` is added as a named optional property. `key` stays as the primary bounded-cardinality key (`vm_id`); `labels` carries the rest.
2. `CardinalityDecl.key_source` enum gains `vm_id`.
3. No new required fields. No new `source`/`name` enum: those are already free strings, so new probe ids (`softirq`, `napi_poll`, `kfree_skb`, `tcp_retransmit`, `tun_xmit`, ...) need no schema edit.

Producer/consumer split holds. The producer (contract crate, orchestrator) writes `labels` and builds strictly. The gate reads `labels` liberally: it groups like-for-like by the label set when present, and ignores label keys it does not recognise. A run with no `labels` grades exactly as today. The gate change is a read-path addition: comparison modes (`ab_permutation`, `longitudinal_drift`, `subsystem_triad`) gain the option to match series by `(name, labels-subset)` rather than `(name, key)` alone.

`labels` is bounded like any keyed series: `lifecycle_state` is a small closed set, `backend` is one value per run, `vm_id` is the existing bounded key. The cardinality class is still declared on the series and rejected at load if unbounded.

## Attribution spine

Everything keys on one shared map, populated from userspace at VM start and on netdev churn:

```
vm_by_ifindex: HASH  u32 ifindex -> struct vm_ctx {
    u64 vm_id;            // ULID low bits, or a dense u64 handle the orchestrator assigns
    u32 netns_inum;
    u8  lifecycle_state;  // RUNNING | PAUSING | PAUSED | RESUMING
}
```

BPF programs read `skb->dev->ifindex` (tc/TCX), the peer ifindex (netkit), or `ctx->ingress_ifindex` (XDP), look up `vm_ctx`, and stamp every emitted sample with `vm_id` and `lifecycle_state` (into series `labels`). Samples that cannot be attributed go to an `unattributed` bucket. An unattributed rate above ~1% means the map is stale; the owner gadget surfaces it in `capture_meta` and the series is flagged, never silently dropped.

In-kernel aggregation keys histograms on `(vm_id, lifecycle_state)` so a VM's pre-pause and paused samples land in separate series without a second pass. The orchestrator flips `lifecycle_state` in the map around the pause; the next sample for that VM is aggregated under the new state.

Two structural options for who owns the map and how signals share it:

### Option A (recommended): family + pinned map

- `capture/netattrib`: a privileged owner gadget. Creates `vm_by_ifindex`, bpffs-pins it at a known path (e.g. `/sys/fs/bpf/assayist/vm_by_ifindex`), and applies orchestrator-driven updates (add VM on start, update on netdev churn, flip `lifecycle_state`). It holds the map's lifetime for the run and reports the unattributed rate.
- Signal gadgets (`netcost`, `netdrops`, `netpath`, later `netmirror`) open the pinned map read-only by path, passed as a gadget arg (`--attrib-map <path>`), and attach their own programs.
- The orchestrator drives `netattrib` over a control channel: a unix socket or a fifo the gadget watches, carrying line-delimited commands (`add <ifindex> <vm_id> <netns>`, `state <vm_id> <RUNNING|PAUSING|PAUSED|RESUMING>`). The orchestrator writes commands; it never touches BPF. This keeps the core BTF-free.

Trade: most moving parts (pin lifecycle, who cleans the pin up on crash, the control channel), cleanest separation. Each signal keeps its own cost and cardinality budget, which is the point: the softirq cost gadget and the drop gadget have very different hot-path exposure and should be graded separately.

### Option B: one expanded `net` gadget

Fold all host-side programs (attribution, softirq, napi, kfree_skb, tap/netkit/xdp traversal) into a single `capture/net` binary that owns the map in-process, no bpffs pin. Simplest map sharing, one process, one window trivially shared. But it becomes one large multi-program gadget, and per-signal cost/cardinality budgets blur. Peer-side TCP (`nettcp`) stays separate regardless, because it runs on the load-generator host, not the VM host.

Recommendation: Option A. The brief's framing ("separate gadgets sharing a common per-VM attribution map") and Assayist's one-binary-per-probe-set convention both point there, and the separate cost budgets matter for grading. Decision confirmed at review.

## Sub-projects, in build order

Dependency order. Each is a later spec/plan/implement cycle.

### 1. Contract additions

`MetricSeries.labels`, `key_source += vm_id`, gate read-path grouping by label subset. Ships first because every gadget below emits `labels`. Builds and tests on any host. Extend `contract/assay-run.schema.json`, the `contract` crate types, and the gate's series-matching. Update `docs/contract-v0.md`.

Limits: does not change grading semantics for existing runs; a labelless run grades as before. Does not add a `labels`-based gate mode beyond like-for-like grouping; richer label queries are out of scope.

### 2. Attribution spine

`capture/netattrib` (Option A owner), the pinned-map convention, and the orchestrator control channel. The orchestrator side (writing commands, wiring VM start/teardown to `add`/`state`) builds and tests here with a fake channel; the BPF owner builds on a BTF host. Surfaces unattributed rate.

Limits: attribution is by ifindex, so it is only as fresh as the last netdev-churn update; a VM whose tap is recreated mid-run shows unattributed samples until the orchestrator re-adds it. netns is recorded for cross-check, not used as the primary key.

### 3. Pause/resume hook

Extends the existing firecracker adapter lifecycle in `crates/orchestrate/src/native.rs`, which already pauses, snapshots, and resumes via the Firecracker API and records named spans through its `timed()` helper (`restore.resume_to_steady`, `snapshot.create`). The hook adds, around a Pause/Resume:

1. Flip `netattrib` state to `PAUSING`, record a monotonic timestamp.
2. Issue `PATCH /vm {"state":"Paused"}` (the adapter already speaks this API).
3. Record when vCPU threads actually stop, correlated off the existing KVM-exit gadget: absence of exits for that VM's vCPU threads is the observable. The skew between the API call and the real halt is itself recorded.
4. State to `PAUSED`; gadgets now tag samples accordingly.
5. Reverse on Resume; record time-to-first-successful-delivery after the state flip.

Per pause window, emit: packets and bytes arriving during the window, drop-reason histogram, peer retransmit count and RTO progression, whether any connection reached CLOSE, and first-packet-after-resume delivery latency.

Limits: the state flip and the real VM state are racy by construction. Both timestamps are recorded and the window is treated as fuzzy at the edges; we do not pretend the boundary is exact. Cross-host signals (peer TCP) are stitched in from sub-project 5, not measured here.

### 4. Phase 0 signal gadgets (tap only, unmodified Firecracker)

Runnable today. Each opens the pinned attribution map.

- `netcost`: `tracepoint:irq:softirq_entry`/`softirq_exit` filtered to NET_RX (vec 3) and NET_TX (vec 2), per-CPU time in softirq divided by active VM count. `tracepoint:napi:napi_poll` recording `work` against `budget` per device. ksoftirqd time separated from in-context softirq time (compare `current` pid against the per-CPU ksoftirqd pid). This is the density-ceiling number.
- `netdrops`: `tracepoint:skb:kfree_skb` histogrammed by `reason` (SKB_DROP_REASON_*, 5.17+) and `vm_id`. Cross-checked against per-CPU NET_RX backlog drops from `/proc/net/softnet_stat`. Primary signal during pause windows.
- `netpath`: `net:netif_receive_skb`, `net:net_dev_queue`, `net:net_dev_xmit` stage timestamps correlated on skb pointer through a bounded LRU map that ages entries out (the skb is not assumed to survive). tap-specific fentry on `tun_net_xmit`, `tun_do_read`, `tun_get_user`, `tun_put_user`.
- Resource sampler (userspace, no BPF; a `resident`-style sampler): `/proc/slabinfo` deltas for `skbuff_head_cache`, `skbuff_fclone_cache`, relevant `kmalloc-*` buckets; netdev and netns counts via rtnetlink dump; open fds and threads in the VMM process (Firecracker services the virtqueue in-process, so that thread cost is part of the per-VM budget).

Limits: netcost's per-VM division assumes softirq work attributes evenly across active VMs on a CPU, which is an approximation the gadget states. netpath's skb-pointer correlation drops samples when an skb is freed and its address reused inside the LRU window; the drop rate is reported. The resource sampler's per-VM attribution is coarse (object counts plus total slab delta), stated as such; per-netdev memory is not directly exposed by the kernel.

### 5. Peer-side TCP (`nettcp`)

Runs on the load-generator host, not the VM host. `tracepoint:tcp:tcp_retransmit_skb`, `tcp:tcp_probe`, `sock:inet_sock_set_state`. Retransmit count and RTO backoff progression during a pause window, plus any transition to CLOSE. This is how the real pause budget is found, rather than derived from `tcp_retries2`. QUIC's idle timeout (commonly ~30s) is shorter than TCP's patience and revalidates the path, so QUIC cells matter.

Limits: cross-host, so its run is separate and provenance-linked to the VM-host run rather than merged into one capture window. It sees the peer's kernel view only; it cannot attribute to `vm_id` directly and correlates by connection 4-tuple and time.

### 6. Mirroring cost (`netmirror`)

Its own gadget and a deliberate comparison. clsact ingress/egress with `bpf_clone_redirect` to a capture device (the CNSM 2018 full-skb-copy pattern), versus the same selection sampling headers only into a `BPF_MAP_TYPE_RINGBUF`. Measure the delta. The point is our own number for what observability costs on the datapath at our packet rates, instead of inheriting a 2018 figure from a nested-VirtualBox testbed.

Limits: measures mirroring cost for the two named strategies at our rates, nothing about downstream capture-consumer cost.

### 7. Blocked arms (gated on a Firecracker VMM patch)

Named as future sub-projects, not specced to implementation depth here. Firecracker upstream has no netkit or AF_XDP netdev backend; these need a VMM patch scoped separately. Phase 0 does not block on it.

- netkit: fentry on `netkit_xmit`, recording the BPF verdict (PASS/DROP/REDIRECT/NEXT).
- AF_XDP copy and zero-copy: `xdp:xdp_redirect`/`_err`/`_map_err`, `xdp:xdp_exception`, `xdp:xdp_cpumap_enqueue`/`_kthread`, `xdp:xdp_devmap_xmit`; fentry on `xsk_rcv`, `__xsk_rcv_zc`, `xsk_generic_rcv` to distinguish zero-copy from copy at runtime rather than trusting bind flags; fill/completion ring occupancy sampled periodically (ring starvation is the failure mode). Zero-copy needs one dedicated NIC hardware queue per socket, so the 256 and 1024 VM cells are not runnable in that configuration on a normal NIC. Design the AF_XDP arm as per-CPU sockets with a shared UMEM and an XDP program demultiplexing to per-VM queues, and record the queue-count ceiling as a finding rather than a failed run.
- In-guest XDP is not attachable on Firecracker's virtio-net today because the device advertises LRO and CSUM offloads (upstream issue #2433). Host-side only for now.

### 8. Experiment matrix and output contract

Matrix cells run as run-defs. Backends: tap (Phase 0), then netkit, AF_XDP copy, AF_XDP zero-copy once the VMM patch lands (tap + vhost-net only if the VMM patch exists). VM counts: 1, 8, 64, 256, 1024, stopping early at whatever count the host stops being credible and recording why. Packet sizes: 64, 512, 1518. Pause durations: 0 (control), 50ms, 500ms, 5s, 30s, 300s. Protocols: TCP, UDP, QUIC.

Metrics per cell: pps per VM, p50/p99/p99.9 latency, host CPU per VM split into softirq versus process context, kernel object count per VM, slab delta per VM, drop-reason distribution.

Output follows the five-file harness contract: one schema-valid AssayRun per cell; a comparison table across backends at each VM count; a failure-mode log where every cell that did not run is kept as data with its reason; raw histograms retained, not just summary percentiles. No mean is reported without the distribution behind it; single-run numbers are marked as such. io_uring is blocked in the seccomp profile for CRIU compatibility, so nothing in the harness reaches for it (it would fail confusingly).

Limits: the matrix as a whole is bounded by host credibility, not by the grid; the failure-mode log is a first-class output, not an exception path.

## Non-goals

- No production datapath implementation. This measures candidates.
- No connection-state preservation across restore. That is a separate track (TCP_REPAIR operates on host sockets and does not reach guest-owned connections).
- No comparison against DPDK or OVS. Neither is a candidate here.

## Open decisions for review

1. Structure: Option A (family + pinned map) vs Option B (one expanded `net` gadget). Recommendation A.
2. `vm_id` representation in `labels`: full ULID string vs a dense u64 handle the orchestrator assigns per run. A handle is cheaper as a BPF map value and a series label; the ULID is self-describing across runs. Leaning dense handle in-kernel, ULID in the AssayRun via an orchestrator-side lookup.
3. Control channel transport: unix socket vs watched fifo for orchestrator to `netattrib`. Leaning unix socket (backpressure, framing, clean EOF on teardown).
