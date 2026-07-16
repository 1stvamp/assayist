# One benchmarking system for all of Compute 2.0: design brief

Status: draft for review. Working name: `spine` (the load-bearing bit is a metric contract plus a capture plane; targets and workloads hang off it as plugins). Rename before we tag anything public.

## Bottom line

One system covers every space we care about (microVM lifecycle, host density, scheduler, networking, storage, long-lived drift, end-to-end run latency, and any future eBPF-as-subsystem experiment) if we stop trying to standardise the *thing under test* and instead standardise three things around it: a metric contract, a host/KVM-side capture plane, and a decision gate. Targets and workloads become adapters behind stable interfaces. The capture plane is genuinely universal because it sits host-side on KVM tracepoints and the virtio/tap path, so it observes a full VM, a Firecracker microVM, a unikernel guest, or a bare process the same way, with no in-guest agent.

That is the whole trick: a fixed spine, two pluggable edges.

```
          target adapter                         workload driver
          (what runs)                            (what loads it)
                \                                    /
                 \                                  /
                  v                                v
        +-----------------------------------------------------+
        |  SPINE                                               |
        |  - metric contract (schema + run identity)          |
        |  - capture plane (host/KVM-side eBPF, AF_XDP)        |
        |  - decision gate (A/B permutation + drift mode)      |
        |  - orchestration + reproducibility                  |
        |  - sinks (Prometheus/Grafana/Axiom/Better Stack)    |
        +-----------------------------------------------------+
```

Everything below is either a spine component (we build and own it, it stays stable) or an adapter (cheap to add, expected to multiply).

## Why one system actually works here

The research report landed on the key enabler already: host-side eBPF on `kvm:kvm_exit` / `kvm_entry` / `kvm_hypercall` / `kvm_mmio` / `kvm_pio`, plus the vhost/virtio functions and the tap/virtio-net path via XDP/AF_XDP, is the only instrumentation that works uniformly across guests with no in-guest agent. That is the property that makes a single system viable rather than a family of bespoke rigs.

So the versatility claim reduces to: can every problem space emit into one metric contract, be captured from one plane, and be judged by one gate? Yes, with two caveats we design for up front (the K8s control-plane space needs a second capture surface, and the 30-day space needs a longitudinal gate mode instead of before/after). Both fold into the spine cleanly, see below.

## Coverage matrix

Each row is a space we already have. Same spine, different adapter and gate mode.

| Space | Target adapter | Workload driver | Primary capture surface | Gate mode |
|---|---|---|---|---|
| microVM boot/snapshot/restore | `firecracker`, `firecracker-in-pod`, `cloud-hypervisor` | synthetic run, replayed task trace | KVM tracepoints + boot-timer marker + restore page-fault counters | A/B permutation |
| Host density (~10k mVMs) | `firecracker-fleet` (N guests) | mixed steady-state fleet | keyed in-kernel histograms (per-guest key), AF_XDP on tap path | A/B permutation on aggregate + fairness percentiles |
| Custom scheduler + CRDs + quota | `k8s-control-plane` | pod-churn generator, quota-stress | scheduler plugin hooks + API-server + reconcile-latency (fentry on controller funcs) | A/B permutation |
| Networking (XDP/AF_XDP) | any guest target | pktgen / wrk / iperf | XDP program counters + AF_XDP capture | A/B permutation |
| Storage/IO | any guest target | fio (psync/libaio) | block-layer tracepoints + virtio-blk fentry | A/B permutation |
| Long-lived (up to 30-day) | `firecracker` (single, held) | steady synthetic + periodic probe | same as microVM, sampled on a schedule | longitudinal drift |
| End-to-end run lifecycle (Parkin/Trigger) | `run-lifecycle` (spans enqueue->schedule->boot->exec->snapshot->restore) | replayed production run mix | lifecycle span markers + all of the above | A/B permutation on per-stage spans |
| eBPF-as-subsystem experiment (scx, XRP-style, etc.) | `subsystem-ab` (vanilla vs eBPF variant) | subsystem-specific (YCSB, fio, wrk) | subsystem tracepoints + the eBPF program's own run-time counters | A/B permutation (triad, see below) |

The `run-lifecycle` adapter is the one that ties Trigger.dev's actual product concern together: it is a composite target that drives a real run through every stage and captures each stage as a named span, so a regression anywhere (scheduler decision, boot, snapshot serialise, restore working-set reload) shows up against the same baseline.

## Spine component 1: the metric contract

This is the most important artifact to get right, because it is the thing every adapter and every sink agrees on, and it is what makes results comparable across heterogeneous targets. It is also the thing that is painful to change after we open source, so we design it once, carefully.

A run emits:

- **Run identity**: target adapter id, workload id, config parameterisation (and a hash of it), git SHA of the system under test, and a full host fingerprint (kernel version, CPU model, SMT on/off, CPU governor, THP setting, mitigations, pinning layout, NUMA topology). Reproducibility lives or dies on the host fingerprint, so it is mandatory, not optional. A result with an incomplete fingerprint is rejected, not stored.
- **Lifecycle spans**: named, timestamped intervals (e.g. `boot.vmm_ready`, `snapshot.serialise`, `restore.resume_to_steady`, `schedule.pod_to_node`). Spans are the unit the gate compares for latency work.
- **Continuous metrics**: name, unit, and aggregation kind (histogram / counter / gauge), plus which capture program produced it. Histograms are the default and the preferred kind: we aggregate in-kernel and ship summaries, we do not stream per-event (see capture plane).
- **Observer-effect self-metrics**: every eBPF program reports its own cost via the kernel's BPF run-time counters (run_time_ns / run_cnt). These are first-class gated metrics, not diagnostics. If a probe's steady-state cost crosses the budget, the harness flags the *result* as contaminated, not just the probe. This is how we make "low observer effect" a measured property rather than a claim.

Schema shape: I would model the continuous side on the OpenTelemetry profiling signal plus AWS-EMF-style embedded metric emission (Firecracker already uses EMF, so the microVM adapters get it nearly for free). One JSON-ish envelope per run, streamable to any sink. Keep the schema versioned from commit one (`schema_version` field), because external users will pin to it.

Cardinality budget is part of the contract, not an afterthought: at 10k guests we cannot carry a per-guest unbounded series, so keyed histograms have a fixed key space (guest key derived from the KVM vcpu pid -> microVM mapping, or the cgroup id) and everything else aggregates. Any adapter that wants to emit unbounded cardinality has to declare it and gets rejected by default.

## Spine component 2: the capture plane

This is the low-observer-effect core, and the rules come straight from the overhead evidence:

- Attach preference, in order: static tracepoints (`tp_btf`, ~15 ns) > `fentry`/`fexit` (~24 ns) > `kprobe` (~137 ns). Uprobes are banned on hot paths (dual context switch, up to ~200% under I/O-heavy load); where we must instrument userspace VMM code, evaluate `bpftime` to cut uprobe cost ~10x, and otherwise sample rather than trace.
- Kernel to user transfer is the BPF ring buffer, never the perf buffer, for anything new.
- **Aggregate in-kernel.** This is the single biggest lever. The `netstacklat` result (in-kernel histogram, ~0.2 to 0.3 us program run-time, ~0.75% CPU, tail latency inflated by no more than 6%) versus the push-a-timestamp-per-event approach (just over 1 us per event) versus probe-everything (`pwru` at ~25% CPU) is the whole argument. We compute latency and bucket it inside eBPF and only summaries cross the boundary.
- The packet path uses XDP/AF_XDP zero-copy so the density space does not drown the host stack.

The capture plane ships as a set of libbpf + CO-RE gadgets (Inspektor-Gadget / Retina plugin texture: image-distributable, version-portable via BTF). The KVM-side agentless gadget is the piece the research flagged as a genuine gap in the wider world, so it is also the most valuable thing we would be open sourcing. Start from BCC `kvmexit` and the KVM-hypercall bpftrace examples, rewrite as a proper CO-RE gadget, and that is the universal vantage other people do not currently have.

Second capture surface (control plane): the scheduler/CRD space cannot be seen from KVM tracepoints, so it gets its own gadget set (fentry on the scheduler plugin entry points and controller reconcile functions, plus API-server request tracepoints). It emits into the *same* metric contract, so from the gate's point of view it is indistinguishable. That is the point: two capture surfaces, one contract.

## Spine component 3: the decision gate

Take Firecracker's `ab_test.py` approach as the decision engine, because it is the most statistically honest thing in this space and we already know it works:

- Non-parametric permutation test (difference of means, ~10k resamples), robust to the non-normal latency distributions we actually see.
- Three gates: significance (p < 0.01), an absolute-strength threshold, and a noise threshold (~5%). Cross-parameterisation averaging to correct for multiple-comparisons noise (a real change shows up across parameterisations, not in one lone cell).
- An IGNORE list for metrics whose variance is too high to gate on (Firecracker tolerates up to ~60% on some), so we do not block CI on noise.
- Minimum two data points per metric per series, single-tenant pinned execution, host tuning captured into the fingerprint.

We need no ground truth up front: the A run generates the baseline, the B run is tested against it, same as Firecracker.

**Longitudinal drift mode** (the 30-day caveat): you cannot A/B a month. So for held long-lived targets the gate switches from before/after to trajectory comparison: sample the full metric set on a schedule (memory footprint, fragmentation proxy, snapshot size, restore-time-if-we-snapshotted-now), fit an expected trajectory from a baseline run, and flag deviation beyond a band. This reuses the same schema and the same capture plane, only the gate logic differs. It answers the question the 30-day workloads actually pose: does restore time or memory drift as the guest ages.

**Subsystem triad** (the eBPF-as-subsystem caveat): for scx / XRP-style experiments the gate runs three comparisons at once, (a) A/B versus the vanilla subsystem, (b) the eBPF program's own cost from its run-time counters, (c) end-to-end workload KPIs. None of BMC/XRP/Electrode/lambda-IO/sched_ext share such a harness, so this is a second genuinely novel open-source contribution sitting in the same repo.

## Spine component 4: orchestration and reproducibility

- Benchmarks are declarative files (committable). A benchmark is a `(target, workload, capture-plan, gate-mode, parameterisation)` tuple in a config file, versioned in git alongside the code under test. This is what makes results reproducible and reviewable: you diff the benchmark definition, not someone's shell history.
- Host preparation is codified (governor, SMT, THP, pinning via the equivalent of Firecracker's `vm.pin_threads`, mitigations) and the applied state is read back into the run fingerprint. If prep did not take, the run is invalid.
- Single-tenant execution is enforced for gated runs. Density runs are the deliberate exception (contention is the point) and are marked as such in the fingerprint so they never get compared against single-tenant baselines by accident.

## Spine component 5: sinks

Pluggable, because our stack already has four (Prometheus/Grafana/Axiom/Better Stack per current setup) and external users will have their own. The contract is emitted once; sink adapters translate. Ship Prometheus/Grafana first (matches the existing dashboards), keep the sink interface small so a stranger can wire their own in an afternoon.

## Proving our own overhead (non-negotiable)

The self-metrics from component 1 feed a standing gate on the harness itself: steady-state capture cost must sit under ~1% of the workload, matching the netstacklat envelope. Any probe that pushes past it is downgraded (sample instead of trace) or dropped, and any result gathered while over budget is marked contaminated. We publish these numbers. A benchmarking tool that will not report its own observer effect has no business claiming a low one.

## Density specifics (~10k mVMs/host)

- In-kernel aggregation is mandatory here, no exceptions: 10k guests streaming per-event is a non-starter.
- Guest key space is fixed and bounded (vcpu-pid or cgroup-id mapping), histograms keyed on it.
- AF_XDP on the tap/virtio-net path for the packet side.
- Fairness is a first-class output: per-guest tail percentiles and a spread metric, so noisy-neighbour shows up as a gated number rather than a hunch.

## Long-lived specifics (up to 30-day)

- Longitudinal drift gate (above).
- The interesting failure is restore-time drift: a guest that restores in 40 ms fresh but 400 ms after three weeks is a product problem, so the scheduled probe includes a synthetic snapshot/restore measurement (or a cheap proxy for it) at intervals.
- Snapshot size growth tracked against the baseline trajectory.

## Open-source shape

What is generic (the public cut) and what stays ours:

- **Public**: the metric contract, the capture plane (KVM-side gadget, control-plane gadget, XDP/AF_XDP capture), the decision gate (permutation + drift + triad), the orchestration/reproducibility layer, the Prometheus/Grafana sink, and a couple of reference adapters (`firecracker`, `cloud-hypervisor`, `fio`/`wrk` workloads). This is a clean, generally useful thing: nobody currently ships a standardised low-observer-effect cross-target eBPF benchmark harness, so it fills a real gap.
- **Ours (private overlay)**: the `run-lifecycle` adapter that encodes Trigger.dev's actual run stages, the production task-trace replay workloads, our internal sink configs (Axiom/Better Stack creds), and any scheduler-plugin-specific gadget that reveals our internal design. These live in a private repo that depends on the public core via the adapter SPI, so the split is a dependency boundary, not a fork.

Repo layout sketch (public):

```
spine/
  contract/        # schema, run identity, versioning
  capture/         # libbpf+CO-RE gadgets: kvm, control-plane, xdp
  gate/            # permutation, drift, triad
  orchestrate/     # benchmark defs, host prep, fingerprinting
  sinks/           # prometheus first, interface for the rest
  adapters/
    targets/       # firecracker, cloud-hypervisor (reference)
    workloads/     # fio, wrk (reference)
  examples/        # runnable benchmark defs
```

Adapter SPI is the whole external-contributor story: a target adapter implements provision / start / reach-steady / mark-lifecycle / teardown, a workload driver implements start / stop / report. Keep those interfaces tiny and stable. The capture plane and gate never need to know what the target is, which is exactly why one system spans all the spaces.

Licence: Apache-2.0 is the safe default for something with eBPF gadgets people will embed, but that is a call for whoever owns the OSS decision (worth checking against our other released bits for consistency).

## What this will not catch (be honest)

- In-guest userspace detail on unikernels and agentless microVMs. Host-side eBPF sees exits, I/O, vCPU scheduling and the packet path, not what the guest's own code is doing internally. For full-VM targets where an agent fits, layer Parca/DeepFlow (<1% overhead) on top, but do not pretend the agentless path gives you stack-level attribution inside the guest, it does not.
- Anything the KVM tracepoints do not expose. Some vhost/virtio internals need kprobe/fentry on specific kernel functions and those are kernel-version-sensitive even with CO-RE, so the gadget set carries a compatibility matrix and we test it per kernel we run.
- Absolute cross-hardware numbers. The gate is A/B and drift, both same-host. Comparing raw latencies across different host fingerprints is out of scope by design (the fingerprint exists partly to stop people doing it by accident).

## Build order

1. Metric contract + run identity + host fingerprint. Nothing works without the shared vocabulary, and it is the expensive-to-change piece, so it goes first.
2. KVM-side capture gadget (CO-RE, in-kernel histograms, ring buffer, self-metrics). This is the universal vantage and the headline open-source nugget.
3. Gate: permutation A/B first, then drift, then the subsystem triad.
4. `firecracker` target adapter + `fio`/`wrk` workloads + Prometheus sink. First real end-to-end benchmark: microVM boot/snapshot/restore A/B, gated.
5. `run-lifecycle` composite adapter (private overlay) once the reference path is proven.
6. Density (AF_XDP, keyed histograms, fairness percentiles) and the control-plane capture surface, in either order depending on which space bites first.

## Decisions needed from us

- Working name (I used `spine`, no attachment to it).
- Schema backbone: OTel profiling signal vs a lean home-grown envelope. OTel buys interop and a standard external users know, at the cost of some weight. I lean OTel for the continuous side plus EMF for the microVM adapters, but it is a real trade and worth ten minutes.
- Public/private split boundary: is the scheduler-plugin gadget releasable or does it reveal too much of the design.
- Licence (see above).
