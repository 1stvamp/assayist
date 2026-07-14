# Research survey: eBPF benchmarking, state of the art

This is the grounding that Assayist's design rests on. It is a synthesis; sources are named inline so they can be re-checked. Numbers are order-of-magnitude and hardware-dependent, cited to justify design choices, not as guarantees.

## The one-line finding

As of 2025-2026 there is no standardised, cross-target, low-observer-effect eBPF benchmarking harness. The building blocks all exist (mature eBPF primitives, continuous profilers at sub-1% overhead, Firecracker's statistically rigorous A/B CI), but nobody has composed them into one system that spans VM, microVM, unikernel, and bare metal. Assayist is that composition.

## Instrumentation-primitive overhead (drives the capture-plane rules)

Attach-mechanism cost, from Ivan Babrou's (Cloudflare) ebpf_exporter microbenchmarks (empty probe on getpid, single core):

- tp_btf (BTF raw tracepoint): ~15 ns
- fentry/fexit (BPF trampoline): ~24 ns
- kprobe (breakpoint): ~137 ns
- uprobe: far worse (two context switches); up to ~200% overhead under I/O-heavy load. Unsafe on Go (stack moves break uretprobe).

So the capture plane's attach preference is tp_btf > tracepoint > fentry/fexit > kprobe, uprobes banned on hot paths.

## In-kernel aggregation is the biggest lever

From "Waiting at the front door" (netstacklat, arXiv:2606.02057, 2026): computing latency and bucketing into histograms entirely in eBPF runs programs in ~220-230 ns and stabilises at ~0.75% CPU, versus pushing a timestamp per event to userspace (~1 us each), versus probe-everything (pwru at ~25% CPU). Across 144 HTTP workload variations, tail latency inflated by no more than 6%.

Lesson, baked into every gadget: aggregate in-kernel into histograms, ship only summaries, never stream per-event. BPF ring buffer over perf buffer for anything that must stream (Nakryiko benchmarks: ~21.4 M/s vs ~1.6 M/s).

## Firecracker's A/B harness is the statistical model

Firecracker's tools/ab_test.py: non-parametric permutation test (SciPy permutation_test, difference of means, 10k resamples at p=0.01), three gates (significance, absolute-strength, ~5% noise), cross-parameterisation averaging (a real regression shows across cells), an IGNORE list for high-variance metrics (tolerates up to ~60% on some), single-tenant pinned execution, minimum two data points per metric per series. Firecracker uses seccomp-BPF for syscall filtering only, not eBPF for telemetry. This is the template the gate implements.

Firecracker's own targets (SPECIFICATION.md): boot <= 125 ms, memory overhead <= 5 MiB, VMM start within 8 CPU ms are CI-enforced; the network/storage numbers (14.5-25 Gbps, ~0.06 ms added latency, ~1 GiB/s) are marked "[integration test pending]", i.e. aspirational.

## The agentless vantage (why one system works)

Host-side eBPF on KVM tracepoints (kvm_exit with exit_reason, kvm_entry, kvm_hypercall, kvm_mmio, kvm_pio), plus vhost/virtio functions and the tap/virtio-net path via XDP/AF_XDP, is the only instrumentation that works uniformly across guests with no in-guest agent. This is the property that makes Assayist a single system rather than a family of bespoke rigs. BCC's kvmexit and the KVM-hypercall bpftrace examples are the starting points; Assayist rewrites them as CO-RE gadgets.

Unikernels have no in-guest agent and often no shell, so in-guest eBPF is impossible; host/KVM-side is the only route. No published standardised eBPF harness targets unikernel guests: an explicit gap Assayist fills.

## Continuous profilers (the overlay, not the core)

Parca, Grafana Pyroscope, Pixie, DeepFlow all sample whole-system stacks at typically <1% overhead (DeepFlow, SIGCOMM 2023, claims <1% zero-code). Microsoft Retina and Inspektor Gadget show the image-distributable host-eBPF gadget model. These are container/K8s-oriented and assume an agent or app-level protocols, so they are an overlay for full-VM targets, correlated by trace_id, not the agentless core.

## eBPF-as-subsystem projects (the triad's subjects)

BMC (NSDI'21, memcached at XDP, up to 18x), XRP (OSDI'22 best paper, storage functions in the NVMe driver), Electrode (NSDI'23, Multi-Paxos, +128% throughput / -42% latency), lambda-IO (FAST'23, computational storage, up to 5.12x), sched_ext/scx (BPF schedulers, mainline in Linux 6.12), eBPF-mm and FetchBPF (memory management / prefetching), and SOSP'25 BPF page-cache policy work. Every one builds a bespoke harness; none share a standardised one. The gate's subsystem_triad mode (A/B vs vanilla + the eBPF program's own cost + end-to-end KPIs) is the missing reusable harness for this class.

Note: the "bpfolio" project named in the original brief does not appear under that spelling; the active eBPF paging/memory work is eBPF-mm (arXiv:2409.11220), FetchBPF (ATC'24), a CMU learned-virtual-memory effort, and the SOSP'25 page-cache work.

## How this maps to Assayist

- overhead hierarchy -> capture-plane attach rules and the uprobe ban
- in-kernel aggregation -> every gadget uses log2/explicit histograms in maps
- netstacklat envelope (~1% CPU) -> the observer-effect budget the self-metrics gate against
- Firecracker ab_test -> the gate's ab_permutation mode
- agentless KVM vantage -> the kvm gadget, the universal surface
- subsystem harnesses' absence -> the triad mode
- profilers as overlay -> OTLP import for full-VM app-level detail
