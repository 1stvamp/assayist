# assayist-capture-ctrlplane

Host-side scheduler-treatment signal for the control-plane pods (kube-scheduler, controllers, kube-apiserver), emitted as an AssayRun fragment.

Per cgroup, it measures run-queue latency (wakeup to on-CPU) and accumulated on-CPU time, using the `sched` tracepoints at `tp_btf` speed with in-kernel histograms. It tells you whether the control plane is being scheduled promptly under load, which is the host-side story behind app-level scheduling and reconcile latency.

## The division of responsibility (read this)

This gadget does **not** measure app-level scheduling latency, reconcile-loop duration, or API-request latency. Those live inside userspace Go binaries. Reaching them with eBPF means uprobes, which the Assayist contract bans on hot paths (dual context switch) and which are unsafe on Go anyway: the runtime moves goroutine stacks, which breaks the uretprobe return trampoline. So we do not go there.

Instead:

- **App-level latency** (scheduling attempt duration, reconcile duration, apiserver request duration) enters Assayist through the **OTLP import plugin**, from the components' existing Prometheus/OTel metrics (`scheduler_scheduling_attempt_duration_seconds`, controller-runtime reconcile histograms, `apiserver_request_duration_seconds`). Those arrive as `grade: valid` imported runs.
- **This gadget** supplies the host-side "why": if reconcile latency spiked, was the controller starved of CPU? Run-queue latency answers that, and no app metric can.

Use both together. Neither replaces the other.

## What it captures

- `sched.runqueue_latency`: log2 histogram (`unit: ns`), keyed by component name.
- `sched.on_cpu_ns`: monotonic counter (`unit: ns`), keyed by component name.
- `self_metrics`: the three sched programs, `attach_kind: tp_btf`.

No contract change was needed for this gadget: `tp_btf`, `cgroup_id`, histograms and counters were all already in v0.

## Run

Point it at the control-plane pods' cgroups (v2). Names are yours; they become the series keys:

```
sudo ./target/release/assayist-capture-ctrlplane \
  --cgroup scheduler=/sys/fs/cgroup/kubepods.slice/kubepods-burstable.slice/.../kube-scheduler \
  --cgroup apiserver=/sys/fs/cgroup/kubepods.slice/.../kube-apiserver \
  --duration 30 --out ctrlplane-fragment.json
```

If cgroup-path resolution does not work on your kernel, pass ids directly (get them from `bpftool cgroup tree`):

```
sudo ./target/release/assayist-capture-ctrlplane --cgroup-id scheduler=1234 --duration 30
```

Build and kernel requirements match the other gadgets.

## Limits (be honest)

- **sched_switch is system-wide.** The program runs on every context switch on every CPU, even with the cgroup filter (the filter is a check inside the program, not a pre-filter). At high context-switch rates this is the most expensive gadget in the set, which is exactly why the self-metrics and the `--budget` gate matter here. Default budget is 2% (higher than the 1% elsewhere) because runqlat inherently costs more. Keep the allow-list narrow and the window short. If `over_budget` fires, narrow the cgroups or sample.
- **cgroup id resolution** uses `name_to_handle_at`, assuming cgroup v2 where the kernfs handle's first 8 bytes are the id. If your ids come back wrong (no data appears), verify one against `bpftool cgroup tree` and use `--cgroup-id`.
- **Run-queue latency, not app latency.** Long runqueue latency means the process waited for a CPU; it does not tell you what the process then did. Pair with the imported app metrics.
- **Capturing all cgroups** (no `--cgroup`) works but is high-cardinality and high-cost; it exists for exploration, not for gated runs.

## Licence

eBPF object GPL-2.0, userspace Apache-2.0, same split as the other gadgets.
