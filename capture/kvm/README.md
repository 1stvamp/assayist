# assayist-capture-kvm

Host-side, agentless capture of KVM exit-handling latency, emitted as an AssayRun fragment.

It measures the time each vCPU spends out of the guest between `kvm_exit` and the next `kvm_entry`, bucketed per exit reason into in-kernel log2 histograms. That interval is host and VMM work, so it is the thing you want when a guest stalls, and it is visible with no in-guest agent. The same gadget observes a full VM, a Firecracker microVM, or a unikernel guest, because it watches KVM on the host, not anything inside the guest.

This is the universal vantage the rest of Assayist is built around: one capture surface for every guest type.

## What it captures

- **Exit-handling latency per exit reason**, as a log2 histogram (`unit: ns`, `kind: histogram`, `layout: log2`). Bucket `i` counts values in `[2^i, 2^(i+1))`, which maps to an OTel exponential histogram at scale 0 on export.
- **Its own cost**, per program, via the kernel BPF run-time counters (`run_time_ns`, `run_cnt`), written into `self_metrics` as `ProbeCost` with `steady_cpu_fraction` and an `over_budget` flag. If the gadget costs more than the budget, the run says so.

Singleton mode (default) aggregates each reason across all guests. Per-guest mode (`--per-guest`) keys histograms by cgroup id, which is the density case (~10k microVMs). Per-guest is a bounded-cardinality series: you set the ceiling with `--max-keys`, and if distinct cgroups exceed it the fragment carries `cardinality_overflow: true` so the gate marks the affected metric contaminated rather than trusting a truncated picture.

## Requirements

- A Linux kernel with `CONFIG_DEBUG_INFO_BTF=y` (for CO-RE) and KVM in use.
- `CAP_BPF` + `CAP_PERFMON` (or `CAP_SYS_ADMIN`) to load programs and enable run-time stats. Run under sudo or with the caps granted.
- Build host needs `clang` (>= 12), `bpftool`, and libelf/zlib dev headers.

**Note**: enabling BPF run-time stats has a small, global, system-wide cost while it is on (every BPF program on the box gets timed, not just ours). The gadget only enables it for the capture window and disables it on exit by closing the stats fd. Do not leave it running.

## Build

Generate `vmlinux.h` once from the running kernel's BTF:

```
bpftool btf dump file /sys/kernel/btf/vmlinux format c > src/bpf/vmlinux.h
```

Then:

```
cargo build --release
```

## Run

```
# 30s window, aggregate across guests, JSON to stdout
sudo ./target/release/assayist-capture-kvm --duration 30

# density: key per guest by cgroup, ceiling 10k, write a fragment file
sudo ./target/release/assayist-capture-kvm --per-guest --max-keys 10000 --out kvm-fragment.json
```

The output is a fragment, not a whole AssayRun:

```json
{
  "series": [ { "name": "kvm.exit_handling_latency:EPT_VIOLATION", "unit": "ns", "kind": "histogram", "source": "kvm_exit", "cardinality": { "class": "singleton" }, "data": { "layout": "log2", "buckets": [ ... ], "count": 12873 } } ],
  "self_metrics": [ { "probe_id": "kvm_exit", "attach_kind": "tracepoint", "run_time_ns": 41200, "run_cnt": 12873, "mean_ns": 3.2, "steady_cpu_fraction": 0.0000013, "over_budget": false, "hot_path": true } ],
  "capture_meta": { "gadget": "assayist-capture-kvm", "window_ns": 30000000000, "cpu_vendor": "amd", "per_guest": false, "cardinality_overflow": false }
}
```

The orchestrator merges `series` and `self_metrics` into a full `AssayRun` and adds identity, fingerprint, and gate context.

## Why classic `tracepoint`, not `tp_btf`

`tp_btf` is the fastest attach (~15 ns), but reading `exit_reason` at `tp_btf` speed means pulling it off `struct kvm_vcpu`, which is arch-specific (VMX vs SVM) and version-fragile. The classic `tracepoint` attach reads `exit_reason` as a formatted field via CO-RE, which is portable, and still sits far below kprobe cost. Portability wins here. That is why `ProbeCost.attach_kind` is `tracepoint` (added to the contract enum for exactly this reason). `kvm_entry` reads no formatted field at all (it keys on the current tid), so it needs no compatibility handling.

## Exit-reason names

Names are a convenience; the histogram is always keyed on the numeric reason. Intel (VMX) and AMD (SVM) use different exit-code spaces, so the loader picks the table from `/proc/cpuinfo` vendor and falls back to `reason_<n>` for anything not in the table. The tables are deliberately partial (common reasons only); extend them as needed. On AMD the SVM codes apply (e.g. `NPF` for nested page faults, `VMMCALL`, `IOIO`).

## Limits (be honest)

- **One field dependency.** `kvm_exit`'s `exit_reason` is read off `trace_event_raw_kvm_exit`. That field has been stable across many kernels, but it is the one place a kernel change could break the gadget, so it carries a per-kernel entry in the compatibility matrix. If it ever moves, CO-RE fails loudly at load rather than reading garbage.
- **Latency, not causation.** A long exit-handling time tells you the vCPU was stuck in host/VMM work, not why. Pair it with the reason (which you have) and the block/net gadgets to attribute further.
- **cgroup id as the guest key** assumes one guest per cgroup (jailer / K8s pod), which holds for Firecracker-in-pod and the jailer, but a deployment that packs multiple guests into one cgroup will collapse them. Check your layout before trusting per-guest keying.
- **Not a whole run.** This emits a fragment. It does not gate, fingerprint, or decide anything; that is the orchestrator and gate's job.

## Licence

The eBPF object (`src/bpf/kvm.bpf.c`) is GPL-2.0 (tracing helpers require it). The userspace loader is Apache-2.0. This split is normal for a libbpf tool and keeps the loadable object GPL-clean while the rest of Assayist stays Apache-2.0.
