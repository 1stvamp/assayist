# Assayist

One benchmarking system for VMs, microVMs, unikernels, hypervisors, and eBPF-as-subsystem experiments. Low observer effect, high information, standardised, and honest about what it cannot see.

Reach for it when you want CI-gradeable A/B benchmarks of a guest workload (a full VM, a Firecracker microVM, a unikernel) without putting an agent inside the guest, and a verdict you can trust because the run records how it was measured.

Assayist does not try to standardise the thing under test. It standardises three things around it: a metric contract, a host/KVM-side eBPF capture plane, and a decision gate. Targets and workloads are pluggable adapters that plug into that fixed spine.

```
      target adapter                         workload driver
      (what runs)                            (what loads it)
            \                                    /
             v                                  v
   +-------------------------------------------------------+
   |  SPINE                                                 |
   |   contract   : one AssayRun record, OTLP-shaped        |
   |   capture    : host/KVM-side eBPF, in-kernel aggreg.   |
   |   gate       : permutation A/B, drift, subsystem triad |
   |   orchestrate: run defs, host prep, assemble, decide   |
   +-------------------------------------------------------+
```

The capture plane is universal because it sits host-side on KVM tracepoints and the virtio/tap path, so it observes a full VM, a Firecracker microVM, or a unikernel guest the same way, with no in-guest agent. So one system covers all of those guest types instead of a separate tool per space. [`docs/architecture.md`](docs/architecture.md) is the fuller design brief with the coverage matrix; [`docs/research-survey.md`](docs/research-survey.md) has the evidence behind the low-overhead numbers.

Why "assay": a benchmark run is an assay, a controlled measurement of one preparation against another under stated conditions. The record it produces is an `AssayRun`.

## Status

| Component | State |
|---|---|
| Metric contract (`docs/contract-v0.md`, `contract/assay-run.schema.json`) | v0 |
| `crates/contract` (typed producer-side model, grading) | built, tested |
| `crates/gate` (permutation A/B, drift, subsystem triad) | built, tested, six scenarios verified |
| `capture/kvm` (exit-handling latency) | built and run: captured 100k+ real exits from a Firecracker microVM |
| `capture/block` (block-IO latency per device) | built and run: per-device read/write latency + byte counters over a cold snapshot restore, driven through `assayist run` alongside the kvm gadget; `--hires` emits a log-linear (`layout: explicit`) histogram with a ~4x finer p99 so the gate can grade the tail |
| `capture/resident` (snapshot residency: mincore on the mem file) | built and run: pure userspace (no BTF), reports resident/total pages + fraction, driven through `assayist run` |
| `capture/net` (tap/virtio-net counters + size histograms) | built and run: attaches XDP/TC and emits; real packet signal needs a tap/NIC (the agentless vsock guests here have none) |
| `capture/ctrlplane` (scheduler-treatment: run-queue latency, on-CPU) | built and run: captured run-queue latency from the sched tracepoints; flags `over_budget` when unscoped, scope with `--cgroup` |
| OTLP export + import (`crates/otlp`) | built, tested; wired as `assayist export` / `import` |
| `crates/orchestrate` (run defs -> host prep -> capture -> assemble -> gate) | v0 built: `run`/`capture`/`inspect`/`export`/`import` |
| native adapters: `firecracker` + `qemu` + `cloud-hypervisor` + `unikernel` targets, `fio` + `wrk` + `vsock` workloads (`crates/orchestrate/src/native.rs`) | built, tested; firecracker + fio validated on real KVM, wrk against real wrk, `vsock` drove a restored microVM's function server, `qemu` and `cloud-hypervisor` cold-booted full VMs, `unikernel` booted a Nanos guest, all with KVM exits the kvm gadget captured unchanged |

Verified by execution: the core (contract, gate, OTLP round-trip), and the whole pipeline end-to-end on a nested-KVM host. The kvm gadget captured a live Firecracker microVM's exits, the firecracker/fio/wrk adapters drove real runs, and a fully-prepped, vCPU-pinned run graded `reproducible`. The block gadget captured per-device I/O latency over a cold snapshot restore in the same run as the kvm gadget. The ctrlplane gadget captured run-queue latency from the scheduler tracepoints, and the net gadget attached XDP and emitted (real packet counts need a tap/NIC). Every capture gadget has now been built and run on a BTF host; they each need clang and bpftool to build per-host.

## Layout

```
assayist/
  Cargo.toml               workspace: core members, gadgets excluded
  rust-toolchain.toml
  contract/
    assay-run.schema.json  machine-checkable contract (JSON Schema)
  docs/
    contract-v0.md         the metric contract spec (normative)
    architecture.md        design brief: why one system spans everything
    compatibility-matrix.md per-kernel field/tracepoint deps for gadgets
  crates/                  host-agnostic core (workspace members)
    contract/              typed AssayRun, grading, fragment merge
    gate/                  the decision engine
    orchestrate/           the orchestrator; native.rs holds the firecracker/fio/wrk adapters
    otlp/                  OTLP export/import
  capture/                 eBPF gadgets (standalone, build per BTF host)
    kvm/  block/  net/  ctrlplane/
  examples/
    firecracker-boot-snapshot.assay.yaml
```

## Data flow

A run is assembled, then judged:

1. The orchestrator reads a benchmark def (`examples/*.assay.yaml`), applies host prep, and reads the applied state back into a host fingerprint.
2. It starts the target adapter and workload driver, and fires the relevant capture gadgets.
3. Each gadget aggregates in-kernel and emits a JSON **fragment** (`series` + `self_metrics` + `capture_meta`).
4. The orchestrator merges the fragments with identity, fingerprint, gate context, and lifecycle spans into one **AssayRun**, and computes its **grade**: `reproducible` (host fully prepped and vCPU-pinned, probes within budget), `valid` (ran cleanly but not fully prepped), or `invalid` (the recorded tuning did not match the host, so the run is a lie).
5. Repeated runs form A and B groups (or a baseline trajectory). The **gate** reduces each run to scalars, runs the permutation test (or drift, or triad), and returns a verdict.

```
gadget --> fragment --\
gadget --> fragment ----> orchestrator --> AssayRun (graded) --\
gadget --> fragment --/                                         > gate --> verdict
                                          AssayRun (graded) --/
```

Producer strict, consumer liberal: the orchestrator builds runs with the typed `contract` crate, so a missing core fingerprint field is a construct error. The gate reads runs liberally (tolerant JSON) so it can grade a slightly-off record rather than refuse it.

## Build

`mise install` sets up the pinned toolchain (rust + python from `mise.toml`), the same versions CI uses. Without mise, rustup reads `rust-toolchain.toml` and installs the same rust; you supply python yourself for the gate scripts.

Common tasks are defined in mise (`mise tasks` lists them):

```
mise run build       # cargo build --release
mise run test        # workspace tests
mise run test-gate   # the gate scenario suite (six verdicts)
mise run lint        # clippy, warnings denied (matches CI)
mise run demo        # generate runs and judge B vs A with the gate
```

Or drive cargo directly, it is a normal Rust workspace:

```
cargo build --release      # contract, gate, orchestrate, otlp
cargo test                 # tests across the core
```

The gadgets are excluded from the workspace and built per host, because they need BTF, clang, and bpftool. Which kernel fields and tracepoints each gadget depends on is in [`docs/compatibility-matrix.md`](docs/compatibility-matrix.md).

```
cd capture/kvm
bpftool btf dump file /sys/kernel/btf/vmlinux format c > src/bpf/vmlinux.h
cargo build --release
```

**Licence split**: userspace is Apache-2.0; the eBPF objects (`capture/*/src/bpf/*.bpf.c`) are GPL-2.0 because kernel tracing helpers require it. Per-file SPDX headers are authoritative. See `LICENSE-APACHE` and `LICENSE-GPL`.

## Quickstart: the gate

The gate works today, on any machine (no eBPF host needed). One command builds it, generates synthetic runs, and checks all six verdicts against their expected exit codes:

```
./scripts/verify-gate.sh
```

To drive it directly, generate a set of runs and judge a candidate group B against a baseline group A:

```
cargo build --release -p assayist-gate
python3 scripts/gen_testdata.py /tmp/runs
./target/release/assayist-gate --mode ab_permutation \
  --a /tmp/runs/a{0..9}.json \
  --b /tmp/runs/bsame{0..9}.json     # bsame -> pass, breg -> fail, bcont -> contaminated
```

The permutation test needs at least two runs per group (a 1-vs-1 comparison has nothing to permute, and grades a hollow `pass`). Exit codes for CI: `0` pass, `1` gate error, `2` fail, `3` contaminated. Modes: `ab_permutation`, `longitudinal_drift`, `subsystem_triad`. See [`crates/gate/README.md`](crates/gate/README.md) for the decision rules and the findings that shaped them.

## The full pipeline

On a BTF+KVM host with the gadgets built, `assayist run` drives everything from a def:

```
./target/release/assayist run examples/firecracker-boot-snapshot.assay.yaml \
  --repeat 4 --a-sut <shaA> --b-sut <shaB> --apply-prep
```

For each parameterisation cell it applies host prep (governor/SMT/THP, verified by read-back), pins vCPU threads if the def asks, boots the target and runs the workload across the capture window, assembles a graded `AssayRun` per repeat, then shells out to the gate and propagates its exit code.

**Note**: `--apply-prep` writes sysfs and needs root. Without it the host is observed read-only, and a run whose tuning the host does not already match grades `invalid`.

`assayist capture` fires the gadgets once; `assayist inspect` is the read-only parse/validate/observe.

### Comparing two configs

By default A and B are two builds of the same config (`--a-sut`/`--b-sut`). To compare two *configurations* of one build instead (a stock restore vs a prefetched one, two snapshot-prep modes, a flag on vs off), name a `parameterise` dimension as the A/B axis with `compare`. Its two values become groups A and B, so a single `assayist run` gates one against the other:

```yaml
compare: variant
parameterise:
  variant: [eph-default, eph-init-on-free]
target:
  adapter: firecracker
  config:
    from_snapshot: "{def_dir}/../run/syn-alloc-heavy/{variant}/snapshot"
    mem_file: "{def_dir}/../run/syn-alloc-heavy/{variant}/mem"
```

The variant is substituted into config templates as `{variant}` and recorded in each run's `params`. Any other `parameterise` dimensions form cells within each group. Config templates also expand `{def_dir}` (the directory of the def file), so a committed def references its assets by repo-relative path rather than a machine-specific absolute one. The `pre_restore` config key runs a shell command before the timed `snapshot/load` (outside the span), which is how a def sets the page-cache state a restore starts from: drop caches for a cold baseline, or warm a working set so resume faults hit cache.

### Driving an agentless guest

An idle guest only shows host background traffic in the capture window. The `vsock` workload driver exercises it: for each invocation it opens Firecracker's host vsock socket, issues the `CONNECT <port>` handshake, optionally sends a payload, and drains the response, which is how a snapshot-restored function server is triggered. It reports the invocation count, errors, and a latency summary. Because the firecracker adapter runs each restore in a `{api_sock}.d` scratch cwd and the guest's uds is relative (`fn.vsock`), set a fixed `api_sock` and point the workload's `uds` at `{that}.d/fn.vsock`:

```yaml
target:
  adapter: firecracker
  config:
    api_sock: /tmp/assayist-fc.sock
    from_snapshot: "{def_dir}/../run/fn/snapshot"
    mem_file: "{def_dir}/../run/fn/mem"
workload:
  driver: vsock
  config: { uds: /tmp/assayist-fc.sock.d/fn.vsock, port: 5000, invocations: 50 }
```

Numbers a workload reports (the `vsock` latency summary, fio's iops, or an external tool's numbers surfaced through the report) are reduced to gradeable `workload:<field>` metrics, so they are compared by the gate rather than left as inert provenance. Polarity follows the field name and unit: a `*_ns` latency reads lower-better, an `iops`/`bytes` field higher-better.

### Host memory

`assayist run` samples `/proc/meminfo` before the target is provisioned and again after it reaches steady, and records the deltas as `hostmem.mem_consumed_kib` (how far `MemAvailable` dropped, lower better) and `hostmem.cached_delta_kib` (page-cache change, left without a graded direction). The window is the target lifecycle, not the gadget window, so it captures the memory cost of preparing and restoring the guest. This is a host, system-level measurement: it sees the machine's memory move, not per-guest attribution, so for a single file-backed restore the signal is small and noisy (pages are shared through the page cache, which is the point). It earns its keep across many concurrent sandboxes, where the aggregate is what separates a deduped restore from a per-sandbox copy.

### Snapshot residency

The `assayist-capture-resident` gadget mincores the snapshot's mem file at the end of the window and reports `resident.snapshot_resident_pages`, `resident.snapshot_total_pages`, and `resident.snapshot_fraction`, the ground-truth working set: how much of the snapshot actually faulted into the page cache. Where `hostmem` is the machine-level cost, this is what the snapshot itself has resident (bpfolio's `resident_fraction`). It is pure userspace (mmap + mincore, no eBPF or BTF), so it builds and runs anywhere; point it at the mem file with a `{def_dir}`-relative path (capture-entry `args` are rendered with the same vars as the target config):

```yaml
capture:
  - probe: snapshot_resident
    gadget: assayist-capture-resident
    cardinality: { class: singleton }
    args: ["--mem", "{def_dir}/../run/fn/mem"]
```

On a cold restore of a 256 MiB snapshot, this read ~5% resident, the working set the guest touched to reach steady. For a file-backed restore it is the set shared through the page cache (so concurrent instances of one snapshot count it once); a userfaultfd restore copies pages into each guest's own anonymous memory, off the file, so this measures the shared/file residency, not per-guest private memory.

The firecracker adapter also reports residency **per guest**, measured orchestrator-side (like the host-memory delta, not an eBPF gadget): after the guests reach steady, `assayist run` mincores each restore's mem file and emits `resident.snapshot_*` keyed per instance. This is the attribution the system-level `hostmem` delta cannot give: the delta is the machine cost, the per-guest resident is what each sandbox faulted in. Under `instances: N` each instance is keyed `instance0..N-1` (bounded cardinality); a lone restore keys as a singleton. No def wiring needed, it rides the restore. Validated: 6 file-backed sandboxes of one snapshot each reported the same ~5% file residency (they share the page cache), the expected file-backed signature seen per instance rather than only in aggregate.

### Concurrent sandboxes

`instances: N` brings up N sandboxes from the same snapshot and holds them all resident through the capture window, so the host-memory delta is the aggregate. A file-backed restore stays roughly flat as N grows (the shared working set counts once); a per-sandbox copy grows with N. Make it the A/B axis to measure the scaling directly:

```yaml
compare: instances
parameterise:
  instances: [1, 8]
target:
  adapter: firecracker
  config:
    from_snapshot: "{def_dir}/../run/fn/snapshot"
    mem_file: "{def_dir}/../run/fn/mem"
```

Concurrency is an orchestration concern, not a firecracker one: N > 1 wraps N single-instance targets in a fanout that drives them all through the lifecycle and records one aggregate `restore.resume_to_steady` span (so a 1-vs-N comparison lines up on the same metric). Each instance is built with a distinct `{instance}` var, so any adapter gets non-colliding sockets and scratch dirs from it: the firecracker adapter folds `{instance}` into its default API socket, and a command-adapter def references `{instance}` in its own templates. So the same knob works for a future QEMU or Cloud Hypervisor adapter with no extra code. With `pin_threads` on, each instance gets a distinct `cpu_base` (instance `i` starts at `i * vcpu`), so concurrent sandboxes pin to disjoint CPUs rather than all landing on CPU 0; `taskset` fails the run if that would need more CPUs than the host has. A pinned, fully-prepped concurrent run grades `reproducible` (validated: two instances pinned to CPUs 0 and 1, layout `{"instance0": {"vcpu0": 0}, "instance1": {"vcpu0": 1}}`).

### Memory backend: file-backed vs userfaultfd

`mem_backend: uffd` restores guest memory from an external userfaultfd handler instead of mmapping the mem file (`mem_backend: file`, the default). File-backed sandboxes share resident pages through the host page cache, so their aggregate memory stays roughly flat as instances grow; a userfaultfd handler that copies pages into each sandbox's own anonymous memory (the REAP baseline) has no such sharing, so it grows with the count. The adapter is generic: it launches whatever `uffd_handler` command the def gives, rendering `{uffd_uds}` (the socket Firecracker connects to) and `{mem_file}`, waits for the socket, then loads with the `Uffd` backend.

```yaml
compare: backend
parameterise:
  backend: [file, uffd]
target:
  adapter: firecracker
  config:
    instances: "4"
    from_snapshot: "{def_dir}/../run/fn/snapshot"
    mem_file: "{def_dir}/../run/fn/mem"
    mem_backend: "{backend}"
    uffd_handler: "/path/to/handler --uds {uffd_uds} --mem {mem_file} ondemand"
```

Combined with `instances`, this measures dedup directly: on one host, four file-backed sandboxes consumed ~1 MB of `hostmem.mem_consumed_kib` while four userfaultfd sandboxes of the same snapshot consumed ~21 MB. The handler is torn down with the run.

### Full VMs (QEMU)

`target.adapter: qemu` cold-boots a QEMU/KVM full VM (`-kernel`/`-drive`, a QMP control socket), timing the VM up to that socket appearing as `boot.vmm_ready`, the same span name the firecracker adapter records for InstanceStart. That is a host-observable marker, not guest userspace init, which the agentless vantage cannot see; an optional `readiness` command bridges to a guest-ready signal. It is v0: cold boot only (QEMU savevm/migration restore and vCPU pinning are not wired yet).

```yaml
target:
  adapter: qemu
  config:
    kernel: "{def_dir}/../vmlinux"
    rootfs: "{def_dir}/../rootfs.ext4"
    boot_args: "console=ttyS0 root=/dev/vda ro"
```

The host-side capture plane is VMM-agnostic: the same kvm gadget captured a QEMU guest's exits (HLT, MSR_WRITE, CR_ACCESS, ...) unchanged. A full VM is chattier than a microVM, so on this host the kvm probe ran just over its default 0.01-core budget and the run graded `contaminated`, the observer-effect check doing its job; raise the gadget's `--budget` for a full VM. Concurrency (`instances`), the host-memory delta, and residency all work through the generic paths, so N-sandbox QEMU runs come for free.

### Full VMs (Cloud Hypervisor)

`target.adapter: cloud-hypervisor` (alias `chv`) cold-boots a Cloud Hypervisor VM, timing it up to its `--api-socket` appearing as `boot.vmm_ready`, the same host-observable marker the qemu adapter uses. It direct-boots an uncompressed `vmlinux`, the same kernel image the firecracker adapter takes, so a firecracker-vs-CH or qemu-vs-CH compare shares kernel and rootfs. It is v0: cold boot only (CH snapshot/restore and vCPU pinning are not wired yet).

```yaml
target:
  adapter: cloud-hypervisor
  config:
    bin: "{def_dir}/../cloud-hypervisor"
    kernel: "{def_dir}/../vmlinux-guest"
    rootfs: "{def_dir}/../rootfs.ext4"
    cmdline: "console=ttyS0 root=/dev/vda ro"
```

Unlike firecracker and qemu, CH does not exit when the guest resets: it keeps rebooting the guest and holds a flock on `<api-socket>.lock`, so teardown waits for the process to die before the next run reuses the socket (else a repeat run fails with `ApiSocketInUse`). Validated: CH v53.0 booted the firecracker `vmlinux` + `.ext4` rootfs, `boot.vmm_ready` ~47ms, and the kvm gadget captured its exits (IO_INSTRUCTION, EPT_VIOLATION, HLT, MSR_WRITE, ...) unchanged, a third VMM through the same capture plane.

### Unikernels

`target.adapter: unikernel` boots a single self-contained unikernel image under QEMU/KVM, timing it up to a QMP socket appearing as `boot.vmm_ready`. A unikernel is the archetypal agentless guest, one address space with no userspace to log into, which is exactly the vantage assayist is built for: the kvm/net gadgets see it host-side without an in-guest agent. Two boot styles: `disk` (a raw disk image, e.g. Nanos/`ops` output; the default) and `kernel` (a multiboot/PVH image via `-kernel`, e.g. Unikraft). An optional `hostfwd` maps a host port to a guest port so a `readiness` probe can reach the guest, the only agentless way to confirm it is actually serving.

```yaml
target:
  adapter: unikernel
  config:
    image: /path/to/unikernel-image      # raw disk (Nanos) by default
    hostfwd: "tcp::18080-:8080"           # optional host->guest port forward
    readiness: "curl -sf --max-time 1 http://127.0.0.1:18080/ >/dev/null"
```

Validated: a Nanos unikernel (a static Go HTTP server, built with `ops`) booted under qemu-kvm, `boot.vmm_ready` ~52ms, the readiness probe reached its forwarded port, and the kvm gadget captured its exits (MSR_WRITE, HLT, IO_INSTRUCTION, ...). It is far quieter than a full-VM or microVM boot (~1.5k exits vs tens of thousands), the small single-purpose guest showing through the capture. v0 is cold boot only (no snapshot/restore, no vCPU pinning).

## The contract is the load-bearing piece

Everything agrees on one record shape, so it is the thing designed most carefully and the most expensive to change once published. It is drawn OTLP-shaped where concepts overlap (a 128-bit `run_id` becomes an OTLP `trace_id`; log2 histograms map to OTel exponential histograms at scale 0), so an OTLP import/export plugin is a rote transform rather than a rewrite. Three concepts have no OTLP equivalent and stay native because they enforce the guarantees: the host fingerprint (reproducibility), the cardinality budget (density-safety), and the observer-effect self-metrics (the low-overhead claim, carried by the ProbeCost numbers that back it up). The self-metrics are gated: a probe that runs over its budget marks the run contaminated, so the overhead claim is checked at grade time rather than taken on faith. Read [`docs/contract-v0.md`](docs/contract-v0.md) before changing the schema.

## What Assayist will not do

- See inside agentless guests (unikernels, microVMs with no agent). Host-side eBPF sees exits, I/O, vCPU scheduling, and the packet path, not the guest's own userspace. Full VMs that run an agent emit their own OTLP and get correlated by `trace_id`.
- Compare across hosts. The gate is same-host A/B or same-host drift; the fingerprint exists partly to make cross-host comparison fail loudly.
- Represent unbounded cardinality. There is no such thing in the contract, on purpose.

## Licence

Apache-2.0 (userspace) and GPL-2.0 (eBPF objects). See the two LICENSE files and per-file SPDX headers.
