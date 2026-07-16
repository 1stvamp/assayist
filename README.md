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
| `capture/block` (block-IO latency per device) | built and run: per-device read/write latency + byte counters over a cold snapshot restore, driven through `assayist run` alongside the kvm gadget |
| `capture/net` (tap/virtio-net counters + size histograms) | written, needs a BTF host |
| `capture/ctrlplane` (scheduler-treatment: run-queue latency, on-CPU) | written, needs a BTF host |
| OTLP export + import (`crates/otlp`) | built, tested; wired as `assayist export` / `import` |
| `crates/orchestrate` (run defs -> host prep -> capture -> assemble -> gate) | v0 built: `run`/`capture`/`inspect`/`export`/`import` |
| native adapters: `firecracker` target, `fio` + `wrk` + `vsock` workloads (`crates/orchestrate/src/native.rs`) | built, tested; firecracker + fio validated on real KVM, wrk against real wrk, `vsock` drove a restored microVM's function server over its host vsock socket |

Verified by execution: the core (contract, gate, OTLP round-trip), and the whole pipeline end-to-end on a nested-KVM host. The kvm gadget captured a live Firecracker microVM's exits, the firecracker/fio/wrk adapters drove real runs, and a fully-prepped, vCPU-pinned run graded `reproducible`. The block gadget captured per-device I/O latency over a cold snapshot restore in the same run as the kvm gadget. The net/ctrlplane gadgets are written but not yet run: they each need a BTF-enabled Linux host with clang and bpftool.

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

Concurrency is an orchestration concern, not a firecracker one: N > 1 wraps N single-instance targets in a fanout that drives them all through the lifecycle and records one aggregate `restore.resume_to_steady` span (so a 1-vs-N comparison lines up on the same metric). Each instance is built with a distinct `{instance}` var, so any adapter gets non-colliding sockets and scratch dirs from it: the firecracker adapter folds `{instance}` into its default API socket, and a command-adapter def references `{instance}` in its own templates. So the same knob works for a future QEMU or Cloud Hypervisor adapter with no extra code. Pinning is not combined with fanout (instances run unpinned).

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

## The contract is the load-bearing piece

Everything agrees on one record shape, so it is the thing designed most carefully and the most expensive to change once published. It is drawn OTLP-shaped where concepts overlap (a 128-bit `run_id` becomes an OTLP `trace_id`; log2 histograms map to OTel exponential histograms at scale 0), so an OTLP import/export plugin is a rote transform rather than a rewrite. Three concepts have no OTLP equivalent and stay native because they enforce the guarantees: the host fingerprint (reproducibility), the cardinality budget (density-safety), and the observer-effect self-metrics (the low-overhead claim, carried by the ProbeCost numbers that back it up). The self-metrics are gated: a probe that runs over its budget marks the run contaminated, so the overhead claim is checked at grade time rather than taken on faith. Read [`docs/contract-v0.md`](docs/contract-v0.md) before changing the schema.

## What Assayist will not do

- See inside agentless guests (unikernels, microVMs with no agent). Host-side eBPF sees exits, I/O, vCPU scheduling, and the packet path, not the guest's own userspace. Full VMs that run an agent emit their own OTLP and get correlated by `trace_id`.
- Compare across hosts. The gate is same-host A/B or same-host drift; the fingerprint exists partly to make cross-host comparison fail loudly.
- Represent unbounded cardinality. There is no such thing in the contract, on purpose.

## Licence

Apache-2.0 (userspace) and GPL-2.0 (eBPF objects). See the two LICENSE files and per-file SPDX headers.
