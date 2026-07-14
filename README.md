# Assayist

One benchmarking system for VMs, microVMs, unikernels, hypervisors, and eBPF-as-subsystem experiments. Low observer effect, high information, standardised, and honest about what it cannot see.

Assayist does not try to standardise the thing under test. It standardises three things around it: a metric contract, a host/KVM-side eBPF capture plane, and a decision gate. Targets and workloads are pluggable adapters. A fixed spine, two pluggable edges.

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

The capture plane is universal because it sits host-side on KVM tracepoints and the virtio/tap path, so it observes a full VM, a Firecracker microVM, or a unikernel guest the same way, with no in-guest agent. That is what lets one system span every problem space.

Why "assay": a benchmark run is an assay, a controlled measurement of one preparation against another under stated conditions. The record it produces is an `AssayRun`.

## Status

| Component | State |
|---|---|
| Metric contract (`docs/contract-v0.md`, `contract/assay-run.schema.json`) | drafted, v0 |
| `crates/contract` (typed producer-side model, grading) | built, tested |
| `crates/gate` (permutation A/B, drift, subsystem triad) | built, tested, verified against synthetic data |
| `capture/kvm` (exit-handling latency) | written, needs a BTF+KVM host to build/run |
| `capture/block` (block-IO latency per device) | written, needs a BTF host |
| `capture/net` (tap/virtio-net counters + size histograms) | written, needs a BTF host |
| `capture/ctrlplane` (scheduler-treatment: run-queue latency, on-CPU) | written, needs a BTF host |
| OTLP import/export plugin | designed (see `docs/contract-v0.md`), not yet built |
| `crates/orchestrate` (run defs -> capture -> assemble -> gate) | stub, next up |
| reference target/workload adapters | not yet started |

The gate is the only piece verified by execution here; the gadgets are written to be correct but need a BTF-enabled Linux host with clang and bpftool to build and run.

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
    orchestrate/           the orchestrator (stub)
  capture/                 eBPF gadgets (standalone, build per BTF host)
    kvm/  block/  net/  ctrlplane/
  adapters/
    targets/               reference target adapters (future)
    workloads/             reference workload drivers (future)
  examples/
    firecracker-boot-snapshot.assay.yaml
```

## Data flow

A run is assembled, then judged:

1. The orchestrator reads a benchmark def (`examples/*.assay.yaml`), applies host prep, and reads the applied state back into a host fingerprint.
2. It starts the target adapter and workload driver, and fires the relevant capture gadgets.
3. Each gadget aggregates in-kernel and emits a JSON **fragment** (`series` + `self_metrics` + `capture_meta`).
4. The orchestrator merges the fragments with identity, fingerprint, gate context, and lifecycle spans into one **AssayRun**, and computes its **grade**.
5. Repeated runs form A and B groups (or a baseline trajectory). The **gate** reduces each run to scalars, runs the permutation test (or drift, or triad), and returns a verdict.

```
gadget --> fragment --\
gadget --> fragment ----> orchestrator --> AssayRun (graded) --\
gadget --> fragment --/                                         > gate --> verdict
                                          AssayRun (graded) --/
```

Producer strict, consumer liberal: the orchestrator builds runs with the typed `contract` crate, so a missing core fingerprint field is a construct error. The gate reads runs liberally (tolerant JSON) so it can grade a slightly-off record rather than refuse it. That split is deliberate.

## Build

The core is a normal Rust workspace:

```
cargo build --release      # contract, gate, orchestrate
cargo test                 # unit tests across the core
```

The gadgets are excluded from the workspace and built per host, because they need BTF, clang, and bpftool:

```
cd capture/kvm
bpftool btf dump file /sys/kernel/btf/vmlinux format c > src/bpf/vmlinux.h
cargo build --release
```

**Licence split**: userspace is Apache-2.0; the eBPF objects (`capture/*/src/bpf/*.bpf.c`) are GPL-2.0 because kernel tracing helpers require it. Per-file SPDX headers are authoritative. See `LICENSE-APACHE` and `LICENSE-GPL`.

## Quickstart: the gate

The gate works today. Judge a candidate group B against a baseline group A:

```
cargo build --release -p assayist-gate
./target/release/assayist-gate --mode ab_permutation \
  --a runs/a0.json runs/a1.json ... \
  --b runs/b0.json runs/b1.json ...
```

Exit codes for CI: `0` pass, `1` gate error, `2` fail, `3` contaminated. Modes: `ab_permutation`, `longitudinal_drift`, `subsystem_triad`. See `crates/gate/README.md` for the decision rules and the findings that shaped them.

## The contract is the load-bearing piece

Everything agrees on one record shape, so it is the thing designed most carefully and the most expensive to change once published. It is drawn OTLP-shaped where concepts overlap (a 128-bit `run_id` becomes an OTLP `trace_id`; log2 histograms map to OTel exponential histograms at scale 0), so an OTLP import/export plugin is a rote transform rather than a rewrite. Three concepts have no OTLP equivalent and stay native because they enforce the guarantees: the host fingerprint (reproducibility), the cardinality budget (density-safety), and the observer-effect self-metrics (the low-overhead claim, measured not asserted). Read `docs/contract-v0.md` before changing the schema.

## What Assayist will not do

- See inside agentless guests (unikernels, microVMs with no agent). Host-side eBPF sees exits, I/O, vCPU scheduling, and the packet path, not the guest's own userspace. Full VMs that run an agent emit their own OTLP and get correlated by `trace_id`.
- Compare across hosts. The gate is same-host A/B or same-host drift; the fingerprint exists partly to make cross-host comparison fail loudly.
- Represent unbounded cardinality. There is no such thing in the contract, on purpose.

## Licence

Apache-2.0 (userspace) and GPL-2.0 (eBPF objects). See the two LICENSE files and per-file SPDX headers.
