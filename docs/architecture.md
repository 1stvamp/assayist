# Architecture

Assayist is a fixed spine with two pluggable edges. The spine is a metric
contract, a host/KVM-side capture plane, and a decision gate; the edges are
target adapters (what runs) and workload drivers (what loads it). The spine never
learns what the target is, which is exactly why one system covers a full VM, a
Firecracker microVM, a Cloud Hypervisor guest, and a unikernel the same way, with
no in-guest agent.

For the reasoning behind this shape (the overhead evidence, why the contract is
the expensive piece, the agentless-KVM insight) see [`design-brief.md`](design-brief.md)
and [`research-survey.md`](research-survey.md).

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

## The spine (workspace crates)

- **contract** (`crates/contract`): the typed, producer-side model. An `AssayRun`
  is built strictly here, so a missing core fingerprint field is a construct
  error. Normative spec: [`contract-v0.md`](contract-v0.md).
- **capture** (`capture/*`): the eBPF gadgets. Host-side, agentless, aggregating
  in-kernel and emitting JSON fragments. Excluded from the workspace, built per
  BTF host. See [the gadgets](#capture-gadgets) below.
- **gate** (`crates/gate`): the decision engine. Consumes runs, returns a verdict
  and an exit code. Modes: `ab_permutation`, `longitudinal_drift`,
  `subsystem_triad`. See [`../crates/gate/README.md`](../crates/gate/README.md).
- **orchestrate** (`crates/orchestrate`): reads a def, prepares the host, drives
  the target and workload across the capture window, assembles a graded run per
  repeat, hands off to the gate. See
  [`../crates/orchestrate/README.md`](../crates/orchestrate/README.md).
- **otlp** (`crates/otlp`): the OTLP export/import bridge (`assayist export` /
  `import`).

## The edges (adapters)

Target adapters and workload drivers implement a tiny, stable SPI
(`crates/orchestrate/src/adapter.rs`): a target does
`provision`/`start`/`reach_steady`/`spans`/`teardown` (plus optional
`pinning_layout`/`resident_files`), a workload does `start`/`stop`/`report`. The
built-in adapters live in `native.rs`; anything else falls back to a command
adapter that runs shell templates keyed by lifecycle phase.

- Targets: `firecracker` (cold boot, snapshot restore, file/uffd backends,
  streaming, per-guest residency, vCPU pinning), `qemu`, `cloud-hypervisor`
  (alias `chv`), `unikernel`. The last three are cold-boot in v0.
- Workloads: `fio`, `wrk`, `vsock` (drives an agentless snapshot-restored
  function server).

Config keys for every adapter and workload: [`config-reference.md`](config-reference.md).
Feature walkthroughs: [`guides/`](guides/README.md).

## Capture gadgets

Five gadgets, all emitting the same fragment shape (`series` + `self_metrics` +
`capture_meta`). Four are eBPF (CO-RE, relocate against the host's BTF at load);
`resident` is pure userspace.

- `kvm`: KVM exit-handling latency per exit reason. The universal vantage.
- `block`: block-IO service latency and throughput per device.
- `net`: per-tap packet/byte counters and size histograms.
- `ctrlplane`: scheduler run-queue latency for control-plane pods.
- `resident`: snapshot residency (mmap + mincore), no eBPF, no BTF.

Kernel-field dependencies and floors: [`compatibility-matrix.md`](compatibility-matrix.md).
Each gadget has its own README under `capture/<name>/`.

## Data flow

```
gadget --> fragment --\
gadget --> fragment ----> orchestrator --> AssayRun (graded) --\
gadget --> fragment --/                                         > gate --> verdict
                                          AssayRun (graded) --/
```

1. The orchestrator reads a def, applies host prep, reads the applied state back
   into a host fingerprint.
2. It brings the target up, fires the gadgets, runs the workload across the
   capture window.
3. Each gadget aggregates in-kernel and emits a fragment.
4. The orchestrator merges fragments with identity, fingerprint, gate context,
   and lifecycle spans into one `AssayRun`, and grades it: `reproducible` (host
   fully prepped and pinned, probes within budget), `valid` (ran cleanly but not
   fully prepped), or `invalid` (recorded tuning did not match the host).
5. Repeated runs form A and B groups; the gate reduces each to scalars, runs the
   permutation test (or drift, or triad), and returns a verdict with a CI exit
   code.

Producer strict, consumer liberal: the orchestrator builds runs with the typed
`contract` crate, so a missing core fingerprint field is a construct error; the
gate reads runs liberally so it can grade a slightly-off record rather than
refuse it.
