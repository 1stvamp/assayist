# HANDOFF

For a Claude Code session picking up Assayist. Read this, then `CLAUDE.md`, then `docs/architecture.md` and `docs/contract-v0.md`. This file is point-in-time; the docs are durable.

## What Assayist is (30 seconds)

A standardised, low-observer-effect eBPF benchmarking system for VMs, microVMs, unikernels, hypervisors, and eBPF-as-subsystem experiments. It standardises three things around the thing under test: a metric contract, a host/KVM-side eBPF capture plane, and a decision gate. Targets and workloads are pluggable adapters. Grounding for every design choice is in `docs/research-survey.md`.

## Current state

Verified by execution here: the `contract` crate and the `gate` (permutation A/B, longitudinal drift, subsystem triad). Written but not built (need a BTF+KVM Linux host with clang and bpftool): the four capture gadgets. Stub: the orchestrator. Designed only: the OTLP plugin and reference adapters.

| Component | Path | State |
|---|---|---|
| Contract spec + JSON Schema | `docs/contract-v0.md`, `contract/assay-run.schema.json` | drafted v0 |
| Typed producer model + grading | `crates/contract` | built, 4 tests pass |
| Gate | `crates/gate` | built, 5 tests pass, 6 scenarios verified |
| KVM gadget (exit-handling latency) | `capture/kvm` | built + run: captured 100k+ real exits from a Firecracker microVM in a nested-KVM Incus VM |
| Block gadget (per-device IO latency) | `capture/block` | written |
| Net gadget (tap counters + size hist) | `capture/net` | written |
| Ctrlplane gadget (runqueue latency, on-CPU) | `capture/ctrlplane` | written |
| Orchestrator | `crates/orchestrate` | v0 complete: `run` (A/B pipeline, `--apply-prep` writes host tuning), `capture`, `inspect`, `export`/`import`. `pinning_layout` + native adapters pending |
| OTLP export + import | `crates/otlp` | built, tested (round-trip); wired as `assayist export` / `assayist import` |
| Native firecracker target + fio workload | `crates/orchestrate/src/native.rs` | built + run end-to-end in a nested-KVM Incus VM: booted real microVMs, real fio reports, assembled+gated |

## Build and verify

```
cargo build --release            # core: contract, gate, orchestrate
cargo test                       # 9 tests, must stay green
bash scripts/verify-gate.sh      # rebuilds gate, checks all 6 gate scenarios
```

Gadgets, per BTF host:
```
cd capture/kvm
bpftool btf dump file /sys/kernel/btf/vmlinux format c > src/bpf/vmlinux.h
cargo build --release
```

Toolchain: builds on stable Rust (verified on 1.75). The gate depends only on `serde_json`; the contract crate adds `serde`.

## The orchestrator (v0): done

`assayist run bench.yaml` works. Built in `crates/orchestrate` on the `assayist-contract` crate (`AssayRun::assemble`, `Fragment`, grading). Three subcommands:

- `assayist run <def.yaml> [--repeat N] [--a-sut SHA] [--b-sut SHA] [--out DIR] [--duration N] [--allow-ungraded]` runs the full A/B pipeline: for each parameterisation cell, N repeats per group, capture, assemble a graded `AssayRun`, then shell out to `assayist-gate` and propagate its exit code (0 pass, 1 error, 2 fail, 3 contaminated).
- `assayist capture <def.yaml> [...]` fires the gadgets once and assembles one run.
- `assayist inspect <def.yaml>` is the read-only parse/validate/expand + host observation.

Module map:
- `def.rs` parse/validate/expand, `benchmark_def_sha`, per-cell `params_hash`. Load-rejects missing cardinality, unbounded, bounded-without-key, unknown gate mode/tenancy, uprobe-on-hot-path.
- `hostprep.rs` `Fingerprint` behind a `Host` trait (`LinuxHost` reads `/proc`+`/sys`, fake for tests); requested-vs-readback tuning rule. `apply_tuning` writes governor/SMT/THP to sysfs; `assayist run --apply-prep` applies (needs root) and refuses the run if readback != requested, else observes read-only. Verified against real sysfs in an Incus VM. Runs grade at most `valid` until `pinning_layout` is recorded (see TODO.md).
- `capture.rs` `GadgetRunner` spawn/wait seam; `capture()` spawns all then waits all so gadgets share one window; `SubprocessRunner` real, fake for tests.
- `adapter.rs` the SPI: `Target` (provision/start/reach_steady/spans/teardown) and `Workload` (start/stop/report) traits, a command-adapter that runs shell templates from the def with `{param}` interpolation, and `execute_run` (spawn gadgets, run workload across the window, wait, wind down). `Shell` seam for tests.
- `native.rs` the reference adapters: `firecracker` target, `fio` workload, and `wrk` HTTP workload, all driving their tool through `Shell` (curl over the api-sock; fio/wrk CLIs). `wrk` runs to completion in the window and parses its text summary (requests/sec, transfer/sec, avg/max latency, total requests); validated end-to-end against real wrk 4.1.0 (driving a local HTTP server through `assayist run`). `main.rs` dispatches on `target.adapter`/`workload.driver`; unknown names fall back to the command adapter. With `host_prep.pin_threads` the firecracker target tasksets each `fc_vcpu <n>` thread to CPU `n` in `reach_steady` and reports the layout via `Target::pinning_layout`, which `run` folds into the per-run fingerprint. Validated on real firecracker in a nested-KVM Incus VM: a 2-vCPU run pinned both threads (affinity readback confirmed) and graded `reproducible` (see TODO.md).
- `run.rs` builds `Identity` + gate context, calls `AssayRun::assemble`, mints run ids.
- `gate.rs` resolves and invokes `assayist-gate`, parses the outcome.

Verified end-to-end by `tests/pipeline.rs` (drives the real binary with a stub gadget + no-op command adapters) and a manual multi-cell run. Load-time rejections and cross-tenancy refusal are covered. What is NOT done is in `TODO.md`: host-prep apply (so `reproducible` grade is unreachable until then), native `firecracker`/`fio` adapters, and where the workload report lands.

## After the orchestrator

1. ~~OTLP export + import~~ done (`crates/otlp`, `assayist export` / `assayist import`). Export: run_id -> trace_id, spans with deterministic ids, log2 -> exponential scale 0, explicit -> histogram, counter -> sum, gauge -> gauge, self_metrics -> `assayist.probe.*`, fingerprint/identity -> resource attrs (semconv where it exists). Import degrades gracefully: fills spans + series + fingerprint core, no self_metrics, `identity.source = imported`, `grade: valid`. Round-trip tested.
2. ~~Reference adapters: `firecracker` target (boot/snapshot/restore spans), `fio` and `wrk` workloads.~~ built in `crates/orchestrate/src/native.rs`, selected by `target.adapter: firecracker` / `workload.driver: fio*`|`wrk*`; settings in the def's `target.config` / `workload.config`. firecracker + fio validated on a real KVM host; `wrk` validated against real wrk 4.1.0 (see TODO.md).
3. Finer histograms for tail gating: log2-derived p50/p99 are too coarse to gate on (see gate README); add an explicit/high-resolution histogram option for metrics whose tail you need to gate.
4. Optional: refactor the gate to read via the `contract` crate types where it helps, but keep it liberal in what it accepts.

## Decisions log (the non-obvious calls and why)

- Host/KVM-side vantage is the whole reason one system spans everything: it observes any guest agentlessly. Do not add in-guest agents to the core.
- Aggregate in-kernel into histograms; never stream per-event. This is the observer-effect story (netstacklat ~0.75% CPU vs ~1 us/event).
- Contract is native, not OTLP, with an OTLP plugin. Three concepts (fingerprint, cardinality budget, self-metrics) have no OTLP equivalent and enforce the guarantees, so they stay native.
- Producer strict, consumer liberal: contract crate + orchestrator strict, gate liberal.
- Gadgets excluded from the workspace: they need a BTF host and are invoked as subprocesses, not linked.
- KVM gadget uses classic `tracepoint` not `tp_btf`, because reading `exit_reason` at tp_btf speed is arch/version-fragile (VMX vs SVM). Added `tracepoint` to the attach_kind enum for this.
- Block gadget keys by device, not guest: completion runs in softirq context where the current task is not the guest, so cgroup-at-completion would be a confident wrong number. Per-guest block needs syscall-level VMM tracing, a separate gadget.
- Ctrlplane gadget does not uprobe Go internals: banned on hot paths, unsafe on Go. It captures host scheduler treatment (runqueue latency, on-CPU); app-level scheduling/reconcile latency comes via OTLP import.
- Gate noise metric is within-group CoV, not pooled: pooling folds a real regression into the spread and hides it. (This was a bug found by running it.)
- Gate polarity is unit-first: a time-unit metric is lower-better by default; name tokens only carry throughput and CPU-ambiguity cases. (Also found by running it: name-token polarity missed `restore.resume_to_steady`.)

## Gotchas (things that will bite)

- Sample-count sets a p-value floor: N-vs-N runs can only reach p ~ 2/C(2N,N). At 4-vs-4 that is ~0.029, so p<0.01 is unreachable. Budget enough repeats; the gate is honest, not broken, when it will not call a small-sample regression.
- log2-derived p50/p99 are coarse (snap to bucket midpoints), so the noise gate usually excludes them. Gate on the mean (from the exact `sum` the gadgets emit); use finer histograms if you must gate a tail.
- Gadget userspace targets libbpf-rs 0.24; the prog-info call uses libbpf-sys directly. Expect minor API drift on other point releases. The tc-attach path in the net gadget is the most version-sensitive bit.
- `name_to_handle_at` cgroup-id resolution (ctrlplane) assumes cgroup v2 kernfs handles; `--cgroup-id` is the escape hatch.
- The two LICENSE files hold TODO placeholders for canonical text. Fill before publishing.
- Contract additions so far (all additive on v0): `attach_kind` gained `tracepoint` and `tc`; `key_source` gained `device` and `netdev`; `AssayRun` gained an optional `workload_report` (opaque provenance, no grading/gating effect). Keep additions additive.
- Module tracepoint BTF: on kernels where KVM is a module (the common case), `trace_event_raw_kvm_exit` is in `/sys/kernel/btf/kvm`, not core vmlinux BTF. Generate the kvm gadget's `vmlinux.h` from the module BTF or the build fails with `incomplete definition of type`. See `capture/kvm/README.md`.
- ProbeCost in nested virt: running the kvm gadget inside a nested-KVM VM cost ~1.2% steady CPU per probe (`over_budget: true`), so the gate correctly graded the run `contaminated`. That is the self-metrics guarantee working, not a bug; expect lower cost on bare metal, but always read `over_budget` before trusting a run.

## File map

- `README.md` project overview and status
- `TODO.md` running list of flagged items and deferred scope
- `CLAUDE.md` conventions for the agent (read this)
- `docs/contract-v0.md` the normative contract spec
- `docs/architecture.md` the design brief (spine plus adapters, coverage matrix)
- `docs/research-survey.md` the evidence behind the design
- `docs/compatibility-matrix.md` per-kernel gadget field/tracepoint deps
- `contract/assay-run.schema.json` machine-checkable contract
- `crates/contract` typed producer model + grading (built, tested)
- `crates/gate` the decision engine (built, tested; see its README for decision rules)
- `crates/orchestrate` the orchestrator (v0 built: def/hostprep/capture/adapter/run/gate; `run`/`capture`/`inspect` subcommands; `tests/pipeline.rs` end-to-end)
- `capture/{kvm,block,net,ctrlplane}` the eBPF gadgets (each has a README with limits)
- `scripts/verify-gate.sh` reproduces the gate scenario suite
- `examples/firecracker-boot-snapshot.assay.yaml` a benchmark def
