# Assayist docs

Start at the [root README](../README.md) for what Assayist is and a quickstart.
This directory is the reference and the guides.

## Reference

- [`contract-v0.md`](contract-v0.md): the metric contract spec (normative). The
  load-bearing agreement every gadget, the orchestrator, and the gate share.
- [`config-reference.md`](config-reference.md): every def key, CLI flag, and
  gadget flag, in one place.
- [`compatibility-matrix.md`](compatibility-matrix.md): per-kernel field and
  tracepoint dependencies for the eBPF gadgets, with kernel floors and failure
  modes.

## Guides

Worked walkthroughs of the feature surface, one topic each. Index in
[`guides/`](guides/README.md):

- [`guides/comparing-configs.md`](guides/comparing-configs.md): the `compare` A/B
  axis (config vs config, not build vs build).
- [`guides/snapshot-restore.md`](guides/snapshot-restore.md): the firecracker
  restore feature set (vsock, host memory, residency, concurrency, memory
  backends, streaming).
- [`guides/other-vmms.md`](guides/other-vmms.md): the qemu, cloud-hypervisor, and
  unikernel adapters.

## Design and background

- [`architecture.md`](architecture.md): how the shipped system fits together
  (spine plus adapters).
- [`design-brief.md`](design-brief.md): the original pre-implementation design
  brief, kept for the rationale. Historical: read `architecture.md` for what
  exists now.
- [`research-survey.md`](research-survey.md): the evidence behind the
  low-overhead design choices.
- [`bpfolio-integration.md`](bpfolio-integration.md): how bpfolio's restore
  milestones map to Assayist features.

## Crate and gadget docs

- Crates: [`../crates/contract`](../crates/contract/README.md),
  [`../crates/orchestrate`](../crates/orchestrate/README.md),
  [`../crates/gate`](../crates/gate/README.md),
  [`../crates/otlp`](../crates/otlp/README.md).
- Gadgets: [`../capture/kvm`](../capture/kvm/README.md),
  [`../capture/block`](../capture/block/README.md),
  [`../capture/net`](../capture/net/README.md),
  [`../capture/ctrlplane`](../capture/ctrlplane/README.md),
  [`../capture/resident`](../capture/resident/README.md).

Machine-checkable schema lives at
[`../contract/assay-run.schema.json`](../contract/assay-run.schema.json).
