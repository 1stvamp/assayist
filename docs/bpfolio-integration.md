# bpfolio integration

bpfolio (formerly snapbpf) is Trigger.dev's Firecracker snapshot-prefetch project
and Assayist's primary consumer. It pulls Assayist as a prebuilt release
(`github:1stvamp/assayist` in its `mise.toml`) and keeps its benchmark defs in its
own repo under `bench/*.assay.yaml`, run through `assayist run`.

This page states the correspondence from Assayist's side: which Assayist feature
exercises which bpfolio restore milestone. It does not duplicate bpfolio's own
tracking.

## Milestone to feature

| bpfolio milestone | What it is | Assayist feature that drives it |
|---|---|---|
| M0 | Stock file-backed restore | firecracker `mem_backend: File` (the baseline A side). |
| M1 | REAP / userfaultfd restore | firecracker `mem_backend: uffd` + `uffd_handler`. See [guides/snapshot-restore.md](guides/snapshot-restore.md#memory-backend-file-backed-vs-userfaultfd). |
| M3 | Userspace prefetch (readahead over the working set) | `pre_restore` warms the working set before the timed load; the A/B is stock-vs-prefetch. |
| M4 | Kernel prefetch (module kfunc) | `pre_restore` runs the kernel prewarm; needs bpfolio's `snapbpf.ko` loaded, else the def skips. |
| M5 | Ephemeral filtering | two snapshot-prep variants gated with `compare` (e.g. `eph-default` vs `eph-init-on-free`). |
| M-stream | Streaming restore (memory served over a mount) | firecracker `stream_source` + `stream_prefetch` (a per-instance FUSE mount). See [guides/snapshot-restore.md](guides/snapshot-restore.md#streaming-restore). |

## What Assayist measures for these

Every milestone above is judged on the same host-side signals, no in-guest agent:

- **Restore latency**: the `restore.resume_to_steady` span plus KVM exit-handling
  latency from the kvm gadget.
- **Memory cost**: the orchestrator's `hostmem.mem_consumed_kib` delta (machine
  level) and per-guest snapshot residency (the resident gadget / orchestrator
  per-guest sampling). The dedup thesis (file-backed shares pages, userfaultfd
  copies per guest) shows up here under `instances: N`.
- **Block I/O**: the block gadget, over a cold restore, when the working set
  faults from disk.

The gate turns those into an A/B verdict per milestone comparison, so a
regression in any restore path fails against its own baseline rather than a
hand-eyeballed number.
