# TODO

Running list of flagged items and deferred scope. Point-in-time; move things
out as they land. Durable design lives in `docs/`, session pickup in `HANDOFF.md`.

## Deferred scope (orchestrator stages 4-5)

- [x] **`pinning_layout` is recorded when `pin_threads` is set (validated on real
  firecracker).** The firecracker target pins each vCPU thread to a matching
  logical CPU (`fc_vcpu <n>` -> CPU `n`, via `taskset`) in `reach_steady` and
  records the layout; `run` folds it into the per-run fingerprint. Validated in a
  nested-KVM Incus VM (firecracker v1.16.1, 6.1 guest kernel, 4 host CPUs):
  confirmed firecracker's threads are named `fc_vcpu 0`/`fc_vcpu 1`, that
  `taskset` affinity actually took (readback showed vcpu0->CPU0, vcpu1->CPU1),
  and that a 2-vCPU run graded **`reproducible`** with `pinning_layout`
  `{"vcpu0":0,"vcpu1":1}`. Still open: the `vcpu n -> cpu n` policy is naive and
  honestly fails the run when the host lacks CPU `n` (a 1-CPU host cannot pin
  vcpu1); a NUMA-aware / isolcpus-aware policy is future work.
- [x] **Fingerprint is re-read per run.** `run` applies prep once (if
  `--apply-prep`) and keeps the fail-fast consistency check up front, then
  re-observes the host (read-only) for each assembled run, so drift between the A
  and B builds surfaces in that run's own fingerprint instead of being masked by a
  single snapshot. Pinning layout is folded in on top per run.
- [x] **Native adapters validated on a real host.** `native.rs` (firecracker
  target + fio workload) ran end-to-end in a nested-KVM Incus VM (Ubuntu 24.04,
  kernel 6.8): booted real Firecracker microVMs, fio produced real reports
  (fio-3.36), runs assembled and the gate returned a verdict. Two bugs found and
  fixed by running it: the kvm gadget was missing `use std::os::fd::AsFd` (would
  never build), and the firecracker teardown used `pkill -f -- "--api-sock ..."`
  which self-matched and SIGTERM'd its own shell (now kills by a pidfile). Still
  open: the `boot.api_to_init` span times the InstanceStart API round-trip, not
  the guest reaching init (the agentless vantage cannot see guest-init); decide
  whether that coarse span earns its keep.

## Deferred scope (orchestrator stage 3)

- [ ] **`run_id` is not the canonical ULID text form.** `run::new_run_id` now uses
  ULID layout (48-bit ms timestamp high, 80-bit entropy low), hex-encoded, so it is
  time-ordered and a valid OTLP `trace_id`. It is not the Crockford base32 ULID
  *string*; add that spelling only if a consumer needs it.
- [x] **Adapter/workload versions come from the adapters.** Both `run` and
  `capture` now stamp the real `target.version()`/`workload.version()` (a
  `--version` query for the native adapters, the `version` phase for the command
  adapter). `AdapterVersions::default` (`0.0.0`) remains only as a test fixture.

## Deferred scope (orchestrator stage 1)

- [x] **Uprobe-on-hot-path check finished; attach-kind is author-declared.**
  Decision: attach kind lives in the def, not discovered from the gadget (the
  orchestrator does not run a gadget to introspect it, and load-time rejection
  must work off static data). A declared `attach` is now validated against the
  contract's `attach_kind` vocabulary, so a typo (`uprob`) is rejected rather than
  silently slipping past the `== "uprobe"` hot-path check. Fixed the stale enum in
  `docs/contract-v0.md` (was missing `tracepoint`/`tc`). Residual: an entry that
  omits `attach` still can't be hot-path-checked; that is inherent to
  author-declaration, and the honest answer is the author must declare `attach`
  for hot-path probes.
