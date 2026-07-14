# TODO

Running list of flagged items and deferred scope. Point-in-time; move things
out as they land. Durable design lives in `docs/`, session pickup in `HANDOFF.md`.

## Deferred scope (orchestrator stages 4-5)

- [ ] **`pinning_layout` is never recorded, so runs cannot reach `reproducible`.**
  `apply_tuning` (governor/SMT/THP) is done and wired behind `assayist run
  --apply-prep` (verified against real sysfs in an Incus VM: THP applies and the
  run proceeds; a governor request on a host with no cpufreq is refused). But
  `has_extended()` also needs `pinning_layout`, which nothing sets. Thread thread
  pinning (the `pin_threads` directive) through the target adapter and record the
  layout so a fully-prepped run can grade `reproducible` rather than `valid`.
- [ ] **Fingerprint is read once and reused across all runs.** `run` builds the
  fingerprint once (apply-or-observe) and clones it into every assembled run. Fine
  while the host is static; re-read per run so prep state that drifts between the A
  and B SUT builds is caught.
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
- [ ] **Adapter/workload versions are placeholders.** `AdapterVersions::default`
  is `0.0.0`. Real versions come from the running adapters in stage 4; the capture
  subcommand stamps the placeholder until then.

## Deferred scope (orchestrator stage 1)

- [ ] **Uprobe-on-hot-path load check is partial.** The load-time rejection of a
  uprobe on a hot path needs attach-kind + hot-path info per capture entry. The
  current `examples/firecracker-boot-snapshot.assay.yaml` carries only
  `probe` + `gadget` + `cardinality`, no `attach`. Stage 1 validates it only when an
  optional `attach`/`hot_path` is present on the entry. Decide whether attach-kind
  belongs in the def (author-declared) or is discovered from the gadget at capture
  time, and finish the check accordingly.
