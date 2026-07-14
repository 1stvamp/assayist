# TODO

Running list of flagged items and deferred scope. Point-in-time; move things
out as they land. Durable design lives in `docs/`, session pickup in `HANDOFF.md`.

## Deferred scope (orchestrator stages 4-5)

- [ ] **Host prep is not applied, only observed.** `hostprep::apply_tuning` returns
  an error (writing sysfs needs root), so `assayist run` uses `observe()`. Runs
  grade at most `valid`, and if a def's `host_prep` requests tuning the host does
  not already match, runs grade `invalid` (honest: prep did not take). Implement
  the sysfs writes with the appropriate root/guard handling, then switch `run` to
  `prepare()` and record `pinning_layout` so runs can reach `reproducible`.
- [ ] **`workload_report` is captured but not stored.** `execute_run` collects the
  workload driver's `report` output and the pipeline logs it, but the contract has
  no field for it, so it is dropped from the `AssayRun`. Decide where it belongs
  (a span attribute, a new optional field) or keep it out deliberately.
- [ ] **Fingerprint is read once and reused across all runs.** `run` observes the
  host once and clones the fingerprint into every assembled run. Fine while the
  host is static, but re-read per run once prep-apply lands (prep state can differ
  between the A and B SUT builds).
- [ ] **Command adapters are the only adapter.** The `Target`/`Workload` traits are
  the SPI; only the shell command-adapter implements them. Real `firecracker`/`fio`
  adapters (native Rust, with genuine lifecycle spans and versions) come next.

## Deferred scope (orchestrator stage 3)

- [ ] **`run_id` is not a canonical ULID.** `run::new_run_id` returns a 128-bit
  hex string derived from time + pid, unique enough for v0 and maps to an OTLP
  `trace_id`, but it is not lexicographically time-ordered. Switch to a real ULID
  (dedicated crate) when it matters.
- [ ] **Adapter/workload versions are placeholders.** `AdapterVersions::default`
  is `0.0.0`. Real versions come from the running adapters in stage 4; the capture
  subcommand stamps the placeholder until then.
- [ ] **`capture` orphans spawned children on a later spawn failure.** If gadget 2
  fails to spawn, gadget 1 is left running. Minor for v0 (spawn failures are fast,
  before real work); tidy with a kill-on-error guard when it matters.

## Deferred scope (orchestrator stage 1)

- [ ] **Uprobe-on-hot-path load check is partial.** The load-time rejection of a
  uprobe on a hot path needs attach-kind + hot-path info per capture entry. The
  current `examples/firecracker-boot-snapshot.assay.yaml` carries only
  `probe` + `gadget` + `cardinality`, no `attach`. Stage 1 validates it only when an
  optional `attach`/`hot_path` is present on the entry. Decide whether attach-kind
  belongs in the def (author-declared) or is discovered from the gadget at capture
  time, and finish the check accordingly.
