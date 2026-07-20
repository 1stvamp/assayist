# assayist-orchestrate

The orchestrator: it reads a benchmark def, prepares the host, drives the target
and workload across the capture window, assembles a graded `AssayRun` per repeat,
and hands off to the gate. This is the `assayist` binary.

## Subcommands

- `run <def>`: the full A/B pipeline. Capture N runs per group per cell,
  assemble, gate, propagate the gate's exit code.
- `capture <def>`: fire the def's gadgets once and assemble one graded run.
- `inspect <def>`: parse, validate, expand the cells, observe the host
  (read-only).
- `export <run.json>` / `import <otlp.json>`: the OTLP bridge (via
  `assayist-otlp`).

## Modules

- `def.rs`: the def parser and validator (`BenchmarkDef`, `Target`, `Workload`,
  `GateSpec`, `CaptureEntry`, cell expansion, the cardinality and uprobe checks).
- `adapter.rs`: the SPI. The `Target` trait (`provision`/`start`/`reach_steady`/
  `spans`/`teardown`/`pinning_layout`/`resident_files`), the `Workload` trait
  (`start`/`stop`/`report`), the `Shell` abstraction, and `execute_run`, the
  per-run driver. Adapters take `&dyn Shell` so they unit-test without real VMs.
- `native.rs`: the built-in adapters. Targets `firecracker`, `qemu`,
  `cloud-hypervisor`, `unikernel`; workloads `fio`, `wrk`, `vsock`.
- `capture.rs`: gadget invocation and the fragment runner.
- `run.rs`: assembly (fragments + spans + identity + fingerprint into an
  `AssayRun`), the run id, adapter versions.
- `gate.rs`: shells out to `assayist-gate` for the verdict.
- `hostprep.rs`: applies host tuning (governor / SMT / THP) and reads it back.

## Where the config lives

Every def key each adapter and workload accepts, and every CLI flag, is in
[`../../docs/config-reference.md`](../../docs/config-reference.md). The runtime
flow (def to graded runs to verdict) and the feature guides are under
[`../../docs/`](../../docs/).

Apache-2.0.
