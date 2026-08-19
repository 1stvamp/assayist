# Config reference

Every key a benchmark def accepts, every CLI flag, and every gadget flag, in one
place. This is the reference; the guides in [`guides/`](guides/) show them in
use and the [contract](contract-v0.md) is the normative spec for the record a run
produces.

Keys are read straight from the source (`crates/orchestrate/src/def.rs`,
`native.rs`, `main.rs`, and each gadget's `main.rs`), so if this drifts from the
code, the code wins: file a bug.

## Def top level (`BenchmarkDef`)

| Key | Req | Notes |
|---|---|---|
| `apiVersion` | yes | `assayist/v0`. |
| `name` | yes | Def name, recorded in identity. |
| `target` | yes | The adapter under test. See below. |
| `workload` | yes | What drives the target. See below. |
| `gate` | yes | Gate mode and thresholds. See below. |
| `parameterise` | no | Map of dimension to value list, e.g. `vcpu: [1, 2, 4]`. The cross-product of dimensions is the cell set; each cell runs the whole pipeline. |
| `compare` | no | Names one `parameterise` dimension to use as the A/B axis: its two values become groups A and B, gated in a single `assayist run`. Absent = A/B by build (`--a-sut`/`--b-sut`). |
| `capture` | no | List of capture entries (gadgets to fire). See below. |
| `host_prep` | no | Host tuning to apply and read back (`cpu_governor`, `smt`, `thp`, `pin_threads`). Applied only with `--apply-prep`. |
| `tenancy` | yes | `single_tenant` or `density`. The gate refuses to compare across the two. |

### `target`

| Key | Notes |
|---|---|
| `adapter` | `firecracker`, `qemu`, `cloud-hypervisor` (alias `chv`), `unikernel`, or any other string (falls back to the command adapter). |
| `version` | Adapter version constraint, recorded in identity (e.g. `">=0.3"`). |
| `config` | Adapter-specific settings (tables below). String values expand template vars. |
| `commands` | Command-adapter only: shell templates keyed by phase (see the command adapter below). |

### `workload`

| Key | Notes |
|---|---|
| `driver` | A name starting `fio` (fio), starting `wrk` (wrk), or `vsock`; anything else falls back to the command adapter. |
| `version` | Recorded in identity. |
| `config` | Driver-specific settings (tables below). |
| `commands` | Command-adapter only: shell templates keyed by phase. |

### `gate` (`GateSpec`)

| Key | Default | Notes |
|---|---|---|
| `mode` | (required) | `ab_permutation`, `longitudinal_drift`, or `subsystem_triad`. |
| `p_threshold` | 0.01 | Significance floor. |
| `noise_threshold` | 0.05 | Within-group CoV ceiling. |
| `resamples` | 10000 | Permutation resamples. |
| `ignore` | `[]` | Metric-name substrings to exempt from gating. |

**Note**: the def's gate surface is a subset of the standalone `assayist-gate`
CLI. `min_effect`, `drift_k`, `seed`, and `strict_single_cell` are CLI-only in
v0: set them on the gate invocation, not in the def.

### `capture` (`CaptureEntry`)

| Key | Req | Notes |
|---|---|---|
| `probe` | yes | The series-source id. |
| `gadget` | yes to run | The capture binary to invoke (e.g. `assayist-capture-kvm`). Validated at load but only required when the run actually fires gadgets. |
| `cardinality` | yes | `{ class: singleton }` or `{ class: bounded, key_source: <source>, max_keys: N }`. A missing decl is a load error. |
| `attach` | no | Declared attach kind (`tp_btf`/`tracepoint`/`fentry`/`fexit`/`kprobe`/`kretprobe`/`uprobe`/`xdp`/`tc`), so the uprobe-on-hot-path check can fire. |
| `hot_path` | no | Marks the probe as hot-path (arms the uprobe rejection). |
| `args` | no | Extra flags passed to the gadget verbatim after `--duration`/`--out`. |

There is no `aggregate` key: histogram-vs-counter is the gadget's shape, emitted
in its fragment, not declared here.

## Target adapters

Every adapter reads `vcpu`/`mem_mib` from the parameterisation cell when those
dimensions are present, falling back to `config`. String config values expand
the template vars in the last section.

### `firecracker`

| Key | Default | Notes |
|---|---|---|
| `bin` | `firecracker` | Binary to launch. |
| `api_sock` | `/tmp/assayist-fc-<pid>[-<instance>].sock` | API socket. Template `{instance}` yourself if you set it for N > 1. |
| `vcpu` | `1` | vCPU count (usually from the cell). |
| `mem_mib` | `128` | Guest memory (usually from the cell). |
| `smt` | `false` | Guest machine-config SMT toggle. **Note**: distinct from `host_prep.smt`, which is host CPU SMT. |
| `kernel` | | Uncompressed kernel image (cold boot). |
| `rootfs` | | Root filesystem image (cold boot). |
| `boot_args` | `console=ttyS0 reboot=k panic=1` | Kernel cmdline (cold boot). |
| `from_snapshot` | | Snapshot file. Its presence switches the adapter to restore mode; needs `mem_file`. |
| `mem_file` | | Snapshot memory file for restore. |
| `mem_backend` | `File` | `File` mmaps the mem file; `uffd` restores through an external userfaultfd handler. |
| `uffd_handler` | | Handler command for `mem_backend: uffd`. Rendered with `{uffd_uds}` and `{mem_file}`. |
| `pre_restore` | | Shell command run before the timed `snapshot/load` (outside the span): set the page-cache state a restore starts from. |
| `stream_source` | | `file://` or `http(s)://` source for a per-instance FUSE mount serving guest memory. |
| `stream_bin` | `bpfoliod` | Binary providing `stream-mount`/`stream-prefetch`. |
| `stream_wsmeta` | | Working-set metadata for stream prefetch. |
| `stream_prefetch` | `false` | `stream`/`true`/`on` warms the working set before load; anything else (e.g. `nostream`) demand-faults. |
| `snapshot_out` | | Create a steady-state snapshot mid-run at this path; needs `snapshot_mem`. |
| `snapshot_mem` | | Memory-file path for `snapshot_out`. |
| `readiness` | | Shell command that must succeed for the guest to count as ready. |
| `network` | (unset) | `tap` to give the VM a host tap device (created on provision, deleted on teardown) and a deterministic locally-administered MAC. Absent means no network interface, the historical behaviour. Required for per-VM network attribution. |

### `qemu`

| Key | Default | Notes |
|---|---|---|
| `bin` | `qemu-system-x86_64` | |
| `qmp_sock` | `/tmp/assayist-qemu-<pid>[-<instance>].sock` | QMP control socket; timed to appearing as `boot.vmm_ready`. |
| `vcpu` | `1` | |
| `mem_mib` | `128` | |
| `kernel` | | `-kernel` image. |
| `rootfs` | | `-drive` image. |
| `boot_args` | `console=ttyS0 reboot=k panic=1 root=/dev/vda ro` | Kernel cmdline. |
| `extra_args` | | Extra QEMU args, appended verbatim. |
| `readiness` | | Optional guest-ready command. |

v0 is cold boot only (no savevm/migration restore, no vCPU pinning).

### `cloud-hypervisor` (alias `chv`)

| Key | Default | Notes |
|---|---|---|
| `bin` | `cloud-hypervisor` | |
| `api_sock` | `/tmp/assayist-chv-<pid>[-<instance>].sock` | `--api-socket`; timed to appearing as `boot.vmm_ready`. |
| `vcpu` | `1` | |
| `mem_mib` | `128` | |
| `kernel` | | Uncompressed `vmlinux` (direct boot), same shape firecracker takes. |
| `rootfs` | | Root disk. |
| `cmdline` | `console=ttyS0 reboot=k panic=1 root=/dev/vda ro` | Kernel cmdline. **Note**: this adapter's boot-args key is `cmdline`, not `boot_args`. |
| `extra_args` | | Extra CH args. |
| `readiness` | | Optional guest-ready command. |

v0 is cold boot only. CH does not exit on guest reset, so teardown waits for the
process to die and removes `<api-socket>.lock` before the next run.

### `unikernel`

| Key | Default | Notes |
|---|---|---|
| `bin` | `qemu-system-x86_64` | Runs the unikernel under QEMU/KVM. |
| `qmp_sock` | `/tmp/assayist-uk-<pid>[-<instance>].sock` | QMP socket; timed to `boot.vmm_ready`. |
| `mem_mib` | `256` | |
| `image` | | The unikernel image. |
| `boot_style` | `disk` | `disk` boots a raw disk image (Nanos/`ops`); `kernel` boots a multiboot/PVH image via `-kernel` (Unikraft). |
| `boot_args` | | Kernel cmdline, used only in `kernel` boot style. |
| `hostfwd` | | Host-to-guest port forward for a `readiness` probe, e.g. `tcp::18080-:8080`. |
| `extra_args` | | Extra QEMU args. |
| `readiness` | | Optional guest-ready command (the only agentless way to confirm it is serving). |

v0 is cold boot only (no snapshot/restore, no vCPU pinning).

### command adapter (fallback)

Any `adapter` not matched above uses the command adapter: you supply shell
templates keyed by lifecycle phase under `target.commands`, and the orchestrator
runs them. Phases: `provision`, `start`, `reach_steady`, `spans`, `teardown`,
`version`. Templates expand `{def_dir}`, `{instance}`, and any cell param as
`{name}`.

```yaml
target:
  adapter: my-thing
  commands:
    provision: "my-thing prepare --root {def_dir}/img"
    start: "my-thing run --id {instance} &"
    reach_steady: "sleep 1"
    teardown: "my-thing stop --id {instance}"
```

## Workload drivers

### fio (driver starts with `fio`)

| Key | Default | fio flag |
|---|---|---|
| `bin` | `fio` | |
| `name` | `assayist` | `--name` |
| `filename` | `/tmp/assayist-fio.dat` | `--filename` |
| `rw` | `randread` | `--rw` |
| `bs` | `4k` | `--bs` |
| `iodepth` | `32` | `--iodepth` |
| `numjobs` | `1` | `--numjobs` |
| `ioengine` | `libaio` | `--ioengine` |
| `direct` | `1` | `--direct` |
| `size` | `1G` | `--size` |
| `runtime` | `30` | `--runtime` (always `--time_based`, JSON output) |

### wrk (driver starts with `wrk`)

| Key | Default | wrk flag |
|---|---|---|
| `bin` | `wrk` | |
| `threads` | `2` | `-t` |
| `connections` | `10` | `-c` |
| `duration` | `30` | `-d<n>s` |
| `rate` | (unset) | `-R` (wrk2-style constant rate), only when set |
| `script` | (unset) | `-s` (Lua), only when set |
| `url` | `http://127.0.0.1:8080/` | positional |

### vsock (driver `vsock`)

| Key | Default | Notes |
|---|---|---|
| `uds` | | Host vsock socket to connect to. |
| `port` | `5252` | Guest port for the `CONNECT` handshake. |
| `invocations` | `50` | How many times to connect/send/drain. |
| `payload` | (empty) | Bytes sent after CONNECT. |
| `timeout_ms` | `5000` | Per-invocation timeout. |

### command workload (fallback)

Any `driver` not matched uses the command workload: templates under
`workload.commands` keyed by `start`, `stop`, `report`, `version`. A `report`
command's stdout is parsed as JSON and its numbers are reduced to gradeable
`workload:<field>` metrics.

## Template vars

String config values (and capture-entry `args`) expand:

| Var | Meaning |
|---|---|
| `{def_dir}` | Directory of the def file, so assets are referenced repo-relative, not by absolute path. |
| `{instance}` | Per-instance index under `instances: N` (empty for a lone instance); gives each concurrent sandbox non-colliding sockets and scratch dirs. |
| `{uffd_uds}` | The userfaultfd socket Firecracker connects to (uffd handler command only). |
| `{mem_file}` | The snapshot memory file (uffd handler command only). |
| `{<param>}` | Any `parameterise` dimension, e.g. `{vcpu}`, `{variant}`, `{mode}`. |

## CLI: `assayist`

| Subcommand | Flags |
|---|---|
| `run <def>` | `--repeat N`, `--a-sut SHA`, `--b-sut SHA`, `--out DIR`, `--duration N`, `--allow-ungraded`, `--apply-prep` |
| `capture <def>` | `--duration N`, `--out PATH`, `--sut-sha SHA`, `--work-dir DIR` |
| `inspect <def>` | (none: parse, validate, expand, observe the host read-only) |
| `export <run.json>` | `--signal both\|traces\|metrics`, `--out PATH` |
| `import <otlp.json>` | `--out PATH` |

**Note**: `--apply-prep` writes host tuning to sysfs and needs root. Without it
the host is observed read-only, and a run whose tuning the host does not already
match grades `invalid`.

## CLI: `assayist-gate`

`--mode ab_permutation|longitudinal_drift|subsystem_triad`, then the groups
(`--a`/`--b` for A/B and triad, `--baseline`/`--candidate` for drift), plus
`--p-threshold`, `--noise-threshold`, `--min-effect`, `--resamples`, `--drift-k`,
`--seed`, `--ignore <substr>` (repeatable), `--allow-ungraded`,
`--strict-single-cell`, `--out <path|->`. See [`../crates/gate/README.md`](../crates/gate/README.md).

## Gadget flags

All gadgets take `--duration <s>` and `--out <path|->` and a `--budget` (the
observer-effect ceiling). Gadget-specific flags:

| Gadget | Flags |
|---|---|
| `assayist-capture-kvm` | `--per-guest` (key by cgroup id), `--max-keys N` (bounded ceiling) |
| `assayist-capture-block` | `--hires` (log-linear histogram, `layout: explicit`, ~4x finer p99) |
| `assayist-capture-net` | `--iface <name>` (repeatable), `--iface-prefix <p>`, `--tx` (tc egress too) |
| `assayist-capture-ctrlplane` | `--cgroup name=path` (repeatable), `--cgroup-id name=id` |
| `assayist-capture-resident` | `--mem <path>` (required, the file to mincore) |

Pass gadget flags from a def through the capture entry's `args`, e.g.
`args: ["--per-guest", "--max-keys", "10000"]`.
