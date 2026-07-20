# Assayist metric contract (v0)

Status: draft for review. This is the expensive-to-change piece, so it is written as a spec with normative keywords (MUST / MUST NOT / SHOULD / MAY) rather than prose. Everything here is designed OTLP-shaped where the concepts overlap, so the OTLP export/import plugin falls out as a rote transform rather than a translation layer.

## Bottom line

One record per benchmark run, called an `AssayRun`. It carries identity, a host fingerprint, lifecycle spans, continuous metric series, and the capture layer's own cost. The record is JSON on disk and on the wire internally. OTLP is reached through a shipped plugin, not by being the native shape. Three concepts have no OTLP equivalent and stay first-class native fields: the host fingerprint (structural, enforces reproducibility), the cardinality budget (declared, enforces density-safety), and the observer-effect self-metrics (gated, enforces the low-overhead claim).

Worked example used throughout: a Firecracker boot/snapshot/restore A/B run, target adapter `firecracker`, workload `fio-libaio`, parameterised over vcpu count.

## The envelope: `AssayRun`

| Field | Type | Req | Notes / OTLP mapping |
|---|---|---|---|
| `schema_version` | string (semver) | MUST | External users pin to this. See versioning. |
| `run_id` | string (ULID, 128-bit) | MUST | 128-bit so it maps to an OTLP `trace_id` near-identity on export. |
| `identity` | `RunIdentity` | MUST | See below. |
| `fingerprint` | `HostFingerprint` | MUST | Structural. A missing fingerprint object is a parse error, not a warning. |
| `spans` | `LifecycleSpan[]` | SHOULD | OTLP trace spans on export. |
| `series` | `MetricSeries[]` | SHOULD | OTLP metric datapoints on export. |
| `self_metrics` | `ProbeCost[]` | MUST if any eBPF probe ran | The observer-effect record. Absence when probes ran is a validity error. |
| `gate` | `GateContext` | MUST | Mode + baseline ref + thresholds. |
| `outcome` | `Outcome` | MAY | Filled by the gate after judging. Absent on a fresh capture. |
| `grade` | enum | MUST | `reproducible` \| `valid` \| `invalid`. Derived at parse (see grading). |

One `AssayRun` is one object. A run does not get shattered across separate trace/metric/resource streams the way native OTel would force. The gate operates on whole runs, so the whole run stays together.

## `RunIdentity`

| Field | Type | Req | Notes |
|---|---|---|---|
| `target_adapter` | string | MUST | e.g. `firecracker`. |
| `target_adapter_version` | string | MUST | Adapter semver, so a result is tied to the code that produced it. |
| `workload_driver` | string | MUST | e.g. `fio-libaio`. |
| `workload_driver_version` | string | MUST | |
| `sut_git_sha` | string | MUST | Commit of the system under test. |
| `params` | map<string, scalar> | MUST | The parameterisation cell, e.g. `{vcpu: 2, mem_mib: 256}`. |
| `params_hash` | string | MUST | Hash of canonicalised `params`. Groups series across runs in the same cell. |
| `benchmark_def_sha` | string | MUST | Hash of the declarative benchmark file (below). Diff the definition, not someone's shell history. |

## `HostFingerprint`

This is the reproducibility spine and the reason the contract is native rather than OTLP: the fingerprint is a *shape constraint*, not a bag of optional attributes. A run that cannot prove the environment it ran in cannot be compared against one that can.

Core fields (absence => `grade: invalid`, parse rejected for gated use):

| Field | Type | OTLP resource attr on export | Notes |
|---|---|---|---|
| `hostname` | string | `host.name` | |
| `kernel_version` | string | `os.version` | `uname -r`. |
| `os_release` | string | `os.description` | |
| `cpu_model` | string | `host.cpu.model.name` | |
| `cpu_count_logical` | int | `assayist.host.cpu_count_logical` | |
| `cpu_count_physical` | int | `assayist.host.cpu_count_physical` | |
| `smt_enabled` | bool | `assayist.host.smt_enabled` | No semconv equivalent, stays namespaced. |
| `cpu_governor` | string | `assayist.host.cpu_governor` | `performance` etc. |
| `thp_setting` | enum | `assayist.host.thp` | `always` \| `madvise` \| `never`. |
| `total_memory_bytes` | int | `assayist.host.memory_bytes` | |
| `kvm_present` | bool | `assayist.host.kvm` | |
| `tenancy` | enum | `assayist.run.tenancy` | `single_tenant` \| `density`. The marker that stops a density run being compared to a single-tenant baseline by accident. |
| `tuning_requested` | map | `assayist.host.tuning_requested` | What host prep asked for. |
| `tuning_readback` | map | `assayist.host.tuning_readback` | What the host actually reported after prep. |

Extended fields (absence => `grade: valid` but not `reproducible`, which is exactly the state an imported OTLP run lands in):

| Field | Type | OTLP resource attr | Notes |
|---|---|---|---|
| `numa_topology` | object | `assayist.host.numa` | Nodes and cpus per node. |
| `pinning_layout` | object | `assayist.host.pinning` | Which threads pinned where (the `vm.pin_threads` equivalent). |
| `mitigations` | map<string, string> | `assayist.host.mitigations` | Per-vuln state (spectre_v2, mds, etc). |
| `microcode_version` | string | `assayist.host.microcode` | |
| `nested_virt` | bool | `assayist.host.nested_virt` | |

Normative constraints:

- MUST reject at parse (`grade: invalid`) if the `fingerprint` object is absent, or any core field is null.
- MUST set `grade: invalid` if `tuning_applied` was requested and `tuning_requested` != `tuning_readback` (prep did not take, the run is a lie, throw it out).
- MUST set `grade: valid` (not `reproducible`) if all core fields are present but any extended field is missing.
- MUST set `grade: reproducible` only when core and extended are all present and tuning is consistent.
- The gate MUST admit only `reproducible` runs into gated A/B baselines. `valid` runs MAY be viewed and compared informally, always flagged as not-reproducible-grade.

## `LifecycleSpan`

Named, timestamped intervals. Deliberately OTLP-span-shaped.

| Field | Type | Req | OTLP span mapping |
|---|---|---|---|
| `name` | string | MUST | `span.name`, e.g. `boot.vmm_ready`, `snapshot.serialise`, `restore.resume_to_steady`. |
| `start_unix_nano` | uint64 | MUST | span start. |
| `end_unix_nano` | uint64 | MUST | span end. |
| `parent` | string (span name) | MAY | Resolves to `parent_span_id` on export. |
| `attributes` | map<string, scalar> | MAY | span attributes. |

On export: `run_id` becomes the `trace_id` (128-bit, direct), each span gets a `span_id` deterministically derived from `hash(run_id, name, index)` so exports are stable and re-runnable.

## `MetricSeries`

The continuous side. Histograms are the default and preferred kind, because in-kernel aggregation into histograms is the single biggest observer-effect lever (netstacklat sits at ~0.75% CPU doing exactly this, versus pushing per-event timestamps at just over 1 us each).

| Field | Type | Req | Notes |
|---|---|---|---|
| `name` | string | MUST | e.g. `kvm.exit_latency`. |
| `unit` | string (UCUM) | MUST | UCUM from day one so OTLP export is clean: `ns`, `By`, `1`, `us`. |
| `kind` | enum | MUST | `histogram` \| `counter` \| `gauge`. |
| `source` | string | MUST | The probe id / tracepoint that produced it. Ties every number to its capture program. |
| `key` | string | MAY | Present only for keyed (per-guest) series at density. Value drawn from a declared bounded key source. |
| `cardinality` | `CardinalityDecl` | MUST | Declared, enforced at load. See budget. |
| `data` | one of below | MUST | Kind-specific. |

Histogram `data` (`kind: histogram`):

| Field | Type | Notes |
|---|---|---|
| `layout` | enum | `log2` \| `explicit`. bpf-native log2 by default. |
| `buckets` | int[] | Counts. For `log2`, bucket `i` counts values in `[2^i, 2^(i+1))`. |
| `explicit_bounds` | float[] | Only for `layout: explicit`. Upper bounds, OTLP explicit-histogram-shaped. |
| `sum` | float | Optional running sum for mean recovery. |
| `count` | uint64 | Total observations. |

Counter `data` (`kind: counter`): `{ value: uint64, start_unix_nano: uint64 }`, monotonic. Gauge `data` (`kind: gauge`): `{ value: float, time_unix_nano: uint64 }`.

## Cardinality budget (normative)

This is the density-safety constraint, written as an actual load-time gate rather than a hope. At ~10k guests a per-guest unbounded series is a non-starter, so unbounded is rejected before the run starts, not discovered at ingest.

`CardinalityDecl`:

| Field | Type | Notes |
|---|---|---|
| `class` | enum | `singleton` \| `bounded`. There is no `unbounded`. |
| `key_source` | enum | Required if `bounded`. One of `vcpu_pid_map` \| `cgroup_id` \| `guest_index`. |
| `max_keys` | int | Required if `bounded`. |

Rules:

- Every `MetricSeries` MUST carry a `cardinality` decl. A series without one MUST be rejected at benchmark-definition load, before capture starts. This is the "rejected by default" property: it fails at registration, not at write time.
- A `bounded` series MUST name a `key_source` from the closed list. A key that does not derive from a declared bounded source MUST be rejected.
- At capture time, if distinct keys for a series exceed `max_keys`, the capture layer MUST truncate and set a `cardinality_overflow` flag on the series, and MUST NOT grow the key space. An overflowed series marks the run `outcome: contaminated` for that metric.
- A per-run global key ceiling MUST be configured (typically derived from guest count) and the sum of all series key counts MUST stay under it. Over the ceiling contaminates the run.

## `ProbeCost` (observer-effect self-metrics)

Every eBPF program reports its own cost. These are gated metrics, not diagnostics: they are how "low observer effect" becomes a measured property we publish rather than a claim we make. A benchmarking tool that will not report its own overhead has no business asserting a low one.

| Field | Type | Req | Notes |
|---|---|---|---|
| `probe_id` | string | MUST | Matches `MetricSeries.source`. |
| `attach_kind` | enum | MUST | `tp_btf` \| `tracepoint` \| `fentry` \| `fexit` \| `kprobe` \| `kretprobe` \| `uprobe` \| `xdp` \| `tc`. |
| `run_time_ns` | uint64 | MUST | Cumulative, from the kernel BPF run-time counters (`run_time_ns`). |
| `run_cnt` | uint64 | MUST | Invocation count (`run_cnt`). |
| `mean_ns` | float | MUST | `run_time_ns / run_cnt`, materialised so sinks do not have to. |
| `steady_cpu_fraction` | float | MUST | Computed steady-state CPU cost of this probe. |
| `over_budget` | bool | MUST | True if `steady_cpu_fraction` crossed the configured budget (default ~1%, the netstacklat envelope). |

Rules:

- If any eBPF probe ran, `self_metrics` MUST be present. Its absence when probes ran is a validity error (`grade` cannot be `reproducible`).
- A probe with `attach_kind: uprobe` on a declared hot path MUST be rejected at load (dual context switch, up to ~200% under I/O-heavy load). Uprobes off the hot path MAY run, sampled.
- Any probe with `over_budget: true` MUST either be downgraded (sampled) on the next run or dropped, and any metric it produced in the current run is marked contaminated.

## `GateContext`

| Field | Type | Req | Notes |
|---|---|---|---|
| `mode` | enum | MUST | `ab_permutation` \| `longitudinal_drift` \| `subsystem_triad`. |
| `baseline_ref` | string | MUST | `run_id` of the A run, or the id of the baseline trajectory for drift. |
| `p_threshold` | float | MUST | Default 0.01. |
| `noise_threshold` | float | MUST | Default 0.05 (the 5% floor). |
| `resamples` | int | MUST | Default 10000. |
| `ignore` | string[] | MAY | Metric names exempt from gating (too-high variance, up to ~60% tolerated on some). |
| `tenancy` | enum | MUST | Mirrors the fingerprint marker; the gate refuses to compare across tenancy classes. |

`Outcome` (gate output): `{ verdict: pass | fail | contaminated, per_metric: map<string, {delta, p, significant, noisy}>, notes: string[] }`.

## OTLP export/import plugin

Export is a rote transform because the shapes were chosen to line up. Import degrades gracefully because the benchmark-only concepts are additive.

Export (`AssayRun` -> OTLP):

| Assayist | OTLP |
|---|---|
| `run_id` (128-bit ULID) | `trace_id` (16 bytes, direct) |
| `spans[]` | `ResourceSpans` -> `Span[]`, name/start/end/attributes direct, `parent` -> `parent_span_id` |
| `identity` + `fingerprint` | `Resource.attributes` (semconv where it exists: `host.name`, `os.version`, `host.cpu.model.name`; everything else namespaced `assayist.*`) |
| `series[histogram, log2]` | `ExponentialHistogram`, scale 0 (base 2). bpf bucket `i` -> exponential bucket index `i`. |
| `series[histogram, explicit]` | `Histogram` with explicit bounds. |
| `series[counter]` | `Sum` (monotonic). |
| `series[gauge]` | `Gauge`. |
| `self_metrics[]` | `Gauge`/`Sum` with `assayist.probe.*` attributes (or the OTel profiling signal once it settles). |
| `outcome` | span status + `assayist.gate.*` attributes. |

The one honest wrinkle: bpf log2 buckets are half-open `[2^i, 2^(i+1))` and OTel exponential buckets at scale 0 are half-closed `(2^i, 2^(i+1)]`, so a sample landing exactly on a power of two lands one bucket over between the two representations. For latency histograms this is negligible (exact-power-of-two nanosecond samples are vanishingly rare), but the plugin documents it rather than hiding it. If it ever matters, the fix is to carry the boundary convention as a flag and offset on export.

Import (OTLP -> `AssayRun`):

- Fills what maps: OTLP spans -> `spans`, exponential histograms -> `series[log2]`, `host.*` / `os.*` resource attrs -> fingerprint core.
- Leaves benchmark-only fields empty: no `self_metrics`, partial fingerprint, no cardinality decls.
- Sets `identity.source = imported` and `grade: valid` (never `reproducible`, because the fingerprint and self-metrics cannot be reconstructed).
- The gate treats an imported run as a reduced-feature run: it CAN do span-latency A/B, it CANNOT do observer-effect gating (no self-metrics) and CANNOT enter a reproducible-grade baseline. That is the graceful degradation: OTLP in gives you the latency comparison, and is honest about what it cannot give you.

This is the interop win stated plainly: every sink you named (Prometheus OTLP ingest, Grafana, Axiom, Better Stack) consumes OTLP off the wire, so the export plugin reaches all of them, and correlation with the product's own OTel run traces works by having the plugin set a matching `trace_id` and resource attributes. You get the correlation with a little discipline instead of by welding the contract to OTLP.

## Benchmark definition file

The declarative file that a run is born from, and the thing `benchmark_def_sha` hashes. Committed next to the code under test.

```yaml
# firecracker-boot-snapshot.assay.yaml
apiVersion: assayist/v0
name: firecracker-boot-snapshot
target:
  adapter: firecracker
  version: ">=0.3"
  config:
    kernel: /var/lib/assayist/vmlinux
    rootfs: /var/lib/assayist/rootfs.ext4
workload:
  driver: fio-libaio
  config:
    filename: /dev/vdb
    rw: randread
gate:
  mode: ab_permutation
  p_threshold: 0.01
  noise_threshold: 0.05
  resamples: 10000
  ignore: []
parameterise:
  vcpu: [1, 2, 4]
  mem_mib: [256, 512]
capture:
  - probe: kvm_exit
    gadget: assayist-capture-kvm
    attach: tracepoint
    cardinality: { class: singleton }
  - probe: block_rq_complete
    gadget: assayist-capture-block
    attach: tracepoint
    cardinality: { class: bounded, key_source: device, max_keys: 256 }
host_prep:
  cpu_governor: performance
  smt: off
  thp: never
  pin_threads: true
tenancy: single_tenant
```

A capture entry is `probe` (the series-source id), `gadget` (the capture binary to run), `cardinality` (required, class `singleton` or `bounded`), and optionally `attach` (declared attach kind, so the uprobe-on-hot-path check can fire), `hot_path`, and `args` (extra flags passed to the gadget verbatim). There is no `aggregate` key: the histogram-vs-counter shape is the gadget's, emitted in its fragment, not something the def declares. `docs/config-reference.md` has the full key set for every adapter, workload, and gadget.

Load-time checks run against this before any capture: every capture entry has a cardinality decl (else reject), no uprobe on a hot path, host_prep is applied and read back. Only then does the run start.

The `gate:` block here is a subset of the standalone `assayist-gate` CLI: a def sets `mode`, `p_threshold`, `noise_threshold`, `resamples`, and `ignore`, but not `min_effect`, `drift_k`, `seed`, or `strict_single_cell` (those are CLI-only in v0, see `crates/gate/README.md`). Set them on the gate invocation, not in the def, until the def surface grows to cover them.

## Versioning and stability

- `schema_version` is semver. Additive fields are minor. Removing or retyping a field, or tightening a constraint, is major.
- External users pin to a major. We absorb OTLP semconv churn (the `http.*` to `http.request.*` kind of migration) inside the export plugin, so the contract's stability is ours to guarantee and is not hostage to OTel's release cadence.
- The `assayist.*` attribute namespace is ours and versioned with the schema. semconv-mapped attributes track whatever semconv major the plugin declares.

## What is deliberately not in the contract

- No in-guest userspace detail. Spans and series come from the host/KVM vantage, so the contract cannot represent what a unikernel or agentless microVM guest is doing internally. Full-VM targets that run an agent (Parca/DeepFlow) emit their own OTLP and get correlated by `trace_id`, they do not extend this schema.
- No absolute cross-host comparison. The fingerprint exists partly to make cross-host comparison fail loudly: the gate is same-host A/B or same-host drift. Comparing raw latencies across different fingerprints is out of scope by design.
- No unbounded cardinality. There is no representation for it, on purpose.
