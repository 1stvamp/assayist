# Firecracker snapshot restore

The firecracker adapter is where most of Assayist's feature surface lives,
because it is the path bpfolio exercises: cold restore, memory backends,
concurrency, residency, and streaming. This guide covers driving a restored
guest and measuring what a restore costs. The per-key config reference is in
[`../config-reference.md`](../config-reference.md); the milestone mapping is in
[`../bpfolio-integration.md`](../bpfolio-integration.md).

## Driving an agentless guest

An idle guest only shows host background traffic in the capture window. The
`vsock` workload driver exercises it: for each invocation it opens Firecracker's
host vsock socket, issues the `CONNECT <port>` handshake, optionally sends a
payload, and drains the response, which is how a snapshot-restored function
server is triggered. It reports the invocation count, errors, and a latency
summary. Because the firecracker adapter runs each restore in a `{api_sock}.d`
scratch cwd and the guest's uds is relative (`fn.vsock`), set a fixed `api_sock`
and point the workload's `uds` at `{that}.d/fn.vsock`:

```yaml
target:
  adapter: firecracker
  config:
    api_sock: /tmp/assayist-fc.sock
    from_snapshot: "{def_dir}/../run/fn/snapshot"
    mem_file: "{def_dir}/../run/fn/mem"
workload:
  driver: vsock
  config: { uds: /tmp/assayist-fc.sock.d/fn.vsock, port: 5000, invocations: 50 }
```

Numbers a workload reports (the `vsock` latency summary, fio's iops, or an
external tool's numbers surfaced through the report) are reduced to gradeable
`workload:<field>` metrics, so they are compared by the gate rather than left as
inert provenance. Polarity follows the field name and unit: a `*_ns` latency
reads lower-better, an `iops`/`bytes` field higher-better.

## Host memory

`assayist run` samples `/proc/meminfo` before the target is provisioned and again
after it reaches steady, and records the deltas as `hostmem.mem_consumed_kib`
(how far `MemAvailable` dropped, lower better) and `hostmem.cached_delta_kib`
(page-cache change, left without a graded direction). The window is the target
lifecycle, not the gadget window, so it captures the memory cost of preparing and
restoring the guest. This is a host, system-level measurement: it sees the
machine's memory move, not per-guest attribution, so for a single file-backed
restore the signal is small and noisy (pages are shared through the page cache,
which is the point). It earns its keep across many concurrent sandboxes, where
the aggregate is what separates a deduped restore from a per-sandbox copy.

## Snapshot residency

The `assayist-capture-resident` gadget mincores the snapshot's mem file at the
end of the window and reports `resident.snapshot_resident_pages`,
`resident.snapshot_total_pages`, and `resident.snapshot_fraction`, the
ground-truth working set: how much of the snapshot actually faulted into the page
cache. Where `hostmem` is the machine-level cost, this is what the snapshot itself
has resident (bpfolio's `resident_fraction`). It is pure userspace (mmap +
mincore, no eBPF or BTF), so it builds and runs anywhere; point it at the mem
file with a `{def_dir}`-relative path (capture-entry `args` are rendered with the
same vars as the target config):

```yaml
capture:
  - probe: snapshot_resident
    gadget: assayist-capture-resident
    cardinality: { class: singleton }
    args: ["--mem", "{def_dir}/../run/fn/mem"]
```

On a cold restore of a 256 MiB snapshot, this read ~5% resident, the working set
the guest touched to reach steady. For a file-backed restore it is the set shared
through the page cache (so concurrent instances of one snapshot count it once); a
userfaultfd restore copies pages into each guest's own anonymous memory, off the
file, so this measures the shared/file residency, not per-guest private memory.

The firecracker adapter also reports residency **per guest**, measured
orchestrator-side (like the host-memory delta, not an eBPF gadget): after the
guests reach steady, `assayist run` mincores each restore's mem file and emits
`resident.snapshot_*` keyed per instance. This is the attribution the system-level
`hostmem` delta cannot give: the delta is the machine cost, the per-guest resident
is what each sandbox faulted in. Under `instances: N` each instance is keyed
`instance0..N-1` (bounded cardinality); a lone restore keys as a singleton. No
def wiring needed, it rides the restore. Validated: 6 file-backed sandboxes of one
snapshot each reported the same ~5% file residency (they share the page cache),
the expected file-backed signature seen per instance rather than only in
aggregate.

## Concurrent sandboxes

`instances: N` brings up N sandboxes from the same snapshot and holds them all
resident through the capture window, so the host-memory delta is the aggregate. A
file-backed restore stays roughly flat as N grows (the shared working set counts
once); a per-sandbox copy grows with N. Make it the A/B axis to measure the
scaling directly:

```yaml
compare: instances
parameterise:
  instances: [1, 8]
target:
  adapter: firecracker
  config:
    from_snapshot: "{def_dir}/../run/fn/snapshot"
    mem_file: "{def_dir}/../run/fn/mem"
```

Concurrency is an orchestration concern, not a firecracker one: N > 1 wraps N
single-instance targets in a fanout that drives them all through the lifecycle and
records one aggregate `restore.resume_to_steady` span (so a 1-vs-N comparison
lines up on the same metric). Each instance is built with a distinct `{instance}`
var, so any adapter gets non-colliding sockets and scratch dirs from it: the
firecracker adapter folds `{instance}` into its default API socket, and a
command-adapter def references `{instance}` in its own templates. So the same knob
works for the QEMU, Cloud Hypervisor, and unikernel adapters with no extra code.
With `pin_threads` on, each instance gets a distinct `cpu_base` (instance `i`
starts at `i * vcpu`), so concurrent sandboxes pin to disjoint CPUs rather than
all landing on CPU 0; `taskset` fails the run if that would need more CPUs than
the host has. A pinned, fully-prepped concurrent run grades `reproducible`
(validated: two instances pinned to CPUs 0 and 1, layout
`{"instance0": {"vcpu0": 0}, "instance1": {"vcpu0": 1}}`).

## Memory backend: file-backed vs userfaultfd

`mem_backend: uffd` restores guest memory from an external userfaultfd handler
instead of mmapping the mem file (`mem_backend: file`, the default). File-backed
sandboxes share resident pages through the host page cache, so their aggregate
memory stays roughly flat as instances grow; a userfaultfd handler that copies
pages into each sandbox's own anonymous memory (the REAP baseline) has no such
sharing, so it grows with the count. The adapter is generic: it launches whatever
`uffd_handler` command the def gives, rendering `{uffd_uds}` (the socket
Firecracker connects to) and `{mem_file}`, waits for the socket, then loads with
the `Uffd` backend.

```yaml
compare: backend
parameterise:
  backend: [file, uffd]
target:
  adapter: firecracker
  config:
    instances: "4"
    from_snapshot: "{def_dir}/../run/fn/snapshot"
    mem_file: "{def_dir}/../run/fn/mem"
    mem_backend: "{backend}"
    uffd_handler: "/path/to/handler --uds {uffd_uds} --mem {mem_file} ondemand"
```

Combined with `instances`, this measures dedup directly: on one host, four
file-backed sandboxes consumed ~1 MB of `hostmem.mem_consumed_kib` while four
userfaultfd sandboxes of the same snapshot consumed ~21 MB. The handler is torn
down with the run.

## Streaming restore

`stream_source` restores the guest memory from a per-instance FUSE mount backed by
a source URL (`file://…` or `http(s)://…`) instead of a local mem file: the
adapter brings up `bpfoliod stream-mount` before `snapshot/load` (sized from the
real mem file), loads File-backed against the mounted file, and unmounts at
teardown. `stream_prefetch` chooses the arm: unset/`nostream` demand-faults every
page over the mount; `stream`/`true` first warms the captured working set from the
source (`stream-prefetch`) inside the pre-restore window. Each restore gets a
unique mountpoint, so repeats do not collide on a half-torn-down FUSE mount.

```yaml
compare: mode
parameterise:
  mode: [nostream, stream]
target:
  adapter: firecracker
  config:
    from_snapshot: "{def_dir}/../run/fn/snapshot"
    mem_file: "{def_dir}/../run/fn/mem"
    stream_source: "file://{def_dir}/../run/fn/mem"   # or http(s):// for a real network test
    stream_bin: "/path/to/bpfoliod"
    stream_wsmeta: "{def_dir}/../run/fn/reap.wsmeta"
    stream_prefetch: "{mode}"
```

Validated with a `file://` source (fuse3 required): demand vs prewarm restores of
a 256 MiB snapshot assembled and gated, mount and unmount clean across repeats.
Needs assayist >= 0.1.2 (the stream-mount lifecycle) and fuse3.
