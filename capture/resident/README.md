# assayist-capture-resident

Host-side snapshot residency: how much of a snapshot's memory file is resident in
the host page cache, emitted as an AssayRun fragment.

It mmaps the mem file `MAP_SHARED` and calls `mincore(2)` once at the end of the
window, so it measures the file's page-cache residency, not this process's own
faults. This is the ground-truth working set: how much of the snapshot actually
faulted into cache to reach steady. Unlike every other gadget it is pure
userspace (no eBPF, no BTF), so it builds and runs anywhere with a `/proc`.

Where the orchestrator's `hostmem` delta is the machine-level cost, this is what
the snapshot itself has resident (bpfolio's `resident_fraction`). For a
file-backed restore it is the set shared through the page cache, so concurrent
instances of one snapshot count it once. A userfaultfd restore copies pages into
each guest's own anonymous memory, off the file, so this measures the
shared/file residency, not per-guest private memory.

## What it captures

- `resident.snapshot_resident_pages`: gauge, pages of the file resident in cache.
- `resident.snapshot_total_pages`: gauge, total pages in the file.
- `resident.snapshot_fraction`: gauge, resident / total.

All singleton cardinality. No `self_metrics`: there is no probe to cost, because
there is no eBPF.

## Run

```
# 30s window, mincore the mem file at the end, JSON to stdout
./target/release/assayist-capture-resident --mem /var/lib/assayist/run/fn/mem

# write a fragment file, shorter window
./target/release/assayist-capture-resident --mem ./run/fn/mem --duration 5 --out resident-fragment.json
```

Flags: `--mem <path>` (required, the file to measure), `--duration <s>` (default
30, residency is sampled once at the end), `--out <path|->` (default `-`).

No root needed if you can read the mem file, no BTF, no clang, no bpftool. Point
it at the mem file from a def with a `{def_dir}`-relative path:

```yaml
capture:
  - probe: snapshot_resident
    gadget: assayist-capture-resident
    cardinality: { class: singleton }
    args: ["--mem", "{def_dir}/../run/fn/mem"]
```

The firecracker adapter also reports residency per guest orchestrator-side (no
def wiring, it rides the restore), keyed per instance under `instances: N`. This
gadget is the standalone form for measuring a mem file directly.

## Limits (be honest)

- **End-of-window sample, not a trajectory.** It reads residency once, at the
  end. It tells you the working set the guest reached, not how it grew.
- **File residency, not private memory.** A userfaultfd restore's per-guest
  copies live off the file, so they are invisible here by design. Pair with the
  `hostmem` delta for the machine-level cost.
- **Whole file.** It measures the entire mem file's residency, not a sub-range.
- **Not a whole run.** This emits a fragment. The orchestrator and gate do the
  identity, fingerprint, and decision.

## Licence

Apache-2.0. There is no eBPF object here, so unlike the other gadgets there is no
GPL-2.0 split: it is userspace-only.
