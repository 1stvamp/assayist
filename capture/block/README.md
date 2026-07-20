# assayist-capture-block

Host-side block-IO service latency and throughput, per device, emitted as an AssayRun fragment.

It matches `block_rq_issue` to `block_rq_complete` by dev+sector, measures the interval, and aggregates into an in-kernel log-linear histogram split read vs write (each power-of-two octave holds 4 linear sub-buckets). A byte counter per device rides alongside for throughput. This is biolatency's measurement wired to the Assayist contract, kept aggregation-in-kernel so nothing streams per request.

By default the sub-buckets are collapsed back to a 40-slot `log2` histogram, the same coarse layout every other gadget emits. `--hires` instead emits the full log-linear histogram as a `layout: explicit` series (160 buckets, `explicit_bounds`), whose p99 is ~4x finer, so the gate can grade the tail rather than treating the quantised log2 percentiles as advisory. See the gate README on why log2 percentiles are excluded.

## What it captures

- `block.io_latency:read` / `block.io_latency:write`: latency histograms (`unit: ns`), keyed by device (`maj:min`). `log2` layout by default, `layout: explicit` (log-linear, finer tail) under `--hires`.
- `block.io_bytes:read` / `block.io_bytes:write`: monotonic byte counters (`unit: By`), keyed by device.
- `self_metrics`: per-program cost via the BPF run-time counters, same as every gadget.

## Run

```
sudo ./target/release/assayist-capture-block --duration 30 --out block-fragment.json
# finer tail, gradeable p99:
sudo ./target/release/assayist-capture-block --hires --duration 30 --out block-fragment.json
```

Requirements and build are the same as `assayist-capture-kvm` (BTF kernel, clang + bpftool, generate `vmlinux.h` once). See that README for the shared setup.

## Why per device, not per guest

Block completion runs in softirq/IRQ context, where the current task is not the guest, so reading a cgroup id at completion time would attribute I/O to whatever happened to be running, which is wrong. Device is the resolution that is actually correct host-side.

**Note**: this means at density (many microVMs sharing host storage) you see per-device aggregate, not per-guest. Real per-guest block attribution needs syscall-level tracing in the VMM thread (io_uring / preadv / pwritev), which is a separate gadget because it measures a different boundary (the VMM's I/O submission, including host page cache) rather than device service time. Do not bolt cgroup keying onto this gadget; it would produce confident wrong numbers.

## Limits (be honest)

- **dev+sector matching, not request pointer.** Two identical (dev, sector) requests in flight at once collapse. Rare, and harmless for a latency histogram, but it is an approximation.
- **Tracepoint struct names.** `block_rq_complete` maps to `trace_event_raw_block_rq_completion` on current kernels; pre-4.x naming differed. CO-RE fails loudly at load if the struct is not present rather than reading garbage. Carries a compatibility-matrix entry.
- **read/write only.** Flush and discard are folded into write. If you need them split out, extend the `is_write` classification.

## See also

Fragment shape and self-metrics: [`../../docs/contract-v0.md`](../../docs/contract-v0.md).
Flags across all gadgets: [`../../docs/config-reference.md`](../../docs/config-reference.md).

## Licence

eBPF object GPL-2.0, userspace Apache-2.0, same split as the other gadgets.
