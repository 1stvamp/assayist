# assayist-otlp

The OTLP export/import bridge. Turns an `AssayRun` into OTLP/JSON and back.

Export is a rote transform because the contract was drawn OTLP-shaped where the
concepts overlap: `run_id` is a 128-bit value that maps onto an OTLP `trace_id`,
log2 histograms map onto OTel exponential histograms at scale 0, spans map
directly. Import degrades gracefully: it fills what maps (spans, histograms,
`host.*`/`os.*` resource attrs into the fingerprint core) and leaves the
benchmark-only fields empty, so an imported run lands at `grade: valid`, never
`reproducible` (the fingerprint and self-metrics cannot be reconstructed).

Wired into the CLI as `assayist export` and `assayist import`. The full mapping
table, including the one honest wrinkle (bpf log2 buckets are half-open, OTel
exponential buckets are half-closed, so an exact power-of-two sample lands one
bucket over), is in [`../../docs/contract-v0.md`](../../docs/contract-v0.md) under
"OTLP export/import plugin".

Apache-2.0.
