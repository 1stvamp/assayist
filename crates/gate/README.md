# assayist-gate

The decision engine. Consumes `AssayRun` records, returns a verdict. Pure userspace, one dependency (`serde_json`), deterministic.

Three modes, matching the contract's `GateContext.mode`:

- `ab_permutation`: non-parametric permutation test (difference of means, 10k resamples) between a baseline group A and a candidate group B, with three gates (significance, effect size, noise), polarity-aware regression detection, and cross-cell awareness.
- `longitudinal_drift`: for held long-lived targets that cannot be A/B'd. Establishes a baseline mean and spread, then tests a candidate trajectory for a level shift (beyond `k` standard deviations) and a trend (OLS slope). Built to catch restore-time drift as a guest ages.
- `subsystem_triad`: `ab_permutation` on the workload KPIs plus an overhead section that reads the eBPF variant's own cost from `self_metrics` and fails if any probe was over budget.

## How it decides (ab_permutation)

For every metric present in both groups with at least two samples each:

1. **Reduce** each run to scalars. Histograms become `mean` (from the exact `sum` when present, else bucket-midpoint estimate), `p50`, `p99`. Counters become `value` (and `rate` when a window is known). Gauges become `value`. Spans become durations.
2. **Permutation test** gives a p-value (deterministic: fixed-seed PRNG, so the same inputs always give the same p).
3. **Three gates**: significant (`p < p_threshold`, default 0.01), strong (`|relative delta| >= min_effect`, default 0.05), not noisy (within-group CoV `<= noise_threshold`, default 0.05). The noise gate uses **within-group** CoV, not pooled, so a real between-group shift is not mistaken for noise.
4. **Polarity** decides regression vs improvement. Time-unit metrics (ns/us/ms/s) are lower-better; byte/packet/throughput metrics are higher-better; CPU-consumption and unknown metrics are left undirected (reported as `changed`, never a fail).
5. **Verdict**: `contaminated` if any compared metric came from an over-budget probe or an overflowed series (contamination wins, because you cannot trust a comparison the capture polluted); else `fail` if any metric regressed; else `pass`.

Single-cell regressions (present in only one parameterisation cell) still fail but carry a note to confirm across cells, unless `--strict-single-cell`. This is the cross-parameterisation discipline: a real regression shows across cells, a lone one is often noise.

## Exit codes (for CI)

`0` pass, `1` gate error (e.g. cross-tenancy comparison refused, ungraded run), `2` fail, `3` contaminated.

## Grades and tenancy

Only `reproducible` runs are admitted to a gated comparison; `--allow-ungraded` overrides for local iteration (and is noted in the outcome). The gate refuses to compare across tenancy classes (`single_tenant` vs `density`), because a contended density run has no business being measured against a single-tenant baseline.

## Usage

```
assayist-gate --mode ab_permutation \
  --a a0.json a1.json a2.json ... \
  --b b0.json b1.json b2.json ...

assayist-gate --mode longitudinal_drift \
  --baseline base0.json ... --candidate cand0.json ...   # candidate is time-ordered

assayist-gate --mode subsystem_triad --a a*.json --b b*.json
```

Options: `--p-threshold --noise-threshold --min-effect --resamples --drift-k --seed --ignore <substr> (repeatable) --allow-ungraded --strict-single-cell --out <path|->`.

Output is a contract-conformant `outcome` (`verdict`, `per_metric` with `delta`/`p`/`significant`/`noisy`, `notes`) plus a richer `report` for humans. See `examples/sample-outcome.json`.

## Things the build surfaced (worth knowing)

These are real findings from running the gate against synthetic data, not hypotheticals:

- **Sample count sets the p-value floor.** With N vs N runs there are only C(2N, N) partitions, so the smallest reachable two-sided p is roughly `2 / C(2N,N)`. At 4 vs 4 that is about 0.029, so `p < 0.01` is unreachable: you need more iterations. The gate is honestly refusing to call significance the sample size cannot support, not missing a regression. Budget for enough repeats (Firecracker runs many).
- **log2-derived percentiles are coarse.** `p50`/`p99` off a 40-slot log2 histogram snap to bucket midpoints, so their run-to-run CoV is high and the noise gate usually excludes them. That is the correct behaviour (do not gate on quantised tails), but it means **gate on the mean** (from the exact `sum` the gadgets emit) and treat log2 percentiles as advisory. If you need to gate a tail, capture a finer or explicit histogram for that metric.
- **Noise must be within-group.** An early version used pooled CoV and a genuine +40% regression disguised itself as noise (pooling the two group means inflates the spread). Within-group CoV fixes it. This is baked in now, but it is the kind of thing to keep in mind if you extend the stats.
- **Polarity is unit-first.** Name-token polarity missed `restore.resume_to_steady` (no "latency" in the name). Deciding direction from the unit (time down is good) is the robust default; name tokens only carry the throughput and CPU-ambiguity cases.

## Limits

- The reduction is mean/p50/p99/value/rate/duration. Multi-modal distributions are not modelled; a bimodal latency shift that leaves the mean unchanged will not fire. Add percentiles or a finer histogram if that matters for a given metric.
- Drift mode's trend test is a simple OLS slope significance; it flags monotonic drift well and is weaker on step changes late in the window (the level-shift test covers those).
- Permutation p uses random resampling with add-one smoothing, not exact enumeration; at tiny N consider that the floor above dominates anyway.

## Build and test

```
cargo build --release
cargo test          # stats unit tests
```

Builds on stable Rust (tested on 1.75). Apache-2.0.
