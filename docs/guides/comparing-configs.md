# Comparing two configs

By default A and B are two builds of the same config (`--a-sut`/`--b-sut`). To
compare two *configurations* of one build instead (a stock restore vs a
prefetched one, two snapshot-prep modes, a flag on vs off), name a `parameterise`
dimension as the A/B axis with `compare`. Its two values become groups A and B,
so a single `assayist run` gates one against the other:

```yaml
compare: variant
parameterise:
  variant: [eph-default, eph-init-on-free]
target:
  adapter: firecracker
  config:
    from_snapshot: "{def_dir}/../run/syn-alloc-heavy/{variant}/snapshot"
    mem_file: "{def_dir}/../run/syn-alloc-heavy/{variant}/mem"
```

The variant is substituted into config templates as `{variant}` and recorded in
each run's `params`. Any other `parameterise` dimensions form cells within each
group. Config templates also expand `{def_dir}` (the directory of the def file),
so a committed def references its assets by repo-relative path rather than a
machine-specific absolute one. The `pre_restore` config key runs a shell command
before the timed `snapshot/load` (outside the span), which is how a def sets the
page-cache state a restore starts from: drop caches for a cold baseline, or warm
a working set so resume faults hit cache.
