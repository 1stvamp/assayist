# assayist-contract

The typed, producer-side model of the metric contract. One dependency (`serde`),
no logic beyond serialisation and grading.

This crate is where an `AssayRun` is built strictly: the orchestrator constructs
runs through these types, so a missing core fingerprint field is a construct
error, not a warning. The gate reads runs liberally (tolerant JSON) from its own
side, which is the producer-strict / consumer-liberal split the whole system
rests on.

## What it owns

- `AssayRun`: the one-record-per-run envelope (identity, fingerprint, spans,
  series, self-metrics, gate context, outcome, grade).
- `Identity`, `Fingerprint`, `Fragment`: the sub-structures a run is assembled
  from. A gadget emits a `Fragment`; the orchestrator merges fragments into a
  run.
- `Grade`: `reproducible` / `valid` / `invalid`, derived at parse from the
  fingerprint.
- `SCHEMA_VERSION`: the contract version stamped into every run.

## The contract is the load-bearing piece

The normative spec, with the field tables, the OTLP mapping, and the versioning
rules, is [`../../docs/contract-v0.md`](../../docs/contract-v0.md). Read it before
changing any type here: on unreleased v0 additive changes are fine (new enum
values, new optional fields), but retyping or removing a field is breaking.

Apache-2.0.
