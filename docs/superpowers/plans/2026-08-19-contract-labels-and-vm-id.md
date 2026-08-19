<!--
SPDX-FileCopyrightText: 2026 Wesley Mason (1stvamp)
SPDX-License-Identifier: Apache-2.0
-->

# Contract labels + vm_id key_source Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the additive contract vocabulary the network datapath gadgets need: an optional `MetricSeries.labels` map, a `vm_id` value in the `key_source` enum, and the gate read-path change that groups series like-for-like by their labels.

**Architecture:** Series are carried as untyped `serde_json::Value` through the contract crate and orchestrator, so the producer-side change is the JSON schema plus docs, with a guard test pinning the schema shape. The one behavioural code change is in the gate's `reduce()`: fold a canonical, order-independent `labels` suffix into each metric's `id` so two runs' series join on `(name, key, labels)`, and series that differ only by label (paused vs running, tap vs netkit) become distinct metrics.

**Tech Stack:** Rust (workspace core, builds anywhere, no BTF), `serde_json`, JSON Schema draft in `contract/assay-run.schema.json`, GitButler (`but`) for commits.

**Spec:** `docs/superpowers/specs/2026-08-19-network-datapath-gadgets-design.md` (sub-project 1).

## Global Constraints

- Additive only on v0: new optional fields and new enum values. Nothing retyped, nothing removed. (`CLAUDE.local.md` contract discipline.)
- Producer strict, consumer liberal: a run with no `labels` grades exactly as today; the gate ignores label keys it does not recognise.
- Every `MetricSeries` still declares a cardinality class; there is no `unbounded`. `labels` does not change that.
- Prose, comments, and commit messages: no em or en dashes; British spelling; no banned AI-tell words.
- Version control is GitButler. Commit with `but commit <branch> -m "..." --changes <ids>` (get ids from `but diff`). Do not use `git` write commands.
- Commit type convention: `type(scope): summary`. This work is `feat(contract)` / `feat(gate)`.
- Run all commits on one session branch: `feat/contract-labels`. Create it on the first commit with `-c`.

---

### Task 1: Schema and docs additions, with a shape-guard test

Adds `labels` to `MetricSeries` and `vm_id` to the `key_source` enum in the JSON schema, documents both in the contract doc, and pins the schema shape with a test in the contract crate so a future edit cannot silently drop them. `def.rs` does not enumerate `key_source` values (it only requires one to be present for bounded), so no Rust validation change is needed for the enum.

**Files:**
- Modify: `contract/assay-run.schema.json` (MetricSeries properties around line 160-173; CardinalityDecl.key_source enum around line 143-146)
- Modify: `docs/contract-v0.md` (MetricSeries and cardinality sections)
- Test: `crates/contract/src/lib.rs` (existing `#[cfg(test)] mod tests` at line 187)

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: the schema property `MetricSeries.labels` (optional object, values are `Scalar`) and the `key_source` enum value `"vm_id"`. Task 2 relies on producers being allowed to emit `labels`, but does not import anything from this task.

- [ ] **Step 1: Write the failing guard test**

Add to the `mod tests` block in `crates/contract/src/lib.rs`:

```rust
#[test]
fn schema_carries_labels_and_vm_id_key_source() {
    // Pin the additive contract vocabulary the network gadgets depend on.
    // The schema file is the authority; this guards against a silent drop.
    let schema: serde_json::Value =
        serde_json::from_str(include_str!("../../../contract/assay-run.schema.json"))
            .expect("schema is valid JSON");

    let series = &schema["$defs"]["MetricSeries"]["properties"];
    assert!(
        series.get("labels").is_some(),
        "MetricSeries must declare an optional labels property"
    );

    let key_source_enum = schema["$defs"]["CardinalityDecl"]["properties"]["key_source"]["enum"]
        .as_array()
        .expect("key_source has an enum");
    assert!(
        key_source_enum.iter().any(|v| v == "vm_id"),
        "key_source enum must include vm_id"
    );
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p assayist-contract schema_carries_labels_and_vm_id_key_source`
Expected: FAIL. The `labels` assertion trips (property absent) or the `vm_id` assertion trips (not in enum).

- [ ] **Step 3: Add `vm_id` to the key_source enum**

In `contract/assay-run.schema.json`, the `CardinalityDecl.key_source` enum currently reads:

```json
"key_source": {
  "type": "string",
  "enum": ["vcpu_pid_map", "cgroup_id", "guest_index", "device", "netdev"]
},
```

Add `"vm_id"`:

```json
"key_source": {
  "type": "string",
  "enum": ["vcpu_pid_map", "cgroup_id", "guest_index", "device", "netdev", "vm_id"]
},
```

- [ ] **Step 4: Add the `labels` property to MetricSeries**

In the `MetricSeries.properties` object, after the `key` property and before `cardinality_overflow`, add:

```json
"labels": {
  "type": "object",
  "description": "Optional attribution dimensions a single key cannot carry (e.g. vm_id, lifecycle_state, backend). Values are scalars. The gate groups like-for-like by the label set and ignores unknown keys.",
  "additionalProperties": { "$ref": "#/$defs/Scalar" }
},
```

`MetricSeries` keeps `additionalProperties: false`; `labels` is a named optional property, so this stays valid.

- [ ] **Step 5: Run test to verify it passes**

Run: `cargo test -p assayist-contract schema_carries_labels_and_vm_id_key_source`
Expected: PASS.

- [ ] **Step 6: Document both additions in the contract doc**

In `docs/contract-v0.md`, in the MetricSeries section, add a paragraph after the `key` description:

```markdown
`labels` (optional): an attribution map for dimensions a single `key`
cannot carry, e.g. `vm_id`, `lifecycle_state`, `backend`. Values are
scalars. The gate groups series like-for-like by the full label set and
ignores label keys it does not recognise, so a run with no `labels`
grades exactly as before. `labels` does not replace `key`: `key` stays
the primary bounded-cardinality key, `labels` carries the rest.
```

In the cardinality section, add `vm_id` to the listed `key_source` values with a one-line gloss:

```markdown
- `vm_id`: per-VM attribution from the network gadgets' shared
  attribution map (ifindex to vm_id).
```

- [ ] **Step 7: Run the whole contract suite**

Run: `cargo test -p assayist-contract`
Expected: PASS (existing tests plus the new guard).

- [ ] **Step 8: Commit**

```bash
but diff
but commit feat/contract-labels -c -m "feat(contract): add MetricSeries.labels and vm_id key_source

Additive v0 vocabulary for the network datapath gadgets: an optional
labels map for multi-dimensional attribution (vm_id, lifecycle_state,
backend) and a vm_id value in the key_source enum. Schema and doc only;
series stay untyped Value, so no producer struct changes. A contract-crate
guard test pins the schema shape." --changes <schema-id>,<doc-id>,<lib-id>
```

---

### Task 2: Gate groups series by labels in `reduce()`

Fold a canonical labels suffix into each metric `id` so series join on `(name, key, labels)` across runs. Order-independent (sorted by label key) so a producer can emit labels in any order and still match. Series differing only by a label become distinct metrics, which is what the pause/resume and backend comparisons need.

**Files:**
- Modify: `crates/gate/src/reduce.rs` (the `base` construction at lines 141-144; add two helper fns near the other free fns around line 82-92)
- Test: `crates/gate/src/reduce.rs` (existing `#[cfg(test)] mod tests` at line 257)

**Interfaces:**
- Consumes: producers may now emit `series[].labels` (Task 1). Reads `s.get("labels")` as an optional object of scalars.
- Produces: metric ids of the form `name|key|k1=v1|k2=v2|...` with label pairs sorted by key. Downstream gate comparison (`gate.rs`) already joins runs by metric `id`, so no change there.

- [ ] **Step 1: Write the failing tests**

Add to the `mod tests` block in `crates/gate/src/reduce.rs`:

```rust
#[test]
fn labels_qualify_the_metric_id() {
    // Same name and key, different lifecycle_state -> distinct metric ids,
    // so paused and running samples never collapse into one series.
    let run = json!({
        "series": [
            {
                "name": "net.softirq_ns", "unit": "ns", "kind": "counter",
                "source": "softirq", "key": "vm7",
                "labels": { "lifecycle_state": "running", "backend": "tap" },
                "data": { "value": 100, "start_unix_nano": 0 }
            },
            {
                "name": "net.softirq_ns", "unit": "ns", "kind": "counter",
                "source": "softirq", "key": "vm7",
                "labels": { "lifecycle_state": "paused", "backend": "tap" },
                "data": { "value": 5, "start_unix_nano": 0 }
            }
        ]
    });
    let m: std::collections::HashMap<String, Metric> =
        reduce(&run).into_iter().map(|x| (x.id.clone(), x)).collect();

    // Label pairs are sorted by key: backend before lifecycle_state.
    assert_eq!(m["net.softirq_ns|vm7|backend=tap|lifecycle_state=running|value"].value, 100.0);
    assert_eq!(m["net.softirq_ns|vm7|backend=tap|lifecycle_state=paused|value"].value, 5.0);
}

#[test]
fn label_order_does_not_change_the_id() {
    // Producer emits the same labels in two different orders; both reduce to
    // the same id so they join across runs.
    let a = json!({ "series": [{
        "name": "net.drops", "unit": "1", "kind": "counter", "source": "kfree_skb",
        "key": "vm1", "labels": { "backend": "tap", "lifecycle_state": "paused" },
        "data": { "value": 3, "start_unix_nano": 0 }
    }]});
    let b = json!({ "series": [{
        "name": "net.drops", "unit": "1", "kind": "counter", "source": "kfree_skb",
        "key": "vm1", "labels": { "lifecycle_state": "paused", "backend": "tap" },
        "data": { "value": 3, "start_unix_nano": 0 }
    }]});
    let id_a = reduce(&a).into_iter().find(|m| m.id.ends_with("|value")).unwrap().id;
    let id_b = reduce(&b).into_iter().find(|m| m.id.ends_with("|value")).unwrap().id;
    assert_eq!(id_a, id_b);
}

#[test]
fn no_labels_reduces_as_before() {
    // Absence of labels leaves the id unchanged (name|key), so existing runs
    // grade identically.
    let run = json!({ "series": [{
        "name": "block.io_bytes:read", "unit": "By", "kind": "counter",
        "source": "block_rq_complete", "key": "254:0",
        "data": { "value": 42, "start_unix_nano": 0 }
    }]});
    let ids: Vec<String> = reduce(&run).into_iter().map(|m| m.id).collect();
    assert!(ids.contains(&"block.io_bytes:read|254:0|value".to_string()));
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p assayist-gate labels_qualify_the_metric_id label_order_does_not_change_the_id no_labels_reduces_as_before`
Expected: FAIL. The label tests fail because `base` ignores `labels` (ids lack the `|k=v` suffix). `no_labels_reduces_as_before` should already PASS, which confirms the no-op path.

- [ ] **Step 3: Add the label-suffix helpers**

In `crates/gate/src/reduce.rs`, near the other small free functions (after `f64s`, around line 92), add:

```rust
/// Render a label value (a Scalar: string, number, integer, or boolean) as a
/// plain string. Strings are used bare (no JSON quotes) so ids read cleanly.
fn scalar_to_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// Canonical, order-independent suffix for a series' labels, appended to the
/// metric id so the gate matches series on (name, key, labels). Sorted by
/// label key, so a producer may emit labels in any order and still join across
/// runs. Empty or absent labels contribute nothing, leaving legacy ids intact.
fn labels_suffix(labels: Option<&Value>) -> String {
    let obj = match labels.and_then(|v| v.as_object()) {
        Some(o) if !o.is_empty() => o,
        _ => return String::new(),
    };
    let mut pairs: Vec<(&String, String)> =
        obj.iter().map(|(k, v)| (k, scalar_to_string(v))).collect();
    pairs.sort_by(|a, b| a.0.cmp(b.0));
    let mut s = String::new();
    for (k, v) in pairs {
        s.push_str(&format!("|{k}={v}"));
    }
    s
}
```

- [ ] **Step 4: Fold the suffix into `base`**

In `reduce()`, the `base` construction currently reads:

```rust
let base = match key {
    Some(k) => format!("{name}|{k}"),
    None => name.to_string(),
};
```

Append the labels suffix:

```rust
let base = match key {
    Some(k) => format!("{name}|{k}"),
    None => name.to_string(),
};
let base = format!("{base}{}", labels_suffix(s.get("labels")));
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test -p assayist-gate labels_qualify_the_metric_id label_order_does_not_change_the_id no_labels_reduces_as_before`
Expected: PASS.

- [ ] **Step 6: Run the whole gate suite and the scenario check**

Run: `cargo test -p assayist-gate`
Expected: PASS (labels folding does not disturb existing labelless series).

Run: `bash scripts/verify-gate.sh`
Expected: all six verdicts and exit codes as before; the synthetic runs carry no labels, so ids are unchanged.

- [ ] **Step 7: Commit**

```bash
but diff
but commit feat/contract-labels -m "feat(gate): group series like-for-like by labels

reduce() folds a canonical, order-independent labels suffix into each
metric id, so series join on (name, key, labels) across runs and series
that differ only by a label (paused vs running, tap vs netkit) become
distinct metrics. Labelless series are untouched, so existing runs grade
identically." --changes <reduce-id>
```

---

## Self-Review

**Spec coverage (sub-project 1):**
- `MetricSeries.labels` optional map: Task 1, Steps 4/6, guard test Step 1.
- `key_source += vm_id`: Task 1, Steps 3/6, guard test Step 1.
- Gate read-path grouping by label subset: Task 2 (helpers + `base` fold + three tests).
- Producer strict / consumer liberal, labelless run grades as before: Task 2, `no_labels_reduces_as_before`, and `verify-gate.sh` at Step 6.
- No new required fields, additive only: Task 1 keeps `additionalProperties: false` and adds only optional property + enum value.

**Placeholder scan:** none. Every code step carries the actual code; `<...-id>` tokens in commit commands are change ids the executor reads from `but diff` at that step, not code placeholders.

**Type consistency:** `labels_suffix(Option<&Value>)` and `scalar_to_string(&Value)` are defined in Task 2 Step 3 and used in Step 4. Metric id shape `name|key|k=v|...|value` in the Task 2 tests matches the `base` fold and the existing `push(... format!("{base}|value"))` in `reduce()`. The guard test in Task 1 reads `$defs.MetricSeries.properties.labels` and `$defs.CardinalityDecl.properties.key_source.enum`, matching the schema paths edited in Steps 3/4.

**Scope:** one dependency-root sub-project, two tasks, each independently testable. Fits one plan.
