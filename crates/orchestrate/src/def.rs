// SPDX-License-Identifier: Apache-2.0
//! Benchmark-definition parsing, hashing, validation, and matrix expansion.
//!
//! A run is born from a declarative def committed next to the code under test.
//! This module turns that file into: a stable `benchmark_def_sha`, a set of
//! parameterisation cells (each with its own `params_hash`), and a load-time
//! verdict that rejects the invalid cases before any capture starts.
//!
//! Load-time rejections (the "fails at registration, not at write time"
//! property): missing cardinality decl (a required field, so parse fails),
//! unbounded cardinality, a bounded series without a key source or ceiling,
//! an unknown gate mode, an unknown tenancy class, and a uprobe declared on a
//! hot path (checked when the entry declares its attach kind).

use std::collections::BTreeMap;

use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

// The def is a parsed data model whose fields are consumed incrementally as the
// pipeline lands: host prep reads `host_prep`, the gate hand-off reads the gate
// thresholds, and so on. Allow the not-yet-read fields until those stages wire in.
#[allow(dead_code)]
#[derive(Deserialize, Debug, Clone)]
pub struct BenchmarkDef {
    #[serde(rename = "apiVersion")]
    pub api_version: String,
    pub name: String,
    pub target: Target,
    pub workload: Workload,
    pub gate: GateSpec,
    #[serde(default)]
    pub parameterise: BTreeMap<String, Vec<Value>>,
    /// Names a `parameterise` dimension to use as the A/B axis: its two values
    /// become groups A and B, and `assayist run` gates one against the other in a
    /// single invocation. The dimension is still substituted into config
    /// templates as `{name}` and recorded in each run's `params`. Other
    /// `parameterise` dimensions form cells within each group. Absent = the
    /// legacy A/B-by-SUT behaviour (same config, two builds).
    #[serde(default)]
    pub compare: Option<String>,
    #[serde(default)]
    pub capture: Vec<CaptureEntry>,
    #[serde(default)]
    pub host_prep: Value,
    pub tenancy: String,
}

#[allow(dead_code)]
#[derive(Deserialize, Debug, Clone)]
pub struct Target {
    pub adapter: String,
    #[serde(default)]
    pub version: String,
    /// v0 command-adapter templates, keyed by phase
    /// (`provision`/`start`/`reach_steady`/`spans`/`teardown`/`version`).
    #[serde(default)]
    pub commands: BTreeMap<String, String>,
    /// Native-adapter settings (e.g. the firecracker adapter's `kernel`,
    /// `rootfs`, `api_sock`). Ignored by the command adapter; string values may
    /// reference cell params as `{name}`.
    #[serde(default)]
    pub config: BTreeMap<String, Value>,
}

#[allow(dead_code)]
#[derive(Deserialize, Debug, Clone)]
pub struct Workload {
    pub driver: String,
    #[serde(default)]
    pub version: String,
    /// v0 command-adapter templates, keyed by phase
    /// (`start`/`stop`/`report`/`version`).
    #[serde(default)]
    pub commands: BTreeMap<String, String>,
    /// Native-adapter settings (e.g. the fio adapter's `filename`, `rw`, `bs`).
    /// Ignored by the command adapter; string values may reference cell params
    /// as `{name}`.
    #[serde(default)]
    pub config: BTreeMap<String, Value>,
}

#[allow(dead_code)]
#[derive(Deserialize, Debug, Clone)]
pub struct GateSpec {
    pub mode: String,
    #[serde(default)]
    pub p_threshold: Option<f64>,
    #[serde(default)]
    pub noise_threshold: Option<f64>,
    #[serde(default)]
    pub resamples: Option<u64>,
    #[serde(default)]
    pub ignore: Vec<String>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct CaptureEntry {
    pub probe: String,
    #[serde(default)]
    pub gadget: Option<String>,
    /// Required: a series without a cardinality decl is rejected at load. Making
    /// it non-optional means a missing decl is a parse error, which is the
    /// contract's "rejected by default" behaviour.
    pub cardinality: Cardinality,
    /// Optional attach kind, so the uprobe-on-hot-path check can fire when the
    /// def author declares it. Attach kind is author-declared, not discovered
    /// from the gadget; a declared value is validated against the contract's
    /// `attach_kind` vocabulary.
    #[serde(default)]
    pub attach: Option<String>,
    #[serde(default)]
    pub hot_path: bool,
    /// Extra gadget flags, passed verbatim after `--duration`/`--out`. Gadget
    /// CLIs differ (kvm `--per-guest --max-keys`, net `--iface`, ctrlplane
    /// `--cgroup`), so the author declares them here rather than the orchestrator
    /// inferring gadget-specific flags from the cardinality decl.
    #[serde(default)]
    pub args: Vec<String>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct Cardinality {
    pub class: String,
    #[serde(default)]
    pub key_source: Option<String>,
    #[serde(default)]
    pub max_keys: Option<u64>,
}

/// One expanded parameterisation cell.
#[derive(Debug, Clone)]
pub struct Cell {
    /// Params as a JSON object, e.g. `{"mem_mib": 256, "vcpu": 2}`.
    pub params: Value,
    /// Hash of the canonicalised params. Groups series across runs in the cell.
    pub params_hash: String,
}

const GATE_MODES: [&str; 3] = ["ab_permutation", "longitudinal_drift", "subsystem_triad"];
const TENANCIES: [&str; 2] = ["single_tenant", "density"];
const CARD_CLASSES: [&str; 2] = ["singleton", "bounded"];
/// The contract's `attach_kind` vocabulary (see `contract/assay-run.schema.json`).
/// Attach kind is author-declared, not discovered: the orchestrator does not run
/// a gadget to introspect it, and the load-time uprobe-on-hot-path rejection has
/// to work off static def data. A declared `attach` is validated against this so
/// a typo cannot silently skip the hot-path check.
const ATTACH_KINDS: [&str; 9] =
    ["tp_btf", "tracepoint", "fentry", "fexit", "kprobe", "kretprobe", "uprobe", "xdp", "tc"];

/// Parse a def from YAML text and compute its `benchmark_def_sha` over the raw
/// bytes. Hashing the source text keeps the identity honest: diff the file, get
/// a different hash, no hidden canonicalisation to reason about.
pub fn parse(text: &str) -> Result<(BenchmarkDef, String), String> {
    let def: BenchmarkDef =
        serde_yaml::from_str(text).map_err(|e| format!("parsing benchmark def: {e}"))?;
    Ok((def, sha256_hex(text.as_bytes())))
}

/// Validate the def against the load-time rules. Returns every problem found,
/// not just the first, so the author fixes the file in one pass.
pub fn validate(def: &BenchmarkDef) -> Result<(), Vec<String>> {
    let mut errs = Vec::new();

    if !GATE_MODES.contains(&def.gate.mode.as_str()) {
        errs.push(format!(
            "gate.mode '{}' unknown (want one of {})",
            def.gate.mode,
            GATE_MODES.join(", ")
        ));
    }
    if !TENANCIES.contains(&def.tenancy.as_str()) {
        errs.push(format!(
            "tenancy '{}' unknown (want one of {})",
            def.tenancy,
            TENANCIES.join(", ")
        ));
    }

    if let Some(dim) = &def.compare {
        match def.parameterise.get(dim) {
            None => errs.push(format!(
                "compare '{dim}' names no parameterise dimension (declare it under parameterise with two values)"
            )),
            Some(values) if values.len() != 2 => errs.push(format!(
                "compare '{dim}' needs exactly two values for an A/B comparison, found {}",
                values.len()
            )),
            Some(_) => {}
        }
    }

    for c in &def.capture {
        let where_ = format!("capture '{}'", c.probe);
        if !CARD_CLASSES.contains(&c.cardinality.class.as_str()) {
            // Catches the explicit `unbounded`, which is rejected on purpose:
            // there is no representation for it in the contract.
            errs.push(format!(
                "{where_}: cardinality.class '{}' unknown (want singleton or bounded; unbounded is rejected by design)",
                c.cardinality.class
            ));
        }
        if c.cardinality.class == "bounded" {
            if c.cardinality.key_source.is_none() {
                errs.push(format!("{where_}: bounded cardinality needs a key_source"));
            }
            match c.cardinality.max_keys {
                None => errs.push(format!("{where_}: bounded cardinality needs max_keys")),
                Some(0) => errs.push(format!("{where_}: bounded cardinality max_keys must be > 0")),
                Some(_) => {}
            }
        }
        if let Some(a) = &c.attach {
            if !ATTACH_KINDS.contains(&a.as_str()) {
                errs.push(format!(
                    "{where_}: attach '{a}' unknown (want one of {})",
                    ATTACH_KINDS.join(", ")
                ));
            }
        }
        if c.attach.as_deref() == Some("uprobe") && c.hot_path {
            errs.push(format!(
                "{where_}: uprobe on a hot path is banned (dual context switch); sample off the hot path instead"
            ));
        }
    }

    if errs.is_empty() {
        Ok(())
    } else {
        Err(errs)
    }
}

/// Expand the `parameterise` matrix into the cartesian product of cells. Order
/// is deterministic: parameter names come from a BTreeMap (sorted), and values
/// keep their declared order. No `parameterise` block yields a single empty
/// cell, so an unparameterised def still produces one run group.
pub fn expand_cells(def: &BenchmarkDef) -> Vec<Cell> {
    let axes: Vec<(&String, &Vec<Value>)> = def.parameterise.iter().collect();

    let mut combos: Vec<Vec<Value>> = vec![vec![]];
    for (_, values) in &axes {
        let mut next = Vec::new();
        for combo in &combos {
            for v in values.iter() {
                let mut c = combo.clone();
                c.push(v.clone());
                next.push(c);
            }
        }
        combos = next;
    }

    combos
        .into_iter()
        .map(|combo| {
            let mut map = serde_json::Map::new();
            for ((name, _), v) in axes.iter().zip(combo) {
                map.insert((*name).clone(), v);
            }
            let params = Value::Object(map);
            let params_hash = params_hash(&params);
            Cell { params, params_hash }
        })
        .collect()
}

/// Hash of the canonicalised params. `serde_json::Value::Object` is backed by a
/// BTreeMap only with the `preserve_order` feature off, but we do not rely on
/// that: we serialise through a canonical form (sorted keys, compact) so the
/// hash is stable regardless of insertion order.
pub fn params_hash(params: &Value) -> String {
    sha256_hex(canonical_json(params).as_bytes())
}

fn canonical_json(v: &Value) -> String {
    match v {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let inner: Vec<String> = keys
                .into_iter()
                .map(|k| format!("{}:{}", serde_json::to_string(k).unwrap(), canonical_json(&map[k])))
                .collect();
            format!("{{{}}}", inner.join(","))
        }
        Value::Array(items) => {
            let inner: Vec<String> = items.iter().map(canonical_json).collect();
            format!("[{}]", inner.join(","))
        }
        other => serde_json::to_string(other).unwrap(),
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    let digest = h.finalize();
    let mut s = String::with_capacity(digest.len() * 2);
    for b in digest {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLE: &str = include_str!("../../../examples/firecracker-boot-snapshot.assay.yaml");

    #[test]
    fn parses_the_example_def() {
        let (def, sha) = parse(EXAMPLE).expect("example def parses");
        assert_eq!(def.name, "firecracker-boot-snapshot");
        assert_eq!(def.gate.mode, "ab_permutation");
        assert_eq!(def.target.adapter, "firecracker");
        assert_eq!(def.capture.len(), 2);
        assert_eq!(sha.len(), 64); // sha256 hex
    }

    #[test]
    fn example_def_validates() {
        let (def, _) = parse(EXAMPLE).unwrap();
        validate(&def).expect("example def is valid");
    }

    #[test]
    fn expands_the_full_matrix() {
        let (def, _) = parse(EXAMPLE).unwrap();
        // vcpu [1,2,4] x mem_mib [256,512] = 6 cells.
        let cells = expand_cells(&def);
        assert_eq!(cells.len(), 6);
        // Every cell carries both params and a distinct hash.
        let mut hashes: Vec<&str> = cells.iter().map(|c| c.params_hash.as_str()).collect();
        hashes.sort();
        hashes.dedup();
        assert_eq!(hashes.len(), 6);
        for c in &cells {
            assert!(c.params.get("vcpu").is_some());
            assert!(c.params.get("mem_mib").is_some());
        }
    }

    #[test]
    fn no_parameterise_yields_one_empty_cell() {
        let def = BenchmarkDef {
            api_version: "assayist/v0".into(),
            name: "n".into(),
            target: Target {
                adapter: "a".into(),
                version: String::new(),
                commands: BTreeMap::new(),
                config: BTreeMap::new(),
            },
            workload: Workload {
                driver: "w".into(),
                version: String::new(),
                commands: BTreeMap::new(),
                config: BTreeMap::new(),
            },
            gate: GateSpec {
                mode: "ab_permutation".into(),
                p_threshold: None,
                noise_threshold: None,
                resamples: None,
                ignore: vec![],
            },
            parameterise: BTreeMap::new(),
            compare: None,
            capture: vec![],
            host_prep: Value::Null,
            tenancy: "single_tenant".into(),
        };
        let cells = expand_cells(&def);
        assert_eq!(cells.len(), 1);
        assert_eq!(cells[0].params, serde_json::json!({}));
    }

    #[test]
    fn benchmark_def_sha_tracks_content() {
        let (_, a) = parse(EXAMPLE).unwrap();
        let (_, b) = parse(&format!("{EXAMPLE}\n# a comment changes the file\n")).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn params_hash_is_key_order_independent() {
        let one = serde_json::json!({"vcpu": 2, "mem_mib": 256});
        let two = serde_json::json!({"mem_mib": 256, "vcpu": 2});
        assert_eq!(params_hash(&one), params_hash(&two));
    }

    #[test]
    fn missing_cardinality_is_a_parse_error() {
        let yaml = r#"
apiVersion: assayist/v0
name: bad
target: { adapter: x }
workload: { driver: y }
gate: { mode: ab_permutation }
capture:
  - probe: p
    gadget: g
tenancy: single_tenant
"#;
        // cardinality is a required field, so the def fails to parse: the
        // load-time rejection of a missing cardinality decl.
        assert!(parse(yaml).is_err());
    }

    #[test]
    fn compare_naming_unknown_dimension_is_rejected() {
        let yaml = r#"
apiVersion: assayist/v0
name: bad
target: { adapter: x }
workload: { driver: y }
gate: { mode: ab_permutation }
compare: variant
parameterise:
  vcpu: [1, 2]
tenancy: single_tenant
"#;
        let (def, _) = parse(yaml).unwrap();
        let errs = validate(&def).unwrap_err();
        assert!(errs.iter().any(|e| e.contains("compare 'variant'")));
    }

    #[test]
    fn compare_dimension_needs_exactly_two_values() {
        let yaml = r#"
apiVersion: assayist/v0
name: bad
target: { adapter: x }
workload: { driver: y }
gate: { mode: ab_permutation }
compare: variant
parameterise:
  variant: [a, b, c]
tenancy: single_tenant
"#;
        let (def, _) = parse(yaml).unwrap();
        let errs = validate(&def).unwrap_err();
        assert!(errs.iter().any(|e| e.contains("exactly two values")));
    }

    #[test]
    fn compare_over_a_two_value_dimension_validates() {
        let yaml = r#"
apiVersion: assayist/v0
name: ok
target: { adapter: x }
workload: { driver: y }
gate: { mode: ab_permutation }
compare: variant
parameterise:
  variant: [stock, prefetch]
tenancy: single_tenant
"#;
        let (def, _) = parse(yaml).unwrap();
        validate(&def).expect("two-value compare is valid");
        // The compare dimension is a normal parameterise axis: it expands to two
        // cells whose params carry the variant, which run_cmd splits into A/B.
        let cells = expand_cells(&def);
        assert_eq!(cells.len(), 2);
    }

    #[test]
    fn unbounded_cardinality_is_rejected() {
        let yaml = r#"
apiVersion: assayist/v0
name: bad
target: { adapter: x }
workload: { driver: y }
gate: { mode: ab_permutation }
capture:
  - probe: p
    cardinality: { class: unbounded }
tenancy: single_tenant
"#;
        let (def, _) = parse(yaml).unwrap();
        let errs = validate(&def).unwrap_err();
        assert!(errs.iter().any(|e| e.contains("unbounded")));
    }

    #[test]
    fn bounded_without_key_source_or_max_keys_is_rejected() {
        let yaml = r#"
apiVersion: assayist/v0
name: bad
target: { adapter: x }
workload: { driver: y }
gate: { mode: ab_permutation }
capture:
  - probe: p
    cardinality: { class: bounded }
tenancy: single_tenant
"#;
        let (def, _) = parse(yaml).unwrap();
        let errs = validate(&def).unwrap_err();
        assert!(errs.iter().any(|e| e.contains("key_source")));
        assert!(errs.iter().any(|e| e.contains("max_keys")));
    }

    #[test]
    fn unknown_gate_mode_and_tenancy_are_rejected() {
        let yaml = r#"
apiVersion: assayist/v0
name: bad
target: { adapter: x }
workload: { driver: y }
gate: { mode: bogus }
capture: []
tenancy: whatever
"#;
        let (def, _) = parse(yaml).unwrap();
        let errs = validate(&def).unwrap_err();
        assert!(errs.iter().any(|e| e.contains("gate.mode")));
        assert!(errs.iter().any(|e| e.contains("tenancy")));
    }

    #[test]
    fn unknown_attach_kind_is_rejected() {
        // A typo like `uprob` must be rejected, not silently skip the hot-path
        // check by failing the `== "uprobe"` comparison.
        let yaml = r#"
apiVersion: assayist/v0
name: bad
target: { adapter: x }
workload: { driver: y }
gate: { mode: ab_permutation }
capture:
  - probe: p
    attach: uprob
    hot_path: true
    cardinality: { class: singleton }
tenancy: single_tenant
"#;
        let (def, _) = parse(yaml).unwrap();
        let errs = validate(&def).unwrap_err();
        assert!(errs.iter().any(|e| e.contains("attach 'uprob' unknown")));
    }

    #[test]
    fn known_attach_kinds_are_accepted() {
        for kind in ["tp_btf", "tracepoint", "fentry", "kprobe", "uprobe", "tc"] {
            let yaml = format!(
                r#"
apiVersion: assayist/v0
name: ok
target: {{ adapter: x }}
workload: {{ driver: y }}
gate: {{ mode: ab_permutation }}
capture:
  - probe: p
    attach: {kind}
    cardinality: {{ class: singleton }}
tenancy: single_tenant
"#
            );
            let (def, _) = parse(&yaml).unwrap();
            validate(&def).unwrap_or_else(|e| panic!("attach {kind} should validate: {e:?}"));
        }
    }

    #[test]
    fn uprobe_on_hot_path_is_rejected_when_declared() {
        let yaml = r#"
apiVersion: assayist/v0
name: bad
target: { adapter: x }
workload: { driver: y }
gate: { mode: ab_permutation }
capture:
  - probe: p
    attach: uprobe
    hot_path: true
    cardinality: { class: singleton }
tenancy: single_tenant
"#;
        let (def, _) = parse(yaml).unwrap();
        let errs = validate(&def).unwrap_err();
        assert!(errs.iter().any(|e| e.contains("uprobe")));
    }
}
