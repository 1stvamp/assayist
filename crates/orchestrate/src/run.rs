// SPDX-License-Identifier: Apache-2.0
//! Assembling one graded `AssayRun` from a fingerprint, an identity, a gate
//! context, and the collected fragments.
//!
//! The heavy lifting (merging series/self_metrics, computing the grade) lives in
//! `assayist_contract::AssayRun::assemble`. This module only builds the pieces
//! the orchestrator owns: the run identity, the gate context, and a run id.

use assayist_contract::{AssayRun, Fingerprint, Fragment, Identity};
use serde_json::{json, Value};

use crate::def::BenchmarkDef;

/// Adapter and workload versions, discovered from the running adapters. Held
/// separately because the def carries a version *constraint* (e.g. `>=0.3`),
/// not the actual version that produced a result. The real adapters supply
/// these in the run-loop stage; a placeholder stands in until then.
#[derive(Clone, Debug)]
pub struct AdapterVersions {
    pub target: String,
    pub workload: String,
}

impl Default for AdapterVersions {
    fn default() -> Self {
        AdapterVersions { target: "0.0.0".into(), workload: "0.0.0".into() }
    }
}

/// Build the run identity for one parameterisation cell.
pub fn build_identity(
    def: &BenchmarkDef,
    params: Value,
    params_hash: String,
    benchmark_def_sha: &str,
    sut_git_sha: &str,
    versions: &AdapterVersions,
) -> Identity {
    Identity {
        target_adapter: def.target.adapter.clone(),
        target_adapter_version: versions.target.clone(),
        workload_driver: def.workload.driver.clone(),
        workload_driver_version: versions.workload.clone(),
        sut_git_sha: sut_git_sha.to_string(),
        params,
        params_hash,
        benchmark_def_sha: benchmark_def_sha.to_string(),
        source: "captured".into(),
    }
}

/// Build the gate context. `baseline_ref` is empty at capture time (the A run's
/// id is only known once both groups exist); the gate hand-off fills it.
pub fn build_gate_context(def: &BenchmarkDef, baseline_ref: &str) -> Value {
    json!({
        "mode": def.gate.mode,
        "baseline_ref": baseline_ref,
        "p_threshold": def.gate.p_threshold.unwrap_or(0.01),
        "noise_threshold": def.gate.noise_threshold.unwrap_or(0.05),
        "resamples": def.gate.resamples.unwrap_or(10_000),
        "ignore": def.gate.ignore,
        "tenancy": def.tenancy,
    })
}

/// Assemble and grade one run.
pub fn assemble(
    run_id: String,
    identity: Identity,
    fingerprint: Fingerprint,
    gate: Value,
    fragments: &[Fragment],
    spans: Vec<Value>,
) -> AssayRun {
    AssayRun::assemble(run_id, identity, fingerprint, gate, fragments, spans)
}

/// A 128-bit run id as 32 hex chars. Not a canonical ULID yet (no lexicographic
/// time ordering, no dedicated crate); good enough to be unique per run and to
/// map onto an OTLP `trace_id`. See TODO.md for switching to a real ULID.
pub fn new_run_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let pid = std::process::id() as u128;
    let mixed = (nanos << 32) ^ pid.wrapping_mul(0x9E37_79B9_7F4A_7C15);
    format!("{mixed:032x}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::def;
    use assayist_contract::Grade;

    const EXAMPLE: &str = include_str!("../../../examples/firecracker-boot-snapshot.assay.yaml");

    // A canned kvm fragment, shaped like the one in capture/kvm/README.md.
    fn kvm_fragment() -> Fragment {
        let v = json!({
            "series": [{
                "name": "kvm.exit_handling_latency:EPT_VIOLATION",
                "unit": "ns", "kind": "histogram", "source": "kvm_exit",
                "cardinality": { "class": "singleton" },
                "data": { "layout": "log2", "buckets": [1, 2, 3], "count": 6 }
            }],
            "self_metrics": [{
                "probe_id": "kvm_exit", "attach_kind": "tracepoint",
                "run_time_ns": 41200, "run_cnt": 12873, "mean_ns": 3.2,
                "steady_cpu_fraction": 0.0000013, "over_budget": false
            }],
            "capture_meta": { "gadget": "assayist-capture-kvm" }
        });
        serde_json::from_value(v).unwrap()
    }

    fn extended_fingerprint() -> Fingerprint {
        Fingerprint {
            hostname: "lab".into(),
            kernel_version: "6.11.0".into(),
            os_release: "Ubuntu".into(),
            cpu_model: "Ryzen".into(),
            cpu_count_logical: 16,
            cpu_count_physical: 8,
            smt_enabled: false,
            cpu_governor: "performance".into(),
            thp_setting: "never".into(),
            total_memory_bytes: 1 << 37,
            kvm_present: true,
            tenancy: "single_tenant".into(),
            tuning_requested: json!({"cpu_governor": "performance"}),
            tuning_readback: json!({"cpu_governor": "performance"}),
            numa_topology: Some(json!({"node0": "0-15"})),
            pinning_layout: Some(json!({"vcpu0": 2})),
            mitigations: Some(json!({})),
            microcode_version: Some("x".into()),
            nested_virt: Some(false),
        }
    }

    #[test]
    fn identity_and_gate_come_from_the_def() {
        let (def, sha) = def::parse(EXAMPLE).unwrap();
        let cell = &def::expand_cells(&def)[0];
        let id = build_identity(
            &def,
            cell.params.clone(),
            cell.params_hash.clone(),
            &sha,
            "cafe1234",
            &AdapterVersions::default(),
        );
        assert_eq!(id.target_adapter, "firecracker");
        assert_eq!(id.workload_driver, "fio-libaio");
        assert_eq!(id.sut_git_sha, "cafe1234");
        assert_eq!(id.benchmark_def_sha, sha);

        let gate = build_gate_context(&def, "");
        assert_eq!(gate["mode"], "ab_permutation");
        assert_eq!(gate["p_threshold"], 0.01);
        assert_eq!(gate["tenancy"], "single_tenant");
    }

    #[test]
    fn assembles_a_graded_run_from_a_fragment() {
        let (def, sha) = def::parse(EXAMPLE).unwrap();
        let cell = &def::expand_cells(&def)[0];
        let id = build_identity(
            &def,
            cell.params.clone(),
            cell.params_hash.clone(),
            &sha,
            "cafe1234",
            &AdapterVersions::default(),
        );
        let gate = build_gate_context(&def, "");
        let run = assemble(
            "01".into(),
            id,
            extended_fingerprint(),
            gate,
            &[kvm_fragment()],
            vec![],
        );
        // Extended fingerprint + consistent tuning + self_metrics present.
        assert_eq!(run.grade, Grade::Reproducible);
        assert_eq!(run.series.len(), 1);
        assert_eq!(run.self_metrics.len(), 1);
        // Round-trips as JSON (what gets written to the output dir).
        assert!(serde_json::to_string(&run).is_ok());
    }

    #[test]
    fn run_ids_are_hex_and_sized() {
        let id = new_run_id();
        assert_eq!(id.len(), 32);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
