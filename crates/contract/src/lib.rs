// SPDX-FileCopyrightText: 2026 Wesley Mason (1stvamp)
// SPDX-License-Identifier: Apache-2.0
//! Typed, producer-side model of the Assayist contract.
//!
//! The gate consumes runs liberally (via serde_json::Value, tolerant of
//! slightly-off records so it can grade rather than hard-fail). This crate is
//! the strict producer side: the orchestrator builds an [`AssayRun`] with these
//! types, so a missing core fingerprint field is a deserialise/construct error,
//! which is exactly the "no complete fingerprint, no valid record" rule.

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const SCHEMA_VERSION: &str = "0.1.0";

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Grade {
    Reproducible,
    Valid,
    Invalid,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Identity {
    pub target_adapter: String,
    pub target_adapter_version: String,
    pub workload_driver: String,
    pub workload_driver_version: String,
    pub sut_git_sha: String,
    pub params: Value,
    pub params_hash: String,
    pub benchmark_def_sha: String,
    #[serde(default = "default_source")]
    pub source: String,
}

fn default_source() -> String {
    "captured".to_string()
}

/// Core fields are required by the type: a record missing any of them fails to
/// deserialise, which is the contract's parse-time rejection. Extended fields
/// are optional and lift the grade to `reproducible` when all present.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Fingerprint {
    pub hostname: String,
    pub kernel_version: String,
    pub os_release: String,
    pub cpu_model: String,
    pub cpu_count_logical: u32,
    pub cpu_count_physical: u32,
    pub smt_enabled: bool,
    pub cpu_governor: String,
    pub thp_setting: String,
    pub total_memory_bytes: u64,
    pub kvm_present: bool,
    pub tenancy: String,
    pub tuning_requested: Value,
    pub tuning_readback: Value,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub numa_topology: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pinning_layout: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mitigations: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub microcode_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nested_virt: Option<bool>,
}

impl Fingerprint {
    /// True when every extended field is present.
    pub fn has_extended(&self) -> bool {
        self.numa_topology.is_some()
            && self.pinning_layout.is_some()
            && self.mitigations.is_some()
            && self.microcode_version.is_some()
            && self.nested_virt.is_some()
    }

    /// Host prep actually took effect: requested tuning equals read-back.
    pub fn tuning_consistent(&self) -> bool {
        self.tuning_requested == self.tuning_readback
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AssayRun {
    pub schema_version: String,
    pub run_id: String,
    pub identity: Identity,
    pub fingerprint: Fingerprint,
    #[serde(default)]
    pub spans: Vec<Value>,
    #[serde(default)]
    pub series: Vec<Value>,
    #[serde(default)]
    pub self_metrics: Vec<Value>,
    pub gate: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<Value>,
    /// Opaque workload-driver report (e.g. fio's JSON output). Provenance only:
    /// it does not affect grading or gating. Additive optional field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workload_report: Option<Value>,
    pub grade: Grade,
}

/// A capture-gadget fragment: series + self_metrics + optional capture_meta.
#[derive(Deserialize, Default, Clone, Debug)]
pub struct Fragment {
    #[serde(default)]
    pub series: Vec<Value>,
    #[serde(default)]
    pub self_metrics: Vec<Value>,
    #[serde(default)]
    pub capture_meta: Option<Value>,
}

impl AssayRun {
    /// Build a run from identity, fingerprint, gate context and merged
    /// fragments, then compute and stamp the grade.
    pub fn assemble(
        run_id: String,
        identity: Identity,
        fingerprint: Fingerprint,
        gate: Value,
        fragments: &[Fragment],
        spans: Vec<Value>,
    ) -> AssayRun {
        let mut series = Vec::new();
        let mut self_metrics = Vec::new();
        for f in fragments {
            series.extend(f.series.iter().cloned());
            self_metrics.extend(f.self_metrics.iter().cloned());
        }
        // A probe ran if any fragment carried series or capture metadata. This
        // is the signal independent of self_metrics: a gadget that produced data
        // but no cost record leaves probes_ran true and self_metrics empty, which
        // is exactly the case the grade must catch.
        let probes_ran = fragments
            .iter()
            .any(|f| !f.series.is_empty() || f.capture_meta.is_some());
        let mut run = AssayRun {
            schema_version: SCHEMA_VERSION.to_string(),
            run_id,
            identity,
            fingerprint,
            spans,
            series,
            self_metrics,
            gate,
            outcome: None,
            workload_report: None,
            grade: Grade::Invalid,
        };
        run.grade = run.compute_grade(probes_ran);
        run
    }

    /// Grade per the contract. Core fields are guaranteed present by the type,
    /// so the only ways to fall below `reproducible` are inconsistent tuning
    /// (=> invalid), missing extended fields, or probes that ran without
    /// emitting their observer-effect self_metrics. `probes_ran` is supplied by
    /// the producer (it knows whether any gadget fired), since a fully-assembled
    /// run cannot tell "no probes" from "probes but no cost record" on its own.
    pub fn compute_grade(&self, probes_ran: bool) -> Grade {
        if !self.fingerprint.tuning_consistent() {
            return Grade::Invalid;
        }
        if self.identity.source == "imported" {
            return Grade::Valid;
        }
        let self_metrics_ok = !probes_ran || !self.self_metrics.is_empty();
        if self.fingerprint.has_extended() && self_metrics_ok {
            Grade::Reproducible
        } else {
            Grade::Valid
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn fp(extended: bool, consistent: bool) -> Fingerprint {
        Fingerprint {
            hostname: "lab".into(),
            kernel_version: "6.11.0".into(),
            os_release: "Ubuntu 26.04".into(),
            cpu_model: "Ryzen".into(),
            cpu_count_logical: 16,
            cpu_count_physical: 8,
            smt_enabled: false,
            cpu_governor: "performance".into(),
            thp_setting: "never".into(),
            total_memory_bytes: 1 << 37,
            kvm_present: true,
            tenancy: "single_tenant".into(),
            tuning_requested: json!({"g": "performance"}),
            tuning_readback: json!({"g": if consistent {"performance"} else {"powersave"}}),
            numa_topology: if extended { Some(json!({})) } else { None },
            pinning_layout: if extended { Some(json!({})) } else { None },
            mitigations: if extended { Some(json!({})) } else { None },
            microcode_version: if extended { Some("x".into()) } else { None },
            nested_virt: if extended { Some(false) } else { None },
        }
    }

    fn id() -> Identity {
        Identity {
            target_adapter: "firecracker".into(),
            target_adapter_version: "0.3.0".into(),
            workload_driver: "fio".into(),
            workload_driver_version: "0.1.0".into(),
            sut_git_sha: "abc1234".into(),
            params: json!({"vcpu": 2}),
            params_hash: "c1".into(),
            benchmark_def_sha: "def5678".into(),
            source: "captured".into(),
        }
    }

    #[test]
    fn full_fingerprint_and_consistent_tuning_is_reproducible() {
        let run = AssayRun::assemble("01".into(), id(), fp(true, true), json!({}), &[], vec![]);
        assert_eq!(run.grade, Grade::Reproducible);
    }

    #[test]
    fn missing_extended_is_valid_not_reproducible() {
        let run = AssayRun::assemble("01".into(), id(), fp(false, true), json!({}), &[], vec![]);
        assert_eq!(run.grade, Grade::Valid);
    }

    #[test]
    fn inconsistent_tuning_is_invalid() {
        let run = AssayRun::assemble("01".into(), id(), fp(true, false), json!({}), &[], vec![]);
        assert_eq!(run.grade, Grade::Invalid);
    }

    #[test]
    fn probes_without_self_metrics_are_not_reproducible() {
        // A gadget produced series but no cost record: the observer-effect
        // record is missing, so an otherwise-reproducible run drops to valid.
        let frag = Fragment {
            series: vec![json!({"name": "kvm.exit"})],
            self_metrics: vec![],
            capture_meta: Some(json!({"gadget": "assayist-capture-kvm"})),
        };
        let run = AssayRun::assemble("01".into(), id(), fp(true, true), json!({}), &[frag], vec![]);
        assert_eq!(run.grade, Grade::Valid);
    }

    #[test]
    fn probes_with_self_metrics_are_reproducible() {
        let frag = Fragment {
            series: vec![json!({"name": "kvm.exit"})],
            self_metrics: vec![json!({"probe_id": "kvm_exit"})],
            capture_meta: None,
        };
        let run = AssayRun::assemble("01".into(), id(), fp(true, true), json!({}), &[frag], vec![]);
        assert_eq!(run.grade, Grade::Reproducible);
    }

    #[test]
    fn workload_report_defaults_none_and_round_trips() {
        let mut run = AssayRun::assemble("01".into(), id(), fp(true, true), json!({}), &[], vec![]);
        // Defaults to None and is omitted from JSON when absent.
        assert!(run.workload_report.is_none());
        assert!(!serde_json::to_string(&run).unwrap().contains("workload_report"));
        // When set, it round-trips.
        run.workload_report = Some(json!({"fio": {"iops": 1234}}));
        let text = serde_json::to_string(&run).unwrap();
        let back: AssayRun = serde_json::from_str(&text).unwrap();
        assert_eq!(back.workload_report, Some(json!({"fio": {"iops": 1234}})));
    }

    #[test]
    fn fragments_merge_series_and_self_metrics() {
        let frag = Fragment {
            series: vec![json!({"name": "x"})],
            self_metrics: vec![json!({"probe_id": "p"})],
            capture_meta: None,
        };
        let run = AssayRun::assemble("01".into(), id(), fp(true, true), json!({}), &[frag], vec![]);
        assert_eq!(run.series.len(), 1);
        assert_eq!(run.self_metrics.len(), 1);
    }
}
