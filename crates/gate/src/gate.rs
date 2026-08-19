// SPDX-FileCopyrightText: 2026 Wesley Mason (1stvamp)
// SPDX-License-Identifier: Apache-2.0
// The decision gate. Three modes, one shared reduction and stats core.

use std::collections::BTreeMap;

use serde_json::{json, Value};

use crate::reduce::{reduce, Polarity};
use crate::stats;

pub struct Config {
    pub p_threshold: f64,
    pub noise_threshold: f64,
    pub min_effect: f64,
    pub resamples: usize,
    pub drift_k: f64,
    pub seed: u64,
    pub ignore: Vec<String>,
    pub allow_ungraded: bool,
    pub strict_single_cell: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            p_threshold: 0.01,
            noise_threshold: 0.05,
            min_effect: 0.05,
            resamples: 10000,
            drift_k: 3.0,
            seed: 0xA55A_1571_D000_0001,
            ignore: Vec::new(),
            allow_ungraded: false,
            strict_single_cell: false,
        }
    }
}

fn grade_of(run: &Value) -> String {
    if let Some(g) = run.get("grade").and_then(|v| v.as_str()) {
        return g.to_string();
    }
    // Fall back to a coarse derivation if grade was not precomputed.
    match run.get("fingerprint") {
        None => "invalid".to_string(),
        Some(fp) => {
            let core = ["kernel_version", "cpu_model", "tenancy", "cpu_governor"];
            if core.iter().all(|k| fp.get(k).map(|v| !v.is_null()).unwrap_or(false)) {
                "valid".to_string()
            } else {
                "invalid".to_string()
            }
        }
    }
}

fn tenancy_of(run: &Value) -> Option<String> {
    run.get("fingerprint")
        .and_then(|fp| fp.get("tenancy"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

fn params_hash(run: &Value) -> String {
    run.get("identity")
        .and_then(|i| i.get("params_hash"))
        .and_then(|v| v.as_str())
        .unwrap_or("_")
        .to_string()
}

/// Collect per-metric samples across a group of runs, tracking contamination,
/// polarity, and which parameterisation cells contributed.
struct Group {
    samples: BTreeMap<String, Vec<f64>>,
    contaminated: BTreeMap<String, bool>,
    polarity: BTreeMap<String, Polarity>,
    cells: BTreeMap<String, Vec<String>>, // metric -> params cells seen
}

fn collect(runs: &[Value]) -> Group {
    let mut g = Group {
        samples: BTreeMap::new(),
        contaminated: BTreeMap::new(),
        polarity: BTreeMap::new(),
        cells: BTreeMap::new(),
    };
    for run in runs {
        let cell = params_hash(run);
        for m in reduce(run) {
            g.samples.entry(m.id.clone()).or_default().push(m.value);
            let c = g.contaminated.entry(m.id.clone()).or_insert(false);
            *c = *c || m.contaminated;
            g.polarity.entry(m.id.clone()).or_insert(m.polarity);
            let cells = g.cells.entry(m.id.clone()).or_default();
            if !cells.contains(&cell) {
                cells.push(cell.clone());
            }
        }
    }
    g
}

fn bad_direction(pol: &Polarity, rel_delta: f64) -> Option<bool> {
    match pol {
        Polarity::LowerBetter => Some(rel_delta > 0.0), // increase is bad
        Polarity::HigherBetter => Some(rel_delta < 0.0), // decrease is bad
        Polarity::Unknown => None,
    }
}

/// Validate that a group is fit for a gated comparison. Returns notes; if any
/// run is not admissible and allow_ungraded is false, returns an error string.
fn validate(a: &[Value], b: &[Value], cfg: &Config) -> Result<Vec<String>, String> {
    let mut notes = Vec::new();
    let mut tenancies = Vec::new();
    for (label, group) in [("A", a), ("B", b)] {
        for run in group {
            let g = grade_of(run);
            if g != "reproducible" && !cfg.allow_ungraded {
                return Err(format!(
                    "{label} run grade is '{g}', not 'reproducible'; pass --allow-ungraded to override"
                ));
            }
            if g != "reproducible" {
                notes.push(format!("{label} run admitted at grade '{g}' (--allow-ungraded)"));
            }
            if let Some(t) = tenancy_of(run) {
                tenancies.push(t);
            }
        }
    }
    tenancies.sort();
    tenancies.dedup();
    if tenancies.len() > 1 {
        return Err(format!(
            "refusing to compare across tenancy classes: {tenancies:?}"
        ));
    }
    Ok(notes)
}

pub fn ab(a: &[Value], b: &[Value], cfg: &Config) -> Result<Value, String> {
    let mut notes = validate(a, b, cfg)?;
    let ga = collect(a);
    let gb = collect(b);

    let mut per_metric = serde_json::Map::new();
    let mut detail = Vec::new();
    let mut any_regressed = false;
    let mut any_contaminated = false;
    let mut single_cell_regressions = Vec::new();

    for (id, avals) in &ga.samples {
        let bvals = match gb.samples.get(id) {
            Some(v) => v,
            None => continue,
        };
        if avals.len() < 2 || bvals.len() < 2 {
            continue;
        }
        let ignored = cfg.ignore.iter().any(|pat| id.contains(pat));
        let contaminated =
            *ga.contaminated.get(id).unwrap_or(&false) || *gb.contaminated.get(id).unwrap_or(&false);

        let ma = stats::mean(avals);
        let mb = stats::mean(bvals);
        let rel = if ma != 0.0 { (mb - ma) / ma } else if mb == 0.0 { 0.0 } else { 1.0 };
        let p = stats::permutation_p(avals, bvals, cfg.resamples, cfg.seed);
        let cov = stats::within_cov(avals, bvals);
        let significant = p < cfg.p_threshold;
        let strong = rel.abs() >= cfg.min_effect;
        let noisy = cov > cfg.noise_threshold;
        let pol = ga.polarity.get(id).cloned().unwrap_or(Polarity::Unknown);

        let status = if ignored {
            "ignored"
        } else if contaminated {
            any_contaminated = true;
            "contaminated"
        } else if !significant || !strong || noisy {
            "stable"
        } else {
            match bad_direction(&pol, rel) {
                Some(true) => {
                    any_regressed = true;
                    let cells = ga.cells.get(id).cloned().unwrap_or_default();
                    if cells.len() < 2 {
                        single_cell_regressions.push(id.clone());
                    }
                    "regressed"
                }
                Some(false) => "improved",
                None => "changed",
            }
        };

        // Contract-conformant Outcome entry (exactly delta/p/significant/noisy).
        per_metric.insert(
            id.clone(),
            json!({ "delta": rel, "p": p, "significant": significant, "noisy": noisy }),
        );
        detail.push(json!({
            "id": id, "status": status, "mean_a": ma, "mean_b": mb,
            "rel_delta": rel, "p": p, "cov": cov, "n_a": avals.len(), "n_b": bvals.len(),
            "cells": ga.cells.get(id).cloned().unwrap_or_default(),
        }));
    }

    // A comparison that tested nothing must not read as a pass. This happens
    // when no series is present in both groups with at least two samples per
    // group (e.g. a 1-vs-1 A/B): there is nothing to permute, so `per_metric`
    // is empty. Refuse it as a gate error rather than returning a hollow pass.
    if per_metric.is_empty() {
        return Err(format!(
            "no metric was comparable: no series appears in both groups with at least two samples per group \
             (A has {} series, B has {}). A comparison this small cannot be gated; add more repeats per group.",
            ga.samples.len(),
            gb.samples.len()
        ));
    }

    let verdict = if any_contaminated {
        "contaminated"
    } else if any_regressed {
        if !single_cell_regressions.is_empty() && !cfg.strict_single_cell {
            notes.push(format!(
                "regressions in a single parameterisation cell (possible noise): {single_cell_regressions:?}; \
                 verdict is fail but confirm across cells or pass --strict-single-cell to treat as definitive"
            ));
        }
        "fail"
    } else {
        "pass"
    };

    Ok(json!({
        "outcome": { "verdict": verdict, "per_metric": per_metric, "notes": notes },
        "report": { "mode": "ab_permutation", "detail": detail }
    }))
}

pub fn drift(baseline: &[Value], candidate: &[Value], cfg: &Config) -> Result<Value, String> {
    // Baseline establishes reference mean/stddev; candidate is an ordered
    // trajectory tested for level shift and trend.
    let gb = collect(baseline);
    let gc = collect(candidate);
    let mut notes = Vec::new();
    let mut per_metric = serde_json::Map::new();
    let mut detail = Vec::new();
    let mut any_drift = false;

    for (id, base_vals) in &gb.samples {
        let cand_vals = match gc.samples.get(id) {
            Some(v) => v,
            None => continue,
        };
        if base_vals.len() < 2 || cand_vals.len() < 2 {
            continue;
        }
        if cfg.ignore.iter().any(|pat| id.contains(pat)) {
            continue;
        }
        let base_mean = stats::mean(base_vals);
        let base_std = stats::stddev(base_vals);
        let cand_mean = stats::mean(cand_vals);
        let rel = if base_mean != 0.0 { (cand_mean - base_mean) / base_mean } else { 0.0 };
        let level_shift = if base_std > 0.0 {
            (cand_mean - base_mean).abs() > cfg.drift_k * base_std
        } else {
            rel.abs() >= cfg.min_effect
        };
        let (slope, stderr) = stats::linreg_slope_stderr(cand_vals);
        let trending = stderr > 0.0 && (slope / stderr).abs() > 2.0;
        let pol = gb.polarity.get(id).cloned().unwrap_or(Polarity::Unknown);

        let drifted = level_shift && rel.abs() >= cfg.min_effect;
        let bad = bad_direction(&pol, rel).unwrap_or(false);
        let status = if drifted && bad {
            any_drift = true;
            "drift_bad"
        } else if drifted {
            "drift"
        } else if trending {
            "trending"
        } else {
            "stable"
        };

        per_metric.insert(
            id.clone(),
            json!({ "delta": rel, "p": 0.0, "significant": drifted, "noisy": false }),
        );
        detail.push(json!({
            "id": id, "status": status, "base_mean": base_mean, "base_std": base_std,
            "cand_mean": cand_mean, "rel_delta": rel, "slope": slope, "slope_stderr": stderr,
        }));
    }

    if per_metric.is_empty() {
        return Err(format!(
            "no metric was comparable: no series appears in both baseline and candidate with at least two samples each \
             (baseline has {} series, candidate has {}). Add more samples per side.",
            gb.samples.len(),
            gc.samples.len()
        ));
    }

    let verdict = if any_drift { "fail" } else { "pass" };
    if verdict == "pass" {
        notes.push("no bad-direction drift beyond band".to_string());
    }
    Ok(json!({
        "outcome": { "verdict": verdict, "per_metric": per_metric, "notes": notes },
        "report": { "mode": "longitudinal_drift", "detail": detail }
    }))
}

pub fn triad(a: &[Value], b: &[Value], cfg: &Config) -> Result<Value, String> {
    // (a) + (c): permutation A/B on all non-overhead metrics.
    let base = ab(a, b, cfg)?;

    // (b): the eBPF variant's own cost, from the B group's self_metrics.
    let mut worst: BTreeMap<String, f64> = BTreeMap::new();
    let mut over_budget = Vec::new();
    for run in b {
        if let Some(sm) = run.get("self_metrics").and_then(|v| v.as_array()) {
            for pc in sm {
                let id = pc.get("probe_id").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let frac = pc.get("steady_cpu_fraction").and_then(|v| v.as_f64()).unwrap_or(0.0);
                let ob = pc.get("over_budget").and_then(|v| v.as_bool()).unwrap_or(false);
                let e = worst.entry(id.clone()).or_insert(0.0);
                if frac > *e {
                    *e = frac;
                }
                if ob && !over_budget.contains(&id) {
                    over_budget.push(id);
                }
            }
        }
    }

    let mut out = base;
    let overhead_verdict = if over_budget.is_empty() { "pass" } else { "fail" };
    out["report"]["mode"] = json!("subsystem_triad");
    out["report"]["overhead"] = json!({
        "verdict": overhead_verdict,
        "worst_steady_cpu_fraction": worst,
        "over_budget": over_budget,
    });
    // Fold overhead failure into the top-line verdict.
    if overhead_verdict == "fail" {
        let cur = out["outcome"]["verdict"].as_str().unwrap_or("pass").to_string();
        if cur != "contaminated" {
            out["outcome"]["verdict"] = json!("fail");
        }
        if let Some(n) = out["outcome"]["notes"].as_array_mut() {
            n.push(json!("subsystem overhead over budget; see report.overhead"));
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> Config {
        Config { allow_ungraded: true, ..Default::default() }
    }

    fn counter_run(name: &str, val: f64) -> Value {
        json!({"series": [{"name": name, "kind": "counter", "unit": "", "source": "s", "data": {"value": val}}]})
    }

    #[test]
    fn ab_with_one_sample_per_group_errors_rather_than_hollow_pass() {
        // 1-vs-1: no series has >= 2 samples per group, so nothing is comparable.
        // This must be a gate error (exit 1), not a silent `pass` (exit 0).
        let a = vec![counter_run("m", 100.0)];
        let b = vec![counter_run("m", 110.0)];
        let err = ab(&a, &b, &cfg()).unwrap_err();
        assert!(err.contains("no metric was comparable"), "got: {err}");
    }

    #[test]
    fn ab_with_disjoint_metrics_errors() {
        // Enough samples, but no shared series -> nothing to compare.
        let a: Vec<Value> = (0..3).map(|_| counter_run("only_a", 1.0)).collect();
        let b: Vec<Value> = (0..3).map(|_| counter_run("only_b", 1.0)).collect();
        assert!(ab(&a, &b, &cfg()).is_err());
    }

    #[test]
    fn ab_with_enough_samples_grades_normally() {
        let a: Vec<Value> = (0..3).map(|i| counter_run("m", 100.0 + i as f64)).collect();
        let b: Vec<Value> = (0..3).map(|i| counter_run("m", 100.0 + i as f64)).collect();
        let out = ab(&a, &b, &cfg()).unwrap();
        assert!(!out["outcome"]["per_metric"].as_object().unwrap().is_empty());
        assert_eq!(out["outcome"]["verdict"], "pass");
    }

    #[test]
    fn drift_with_one_sample_each_errors() {
        let base = vec![counter_run("m", 100.0)];
        let cand = vec![counter_run("m", 100.0)];
        assert!(drift(&base, &cand, &cfg()).is_err());
    }

    fn labelled_counter_run(name: &str, state: &str, val: f64) -> Value {
        json!({"series": [{
            "name": name, "kind": "counter", "unit": "", "source": "s",
            "labels": { "lifecycle_state": state },
            "data": {"value": val}
        }]})
    }

    #[test]
    fn ab_grades_label_variants_as_distinct_metrics() {
        // Each run carries two series sharing a name but differing only by
        // label (running vs paused). The gate must grade each label variant as
        // its own metric and match like-for-like across A and B, not merge the
        // two into one series.
        let mk = |base: f64| -> Value {
            json!({"series": [
                {"name": "net.softirq_ns", "kind": "counter", "unit": "", "source": "s",
                 "labels": {"lifecycle_state": "running"}, "data": {"value": base}},
                {"name": "net.softirq_ns", "kind": "counter", "unit": "", "source": "s",
                 "labels": {"lifecycle_state": "paused"}, "data": {"value": base / 20.0}},
            ]})
        };
        let a: Vec<Value> = (0..3).map(|i| mk(100.0 + i as f64)).collect();
        let b: Vec<Value> = (0..3).map(|i| mk(100.0 + i as f64)).collect();
        let out = ab(&a, &b, &cfg()).unwrap();
        let per = out["outcome"]["per_metric"].as_object().unwrap();
        assert!(
            per.contains_key("net.softirq_ns|lifecycle_state=running|value"),
            "running variant graded as its own metric; got {:?}",
            per.keys().collect::<Vec<_>>()
        );
        assert!(
            per.contains_key("net.softirq_ns|lifecycle_state=paused|value"),
            "paused variant graded as its own metric; got {:?}",
            per.keys().collect::<Vec<_>>()
        );
    }

    #[test]
    fn ab_does_not_compare_across_differing_labels() {
        // Same series name, but A is all running and B is all paused. Different
        // labels give different metric ids, so the two are disjoint and nothing
        // is comparable: a gate error, not a hollow pass over a false match.
        let a: Vec<Value> = (0..3).map(|_| labelled_counter_run("m", "running", 1.0)).collect();
        let b: Vec<Value> = (0..3).map(|_| labelled_counter_run("m", "paused", 1.0)).collect();
        assert!(ab(&a, &b, &cfg()).is_err());
    }
}
