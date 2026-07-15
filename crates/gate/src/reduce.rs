// SPDX-License-Identifier: Apache-2.0
// Reduce an AssayRun (as serde_json::Value) to a flat set of scalar metrics.
// Histograms become mean/p50/p99; counters and gauges become value (and rate
// for counters when a window is known); spans become durations.

use std::collections::HashSet;

use serde_json::Value;

use crate::stats;

#[derive(Debug, Clone, PartialEq)]
pub enum Polarity {
    LowerBetter,
    HigherBetter,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct Metric {
    pub id: String,
    pub value: f64,
    pub contaminated: bool,
    pub polarity: Polarity,
}

pub fn polarity_of(id: &str, unit: &str) -> Polarity {
    let l = id.to_lowercase();
    // Throughput-like: more is better.
    if l.contains("bytes")
        || l.contains("packets")
        || l.contains("throughput")
        || l.contains("iops")
        || unit == "By"
    {
        return Polarity::HigherBetter;
    }
    // CPU-consumption metrics are genuinely ambiguous (more scheduled time can
    // be fine or a sign of inefficiency); do not guess a direction.
    if l.contains("on_cpu") || l.contains("utilis") || l.contains("cpu_ns") {
        return Polarity::Unknown;
    }
    // Time-unit metrics (latency, duration, boot, restore, runqueue, spans):
    // lower is better. This is the right default for a benchmark harness.
    if matches!(unit, "ns" | "us" | "ms" | "s") {
        return Polarity::LowerBetter;
    }
    Polarity::Unknown
}

fn f(v: &Value, k: &str) -> Option<f64> {
    v.get(k).and_then(|x| x.as_f64())
}

/// Collect every numeric leaf of a JSON value, keyed by its dotted path. Used to
/// turn a workload report (flat or nested, e.g. fio's read/write objects) into
/// gradeable scalars. Non-numeric leaves (a `driver` tag, strings) are skipped.
fn flatten_numbers(prefix: &str, v: &Value, out: &mut Vec<(String, f64)>) {
    match v {
        Value::Object(m) => {
            for (k, val) in m {
                let key = if prefix.is_empty() { k.clone() } else { format!("{prefix}.{k}") };
                flatten_numbers(&key, val, out);
            }
        }
        Value::Number(n) => {
            if let Some(x) = n.as_f64() {
                out.push((prefix.to_string(), x));
            }
        }
        _ => {}
    }
}

fn u64s(v: &Value) -> Vec<u64> {
    v.as_array()
        .map(|a| a.iter().filter_map(|x| x.as_u64()).collect())
        .unwrap_or_default()
}

fn f64s(v: &Value) -> Vec<f64> {
    v.as_array()
        .map(|a| a.iter().filter_map(|x| x.as_f64()).collect())
        .unwrap_or_default()
}

/// Set of probe ids that reported over_budget, whose sourced series are
/// contaminated.
fn overbudget_sources(run: &Value) -> HashSet<String> {
    let mut s = HashSet::new();
    if let Some(arr) = run.get("self_metrics").and_then(|v| v.as_array()) {
        for pc in arr {
            let ob = pc.get("over_budget").and_then(|v| v.as_bool()).unwrap_or(false);
            if ob {
                if let Some(id) = pc.get("probe_id").and_then(|v| v.as_str()) {
                    s.insert(id.to_string());
                }
            }
        }
    }
    s
}

pub fn window_ns(run: &Value) -> Option<f64> {
    run.get("capture_meta")
        .and_then(|m| m.get("window_ns"))
        .and_then(|v| v.as_f64())
}

pub fn reduce(run: &Value) -> Vec<Metric> {
    let mut out = Vec::new();
    let over = overbudget_sources(run);
    let global_overflow = run
        .get("capture_meta")
        .and_then(|m| m.get("cardinality_overflow"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let win = window_ns(run);

    if let Some(series) = run.get("series").and_then(|v| v.as_array()) {
        for s in series {
            let name = s.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let unit = s.get("unit").and_then(|v| v.as_str()).unwrap_or("");
            let kind = s.get("kind").and_then(|v| v.as_str()).unwrap_or("");
            let source = s.get("source").and_then(|v| v.as_str()).unwrap_or("");
            let key = s.get("key").and_then(|v| v.as_str());
            let series_overflow = s
                .get("cardinality_overflow")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let contaminated =
                over.contains(source) || series_overflow || global_overflow;

            let base = match key {
                Some(k) => format!("{name}|{k}"),
                None => name.to_string(),
            };
            let data = match s.get("data") {
                Some(d) => d,
                None => continue,
            };

            let push = |out: &mut Vec<Metric>, id: String, value: f64| {
                let polarity = polarity_of(&id, unit);
                out.push(Metric { id, value, contaminated, polarity });
            };

            match kind {
                "histogram" => {
                    let layout = data.get("layout").and_then(|v| v.as_str()).unwrap_or("log2");
                    let buckets = u64s(data.get("buckets").unwrap_or(&Value::Null));
                    let (mean_v, p50, p99) = if layout == "explicit" {
                        let bounds = f64s(data.get("explicit_bounds").unwrap_or(&Value::Null));
                        // mean estimate: reuse percentile midpoints weighted.
                        let total: u64 = buckets.iter().sum();
                        let mean_v = if total == 0 {
                            0.0
                        } else {
                            let mut acc = 0.0;
                            for (i, &b) in buckets.iter().enumerate() {
                                let lo = if i == 0 { 0.0 } else { bounds[i - 1] };
                                let hi = if i < bounds.len() { bounds[i] } else { lo * 2.0 };
                                acc += b as f64 * (lo + hi) / 2.0;
                            }
                            acc / total as f64
                        };
                        (
                            mean_v,
                            stats::explicit_percentile(&buckets, &bounds, 0.50),
                            stats::explicit_percentile(&buckets, &bounds, 0.99),
                        )
                    } else {
                        // Prefer exact sum/count for the mean when present.
                        let mean_v = match (f(data, "sum"), f(data, "count")) {
                            (Some(sum), Some(c)) if c > 0.0 => sum / c,
                            _ => stats::log2_mean(&buckets),
                        };
                        (
                            mean_v,
                            stats::log2_percentile(&buckets, 0.50),
                            stats::log2_percentile(&buckets, 0.99),
                        )
                    };
                    push(&mut out, format!("{base}|mean"), mean_v);
                    push(&mut out, format!("{base}|p50"), p50);
                    push(&mut out, format!("{base}|p99"), p99);
                }
                "counter" => {
                    let value = f(data, "value").unwrap_or(0.0);
                    push(&mut out, format!("{base}|value"), value);
                    if let Some(w) = win {
                        if w > 0.0 {
                            push(&mut out, format!("{base}|rate"), value / w * 1e9);
                        }
                    }
                }
                "gauge" => {
                    let value = f(data, "value").unwrap_or(0.0);
                    push(&mut out, format!("{base}|value"), value);
                }
                _ => {}
            }
        }
    }

    // Workload report -> gradeable scalars. A native workload (fio, wrk, vsock)
    // or an imported external tool reports its own numbers here; surface every
    // numeric leaf (nested objects flatten with dotted keys) as `workload:<key>`
    // so the gate can compare them rather than leaving them as inert provenance.
    // Polarity comes from the key/unit like any other metric, so a latency field
    // reads lower-better and a throughput field higher-better; a field with no
    // known direction stays Unknown and cannot by itself fail the gate.
    if let Some(rep) = run.get("workload_report") {
        let mut flat = Vec::new();
        flatten_numbers("", rep, &mut flat);
        for (k, n) in flat {
            let id = format!("workload:{k}");
            let unit = if k.ends_with("_ns") {
                "ns"
            } else if k.ends_with("_us") {
                "us"
            } else if k.ends_with("_ms") {
                "ms"
            } else {
                ""
            };
            let polarity = polarity_of(&id, unit);
            out.push(Metric { id, value: n, contaminated: false, polarity });
        }
    }

    // Spans -> durations.
    if let Some(spans) = run.get("spans").and_then(|v| v.as_array()) {
        for sp in spans {
            let name = sp.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let start = sp.get("start_unix_nano").and_then(|v| v.as_f64());
            let end = sp.get("end_unix_nano").and_then(|v| v.as_f64());
            if let (Some(s), Some(e)) = (start, end) {
                let id = format!("span:{name}|dur");
                let polarity = Polarity::LowerBetter; // span durations: shorter is better
                out.push(Metric { id, value: e - s, contaminated: false, polarity });
            }
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn workload_report_numbers_become_gradeable_metrics() {
        let run = json!({
            "workload_report": {
                "driver": "vsock",
                "invocations": 30,
                "latency_p50_ns": 350000,
                "read": { "iops": 12000.0 }
            }
        });
        let m: std::collections::HashMap<String, Metric> =
            reduce(&run).into_iter().map(|x| (x.id.clone(), x)).collect();

        // The string driver tag is skipped; numeric leaves (incl. nested) surface.
        assert!(!m.contains_key("workload:driver"));
        assert_eq!(m["workload:invocations"].value, 30.0);
        // Latency in ns reads lower-better; nested iops reads higher-better.
        assert_eq!(m["workload:latency_p50_ns"].polarity, Polarity::LowerBetter);
        assert_eq!(m["workload:read.iops"].polarity, Polarity::HigherBetter);
    }
}
