// SPDX-License-Identifier: Apache-2.0
//! OTLP export for the Assayist contract.
//!
//! The contract was drawn OTLP-shaped where the concepts overlap, so export is a
//! rote transform rather than a translation layer (see `docs/contract-v0.md`).
//! Output is OTLP/JSON: the same shape a collector accepts over OTLP/HTTP with
//! `Content-Type: application/json`. Traces and metrics are separate OTLP signals
//! with separate endpoints, so [`export_traces`] and [`export_metrics`] each
//! return a request-shaped document; [`export`] bundles both for convenience.
//!
//! Mappings (from the contract spec):
//! - `run_id` (128-bit hex) -> `traceId` (direct)
//! - `spans[]` -> `Span[]`, `span_id` = hash(run_id, name, index), `parent` name resolved to `parentSpanId`
//! - `identity` + `fingerprint` -> `Resource.attributes` (semconv where it exists, else `assayist.*`)
//! - histogram `log2` -> `ExponentialHistogram` scale 0; `explicit` -> `Histogram`
//! - counter -> monotonic `Sum`; gauge -> `Gauge`
//! - `self_metrics[]` -> `assayist.probe.*` gauge/sum
//!
//! Honest wrinkle carried from the spec: bpf log2 buckets are half-open
//! `[2^i, 2^(i+1))` while OTel exponential buckets at scale 0 are `(2^i, 2^(i+1)]`,
//! so a sample landing exactly on a power of two lands one bucket over. Negligible
//! for latency histograms; not corrected here.

use assayist_contract::{AssayRun, Grade};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

const SCOPE_NAME: &str = "assayist";

/// Both signals in one object: `{ resourceSpans, resourceMetrics }`.
pub fn export(run: &AssayRun) -> Value {
    json!({
        "resourceSpans": export_traces(run)["resourceSpans"],
        "resourceMetrics": export_metrics(run)["resourceMetrics"],
    })
}

/// OTLP `ExportTraceServiceRequest`-shaped: `{ resourceSpans: [...] }`.
pub fn export_traces(run: &AssayRun) -> Value {
    json!({
        "resourceSpans": [{
            "resource": { "attributes": resource_attributes(run) },
            "scopeSpans": [{
                "scope": { "name": SCOPE_NAME },
                "spans": spans(run),
            }],
        }],
    })
}

/// OTLP `ExportMetricsServiceRequest`-shaped: `{ resourceMetrics: [...] }`.
pub fn export_metrics(run: &AssayRun) -> Value {
    let mut metrics = series_metrics(run);
    metrics.extend(probe_metrics(run));
    json!({
        "resourceMetrics": [{
            "resource": { "attributes": resource_attributes(run) },
            "scopeMetrics": [{
                "scope": { "name": SCOPE_NAME },
                "metrics": metrics,
            }],
        }],
    })
}

// --- resource ---------------------------------------------------------------

fn resource_attributes(run: &AssayRun) -> Vec<Value> {
    let f = &run.fingerprint;
    let id = &run.identity;
    let mut a = vec![
        kv_str("host.name", &f.hostname),
        kv_str("os.version", &f.kernel_version),
        kv_str("os.description", &f.os_release),
        kv_str("host.cpu.model.name", &f.cpu_model),
        kv_int("assayist.host.cpu_count_logical", f.cpu_count_logical as i64),
        kv_int("assayist.host.cpu_count_physical", f.cpu_count_physical as i64),
        kv_bool("assayist.host.smt_enabled", f.smt_enabled),
        kv_str("assayist.host.cpu_governor", &f.cpu_governor),
        kv_str("assayist.host.thp", &f.thp_setting),
        kv_int("assayist.host.memory_bytes", f.total_memory_bytes as i64),
        kv_bool("assayist.host.kvm", f.kvm_present),
        kv_str("assayist.run.tenancy", &f.tenancy),
        kv_str("assayist.target_adapter", &id.target_adapter),
        kv_str("assayist.target_adapter_version", &id.target_adapter_version),
        kv_str("assayist.workload_driver", &id.workload_driver),
        kv_str("assayist.workload_driver_version", &id.workload_driver_version),
        kv_str("assayist.sut_git_sha", &id.sut_git_sha),
        kv_str("assayist.params_hash", &id.params_hash),
        kv_str("assayist.benchmark_def_sha", &id.benchmark_def_sha),
        kv_str("assayist.grade", grade_str(&run.grade)),
    ];
    // outcome -> assayist.gate.* (the spec also maps it to span status; kept as
    // resource attributes here, span status left UNSET).
    if let Some(v) = run.outcome.as_ref().and_then(|o| o.get("verdict")).and_then(|v| v.as_str()) {
        a.push(kv_str("assayist.gate.verdict", v));
    }
    a
}

// --- spans ------------------------------------------------------------------

fn spans(run: &AssayRun) -> Vec<Value> {
    // First pass: assign a deterministic span id per span, indexed by name so
    // `parent` (a span name) resolves to a `parentSpanId`.
    let mut id_by_name: Map<String, Value> = Map::new();
    let ids: Vec<String> = run
        .spans
        .iter()
        .enumerate()
        .map(|(i, s)| {
            let name = s.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let sid = span_id(&run.run_id, name, i);
            id_by_name.entry(name.to_string()).or_insert_with(|| Value::String(sid.clone()));
            sid
        })
        .collect();

    run.spans
        .iter()
        .enumerate()
        .map(|(i, s)| {
            let name = s.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let mut span = Map::new();
            span.insert("traceId".into(), json!(run.run_id));
            span.insert("spanId".into(), json!(ids[i]));
            if let Some(parent) = s.get("parent").and_then(|v| v.as_str()) {
                if let Some(pid) = id_by_name.get(parent) {
                    span.insert("parentSpanId".into(), pid.clone());
                }
            }
            span.insert("name".into(), json!(name));
            span.insert("kind".into(), json!(1)); // SPAN_KIND_INTERNAL
            span.insert("startTimeUnixNano".into(), u64_str(s.get("start_unix_nano")));
            span.insert("endTimeUnixNano".into(), u64_str(s.get("end_unix_nano")));
            span.insert("attributes".into(), Value::Array(attributes_from(s.get("attributes"))));
            Value::Object(span)
        })
        .collect()
}

/// Deterministic 64-bit span id (16 hex chars) from run id, name, and index, so
/// exports are stable and re-runnable.
fn span_id(run_id: &str, name: &str, index: usize) -> String {
    let mut h = Sha256::new();
    h.update(run_id.as_bytes());
    h.update([0]);
    h.update(name.as_bytes());
    h.update([0]);
    h.update(index.to_le_bytes());
    let d = h.finalize();
    d[..8].iter().map(|b| format!("{b:02x}")).collect()
}

// --- metrics ----------------------------------------------------------------

fn series_metrics(run: &AssayRun) -> Vec<Value> {
    run.series.iter().filter_map(series_to_metric).collect()
}

fn series_to_metric(s: &Value) -> Option<Value> {
    let name = s.get("name")?.as_str()?;
    let unit = s.get("unit").and_then(|v| v.as_str()).unwrap_or("");
    let kind = s.get("kind")?.as_str()?;
    let mut attrs = Vec::new();
    if let Some(src) = s.get("source").and_then(|v| v.as_str()) {
        attrs.push(kv_str("assayist.source", src));
    }
    if let Some(key) = s.get("key").and_then(|v| v.as_str()) {
        attrs.push(kv_str("assayist.key", key));
    }
    let data = s.get("data")?;

    let body = match kind {
        "histogram" => histogram_body(data, &attrs)?,
        "counter" => json!({
            "sum": {
                "isMonotonic": true,
                "aggregationTemporality": 2, // CUMULATIVE
                "dataPoints": [{
                    "attributes": attrs,
                    "asInt": u64_str(data.get("value")),
                    "startTimeUnixNano": u64_str(data.get("start_unix_nano")),
                    "timeUnixNano": u64_str(data.get("start_unix_nano")),
                }],
            }
        }),
        "gauge" => json!({
            "gauge": {
                "dataPoints": [{
                    "attributes": attrs,
                    "asDouble": data.get("value").and_then(|v| v.as_f64()).unwrap_or(0.0),
                    "timeUnixNano": u64_str(data.get("time_unix_nano")),
                }],
            }
        }),
        _ => return None,
    };

    let mut metric = Map::new();
    metric.insert("name".into(), json!(name));
    metric.insert("unit".into(), json!(unit));
    if let Value::Object(b) = body {
        for (k, v) in b {
            metric.insert(k, v);
        }
    }
    Some(Value::Object(metric))
}

fn histogram_body(data: &Value, attrs: &[Value]) -> Option<Value> {
    let layout = data.get("layout").and_then(|v| v.as_str()).unwrap_or("log2");
    let buckets: Vec<i64> = data
        .get("buckets")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_i64()).collect())
        .unwrap_or_default();
    let count = u64_str(data.get("count"));
    let sum = data.get("sum").and_then(|v| v.as_f64());

    match layout {
        "log2" => {
            // scale 0 (base 2), bpf bucket i -> exponential bucket index i,
            // offset 0.
            let mut dp = Map::new();
            dp.insert("attributes".into(), Value::Array(attrs.to_vec()));
            dp.insert("count".into(), count);
            if let Some(sum) = sum {
                dp.insert("sum".into(), json!(sum));
            }
            dp.insert("scale".into(), json!(0));
            dp.insert("zeroCount".into(), json!("0"));
            dp.insert(
                "positive".into(),
                json!({ "offset": 0, "bucketCounts": buckets.iter().map(|b| b.to_string()).collect::<Vec<_>>() }),
            );
            Some(json!({
                "exponentialHistogram": {
                    "aggregationTemporality": 2,
                    "dataPoints": [Value::Object(dp)],
                }
            }))
        }
        "explicit" => {
            let bounds: Vec<f64> = data
                .get("explicit_bounds")
                .and_then(|v| v.as_array())
                .map(|a| a.iter().filter_map(|x| x.as_f64()).collect())
                .unwrap_or_default();
            let mut dp = Map::new();
            dp.insert("attributes".into(), Value::Array(attrs.to_vec()));
            dp.insert("count".into(), count);
            if let Some(sum) = sum {
                dp.insert("sum".into(), json!(sum));
            }
            dp.insert("explicitBounds".into(), json!(bounds));
            dp.insert(
                "bucketCounts".into(),
                json!(buckets.iter().map(|b| b.to_string()).collect::<Vec<_>>()),
            );
            Some(json!({
                "histogram": {
                    "aggregationTemporality": 2,
                    "dataPoints": [Value::Object(dp)],
                }
            }))
        }
        _ => None,
    }
}

/// self_metrics -> the observer-effect signal as OTLP metrics.
fn probe_metrics(run: &AssayRun) -> Vec<Value> {
    let mut out = Vec::new();
    for pm in &run.self_metrics {
        let mut attrs = Vec::new();
        if let Some(pid) = pm.get("probe_id").and_then(|v| v.as_str()) {
            attrs.push(kv_str("assayist.probe.id", pid));
        }
        if let Some(ak) = pm.get("attach_kind").and_then(|v| v.as_str()) {
            attrs.push(kv_str("assayist.probe.attach_kind", ak));
        }
        if let Some(ob) = pm.get("over_budget").and_then(|v| v.as_bool()) {
            attrs.push(kv_bool("assayist.probe.over_budget", ob));
        }
        out.push(json!({
            "name": "assayist.probe.steady_cpu_fraction",
            "unit": "1",
            "gauge": { "dataPoints": [{
                "attributes": attrs,
                "asDouble": pm.get("steady_cpu_fraction").and_then(|v| v.as_f64()).unwrap_or(0.0),
                "timeUnixNano": "0",
            }]},
        }));
        out.push(json!({
            "name": "assayist.probe.run_time_ns",
            "unit": "ns",
            "sum": {
                "isMonotonic": true,
                "aggregationTemporality": 2,
                "dataPoints": [{
                    "attributes": attrs,
                    "asInt": u64_str(pm.get("run_time_ns")),
                    "timeUnixNano": "0",
                }],
            },
        }));
    }
    out
}

// --- attribute helpers ------------------------------------------------------

fn attributes_from(v: Option<&Value>) -> Vec<Value> {
    let Some(Value::Object(map)) = v else { return vec![] };
    map.iter().map(|(k, val)| any_kv(k, val)).collect()
}

fn any_kv(key: &str, v: &Value) -> Value {
    let any = match v {
        Value::String(s) => json!({ "stringValue": s }),
        Value::Bool(b) => json!({ "boolValue": b }),
        Value::Number(n) if n.is_f64() => json!({ "doubleValue": n.as_f64() }),
        Value::Number(n) => json!({ "intValue": n.to_string() }),
        other => json!({ "stringValue": other.to_string() }),
    };
    json!({ "key": key, "value": any })
}

fn kv_str(key: &str, v: &str) -> Value {
    json!({ "key": key, "value": { "stringValue": v } })
}
fn kv_int(key: &str, v: i64) -> Value {
    json!({ "key": key, "value": { "intValue": v.to_string() } })
}
fn kv_bool(key: &str, v: bool) -> Value {
    json!({ "key": key, "value": { "boolValue": v } })
}

/// OTLP/JSON encodes uint64 as a decimal string. Missing -> "0".
fn u64_str(v: Option<&Value>) -> Value {
    let n = v.and_then(|x| x.as_u64()).unwrap_or(0);
    Value::String(n.to_string())
}

fn grade_str(g: &Grade) -> &'static str {
    match g {
        Grade::Reproducible => "reproducible",
        Grade::Valid => "valid",
        Grade::Invalid => "invalid",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use assayist_contract::{Fingerprint, Fragment, Identity};

    fn identity() -> Identity {
        Identity {
            target_adapter: "firecracker".into(),
            target_adapter_version: "0.3.0".into(),
            workload_driver: "fio".into(),
            workload_driver_version: "0.1.0".into(),
            sut_git_sha: "cafe".into(),
            params: json!({"vcpu": 2}),
            params_hash: "ph".into(),
            benchmark_def_sha: "bd".into(),
            source: "captured".into(),
        }
    }

    fn fingerprint() -> Fingerprint {
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
            tuning_requested: json!({}),
            tuning_readback: json!({}),
            numa_topology: None,
            pinning_layout: None,
            mitigations: None,
            microcode_version: None,
            nested_virt: None,
        }
    }

    fn run_with(series: Vec<Value>, self_metrics: Vec<Value>, spans: Vec<Value>) -> AssayRun {
        let frags = [Fragment { series, self_metrics, capture_meta: None }];
        AssayRun::assemble("0123456789abcdef0123456789abcdef".into(), identity(), fingerprint(), json!({}), &frags, spans)
    }

    fn find_attr<'a>(attrs: &'a Value, key: &str) -> Option<&'a Value> {
        attrs.as_array()?.iter().find(|a| a["key"] == key).map(|a| &a["value"])
    }

    #[test]
    fn run_id_maps_to_trace_id_and_resource_uses_semconv() {
        let run = run_with(vec![], vec![], vec![]);
        let doc = export_traces(&run);
        let rs = &doc["resourceSpans"][0];
        let attrs = &rs["resource"]["attributes"];
        assert_eq!(find_attr(attrs, "host.name").unwrap()["stringValue"], "lab");
        assert_eq!(find_attr(attrs, "os.version").unwrap()["stringValue"], "6.11.0");
        assert_eq!(find_attr(attrs, "host.cpu.model.name").unwrap()["stringValue"], "Ryzen");
        assert_eq!(find_attr(attrs, "assayist.run.tenancy").unwrap()["stringValue"], "single_tenant");
    }

    #[test]
    fn spans_get_deterministic_ids_and_parent_links() {
        let spans = vec![
            json!({"name": "boot", "start_unix_nano": 10, "end_unix_nano": 20}),
            json!({"name": "boot.init", "parent": "boot", "start_unix_nano": 11, "end_unix_nano": 19}),
        ];
        let run = run_with(vec![], vec![], spans);
        let out = export_traces(&run);
        let s = &out["resourceSpans"][0]["scopeSpans"][0]["spans"];
        assert_eq!(s[0]["traceId"], "0123456789abcdef0123456789abcdef");
        // start time is a string (OTLP/JSON uint64).
        assert_eq!(s[0]["startTimeUnixNano"], "10");
        // child's parentSpanId equals the parent's spanId.
        assert_eq!(s[1]["parentSpanId"], s[0]["spanId"]);
        // ids are deterministic across exports.
        let again = export_traces(&run);
        assert_eq!(s[0]["spanId"], again["resourceSpans"][0]["scopeSpans"][0]["spans"][0]["spanId"]);
    }

    #[test]
    fn log2_histogram_maps_to_exponential_scale_zero() {
        let series = vec![json!({
            "name": "kvm.exit_latency", "unit": "ns", "kind": "histogram", "source": "kvm_exit",
            "cardinality": {"class": "singleton"},
            "data": {"layout": "log2", "buckets": [3, 9, 14], "count": 26, "sum": 4242}
        })];
        let run = run_with(series, vec![], vec![]);
        let m = &export_metrics(&run)["resourceMetrics"][0]["scopeMetrics"][0]["metrics"][0];
        assert_eq!(m["name"], "kvm.exit_latency");
        let dp = &m["exponentialHistogram"]["dataPoints"][0];
        assert_eq!(dp["scale"], 0);
        assert_eq!(dp["count"], "26");
        assert_eq!(dp["positive"]["offset"], 0);
        assert_eq!(dp["positive"]["bucketCounts"], json!(["3", "9", "14"]));
    }

    #[test]
    fn counter_maps_to_monotonic_sum() {
        let series = vec![json!({
            "name": "block.io_bytes", "unit": "By", "kind": "counter", "source": "block",
            "cardinality": {"class": "singleton"},
            "data": {"value": 4096, "start_unix_nano": 5}
        })];
        let run = run_with(series, vec![], vec![]);
        let m = &export_metrics(&run)["resourceMetrics"][0]["scopeMetrics"][0]["metrics"][0];
        assert_eq!(m["sum"]["isMonotonic"], true);
        assert_eq!(m["sum"]["aggregationTemporality"], 2);
        assert_eq!(m["sum"]["dataPoints"][0]["asInt"], "4096");
    }

    #[test]
    fn self_metrics_become_probe_gauge_and_sum() {
        let sm = vec![json!({
            "probe_id": "kvm_exit", "attach_kind": "tracepoint",
            "run_time_ns": 41200, "run_cnt": 12873, "mean_ns": 3.2,
            "steady_cpu_fraction": 0.0075, "over_budget": false
        })];
        let run = run_with(vec![json!({"name":"x"})], sm, vec![]);
        let metrics = &export_metrics(&run)["resourceMetrics"][0]["scopeMetrics"][0]["metrics"];
        let names: Vec<&str> = metrics.as_array().unwrap().iter().filter_map(|m| m["name"].as_str()).collect();
        assert!(names.contains(&"assayist.probe.steady_cpu_fraction"));
        assert!(names.contains(&"assayist.probe.run_time_ns"));
    }

    #[test]
    fn export_bundles_both_signals() {
        let run = run_with(vec![], vec![], vec![]);
        let doc = export(&run);
        assert!(doc.get("resourceSpans").is_some());
        assert!(doc.get("resourceMetrics").is_some());
    }
}
