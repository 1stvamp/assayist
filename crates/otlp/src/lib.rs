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

/// Both signals in one object: `{ resourceSpans, resourceMetrics }`. Uses
/// timestamp 0 for data points the contract does not timestamp (histograms,
/// probe cost); use [`export_at`] to stamp a real time.
pub fn export(run: &AssayRun) -> Value {
    export_at(run, 0)
}

/// Like [`export`] but stamps `ts` (unix nanos) onto the data points the
/// contract carries no timestamp for. Callers typically pass the capture-window
/// end (or export time).
pub fn export_at(run: &AssayRun, ts: u64) -> Value {
    json!({
        "resourceSpans": export_traces(run)["resourceSpans"],
        "resourceMetrics": export_metrics_at(run, ts)["resourceMetrics"],
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
/// Stamps timestamp 0 for un-timestamped data points; see [`export_metrics_at`].
pub fn export_metrics(run: &AssayRun) -> Value {
    export_metrics_at(run, 0)
}

/// Like [`export_metrics`] but stamps `ts` (unix nanos) onto histogram and
/// probe-cost data points, which the contract carries no timestamp for.
pub fn export_metrics_at(run: &AssayRun, ts: u64) -> Value {
    let mut metrics = series_metrics(run, ts);
    metrics.extend(probe_metrics(run, ts));
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

fn series_metrics(run: &AssayRun, ts: u64) -> Vec<Value> {
    run.series.iter().filter_map(|s| series_to_metric(s, ts)).collect()
}

fn series_to_metric(s: &Value, ts: u64) -> Option<Value> {
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
        "histogram" => histogram_body(data, &attrs, ts)?,
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

fn histogram_body(data: &Value, attrs: &[Value], ts: u64) -> Option<Value> {
    let layout = data.get("layout").and_then(|v| v.as_str()).unwrap_or("log2");
    let ts = Value::String(ts.to_string());
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
            dp.insert("timeUnixNano".into(), ts.clone());
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
            dp.insert("timeUnixNano".into(), ts.clone());
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
fn probe_metrics(run: &AssayRun, ts: u64) -> Vec<Value> {
    let ts = ts.to_string();
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
                "timeUnixNano": ts,
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
                    "timeUnixNano": ts,
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

// --- import -----------------------------------------------------------------

/// Import an OTLP/JSON document (with `resourceSpans` and/or `resourceMetrics`)
/// into an AssayRun. This is the graceful-degradation path: it fills what maps
/// (spans, exponential histograms -> log2 series, `host.*`/`os.*` -> fingerprint
/// core) and leaves the benchmark-only fields empty. The run is stamped
/// `identity.source = imported` and grades `valid` (never `reproducible`),
/// because self_metrics and the full fingerprint cannot be reconstructed.
pub fn import(doc: &Value) -> Result<AssayRun, String> {
    let attrs = doc
        .get("resourceSpans")
        .and_then(|rs| rs.get(0))
        .or_else(|| doc.get("resourceMetrics").and_then(|rm| rm.get(0)))
        .map(|r| r["resource"]["attributes"].clone())
        .unwrap_or(Value::Array(vec![]));

    let spans = import_spans(doc);
    let series = import_series(doc);

    let run_id = spans
        .first()
        .and_then(|s| s.get("_trace_id").and_then(|v| v.as_str()))
        .map(String::from)
        .unwrap_or_default();
    // Strip the private carrier now that the run id is lifted out.
    let spans: Vec<Value> = spans
        .into_iter()
        .map(|mut s| {
            if let Some(o) = s.as_object_mut() {
                o.remove("_trace_id");
            }
            s
        })
        .collect();

    let fingerprint = assayist_contract::Fingerprint {
        hostname: attr_str(&attrs, "host.name").unwrap_or_default(),
        kernel_version: attr_str(&attrs, "os.version").unwrap_or_default(),
        os_release: attr_str(&attrs, "os.description").unwrap_or_default(),
        cpu_model: attr_str(&attrs, "host.cpu.model.name").unwrap_or_default(),
        cpu_count_logical: attr_int(&attrs, "assayist.host.cpu_count_logical").unwrap_or(0) as u32,
        cpu_count_physical: attr_int(&attrs, "assayist.host.cpu_count_physical").unwrap_or(0) as u32,
        smt_enabled: attr_bool(&attrs, "assayist.host.smt_enabled").unwrap_or(false),
        cpu_governor: attr_str(&attrs, "assayist.host.cpu_governor").unwrap_or_else(|| "unknown".into()),
        thp_setting: attr_str(&attrs, "assayist.host.thp").unwrap_or_else(|| "unknown".into()),
        total_memory_bytes: attr_int(&attrs, "assayist.host.memory_bytes").unwrap_or(0) as u64,
        kvm_present: attr_bool(&attrs, "assayist.host.kvm").unwrap_or(false),
        tenancy: attr_str(&attrs, "assayist.run.tenancy").unwrap_or_else(|| "single_tenant".into()),
        // Consistent (both empty) so the run does not grade invalid; imported
        // runs carry no tuning record.
        tuning_requested: json!({}),
        tuning_readback: json!({}),
        // Extended fields cannot be reconstructed: partial fingerprint.
        numa_topology: None,
        pinning_layout: None,
        mitigations: None,
        microcode_version: None,
        nested_virt: None,
    };

    let identity = assayist_contract::Identity {
        target_adapter: attr_str(&attrs, "assayist.target_adapter").unwrap_or_else(|| "unknown".into()),
        target_adapter_version: attr_str(&attrs, "assayist.target_adapter_version").unwrap_or_else(|| "unknown".into()),
        workload_driver: attr_str(&attrs, "assayist.workload_driver").unwrap_or_else(|| "unknown".into()),
        workload_driver_version: attr_str(&attrs, "assayist.workload_driver_version").unwrap_or_else(|| "unknown".into()),
        sut_git_sha: attr_str(&attrs, "assayist.sut_git_sha").unwrap_or_else(|| "unknown".into()),
        params: json!({}),
        params_hash: attr_str(&attrs, "assayist.params_hash").unwrap_or_default(),
        benchmark_def_sha: attr_str(&attrs, "assayist.benchmark_def_sha").unwrap_or_default(),
        source: "imported".into(),
    };

    let mut run = AssayRun {
        schema_version: assayist_contract::SCHEMA_VERSION.to_string(),
        run_id,
        identity,
        fingerprint,
        spans,
        series,
        self_metrics: vec![], // never reconstructed on import
        gate: json!({}),
        outcome: None,
        workload_report: None,
        grade: Grade::Invalid,
    };
    // Imported source -> Valid (compute_grade short-circuits on source).
    run.grade = run.compute_grade(false);
    Ok(run)
}

fn import_spans(doc: &Value) -> Vec<Value> {
    let mut raw: Vec<&Value> = Vec::new();
    if let Some(rs) = doc.get("resourceSpans").and_then(|v| v.as_array()) {
        for r in rs {
            if let Some(ss) = r.get("scopeSpans").and_then(|v| v.as_array()) {
                for s in ss {
                    if let Some(spans) = s.get("spans").and_then(|v| v.as_array()) {
                        raw.extend(spans.iter());
                    }
                }
            }
        }
    }
    // Map span id -> name so parentSpanId resolves back to a parent name.
    let mut name_by_id: Map<String, Value> = Map::new();
    for s in &raw {
        if let (Some(id), Some(name)) = (
            s.get("spanId").and_then(|v| v.as_str()),
            s.get("name").and_then(|v| v.as_str()),
        ) {
            name_by_id.insert(id.to_string(), Value::String(name.to_string()));
        }
    }

    raw.into_iter()
        .map(|s| {
            let mut out = Map::new();
            out.insert("name".into(), s.get("name").cloned().unwrap_or(Value::Null));
            out.insert("start_unix_nano".into(), json!(str_u64(s.get("startTimeUnixNano"))));
            out.insert("end_unix_nano".into(), json!(str_u64(s.get("endTimeUnixNano"))));
            if let Some(pid) = s.get("parentSpanId").and_then(|v| v.as_str()) {
                if let Some(name) = name_by_id.get(pid) {
                    out.insert("parent".into(), name.clone());
                }
            }
            let attrs = kv_list_to_object(s.get("attributes"));
            if !attrs.is_empty() {
                out.insert("attributes".into(), Value::Object(attrs));
            }
            // Private carrier for the run id; stripped by the caller.
            if let Some(tid) = s.get("traceId").and_then(|v| v.as_str()) {
                out.insert("_trace_id".into(), json!(tid));
            }
            Value::Object(out)
        })
        .collect()
}

fn import_series(doc: &Value) -> Vec<Value> {
    let mut out = Vec::new();
    let Some(rm) = doc.get("resourceMetrics").and_then(|v| v.as_array()) else {
        return out;
    };
    for r in rm {
        let Some(sms) = r.get("scopeMetrics").and_then(|v| v.as_array()) else { continue };
        for sm in sms {
            let Some(metrics) = sm.get("metrics").and_then(|v| v.as_array()) else { continue };
            for m in metrics {
                let name = m.get("name").and_then(|v| v.as_str()).unwrap_or("");
                // Probe-cost metrics are not series; imported runs have no self_metrics.
                if name.starts_with("assayist.probe.") {
                    continue;
                }
                if let Some(s) = metric_to_series(m) {
                    out.push(s);
                }
            }
        }
    }
    out
}

fn metric_to_series(m: &Value) -> Option<Value> {
    let name = m.get("name")?.as_str()?;
    let unit = m.get("unit").and_then(|v| v.as_str()).unwrap_or("");
    let mut s = Map::new();
    s.insert("name".into(), json!(name));
    s.insert("unit".into(), json!(unit));

    if let Some(eh) = m.get("exponentialHistogram") {
        let dp = eh.get("dataPoints")?.get(0)?;
        let buckets = str_array_u64(dp.get("positive").and_then(|p| p.get("bucketCounts")));
        s.insert("kind".into(), json!("histogram"));
        carry_source_key(dp, &mut s);
        let mut data = json!({
            "layout": "log2",
            "buckets": buckets,
            "count": str_u64(dp.get("count")),
        });
        if let Some(sum) = dp.get("sum").and_then(|v| v.as_f64()) {
            data["sum"] = json!(sum);
        }
        s.insert("data".into(), data);
    } else if let Some(h) = m.get("histogram") {
        let dp = h.get("dataPoints")?.get(0)?;
        s.insert("kind".into(), json!("histogram"));
        carry_source_key(dp, &mut s);
        let mut data = json!({
            "layout": "explicit",
            "buckets": str_array_u64(dp.get("bucketCounts")),
            "explicit_bounds": dp.get("explicitBounds").cloned().unwrap_or(json!([])),
            "count": str_u64(dp.get("count")),
        });
        if let Some(sum) = dp.get("sum").and_then(|v| v.as_f64()) {
            data["sum"] = json!(sum);
        }
        s.insert("data".into(), data);
    } else if let Some(sum) = m.get("sum") {
        let dp = sum.get("dataPoints")?.get(0)?;
        s.insert("kind".into(), json!("counter"));
        carry_source_key(dp, &mut s);
        s.insert("data".into(), json!({ "value": str_u64(dp.get("asInt")), "start_unix_nano": str_u64(dp.get("timeUnixNano")) }));
    } else {
        let g = m.get("gauge")?;
        let dp = g.get("dataPoints")?.get(0)?;
        s.insert("kind".into(), json!("gauge"));
        carry_source_key(dp, &mut s);
        s.insert("data".into(), json!({ "value": dp.get("asDouble").and_then(|v| v.as_f64()).unwrap_or(0.0), "time_unix_nano": str_u64(dp.get("timeUnixNano")) }));
    }
    Some(Value::Object(s))
}

fn carry_source_key(dp: &Value, s: &mut Map<String, Value>) {
    if let Some(src) = dp_attr(dp, "assayist.source") {
        s.insert("source".into(), json!(src));
    }
    if let Some(key) = dp_attr(dp, "assayist.key") {
        s.insert("key".into(), json!(key));
    }
}

fn dp_attr(dp: &Value, key: &str) -> Option<String> {
    attr_str(dp.get("attributes")?, key)
}

// OTLP/JSON attribute readers.
fn attr_val<'a>(attrs: &'a Value, key: &str) -> Option<&'a Value> {
    attrs.as_array()?.iter().find(|a| a["key"] == key).map(|a| &a["value"])
}
fn attr_str(attrs: &Value, key: &str) -> Option<String> {
    attr_val(attrs, key)?.get("stringValue")?.as_str().map(String::from)
}
fn attr_int(attrs: &Value, key: &str) -> Option<i64> {
    let v = attr_val(attrs, key)?.get("intValue")?;
    v.as_str().and_then(|s| s.parse().ok()).or_else(|| v.as_i64())
}
fn attr_bool(attrs: &Value, key: &str) -> Option<bool> {
    attr_val(attrs, key)?.get("boolValue")?.as_bool()
}

fn kv_list_to_object(v: Option<&Value>) -> Map<String, Value> {
    let mut m = Map::new();
    let Some(arr) = v.and_then(|x| x.as_array()) else { return m };
    for kv in arr {
        let Some(k) = kv.get("key").and_then(|x| x.as_str()) else { continue };
        let val = kv.get("value");
        let plain = if let Some(s) = val.and_then(|x| x.get("stringValue")).and_then(|x| x.as_str()) {
            json!(s)
        } else if let Some(b) = val.and_then(|x| x.get("boolValue")).and_then(|x| x.as_bool()) {
            json!(b)
        } else if let Some(d) = val.and_then(|x| x.get("doubleValue")).and_then(|x| x.as_f64()) {
            json!(d)
        } else if let Some(i) = val.and_then(|x| x.get("intValue")) {
            i.as_str().and_then(|s| s.parse::<i64>().ok()).map(|n| json!(n)).unwrap_or(Value::Null)
        } else {
            Value::Null
        };
        m.insert(k.to_string(), plain);
    }
    m
}

fn str_u64(v: Option<&Value>) -> u64 {
    v.and_then(|x| x.as_str().and_then(|s| s.parse().ok()).or_else(|| x.as_u64()))
        .unwrap_or(0)
}

fn str_array_u64(v: Option<&Value>) -> Vec<u64> {
    v.and_then(|x| x.as_array())
        .map(|a| a.iter().map(|x| str_u64(Some(x))).collect())
        .unwrap_or_default()
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
        // default export stamps 0.
        assert_eq!(dp["timeUnixNano"], "0");
    }

    #[test]
    fn export_at_stamps_histogram_and_probe_timestamps() {
        let series = vec![json!({
            "name": "kvm.exit_latency", "unit": "ns", "kind": "histogram", "source": "kvm_exit",
            "cardinality": {"class": "singleton"},
            "data": {"layout": "log2", "buckets": [1], "count": 1}
        })];
        let sm = vec![json!({"probe_id": "p", "attach_kind": "tracepoint", "run_time_ns": 5, "steady_cpu_fraction": 0.1, "over_budget": false})];
        let run = run_with(series, sm, vec![]);
        let metrics = &export_metrics_at(&run, 1234)["resourceMetrics"][0]["scopeMetrics"][0]["metrics"];
        let hist = metrics.as_array().unwrap().iter().find(|m| m["name"] == "kvm.exit_latency").unwrap();
        assert_eq!(hist["exponentialHistogram"]["dataPoints"][0]["timeUnixNano"], "1234");
        let cpu = metrics.as_array().unwrap().iter().find(|m| m["name"] == "assayist.probe.steady_cpu_fraction").unwrap();
        assert_eq!(cpu["gauge"]["dataPoints"][0]["timeUnixNano"], "1234");
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

    #[test]
    fn round_trips_through_export_and_import() {
        let series = vec![
            json!({
                "name": "kvm.exit_latency", "unit": "ns", "kind": "histogram", "source": "kvm_exit",
                "cardinality": {"class": "singleton"},
                "data": {"layout": "log2", "buckets": [3, 9, 14], "count": 26, "sum": 4242}
            }),
            json!({
                "name": "block.io_bytes", "unit": "By", "kind": "counter", "source": "block",
                "cardinality": {"class": "singleton"},
                "data": {"value": 4096, "start_unix_nano": 5}
            }),
        ];
        let sm = vec![json!({
            "probe_id": "kvm_exit", "attach_kind": "tracepoint",
            "run_time_ns": 41200, "run_cnt": 1, "mean_ns": 3.2,
            "steady_cpu_fraction": 0.0075, "over_budget": false
        })];
        let spans = vec![
            json!({"name": "boot", "start_unix_nano": 10, "end_unix_nano": 20}),
            json!({"name": "boot.init", "parent": "boot", "start_unix_nano": 11, "end_unix_nano": 19}),
        ];
        let run = run_with(series, sm, spans);

        let doc = export(&run);
        let back = import(&doc).unwrap();

        // Imported runs are always valid, never reproducible, with no self_metrics.
        assert_eq!(back.identity.source, "imported");
        assert_eq!(back.grade, Grade::Valid);
        assert!(back.self_metrics.is_empty());

        // Fingerprint core lifted from resource attrs.
        assert_eq!(back.fingerprint.hostname, "lab");
        assert_eq!(back.fingerprint.kernel_version, "6.11.0");

        // run_id lifted from traceId.
        assert_eq!(back.run_id, "0123456789abcdef0123456789abcdef");

        // Spans preserved with parent resolved back to a name.
        assert_eq!(back.spans.len(), 2);
        assert_eq!(back.spans[1]["name"], "boot.init");
        assert_eq!(back.spans[1]["parent"], "boot");
        assert_eq!(back.spans[0]["start_unix_nano"], 10);

        // The two series come back (probe metrics are dropped, not turned into series).
        assert_eq!(back.series.len(), 2);
        let hist = back.series.iter().find(|s| s["name"] == "kvm.exit_latency").unwrap();
        assert_eq!(hist["kind"], "histogram");
        assert_eq!(hist["data"]["layout"], "log2");
        assert_eq!(hist["data"]["buckets"], json!([3, 9, 14]));
        assert_eq!(hist["data"]["count"], 26);
        assert_eq!(hist["source"], "kvm_exit");
        let ctr = back.series.iter().find(|s| s["name"] == "block.io_bytes").unwrap();
        assert_eq!(ctr["kind"], "counter");
        assert_eq!(ctr["data"]["value"], 4096);
    }

    #[test]
    fn imports_metrics_only_document() {
        let doc = json!({
            "resourceMetrics": [{
                "resource": { "attributes": [
                    { "key": "host.name", "value": { "stringValue": "remote" } },
                    { "key": "os.version", "value": { "stringValue": "5.15.0" } }
                ]},
                "scopeMetrics": [{ "scope": { "name": "otel" }, "metrics": [{
                    "name": "app.latency", "unit": "ns",
                    "gauge": { "dataPoints": [{ "asDouble": 1.5, "timeUnixNano": "0" }] }
                }]}]
            }]
        });
        let run = import(&doc).unwrap();
        assert_eq!(run.fingerprint.hostname, "remote");
        assert_eq!(run.identity.source, "imported");
        assert_eq!(run.grade, Grade::Valid);
        assert_eq!(run.series.len(), 1);
        assert_eq!(run.series[0]["kind"], "gauge");
    }
}
