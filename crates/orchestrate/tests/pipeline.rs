// SPDX-License-Identifier: Apache-2.0
//! End-to-end pipeline test: drive the real `assayist run` binary over a def
//! whose target/workload are no-op command adapters and whose one gadget is a
//! stub script that emits a canned fragment. No BTF host or eBPF needed.
//!
//! Asserts the pipeline assembles the expected run files and reaches a gate
//! verdict (pass, since both groups emit identical fragments).

#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Command;

fn bin_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_assayist"))
        .parent()
        .unwrap()
        .to_path_buf()
}

/// The gate is a sibling binary. Build it if a prior workspace build did not.
fn gate_bin() -> PathBuf {
    let gate = bin_dir().join("assayist-gate");
    if !gate.exists() {
        let status = Command::new(env!("CARGO"))
            .args(["build", "-p", "assayist-gate"])
            .status()
            .expect("building assayist-gate");
        assert!(status.success(), "could not build assayist-gate");
    }
    assert!(gate.exists(), "gate binary missing at {}", gate.display());
    gate
}

#[test]
fn full_pipeline_produces_runs_and_a_verdict() {
    let gate = gate_bin();

    let dir = std::env::temp_dir().join(format!("assayist-it-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();

    // Stub gadget: parse --out, write a canned fragment there.
    let gadget = dir.join("stub-gadget");
    fs::write(
        &gadget,
        r#"#!/usr/bin/env bash
out=""
while [ $# -gt 0 ]; do
  case "$1" in
    --out) out="$2"; shift 2;;
    --duration) shift 2;;
    *) shift;;
  esac
done
cat > "$out" <<'JSON'
{
  "series": [{
    "name": "kvm.exit_handling_latency:EPT_VIOLATION",
    "unit": "ns", "kind": "histogram", "source": "kvm_exit",
    "cardinality": {"class": "singleton"},
    "data": {"layout": "log2", "buckets": [3,9,14,22,5], "count": 53, "sum": 91234}
  }],
  "self_metrics": [{
    "probe_id": "kvm_exit", "attach_kind": "tracepoint",
    "run_time_ns": 41200, "run_cnt": 12873, "mean_ns": 3.2,
    "steady_cpu_fraction": 0.0000013, "over_budget": false
  }],
  "capture_meta": {"gadget": "stub-gadget"}
}
JSON
"#,
    )
    .unwrap();
    fs::set_permissions(&gadget, fs::Permissions::from_mode(0o755)).unwrap();

    // Def: no host_prep (so tuning is trivially consistent), no-op command
    // adapters, one stub gadget.
    let def = dir.join("demo.assay.yaml");
    fs::write(
        &def,
        format!(
            r#"apiVersion: assayist/v0
name: pipeline-it
target: {{ adapter: firecracker, version: ">=0.3" }}
workload: {{ driver: fio-libaio }}
gate:
  mode: ab_permutation
  p_threshold: 0.01
  noise_threshold: 0.05
  resamples: 2000
capture:
  - probe: kvm_exit
    gadget: {gadget}
    cardinality: {{ class: singleton }}
tenancy: single_tenant
"#,
            gadget = gadget.display()
        ),
    )
    .unwrap();

    let out = dir.join("out");
    let result = Command::new(env!("CARGO_BIN_EXE_assayist"))
        .args([
            "run",
            def.to_str().unwrap(),
            "--repeat",
            "2",
            "--a-sut",
            "shaA",
            "--b-sut",
            "shaB",
            "--duration",
            "1",
            "--allow-ungraded",
            "--out",
            out.to_str().unwrap(),
        ])
        .env("ASSAYIST_GATE", &gate)
        .output()
        .expect("running assayist");

    let stderr = String::from_utf8_lossy(&result.stderr);

    // One cell (no parameterise), 2 repeats per group.
    assert!(out.join("a_0_0.json").exists(), "missing a_0_0.json\n{stderr}");
    assert!(out.join("a_0_1.json").exists(), "missing a_0_1.json\n{stderr}");
    assert!(out.join("b_0_0.json").exists(), "missing b_0_0.json\n{stderr}");
    assert!(out.join("b_0_1.json").exists(), "missing b_0_1.json\n{stderr}");
    assert!(out.join("outcome.json").exists(), "missing outcome.json\n{stderr}");

    // Identical fragments in both groups => no regression => pass => exit 0.
    assert!(
        result.status.success(),
        "expected pass (exit 0), got {:?}\n{stderr}",
        result.status.code()
    );

    // The assembled run is contract-shaped.
    let a0: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(out.join("a_0_0.json")).unwrap()).unwrap();
    assert_eq!(a0["identity"]["sut_git_sha"], "shaA");
    assert_eq!(a0["series"][0]["source"], "kvm_exit");
    assert_eq!(a0["grade"], "valid");

    let outcome: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(out.join("outcome.json")).unwrap()).unwrap();
    assert_eq!(outcome["outcome"]["verdict"], "pass");

    let _ = fs::remove_dir_all(&dir);
}
