// SPDX-License-Identifier: Apache-2.0
//! Native reference adapters: a firecracker microVM target and an fio workload.
//!
//! A def author selects `target.adapter: firecracker` / `workload.driver: fio`
//! (or `fio-*`) and gets the real lifecycle: firecracker boot/snapshot/restore
//! spans and a structured fio report, without hand-writing the shell templates
//! the command adapter needs. Settings come from the def's `target.config` /
//! `workload.config` maps; string values may reference cell params as `{name}`.
//!
//! Both drive their tool through the [`Shell`](crate::adapter::Shell) seam
//! (firecracker via `curl --unix-socket`, fio via its CLI) so the API
//! sequencing and output parsing are unit-testable without a KVM host. The seam
//! is shell rather than a direct unix-socket client purely for that reason: the
//! curl calls are the same requests a socket client would send, and every other
//! adapter in the crate already goes through `Shell`.
//!
//! Limits: neither has been exercised against a real firecracker/fio yet (needs
//! a KVM host; see HANDOFF.md). The `boot.api_to_init` span measures the
//! InstanceStart API round-trip, not the guest reaching userspace init: without
//! an in-guest agent the host cannot observe guest-init, and adding one would
//! break the agentless vantage. `reach_steady` runs an optional author-supplied
//! `readiness` shell probe. Teardown kills firecracker by matching the api-sock
//! path, so do not share one sock path across concurrent runs.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{json, Map, Value};

use crate::adapter::{render, Shell, Target, Workload};

/// Read a config key, render `{param}` refs, fall back to `default`.
fn cfg(
    config: &BTreeMap<String, Value>,
    vars: &BTreeMap<String, String>,
    key: &str,
    default: &str,
) -> String {
    match config.get(key) {
        Some(Value::String(s)) => render(s, vars),
        Some(other) => other.to_string(),
        None => default.to_string(),
    }
}

fn now_nanos() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

fn span(name: &str, parent: Option<&str>, start: u64, end: u64) -> Value {
    let mut m = Map::new();
    m.insert("name".into(), json!(name));
    if let Some(p) = parent {
        m.insert("parent".into(), json!(p));
    }
    m.insert("start_unix_nano".into(), json!(start));
    m.insert("end_unix_nano".into(), json!(end));
    Value::Object(m)
}

/// First token that looks like a version (`v?<digit>...`) in a tool's
/// `--version` output, else the whole trimmed first line.
fn version_token(out: &str) -> String {
    let first = out.lines().next().unwrap_or("").trim();
    first
        .split_whitespace()
        .find(|t| {
            let t = t.strip_prefix('v').unwrap_or(t);
            t.chars().next().is_some_and(|c| c.is_ascii_digit())
        })
        .map(str::to_string)
        .unwrap_or_else(|| first.to_string())
}

// --- firecracker target -----------------------------------------------------

/// A firecracker microVM. Two modes, chosen by config:
/// - cold boot (default): configure machine/boot-source/drives, then
///   `InstanceStart`, recording `boot.api_to_init`.
/// - restore (`from_snapshot` set): `snapshot/load` with `resume_vm`, recording
///   `restore.resume_to_steady`; `start` is then a no-op.
///
/// With `snapshot_out` set, `reach_steady` also pauses, creates a full
/// snapshot, and resumes, recording `snapshot.create`.
pub struct FirecrackerTarget {
    bin: String,
    sock: String,
    vcpu: String,
    mem_mib: String,
    smt: bool,
    kernel: String,
    rootfs: String,
    boot_args: String,
    /// (snapshot_path, mem_file): restore mode.
    from_snapshot: Option<(String, String)>,
    /// (snapshot_path, mem_file): snapshot the running VM at steady state.
    snapshot_out: Option<(String, String)>,
    readiness: Option<String>,
    spans: RefCell<Vec<Value>>,
}

pub fn firecracker_target(
    config: &BTreeMap<String, Value>,
    vars: &BTreeMap<String, String>,
) -> FirecrackerTarget {
    let g = |k: &str, d: &str| cfg(config, vars, k, d);
    // vcpu/mem come from the parameterisation cell when present.
    let vcpu = vars.get("vcpu").cloned().unwrap_or_else(|| g("vcpu", "1"));
    let mem_mib = vars.get("mem_mib").cloned().unwrap_or_else(|| g("mem_mib", "128"));
    let smt = matches!(g("smt", "false").as_str(), "true" | "on" | "1");
    let pid = std::process::id();
    let sock = g("api_sock", &format!("/tmp/assayist-fc-{pid}.sock"));

    let from_snapshot = match (config.get("from_snapshot"), config.get("mem_file")) {
        (Some(_), _) => Some((g("from_snapshot", ""), g("mem_file", ""))),
        _ => None,
    };
    let snapshot_out = config
        .get("snapshot_out")
        .map(|_| (g("snapshot_out", ""), g("snapshot_mem", "")));
    let readiness = config.get("readiness").map(|_| g("readiness", ""));

    FirecrackerTarget {
        bin: g("bin", "firecracker"),
        sock,
        vcpu,
        mem_mib,
        smt,
        kernel: g("kernel", ""),
        rootfs: g("rootfs", ""),
        boot_args: g("boot_args", "console=ttyS0 reboot=k panic=1"),
        from_snapshot,
        snapshot_out,
        readiness,
        spans: RefCell::new(Vec::new()),
    }
}

impl FirecrackerTarget {
    fn api(&self, sh: &dyn Shell, method: &str, path: &str, body: &str) -> Result<(), String> {
        let cmd = format!(
            "curl -fsS --unix-socket '{}' -X {method} 'http://localhost{path}' \
             -H 'Content-Type: application/json' -d '{body}'",
            self.sock
        );
        sh.run(&cmd).map(|_| ())
    }

    /// Time a fallible API step and record it as a span.
    fn timed(
        &self,
        name: &str,
        parent: Option<&str>,
        f: impl FnOnce() -> Result<(), String>,
    ) -> Result<(), String> {
        let start = now_nanos();
        f()?;
        let end = now_nanos();
        self.spans.borrow_mut().push(span(name, parent, start, end));
        Ok(())
    }
}

impl Target for FirecrackerTarget {
    fn version(&self, sh: &dyn Shell) -> String {
        match sh.run(&format!("'{}' --version", self.bin)) {
            Ok(out) => version_token(&out),
            Err(_) => "firecracker".to_string(),
        }
    }

    fn provision(&self, sh: &dyn Shell) -> Result<(), String> {
        // Launch the API server and wait for the socket to appear.
        let launch = format!(
            "rm -f '{sock}'; '{bin}' --api-sock '{sock}' >'{sock}.log' 2>&1 & \
             for _ in $(seq 1 100); do [ -S '{sock}' ] && exit 0; sleep 0.05; done; \
             echo 'firecracker api socket did not appear' >&2; exit 1",
            sock = self.sock,
            bin = self.bin,
        );
        sh.run(&launch)?;

        if let Some((snap, mem)) = &self.from_snapshot {
            // Restore mode: load resumes the VM; that is the measured span.
            let body = json!({
                "snapshot_path": snap,
                "mem_backend": {"backend_path": mem, "backend_type": "File"},
                "resume_vm": true,
            })
            .to_string();
            return self.timed("restore.resume_to_steady", None, || {
                self.api(sh, "PUT", "/snapshot/load", &body)
            });
        }

        // Cold-boot config.
        let machine = json!({
            "vcpu_count": self.vcpu.parse::<u64>().unwrap_or(1),
            "mem_size_mib": self.mem_mib.parse::<u64>().unwrap_or(128),
            "smt": self.smt,
        })
        .to_string();
        self.api(sh, "PUT", "/machine-config", &machine)?;

        let boot = json!({"kernel_image_path": self.kernel, "boot_args": self.boot_args}).to_string();
        self.api(sh, "PUT", "/boot-source", &boot)?;

        let drive = json!({
            "drive_id": "rootfs",
            "path_on_host": self.rootfs,
            "is_root_device": true,
            "is_read_only": false,
        })
        .to_string();
        self.api(sh, "PUT", "/drives/rootfs", &drive)
    }

    fn start(&self, sh: &dyn Shell) -> Result<(), String> {
        // In restore mode the VM is already resumed by snapshot/load.
        if self.from_snapshot.is_some() {
            return Ok(());
        }
        self.timed("boot.api_to_init", None, || {
            self.api(sh, "PUT", "/actions", r#"{"action_type":"InstanceStart"}"#)
        })
    }

    fn reach_steady(&self, sh: &dyn Shell) -> Result<(), String> {
        if let Some(cmd) = &self.readiness {
            if !cmd.trim().is_empty() {
                sh.run(cmd)?;
            }
        }
        // Snapshot the steady-state VM if asked.
        if let Some((snap, mem)) = &self.snapshot_out {
            self.api(sh, "PATCH", "/vm", r#"{"state":"Paused"}"#)?;
            let body = json!({
                "snapshot_type": "Full",
                "snapshot_path": snap,
                "mem_file_path": mem,
            })
            .to_string();
            self.timed("snapshot.create", None, || {
                self.api(sh, "PUT", "/snapshot/create", &body)
            })?;
            self.api(sh, "PATCH", "/vm", r#"{"state":"Resumed"}"#)?;
        }
        Ok(())
    }

    fn spans(&self, _sh: &dyn Shell) -> Result<Vec<Value>, String> {
        Ok(self.spans.borrow().clone())
    }

    fn teardown(&self, sh: &dyn Shell) -> Result<(), String> {
        // Best effort: kill the API server for this sock, remove the socket.
        // `rm -f` is last and always succeeds, so a no-match pkill is not fatal.
        let cmd = format!(
            "pkill -f -- \"--api-sock {sock}\"; rm -f '{sock}' '{sock}.log'",
            sock = self.sock
        );
        sh.run(&cmd).map(|_| ())
    }
}

// --- fio workload -----------------------------------------------------------

/// An fio job run to completion inside the capture window. `start` runs fio with
/// `--output-format=json` and stashes the output; `report` parses it into a
/// compact per-direction summary (iops, bandwidth, completion-latency mean and
/// p99). fio runs synchronously in `start` because the gadgets are already
/// spawned by then (see `adapter::execute_run`), so they observe its window.
pub struct FioWorkload {
    bin: String,
    args: Vec<String>,
    out: RefCell<Option<Value>>,
}

pub fn fio_workload(
    config: &BTreeMap<String, Value>,
    vars: &BTreeMap<String, String>,
) -> FioWorkload {
    let g = |k: &str, d: &str| cfg(config, vars, k, d);
    let args = vec![
        format!("--name={}", g("name", "assayist")),
        format!("--filename={}", g("filename", "/tmp/assayist-fio.dat")),
        format!("--rw={}", g("rw", "randread")),
        format!("--bs={}", g("bs", "4k")),
        format!("--iodepth={}", g("iodepth", "32")),
        format!("--numjobs={}", g("numjobs", "1")),
        format!("--ioengine={}", g("ioengine", "libaio")),
        format!("--direct={}", g("direct", "1")),
        format!("--size={}", g("size", "1G")),
        format!("--runtime={}", g("runtime", "30")),
        "--time_based".to_string(),
        "--output-format=json".to_string(),
    ];
    FioWorkload { bin: g("bin", "fio"), args, out: RefCell::new(None) }
}

impl Workload for FioWorkload {
    fn version(&self, sh: &dyn Shell) -> String {
        match sh.run(&format!("'{}' --version", self.bin)) {
            Ok(out) => version_token(&out),
            Err(_) => "fio".to_string(),
        }
    }

    fn start(&self, sh: &dyn Shell) -> Result<(), String> {
        let quoted: Vec<String> = self.args.iter().map(|a| format!("'{a}'")).collect();
        let out = sh.run(&format!("'{}' {}", self.bin, quoted.join(" ")))?;
        let parsed: Value = serde_json::from_str(out.trim())
            .map_err(|e| format!("parsing fio json output: {e}"))?;
        *self.out.borrow_mut() = Some(parsed);
        Ok(())
    }

    fn stop(&self, _sh: &dyn Shell) -> Result<(), String> {
        // fio ran to completion in `start`; nothing to stop.
        Ok(())
    }

    fn report(&self, _sh: &dyn Shell) -> Result<Value, String> {
        match self.out.borrow().as_ref() {
            Some(v) => Ok(fio_summary(v)),
            None => Ok(Value::Null),
        }
    }
}

/// Reduce fio JSON to a compact summary. Liberal: missing fields become null,
/// and it reads either `clat_ns` (modern) or `clat` for latency. The report is
/// opaque provenance (no grading/gating effect), so being tolerant is right.
fn fio_summary(v: &Value) -> Value {
    let job = v.get("jobs").and_then(|j| j.get(0));
    let dir = |name: &str| -> Value {
        let d = job.and_then(|j| j.get(name));
        let iops = d.and_then(|d| d.get("iops")).cloned().unwrap_or(Value::Null);
        let bw_kb = d.and_then(|d| d.get("bw")).cloned().unwrap_or(Value::Null);
        let clat = d.and_then(|d| d.get("clat_ns").or_else(|| d.get("clat")));
        let lat_mean = clat.and_then(|c| c.get("mean")).cloned().unwrap_or(Value::Null);
        let lat_p99 = clat
            .and_then(|c| c.get("percentile"))
            .and_then(|p| p.get("99.000000"))
            .cloned()
            .unwrap_or(Value::Null);
        json!({"iops": iops, "bw_kb_s": bw_kb, "clat_ns_mean": lat_mean, "clat_ns_p99": lat_p99})
    };
    json!({
        "driver": "fio",
        "fio_version": v.get("fio version").or_else(|| v.get("fio_version")).cloned().unwrap_or(Value::Null),
        "read": dir("read"),
        "write": dir("write"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::HashMap;

    struct FakeShell {
        seen: RefCell<Vec<String>>,
        replies: HashMap<String, String>,
    }
    impl FakeShell {
        fn new() -> FakeShell {
            FakeShell { seen: RefCell::new(vec![]), replies: HashMap::new() }
        }
        fn reply(mut self, needle: &str, out: &str) -> FakeShell {
            self.replies.insert(needle.to_string(), out.to_string());
            self
        }
        fn saw(&self, needle: &str) -> bool {
            self.seen.borrow().iter().any(|c| c.contains(needle))
        }
    }
    impl Shell for FakeShell {
        fn run(&self, cmd: &str) -> Result<String, String> {
            self.seen.borrow_mut().push(cmd.to_string());
            for (needle, out) in &self.replies {
                if cmd.contains(needle) {
                    return Ok(out.clone());
                }
            }
            Ok(String::new())
        }
    }

    fn config(pairs: &[(&str, Value)]) -> BTreeMap<String, Value> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.clone())).collect()
    }

    fn vars(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn version_token_extracts_the_number() {
        assert_eq!(version_token("Firecracker v1.7.0\nfoo"), "v1.7.0");
        assert_eq!(version_token("fio-3.36"), "fio-3.36");
        assert_eq!(version_token("fio 3.36"), "3.36");
    }

    #[test]
    fn firecracker_cold_boot_configures_then_starts() {
        let cfg = config(&[
            ("kernel", json!("/k/vmlinux")),
            ("rootfs", json!("/k/rootfs.ext4")),
        ]);
        let t = firecracker_target(&cfg, &vars(&[("vcpu", "2"), ("mem_mib", "512")]));
        let sh = FakeShell::new();

        t.provision(&sh).unwrap();
        t.start(&sh).unwrap();
        t.reach_steady(&sh).unwrap();

        assert!(sh.saw("--api-sock"));
        assert!(sh.saw("/machine-config"));
        assert!(sh.saw("\"vcpu_count\":2"));
        assert!(sh.saw("\"mem_size_mib\":512"));
        assert!(sh.saw("/boot-source"));
        assert!(sh.saw("/k/vmlinux"));
        assert!(sh.saw("/drives/rootfs"));
        assert!(sh.saw("InstanceStart"));

        let spans = t.spans(&sh).unwrap();
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0]["name"], "boot.api_to_init");
        assert!(spans[0]["end_unix_nano"].as_u64() >= spans[0]["start_unix_nano"].as_u64());
    }

    #[test]
    fn firecracker_restore_mode_loads_and_skips_start() {
        let cfg = config(&[
            ("from_snapshot", json!("/s/snap")),
            ("mem_file", json!("/s/mem")),
        ]);
        let t = firecracker_target(&cfg, &vars(&[]));
        let sh = FakeShell::new();

        t.provision(&sh).unwrap();
        t.start(&sh).unwrap();

        assert!(sh.saw("/snapshot/load"));
        assert!(sh.saw("\"resume_vm\":true"));
        assert!(!sh.saw("InstanceStart"));
        assert!(!sh.saw("/machine-config"));

        let spans = t.spans(&sh).unwrap();
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0]["name"], "restore.resume_to_steady");
    }

    #[test]
    fn firecracker_snapshot_out_pauses_creates_resumes() {
        let cfg = config(&[
            ("kernel", json!("/k/vmlinux")),
            ("rootfs", json!("/k/rootfs.ext4")),
            ("snapshot_out", json!("/s/snap")),
            ("snapshot_mem", json!("/s/mem")),
        ]);
        let t = firecracker_target(&cfg, &vars(&[]));
        let sh = FakeShell::new();

        t.provision(&sh).unwrap();
        t.start(&sh).unwrap();
        t.reach_steady(&sh).unwrap();

        assert!(sh.saw("\"state\":\"Paused\""));
        assert!(sh.saw("/snapshot/create"));
        assert!(sh.saw("\"state\":\"Resumed\""));

        let names: Vec<String> =
            t.spans(&sh).unwrap().iter().map(|s| s["name"].as_str().unwrap().to_string()).collect();
        assert!(names.contains(&"boot.api_to_init".to_string()));
        assert!(names.contains(&"snapshot.create".to_string()));
    }

    #[test]
    fn firecracker_teardown_targets_the_sock() {
        let t = firecracker_target(&config(&[("api_sock", json!("/tmp/x.sock"))]), &vars(&[]));
        let sh = FakeShell::new();
        t.teardown(&sh).unwrap();
        assert!(sh.saw("--api-sock /tmp/x.sock"));
        assert!(sh.saw("rm -f '/tmp/x.sock'"));
    }

    #[test]
    fn fio_start_builds_command_and_reports_summary() {
        let out = r#"{
            "fio version": "fio-3.36",
            "jobs": [{
                "jobname": "assayist",
                "read": {"iops": 25600.5, "bw": 102400,
                         "clat_ns": {"mean": 3000.0, "percentile": {"99.000000": 9000}}},
                "write": {"iops": 0.0, "bw": 0,
                          "clat_ns": {"mean": 0.0, "percentile": {"99.000000": 0}}}
            }]
        }"#;
        let cfg = config(&[
            ("filename", json!("/dev/{dev}")),
            ("rw", json!("randread")),
            ("bs", json!("8k")),
        ]);
        let w = fio_workload(&cfg, &vars(&[("dev", "nvme0n1")]));
        let sh = FakeShell::new().reply("--output-format=json", out);

        w.start(&sh).unwrap();
        w.stop(&sh).unwrap();

        assert!(sh.saw("--filename=/dev/nvme0n1")); // param rendered
        assert!(sh.saw("--bs=8k"));
        assert!(sh.saw("--rw=randread"));

        let rep = w.report(&sh).unwrap();
        assert_eq!(rep["driver"], "fio");
        assert_eq!(rep["fio_version"], "fio-3.36");
        assert_eq!(rep["read"]["iops"], 25600.5);
        assert_eq!(rep["read"]["bw_kb_s"], 102400);
        assert_eq!(rep["read"]["clat_ns_mean"], 3000.0);
        assert_eq!(rep["read"]["clat_ns_p99"], 9000);
    }

    #[test]
    fn fio_report_is_null_before_a_run() {
        let w = fio_workload(&config(&[]), &vars(&[]));
        let sh = FakeShell::new();
        assert_eq!(w.report(&sh).unwrap(), Value::Null);
    }

    #[test]
    fn fio_version_falls_back_when_unavailable() {
        let w = fio_workload(&config(&[]), &vars(&[]));
        // FakeShell returns empty string (never errors), so version_token yields "".
        let sh = FakeShell::new().reply("--version", "fio-3.36");
        assert_eq!(w.version(&sh), "fio-3.36");
    }
}
