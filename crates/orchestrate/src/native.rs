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
//! Limits: the `boot.api_to_init` span measures the
//! InstanceStart API round-trip, not the guest reaching userspace init: without
//! an in-guest agent the host cannot observe guest-init, and adding one would
//! break the agentless vantage. `reach_steady` runs an optional author-supplied
//! `readiness` shell probe. Teardown kills firecracker by matching the api-sock
//! path, so do not share one sock path across concurrent runs.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

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
    /// Shell command run in restore mode after the API server is up but before
    /// `snapshot/load`, outside the measured span. Lets a def set the page-cache
    /// state the restore starts from: drop caches for a cold baseline, or warm a
    /// captured working set (e.g. `bpfoliod prefetch`) so resume faults hit cache.
    pre_restore: Option<String>,
    /// Pin each vCPU thread to a dedicated logical CPU and record the layout.
    pin_threads: bool,
    spans: RefCell<Vec<Value>>,
    pinning: RefCell<Option<Value>>,
}

pub fn firecracker_target(
    config: &BTreeMap<String, Value>,
    vars: &BTreeMap<String, String>,
    pin_threads: bool,
) -> FirecrackerTarget {
    let g = |k: &str, d: &str| cfg(config, vars, k, d);
    // vcpu/mem come from the parameterisation cell when present.
    let vcpu = vars.get("vcpu").cloned().unwrap_or_else(|| g("vcpu", "1"));
    let mem_mib = vars.get("mem_mib").cloned().unwrap_or_else(|| g("mem_mib", "128"));
    let smt = matches!(g("smt", "false").as_str(), "true" | "on" | "1");
    let pid = std::process::id();
    // The default socket carries the per-instance index (empty for a lone
    // instance) so concurrent instances of one def do not collide on it. A def
    // that sets `api_sock` for N > 1 should template `{instance}` itself.
    let inst = vars.get("instance").map(|i| format!("-{i}")).filter(|_| vars.contains_key("instance"));
    let sock = g("api_sock", &format!("/tmp/assayist-fc-{pid}{}.sock", inst.unwrap_or_default()));

    let from_snapshot = match (config.get("from_snapshot"), config.get("mem_file")) {
        (Some(_), _) => Some((g("from_snapshot", ""), g("mem_file", ""))),
        _ => None,
    };
    let snapshot_out = config
        .get("snapshot_out")
        .map(|_| (g("snapshot_out", ""), g("snapshot_mem", "")));
    let readiness = config.get("readiness").map(|_| g("readiness", ""));
    let pre_restore = config.get("pre_restore").map(|_| g("pre_restore", ""));

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
        pre_restore,
        pin_threads,
        spans: RefCell::new(Vec::new()),
        pinning: RefCell::new(None),
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

    /// Launch the firecracker API server in a fresh, wiped scratch cwd (see the
    /// vsock note in `provision`), recording its pid for teardown.
    fn launch_cmd(&self) -> String {
        format!(
            "rm -f '{sock}' '{sock}.pid'; wd='{sock}.d'; rm -rf \"$wd\"; mkdir -p \"$wd\"; \
             ( cd \"$wd\" && exec '{bin}' --api-sock '{sock}' ) >'{sock}.log' 2>&1 & \
             echo $! > '{sock}.pid'; \
             for _ in $(seq 1 100); do [ -S '{sock}' ] && exit 0; sleep 0.05; done; \
             echo 'firecracker api socket did not appear' >&2; exit 1",
            sock = self.sock,
            bin = self.bin,
        )
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

    /// Shell that pins each firecracker vCPU thread to a matching logical CPU
    /// (`fc_vcpu <n>` -> CPU `n`) via `taskset` and prints the applied layout as
    /// JSON on stdout. It reads the pid recorded at launch, so it must run after
    /// the VM has started (threads exist). A vcpu whose `taskset` fails aborts
    /// the run: a run that asked to pin and could not must not claim it did.
    fn pin_cmd(&self) -> String {
        format!(
            "pid=$(cat '{sock}.pid'); layout=''; \
             for t in /proc/$pid/task/*; do \
               comm=$(cat \"$t/comm\" 2>/dev/null); \
               case \"$comm\" in \"fc_vcpu \"*) \
                 n=${{comm#fc_vcpu }}; tid=${{t##*/}}; \
                 taskset -pc \"$n\" \"$tid\" >/dev/null 2>&1 || {{ echo \"pin vcpu $n failed\" >&2; exit 7; }}; \
                 layout=\"$layout,\\\"vcpu$n\\\":$n\"; \
               ;; esac; \
             done; \
             printf '{{%s}}' \"${{layout#,}}\"",
            sock = self.sock,
        )
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
        // Each firecracker runs in a fresh, wiped scratch cwd. A restored
        // snapshot can carry a vsock device whose host-side uds is a *relative*
        // path (Firecracker resolves it against cwd); without an isolated, wiped
        // cwd a leftover socket from the previous repeat makes the next
        // `snapshot/load` fail with EADDRINUSE, and N concurrent instances would
        // collide on one path. Def paths are absolute, so cd does not affect
        // kernel/rootfs/snapshot resolution. The pid goes to a file so teardown
        // can kill by pid rather than matching the command line (which would also
        // match the shell running the command and SIGTERM itself).
        sh.run(&self.launch_cmd())?;

        if let Some((snap, mem)) = &self.from_snapshot {
            // Set the page-cache state the restore starts from (drop caches for a
            // cold baseline, or warm a captured working set). Run before the
            // timed load so the prewarm cost is not charged to restore latency.
            if let Some(cmd) = &self.pre_restore {
                if !cmd.trim().is_empty() {
                    sh.run(cmd)?;
                }
            }
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
        // Pin vCPU threads once they exist (post start/resume) and record the
        // layout so a fully-prepped run can grade `reproducible`.
        if self.pin_threads {
            let out = sh.run(&self.pin_cmd())?;
            let layout: Value = serde_json::from_str(out.trim())
                .map_err(|e| format!("parsing pinning layout '{}': {e}", out.trim()))?;
            match layout.as_object() {
                Some(m) if !m.is_empty() => *self.pinning.borrow_mut() = Some(layout),
                _ => return Err("pin_threads requested but no fc_vcpu threads were pinned".into()),
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
        // Best effort: kill the API server by the pid recorded at launch, then
        // remove the socket/pid/log/scratch. `rm -rf` is last and always
        // succeeds, so a stale or missing pid is not fatal. Killing by pid (not
        // by command-line match) avoids SIGTERMing the shell that runs this very
        // command.
        let cmd = format!(
            "[ -f '{sock}.pid' ] && kill \"$(cat '{sock}.pid')\" 2>/dev/null; \
             rm -rf '{sock}' '{sock}.log' '{sock}.pid' '{sock}.d'",
            sock = self.sock
        );
        sh.run(&cmd).map(|_| ())
    }

    fn pinning_layout(&self) -> Option<Value> {
        self.pinning.borrow().clone()
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

// --- wrk workload -----------------------------------------------------------

/// An HTTP load test run to completion inside the capture window. Like fio,
/// `start` runs wrk synchronously (the gadgets are already spawned) and stashes
/// its stdout; `report` parses the text summary into requests/sec, transfer/sec,
/// average/max latency, and total requests. wrk has no native JSON output, so
/// the parse is text-based and liberal (missing fields become null). The report
/// is opaque provenance, no grading effect.
pub struct WrkWorkload {
    bin: String,
    args: Vec<String>,
    out: RefCell<Option<String>>,
}

pub fn wrk_workload(
    config: &BTreeMap<String, Value>,
    vars: &BTreeMap<String, String>,
) -> WrkWorkload {
    let g = |k: &str, d: &str| cfg(config, vars, k, d);
    let mut args = vec![
        format!("-t{}", g("threads", "2")),
        format!("-c{}", g("connections", "10")),
        format!("-d{}s", g("duration", "30")),
        "--latency".to_string(),
    ];
    // Optional constant request rate (wrk2-style) and Lua script.
    if config.contains_key("rate") {
        args.push(format!("-R{}", g("rate", "")));
    }
    if config.contains_key("script") {
        args.push(format!("-s{}", g("script", "")));
    }
    args.push(g("url", "http://127.0.0.1:8080/"));
    WrkWorkload { bin: g("bin", "wrk"), args, out: RefCell::new(None) }
}

impl Workload for WrkWorkload {
    fn version(&self, sh: &dyn Shell) -> String {
        // wrk prints its version to stderr and exits non-zero, so `run` reports
        // an error; fall back to the driver name rather than a bogus version.
        match sh.run(&format!("'{}' --version 2>&1", self.bin)) {
            Ok(out) => version_token(&out),
            Err(_) => "wrk".to_string(),
        }
    }

    fn start(&self, sh: &dyn Shell) -> Result<(), String> {
        let quoted: Vec<String> = self.args.iter().map(|a| format!("'{a}'")).collect();
        let out = sh.run(&format!("'{}' {}", self.bin, quoted.join(" ")))?;
        *self.out.borrow_mut() = Some(out);
        Ok(())
    }

    fn stop(&self, _sh: &dyn Shell) -> Result<(), String> {
        // wrk ran to completion in `start`; nothing to stop.
        Ok(())
    }

    fn report(&self, _sh: &dyn Shell) -> Result<Value, String> {
        match self.out.borrow().as_ref() {
            Some(text) => Ok(wrk_summary(text)),
            None => Ok(Value::Null),
        }
    }
}

/// Parse wrk's text summary. Liberal: any field it cannot find stays null.
fn wrk_summary(text: &str) -> Value {
    // "Requests/sec:  8123.40" / "Transfer/sec:   1.23MB"
    let after_colon = |label: &str| -> Option<String> {
        text.lines()
            .find(|l| l.trim_start().starts_with(label))
            .and_then(|l| l.split(':').nth(1))
            .map(|s| s.trim().to_string())
    };
    let req_per_sec = after_colon("Requests/sec")
        .and_then(|s| s.parse::<f64>().ok())
        .map(|f| json!(f))
        .unwrap_or(Value::Null);
    let transfer_per_sec = after_colon("Transfer/sec").map(Value::String).unwrap_or(Value::Null);

    // "    Latency   1.23ms   0.45ms   10.50ms   80.00%": avg is the first
    // whitespace token after the "Latency" label.
    let latency_field = |label: &str, idx: usize| -> Value {
        text.lines()
            .find(|l| l.trim_start().starts_with(label))
            .and_then(|l| l.trim_start().strip_prefix(label))
            .and_then(|rest| rest.split_whitespace().nth(idx))
            .map(|s| Value::String(s.to_string()))
            .unwrap_or(Value::Null)
    };

    // "  81234 requests in 10.00s, 12.34MB read"
    let total_requests = text
        .lines()
        .find(|l| l.contains("requests in"))
        .and_then(|l| l.split_whitespace().next())
        .and_then(|s| s.parse::<u64>().ok())
        .map(|n| json!(n))
        .unwrap_or(Value::Null);

    json!({
        "driver": "wrk",
        "requests_per_sec": req_per_sec,
        "transfer_per_sec": transfer_per_sec,
        "latency_avg": latency_field("Latency", 0),
        "latency_max": latency_field("Latency", 2),
        "total_requests": total_requests,
    })
}

// --- vsock workload ---------------------------------------------------------

/// Drives an agentless guest over Firecracker's host-side vsock socket. For each
/// invocation it opens the uds, issues the Firecracker `CONNECT <port>`
/// handshake, optionally sends a payload, and drains the guest's response to EOF.
/// The connection itself is the invocation (that is how a snapshot-restored
/// function server is triggered), so this exercises the guest's working set
/// inside the capture window rather than letting it sit idle. `report` gives the
/// invocation count, error count, and a latency summary; timings are wall-clock
/// round-trips measured host-side.
///
/// The uds is the firecracker adapter's per-run vsock path. Because the adapter
/// runs each restore in a `{api_sock}.d` scratch cwd and the guest's uds is
/// relative (`fn.vsock`), a def coordinates the two: set a fixed `api_sock` on
/// the target and point `uds` at `{that}.d/{relative-name}`.
pub struct VsockWorkload {
    uds: String,
    port: u32,
    invocations: u32,
    payload: Vec<u8>,
    timeout: Duration,
    latencies_ns: RefCell<Vec<u128>>,
    errors: RefCell<u32>,
}

pub fn vsock_workload(
    config: &BTreeMap<String, Value>,
    vars: &BTreeMap<String, String>,
) -> VsockWorkload {
    let g = |k: &str, d: &str| cfg(config, vars, k, d);
    VsockWorkload {
        uds: g("uds", ""),
        port: g("port", "5252").parse().unwrap_or(5252),
        invocations: g("invocations", "50").parse().unwrap_or(50),
        payload: g("payload", "").into_bytes(),
        timeout: Duration::from_millis(g("timeout_ms", "5000").parse().unwrap_or(5000)),
        latencies_ns: RefCell::new(Vec::new()),
        errors: RefCell::new(0),
    }
}

impl VsockWorkload {
    /// One invocation: connect, CONNECT handshake, optional payload, drain the
    /// response to EOF. Returns the host-side round-trip.
    fn invoke_once(&self) -> Result<Duration, String> {
        let t0 = Instant::now();
        let mut stream =
            UnixStream::connect(&self.uds).map_err(|e| format!("connect {}: {e}", self.uds))?;
        stream.set_read_timeout(Some(self.timeout)).map_err(|e| format!("read timeout: {e}"))?;
        stream.set_write_timeout(Some(self.timeout)).map_err(|e| format!("write timeout: {e}"))?;
        writeln!(stream, "CONNECT {}", self.port).map_err(|e| format!("CONNECT: {e}"))?;
        let mut reader =
            BufReader::new(stream.try_clone().map_err(|e| format!("clone stream: {e}"))?);
        // Firecracker replies "OK <host_port>\n" once the guest accepts.
        let mut line = String::new();
        reader.read_line(&mut line).map_err(|e| format!("read OK: {e}"))?;
        if !line.starts_with("OK ") {
            return Err(format!("vsock CONNECT {} rejected: {line:?}", self.port));
        }
        if !self.payload.is_empty() {
            stream.write_all(&self.payload).map_err(|e| format!("write payload: {e}"))?;
        }
        // The guest treats the connection as the request, writes its response,
        // then closes: draining to EOF makes the round-trip include the
        // working-set touch.
        let mut resp = Vec::new();
        reader.read_to_end(&mut resp).map_err(|e| format!("read response: {e}"))?;
        Ok(t0.elapsed())
    }
}

impl Workload for VsockWorkload {
    fn version(&self, _sh: &dyn Shell) -> String {
        "vsock".to_string()
    }

    fn start(&self, _sh: &dyn Shell) -> Result<(), String> {
        if self.uds.trim().is_empty() {
            return Err("vsock workload needs a 'uds' (the firecracker host vsock socket)".into());
        }
        // Retry the first invocation until the guest is accepting or the timeout
        // is up: a just-resumed guest may not have re-bound its listener yet.
        // Once it answers, the remaining invocations run back to back.
        let deadline = Instant::now() + self.timeout;
        let mut last_err = String::new();
        let first = loop {
            match self.invoke_once() {
                Ok(d) => break Some(d),
                Err(e) => {
                    last_err = e;
                    if Instant::now() >= deadline {
                        break None;
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
            }
        };
        match first {
            Some(d) => self.latencies_ns.borrow_mut().push(d.as_nanos()),
            None => return Err(format!("vsock first invocation failed: {last_err}")),
        }
        for _ in 1..self.invocations {
            match self.invoke_once() {
                Ok(d) => self.latencies_ns.borrow_mut().push(d.as_nanos()),
                Err(_) => *self.errors.borrow_mut() += 1,
            }
        }
        Ok(())
    }

    fn stop(&self, _sh: &dyn Shell) -> Result<(), String> {
        Ok(())
    }

    fn report(&self, _sh: &dyn Shell) -> Result<Value, String> {
        Ok(vsock_summary(&self.latencies_ns.borrow(), *self.errors.borrow(), self.invocations))
    }
}

/// Summarise vsock invocation round-trips. Percentiles are nearest-rank on the
/// sorted samples; an all-failed run reports zero invocations and the error count.
fn vsock_summary(latencies_ns: &[u128], errors: u32, requested: u32) -> Value {
    if latencies_ns.is_empty() {
        return json!({"driver": "vsock", "invocations": 0, "requested": requested, "errors": errors});
    }
    let mut sorted = latencies_ns.to_vec();
    sorted.sort_unstable();
    let n = sorted.len();
    let sum: u128 = sorted.iter().sum();
    let pct = |p: f64| -> u64 {
        let idx = ((p * (n as f64 - 1.0)).round() as usize).min(n - 1);
        sorted[idx] as u64
    };
    json!({
        "driver": "vsock",
        "invocations": n,
        "requested": requested,
        "errors": errors,
        "latency_avg_ns": (sum / n as u128) as u64,
        "latency_p50_ns": pct(0.50),
        "latency_p99_ns": pct(0.99),
        "latency_max_ns": sorted[n - 1] as u64,
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
        fn first_containing(&self, needle: &str) -> Option<String> {
            self.seen.borrow().iter().find(|c| c.contains(needle)).cloned()
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
        let t = firecracker_target(&cfg, &vars(&[("vcpu", "2"), ("mem_mib", "512")]), false);
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
        let t = firecracker_target(&cfg, &vars(&[]), false);
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
    fn firecracker_default_socket_carries_the_instance_index() {
        let base = firecracker_target(&config(&[("from_snapshot", json!("/s"))]), &vars(&[]), false);
        let sh = FakeShell::new();
        base.provision(&sh).unwrap();
        assert!(sh.seen.borrow().iter().any(|c| c.contains("assayist-fc-") && !c.contains(".sock-")));

        let mut v = vars(&[]);
        v.insert("instance".into(), "2".into());
        let inst = firecracker_target(&config(&[("from_snapshot", json!("/s"))]), &v, false);
        let sh2 = FakeShell::new();
        inst.provision(&sh2).unwrap();
        // The per-instance socket is discriminated so concurrent instances of
        // one def do not collide.
        assert!(sh2.seen.borrow().iter().any(|c| c.contains("-2.sock")));
    }

    #[test]
    fn firecracker_pre_restore_runs_before_load_not_in_span() {
        let cfg = config(&[
            ("from_snapshot", json!("/s/snap")),
            ("mem_file", json!("/s/mem")),
            ("pre_restore", json!("warm-the-working-set")),
        ]);
        let t = firecracker_target(&cfg, &vars(&[]), false);
        let sh = FakeShell::new();
        t.provision(&sh).unwrap();

        let seen = sh.seen.borrow();
        let warm = seen.iter().position(|c| c.contains("warm-the-working-set"));
        let load = seen.iter().position(|c| c.contains("/snapshot/load"));
        assert!(warm.is_some() && load.is_some(), "both ran");
        assert!(warm < load, "prewarm runs before the load");
        // The prewarm is outside the timed span: only the load is a span.
        let spans = t.spans(&sh).unwrap();
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0]["name"], "restore.resume_to_steady");
    }

    #[test]
    fn firecracker_launches_in_a_wiped_scratch_cwd() {
        // A vsock-bearing snapshot binds a relative host uds; each restore must
        // run in a fresh, wiped cwd so a leftover socket cannot collide.
        let cfg = config(&[("kernel", json!("/k/vmlinux")), ("rootfs", json!("/r/rootfs"))]);
        let t = firecracker_target(&cfg, &vars(&[]), false);
        let sh = FakeShell::new();
        t.provision(&sh).unwrap();
        let launch = sh.first_containing("--api-sock").expect("launch ran");
        assert!(launch.contains("rm -rf \"$wd\""), "scratch cwd is wiped: {launch}");
        assert!(launch.contains("cd \"$wd\""), "fc runs in scratch cwd: {launch}");

        t.teardown(&sh).unwrap();
        assert!(sh.saw(".sock.d"), "teardown removes the scratch dir");
    }

    #[test]
    fn firecracker_snapshot_out_pauses_creates_resumes() {
        let cfg = config(&[
            ("kernel", json!("/k/vmlinux")),
            ("rootfs", json!("/k/rootfs.ext4")),
            ("snapshot_out", json!("/s/snap")),
            ("snapshot_mem", json!("/s/mem")),
        ]);
        let t = firecracker_target(&cfg, &vars(&[]), false);
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
    fn firecracker_pins_vcpu_threads_and_records_layout() {
        let cfg = config(&[
            ("kernel", json!("/k/vmlinux")),
            ("rootfs", json!("/k/rootfs.ext4")),
            ("api_sock", json!("/tmp/p.sock")),
        ]);
        let t = firecracker_target(&cfg, &vars(&[("vcpu", "2")]), true);
        // The pin command reads the launch pidfile and tasksets threads; the
        // fake returns the layout it "applied".
        let sh = FakeShell::new().reply("taskset", r#"{"vcpu0":0,"vcpu1":1}"#);

        t.provision(&sh).unwrap();
        t.start(&sh).unwrap();
        t.reach_steady(&sh).unwrap();

        assert!(sh.saw("taskset"));
        assert!(sh.saw("/tmp/p.sock.pid"));
        assert!(sh.saw("fc_vcpu"));
        assert_eq!(t.pinning_layout(), Some(json!({"vcpu0": 0, "vcpu1": 1})));
    }

    #[test]
    fn firecracker_no_pin_records_no_layout() {
        let cfg = config(&[("kernel", json!("/k/v")), ("rootfs", json!("/k/r"))]);
        let t = firecracker_target(&cfg, &vars(&[]), false);
        let sh = FakeShell::new();
        t.provision(&sh).unwrap();
        t.start(&sh).unwrap();
        t.reach_steady(&sh).unwrap();
        assert!(!sh.saw("taskset"));
        assert_eq!(t.pinning_layout(), None);
    }

    #[test]
    fn firecracker_pin_with_no_vcpu_threads_errors() {
        let cfg = config(&[("kernel", json!("/k/v")), ("rootfs", json!("/k/r"))]);
        let t = firecracker_target(&cfg, &vars(&[]), true);
        // No vcpu threads found -> pin command prints an empty object.
        let sh = FakeShell::new().reply("taskset", "{}");
        t.provision(&sh).unwrap();
        t.start(&sh).unwrap();
        assert!(t.reach_steady(&sh).is_err());
    }

    #[test]
    fn firecracker_teardown_kills_by_pidfile_not_cmdline() {
        let t = firecracker_target(&config(&[("api_sock", json!("/tmp/x.sock"))]), &vars(&[]), false);
        let sh = FakeShell::new();
        t.teardown(&sh).unwrap();
        // Kills by the recorded pid and cleans up; must NOT match on the
        // command line (that would SIGTERM the shell running the command).
        assert!(sh.saw("/tmp/x.sock.pid"));
        assert!(sh.saw("kill"));
        assert!(sh.saw("rm -rf '/tmp/x.sock'"));
        assert!(!sh.saw("pkill"));
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

    #[test]
    fn wrk_start_builds_command_and_reports_summary() {
        let out = "Running 10s test @ http://127.0.0.1:8080/\n\
             \x20 2 threads and 10 connections\n\
             \x20 Thread Stats   Avg      Stdev     Max   +/- Stdev\n\
             \x20   Latency     1.23ms    0.45ms   10.50ms   80.00%\n\
             \x20   Req/Sec     4.10k     0.50k     5.00k    75.00%\n\
             \x20 Latency Distribution\n\
             \x20    50%    1.10ms\n\
             \x20 81234 requests in 10.00s, 12.34MB read\n\
             Requests/sec:   8123.40\n\
             Transfer/sec:      1.23MB\n";
        let cfg = config(&[
            ("url", json!("http://{host}:8080/")),
            ("threads", json!("4")),
            ("connections", json!("100")),
            ("duration", json!("5")),
        ]);
        let w = wrk_workload(&cfg, &vars(&[("host", "10.0.0.5")]));
        // Reply keyed on a substring of the wrk command line (the rendered url).
        let sh = FakeShell::new().reply("http://10.0.0.5:8080/", out);

        w.start(&sh).unwrap();
        w.stop(&sh).unwrap();

        assert!(sh.saw("-t4"));
        assert!(sh.saw("-c100"));
        assert!(sh.saw("-d5s"));
        assert!(sh.saw("http://10.0.0.5:8080/")); // param rendered

        let rep = w.report(&sh).unwrap();
        assert_eq!(rep["driver"], "wrk");
        assert_eq!(rep["requests_per_sec"], 8123.40);
        assert_eq!(rep["transfer_per_sec"], "1.23MB");
        assert_eq!(rep["latency_avg"], "1.23ms");
        assert_eq!(rep["latency_max"], "10.50ms");
        assert_eq!(rep["total_requests"], 81234);
    }

    #[test]
    fn wrk_report_is_null_before_a_run() {
        let w = wrk_workload(&config(&[("url", json!("http://x/"))]), &vars(&[]));
        let sh = FakeShell::new();
        assert_eq!(w.report(&sh).unwrap(), Value::Null);
    }

    #[test]
    fn wrk_rate_and_script_are_optional_flags() {
        let base = wrk_workload(&config(&[("url", json!("http://x/"))]), &vars(&[]));
        let sh = FakeShell::new();
        base.start(&sh).unwrap();
        assert!(!sh.saw("-R"));
        assert!(!sh.saw("-s"));

        let withopts = wrk_workload(
            &config(&[("url", json!("http://x/")), ("rate", json!("2000")), ("script", json!("/s.lua"))]),
            &vars(&[]),
        );
        let sh2 = FakeShell::new();
        withopts.start(&sh2).unwrap();
        assert!(sh2.saw("-R2000"));
        assert!(sh2.saw("-s/s.lua"));
    }

    #[test]
    fn vsock_summary_reports_percentiles_and_average() {
        // 10 samples 1000..10000 ns.
        let lat: Vec<u128> = (1..=10).map(|i| i as u128 * 1000).collect();
        let r = vsock_summary(&lat, 2, 12);
        assert_eq!(r["invocations"], 10);
        assert_eq!(r["requested"], 12);
        assert_eq!(r["errors"], 2);
        assert_eq!(r["latency_avg_ns"], 5500);
        assert_eq!(r["latency_max_ns"], 10000);
        assert_eq!(r["latency_p50_ns"], 6000); // nearest-rank idx round(0.5*9)=5 -> 6000
        assert_eq!(r["latency_p99_ns"], 10000);
    }

    #[test]
    fn vsock_summary_with_no_samples_is_zero() {
        let r = vsock_summary(&[], 5, 5);
        assert_eq!(r["invocations"], 0);
        assert_eq!(r["errors"], 5);
        assert!(r.get("latency_avg_ns").is_none());
    }

    #[test]
    fn vsock_start_without_uds_is_an_error() {
        let w = vsock_workload(&config(&[("port", json!("5252"))]), &vars(&[]));
        let sh = FakeShell::new();
        let err = w.start(&sh).unwrap_err();
        assert!(err.contains("uds"), "{err}");
    }
}
