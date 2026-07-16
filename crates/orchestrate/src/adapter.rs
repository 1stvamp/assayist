// SPDX-License-Identifier: Apache-2.0
//! Target and workload adapters, and the per-run loop that drives them.
//!
//! The adapter SPI is the external-contributor surface: a target implements
//! provision/start/reach_steady/mark-spans/teardown, a workload implements
//! start/stop/report. The capture plane and gate never learn what the target
//! is, which is exactly why one system spans every space.
//!
//! v0 ships a command adapter: it runs shell templates from the def, so a target
//! can be wired without writing Rust. Templates interpolate the cell's params as
//! `{name}`. Shell access sits behind [`Shell`] so tests never exec anything.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use assayist_contract::Fragment;
use serde_json::{json, Value};

use crate::capture::{GadgetInvocation, GadgetRunner};
use crate::def::BenchmarkDef;

/// The seam over the shell so tests do not run commands.
pub trait Shell {
    /// Run a command line, returning stdout. Non-zero exit is an error.
    fn run(&self, cmd: &str) -> Result<String, String>;
}

/// Real shell: `sh -c <cmd>`.
pub struct SystemShell;

impl Shell for SystemShell {
    fn run(&self, cmd: &str) -> Result<String, String> {
        let out = std::process::Command::new("sh")
            .arg("-c")
            .arg(cmd)
            .output()
            .map_err(|e| format!("running `{cmd}`: {e}"))?;
        if !out.status.success() {
            return Err(format!(
                "command failed ({}): {cmd}\n{}",
                out.status,
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }
}

pub trait Target {
    fn version(&self, sh: &dyn Shell) -> String;
    fn provision(&self, sh: &dyn Shell) -> Result<(), String>;
    fn start(&self, sh: &dyn Shell) -> Result<(), String>;
    fn reach_steady(&self, sh: &dyn Shell) -> Result<(), String>;
    /// Lifecycle spans the target recorded (boot/snapshot/restore markers).
    fn spans(&self, sh: &dyn Shell) -> Result<Vec<Value>, String>;
    fn teardown(&self, sh: &dyn Shell) -> Result<(), String>;
    /// The thread-pinning layout the target applied this run, if any (e.g.
    /// `{"vcpu0": 0, "vcpu1": 1}`). Recorded into the per-run fingerprint; a
    /// `None` leaves the run un-pinned, so it can grade at most `valid`. Default
    /// is `None` for targets that do not pin.
    fn pinning_layout(&self) -> Option<Value> {
        None
    }
}

pub trait Workload {
    fn version(&self, sh: &dyn Shell) -> String;
    fn start(&self, sh: &dyn Shell) -> Result<(), String>;
    fn stop(&self, sh: &dyn Shell) -> Result<(), String>;
    fn report(&self, sh: &dyn Shell) -> Result<Value, String>;
}

/// Command adapter shared shape: a phase->template map plus the vars to render.
#[derive(Clone, Debug)]
pub struct CommandSet {
    pub commands: BTreeMap<String, String>,
    pub vars: BTreeMap<String, String>,
}

impl CommandSet {
    /// Run the template for `phase` if present. Absent phase is a no-op.
    fn exec(&self, sh: &dyn Shell, phase: &str) -> Result<Option<String>, String> {
        match self.commands.get(phase) {
            Some(t) => sh.run(&render(t, &self.vars)).map(Some),
            None => Ok(None),
        }
    }

    fn version_or(&self, sh: &dyn Shell, default: &str) -> String {
        self.exec(sh, "version")
            .ok()
            .flatten()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| default.to_string())
    }
}

pub struct CommandTarget(pub CommandSet);
pub struct CommandWorkload(pub CommandSet);

impl Target for CommandTarget {
    fn version(&self, sh: &dyn Shell) -> String {
        self.0.version_or(sh, "command-adapter")
    }
    fn provision(&self, sh: &dyn Shell) -> Result<(), String> {
        self.0.exec(sh, "provision").map(|_| ())
    }
    fn start(&self, sh: &dyn Shell) -> Result<(), String> {
        self.0.exec(sh, "start").map(|_| ())
    }
    fn reach_steady(&self, sh: &dyn Shell) -> Result<(), String> {
        self.0.exec(sh, "reach_steady").map(|_| ())
    }
    fn spans(&self, sh: &dyn Shell) -> Result<Vec<Value>, String> {
        match self.0.exec(sh, "spans")? {
            Some(out) if !out.trim().is_empty() => {
                serde_json::from_str(out.trim()).map_err(|e| format!("parsing spans json: {e}"))
            }
            _ => Ok(vec![]),
        }
    }
    fn teardown(&self, sh: &dyn Shell) -> Result<(), String> {
        self.0.exec(sh, "teardown").map(|_| ())
    }
}

impl Workload for CommandWorkload {
    fn version(&self, sh: &dyn Shell) -> String {
        self.0.version_or(sh, "command-adapter")
    }
    fn start(&self, sh: &dyn Shell) -> Result<(), String> {
        self.0.exec(sh, "start").map(|_| ())
    }
    fn stop(&self, sh: &dyn Shell) -> Result<(), String> {
        self.0.exec(sh, "stop").map(|_| ())
    }
    fn report(&self, sh: &dyn Shell) -> Result<Value, String> {
        match self.0.exec(sh, "report")? {
            Some(out) if !out.trim().is_empty() => {
                serde_json::from_str(out.trim()).map_err(|e| format!("parsing report json: {e}"))
            }
            _ => Ok(Value::Null),
        }
    }
}

/// Build the v0 command adapters for a cell.
pub fn command_target(def: &BenchmarkDef, vars: BTreeMap<String, String>) -> CommandTarget {
    CommandTarget(CommandSet { commands: def.target.commands.clone(), vars })
}

pub fn command_workload(def: &BenchmarkDef, vars: BTreeMap<String, String>) -> CommandWorkload {
    CommandWorkload(CommandSet { commands: def.workload.commands.clone(), vars })
}

/// Cell params as `{name}` substitution vars, plus the SUT sha.
pub fn vars(params: &Value, sut_sha: &str) -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    if let Some(obj) = params.as_object() {
        for (k, v) in obj {
            m.insert(k.clone(), value_to_plain(v));
        }
    }
    m.insert("sut_sha".to_string(), sut_sha.to_string());
    m
}

pub(crate) fn render(template: &str, vars: &BTreeMap<String, String>) -> String {
    let mut s = template.to_string();
    for (k, v) in vars {
        s = s.replace(&format!("{{{k}}}"), v);
    }
    s
}

fn value_to_plain(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

/// What one run produced.
pub struct RunArtifacts {
    pub fragments: Vec<Fragment>,
    pub spans: Vec<Value>,
    pub workload_report: Value,
}

fn now_nanos() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos() as u64).unwrap_or(0)
}

/// Runs N inner targets as one, for concurrency benchmarks: it brings every
/// instance up and holds it resident through the capture window, so a host-side
/// capture (the memory delta especially) measures the aggregate. A file-backed
/// restore stays roughly flat as N grows; a per-sandbox copy grows with N.
///
/// This is where concurrency lives, generic over the inner `Target`, so any
/// adapter (firecracker, the command adapter, a future hypervisor) gets
/// N-sandbox runs without its own fanout code. Each inner is built with a
/// distinct `{instance}` var so its sockets and scratch dirs do not collide. It
/// records one aggregate lifecycle span (wall time to bring all instances to
/// steady) under the inner adapter's own span name, so a 1-vs-N comparison lines
/// the metric up, and drops the per-instance lifecycle spans that would
/// otherwise collide on that id.
pub struct FanoutTarget {
    inners: Vec<Box<dyn Target>>,
    start_ns: RefCell<u64>,
    spans: RefCell<Vec<Value>>,
}

impl FanoutTarget {
    pub fn new(inners: Vec<Box<dyn Target>>) -> FanoutTarget {
        FanoutTarget { inners, start_ns: RefCell::new(0), spans: RefCell::new(Vec::new()) }
    }
}

impl Target for FanoutTarget {
    fn version(&self, sh: &dyn Shell) -> String {
        self.inners.first().map(|t| t.version(sh)).unwrap_or_else(|| "fanout".to_string())
    }
    fn provision(&self, sh: &dyn Shell) -> Result<(), String> {
        *self.start_ns.borrow_mut() = now_nanos();
        for t in &self.inners {
            t.provision(sh)?;
        }
        Ok(())
    }
    fn start(&self, sh: &dyn Shell) -> Result<(), String> {
        for t in &self.inners {
            t.start(sh)?;
        }
        Ok(())
    }
    fn reach_steady(&self, sh: &dyn Shell) -> Result<(), String> {
        for t in &self.inners {
            t.reach_steady(sh)?;
        }
        let end = now_nanos();
        // Name the aggregate span after the inner adapter's own lifecycle span
        // (restore.resume_to_steady, boot.vmm_ready, ...), so a 1-vs-N compare
        // reduces to the same metric id.
        let name = self
            .inners
            .first()
            .and_then(|t| t.spans(sh).ok())
            .and_then(|s| s.last().and_then(|sp| sp.get("name").and_then(|n| n.as_str()).map(String::from)))
            .unwrap_or_else(|| "reach_steady".to_string());
        self.spans.borrow_mut().push(json!({
            "name": name,
            "start_unix_nano": *self.start_ns.borrow(),
            "end_unix_nano": end,
        }));
        Ok(())
    }
    fn spans(&self, _sh: &dyn Shell) -> Result<Vec<Value>, String> {
        Ok(self.spans.borrow().clone())
    }
    fn teardown(&self, sh: &dyn Shell) -> Result<(), String> {
        let mut last = Ok(());
        for t in &self.inners {
            if let Err(e) = t.teardown(sh) {
                last = Err(e);
            }
        }
        last
    }
    fn pinning_layout(&self) -> Option<Value> {
        // Merge the instances' layouts as {"instance0": {...}, ...}. None unless
        // at least one instance pinned, so an unpinned fanout stays unpinned.
        let mut map = serde_json::Map::new();
        for (i, t) in self.inners.iter().enumerate() {
            if let Some(layout) = t.pinning_layout() {
                map.insert(format!("instance{i}"), layout);
            }
        }
        if map.is_empty() {
            None
        } else {
            Some(Value::Object(map))
        }
    }
}

/// Parse `MemAvailable` and `Cached` (both KiB) out of /proc/meminfo text.
/// Missing fields read as 0. `starts_with("Cached:")` deliberately does not
/// match `SwapCached:`.
fn parse_meminfo(text: &str) -> (i64, i64) {
    let field = |name: &str| -> i64 {
        text.lines()
            .find(|l| l.starts_with(name))
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|n| n.parse::<i64>().ok())
            .unwrap_or(0)
    };
    (field("MemAvailable:"), field("Cached:"))
}

/// Sample (MemAvailable, Cached) in KiB, through the shell seam so it is
/// stubbable in tests.
fn sample_meminfo(sh: &dyn Shell) -> (i64, i64) {
    parse_meminfo(&sh.run("cat /proc/meminfo").unwrap_or_default())
}

/// A synthetic capture fragment carrying host memory deltas measured around the
/// target lifecycle (before provision vs. after reaching steady). It is not an
/// eBPF gadget, but it rides the same fragment path so the deltas become
/// gradeable series. `mem_consumed_kib` is how far MemAvailable dropped reaching
/// steady (positive = memory used, lower better). `cached_delta_kib` is the
/// page-cache change: sharing through the page cache lowers it, growth raises
/// it, so it is left without a graded direction. This is a host, system-level
/// measurement: it sees the machine's memory move, not per-guest attribution,
/// which needs the guest's own numbers.
fn hostmem_fragment(before: (i64, i64), after: (i64, i64)) -> Fragment {
    let gauge = |name: &str, value: i64| {
        json!({
            "name": name,
            "unit": "KiBy",
            "kind": "gauge",
            "source": "hostmem",
            "cardinality": {"class": "singleton"},
            "data": {"value": value, "time_unix_nano": 0},
        })
    };
    Fragment {
        series: vec![
            gauge("hostmem.mem_consumed_kib", before.0 - after.0),
            gauge("hostmem.cached_delta_kib", after.1 - before.1),
        ],
        self_metrics: vec![],
        capture_meta: Some(json!({"gadget": "hostmem", "source": "/proc/meminfo"})),
    }
}

/// Drive one run: bring the target up, spawn the gadgets, run the workload
/// across the capture window, collect fragments, then wind everything down.
/// Gadgets are spawned before the workload starts and waited on after, so they
/// observe the workload's window rather than dead air. Teardown is attempted
/// even when a step fails.
pub fn execute_run<S: Shell, R: GadgetRunner>(
    sh: &S,
    runner: &R,
    target: &dyn Target,
    workload: &dyn Workload,
    gadgets: &[GadgetInvocation],
) -> Result<RunArtifacts, String> {
    // Host memory before the target exists, and after it reaches steady: the
    // delta is the memory cost of preparing and restoring the guest, measured
    // outside the gadget window (which only opens post-steady).
    let mem_before = sample_meminfo(sh);
    target.provision(sh)?;
    target.start(sh)?;
    target.reach_steady(sh)?;
    let mem_after = sample_meminfo(sh);

    let mut handles = Vec::with_capacity(gadgets.len());
    for inv in gadgets {
        match runner.spawn(inv) {
            Ok(h) => handles.push(h),
            Err(e) => {
                let _ = target.teardown(sh);
                return Err(e);
            }
        }
    }

    if let Err(e) = workload.start(sh) {
        let _ = target.teardown(sh);
        return Err(e);
    }

    let mut fragments = Vec::with_capacity(gadgets.len());
    for (inv, handle) in gadgets.iter().zip(handles) {
        match runner.wait(inv, handle) {
            Ok(f) => fragments.push(f),
            Err(e) => {
                let _ = workload.stop(sh);
                let _ = target.teardown(sh);
                return Err(e);
            }
        }
    }

    let _ = workload.stop(sh);
    let workload_report = workload.report(sh).unwrap_or(Value::Null);
    let spans = target.spans(sh)?;
    target.teardown(sh)?;

    fragments.push(hostmem_fragment(mem_before, mem_after));

    Ok(RunArtifacts { fragments, spans, workload_report })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::plan_gadgets;
    use crate::def::{Cardinality, CaptureEntry};
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::path::Path;

    /// Records the commands it was asked to run and returns canned stdout keyed
    /// by a substring match, so tests assert ordering and templating.
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

    struct FakeRunner {
        frag: Fragment,
    }
    impl GadgetRunner for FakeRunner {
        type Handle = ();
        fn spawn(&self, _inv: &GadgetInvocation) -> Result<(), String> {
            Ok(())
        }
        fn wait(&self, _inv: &GadgetInvocation, _h: ()) -> Result<Fragment, String> {
            Ok(self.frag.clone())
        }
    }

    fn cset(pairs: &[(&str, &str)]) -> CommandSet {
        let mut commands = BTreeMap::new();
        for (k, v) in pairs {
            commands.insert(k.to_string(), v.to_string());
        }
        let mut vars = BTreeMap::new();
        vars.insert("vcpu".to_string(), "2".to_string());
        CommandSet { commands, vars }
    }

    #[test]
    fn render_substitutes_params() {
        let mut vars = BTreeMap::new();
        vars.insert("vcpu".to_string(), "4".to_string());
        assert_eq!(render("boot --vcpu {vcpu}", &vars), "boot --vcpu 4");
    }

    #[test]
    fn vars_carry_params_and_sut() {
        let m = vars(&serde_json::json!({"vcpu": 2, "mem_mib": 256}), "cafe");
        assert_eq!(m.get("vcpu").unwrap(), "2");
        assert_eq!(m.get("mem_mib").unwrap(), "256");
        assert_eq!(m.get("sut_sha").unwrap(), "cafe");
    }

    #[test]
    fn absent_phase_is_a_noop() {
        let sh = FakeShell::new();
        let t = CommandTarget(cset(&[("start", "echo up")]));
        // provision has no template: no command runs.
        t.provision(&sh).unwrap();
        assert!(sh.seen.borrow().is_empty());
        t.start(&sh).unwrap();
        assert_eq!(sh.seen.borrow().len(), 1);
        assert_eq!(sh.seen.borrow()[0], "echo up");
    }

    #[test]
    fn spans_parse_from_command_output() {
        let sh = FakeShell::new()
            .reply("emit-spans", r#"[{"name":"boot.vmm_ready","start_unix_nano":1,"end_unix_nano":9}]"#);
        let t = CommandTarget(cset(&[("spans", "emit-spans")]));
        let spans = t.spans(&sh).unwrap();
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0]["name"], "boot.vmm_ready");
    }

    #[test]
    fn execute_run_drives_the_full_sequence() {
        let sh = FakeShell::new().reply("emit-spans", r#"[{"name":"boot","start_unix_nano":1,"end_unix_nano":2}]"#);
        let frag = Fragment {
            series: vec![serde_json::json!({"name": "kvm.exit"})],
            self_metrics: vec![serde_json::json!({"probe_id": "kvm_exit"})],
            capture_meta: None,
        };
        let runner = FakeRunner { frag };

        let target = CommandTarget(cset(&[
            ("provision", "provision {vcpu}"),
            ("start", "start"),
            ("reach_steady", "steady"),
            ("spans", "emit-spans"),
            ("teardown", "teardown"),
        ]));
        let workload = CommandWorkload(cset(&[("start", "load"), ("stop", "halt")]));

        let entries = vec![CaptureEntry {
            probe: "kvm_exit".into(),
            gadget: Some("g".into()),
            cardinality: Cardinality { class: "singleton".into(), key_source: None, max_keys: None },
            attach: None,
            hot_path: false,
            args: vec![],
        }];
        let plan = plan_gadgets(&entries, 1, Path::new("/tmp"), &BTreeMap::new()).unwrap();

        let art = execute_run(&sh, &runner, &target, &workload, &plan).unwrap();
        // The gadget fragment plus the synthesized hostmem fragment.
        assert_eq!(art.fragments.len(), 2);
        assert!(art
            .fragments
            .iter()
            .any(|f| f.series.iter().any(|s| s["name"] == "hostmem.mem_consumed_kib")));
        assert_eq!(art.spans.len(), 1);

        let seen = sh.seen.borrow().clone();
        // Memory is sampled before the target is provisioned...
        assert_eq!(seen[0], "cat /proc/meminfo");
        // ...and again after it is steady, before the workload starts.
        let steady = seen.iter().position(|c| c == "steady").unwrap();
        let load = seen.iter().position(|c| c == "load").unwrap();
        assert!(seen[steady + 1..load].iter().any(|c| c == "cat /proc/meminfo"));

        // Lifecycle order, ignoring the two meminfo samples: target
        // provision/start/reach_steady, then workload start (gadgets spawn in
        // between), then stop, spans, teardown.
        let life: Vec<&str> = seen.iter().map(String::as_str).filter(|c| *c != "cat /proc/meminfo").collect();
        assert_eq!(life, ["provision 2", "start", "steady", "load", "halt", "emit-spans", "teardown"]);
    }

    #[test]
    fn parse_meminfo_reads_available_and_cached_not_swapcached() {
        let text = "MemTotal:       16000000 kB\nMemAvailable:    8000000 kB\nBuffers:          100000 kB\nCached:          2000000 kB\nSwapCached:         5000 kB\n";
        assert_eq!(parse_meminfo(text), (8_000_000, 2_000_000));
    }

    #[test]
    fn hostmem_fragment_reports_consumed_and_cached_delta() {
        // Available dropped 300 MiB (memory consumed); cached rose 50 MiB.
        let frag = hostmem_fragment((8_000_000, 2_000_000), (7_700_000, 2_050_000));
        let by_name = |n: &str| frag.series.iter().find(|s| s["name"] == n).unwrap()["data"]["value"].as_i64().unwrap();
        assert_eq!(by_name("hostmem.mem_consumed_kib"), 300_000);
        assert_eq!(by_name("hostmem.cached_delta_kib"), 50_000);
    }

    #[test]
    fn fanout_drives_every_inner_and_emits_one_aggregate_span() {
        let sh = FakeShell::new()
            .reply("emit", r#"[{"name":"boot.vmm_ready","start_unix_nano":1,"end_unix_nano":2}]"#);
        let inners: Vec<Box<dyn Target>> = (0..3)
            .map(|_| {
                Box::new(CommandTarget(cset(&[
                    ("provision", "prov"),
                    ("start", "st"),
                    ("reach_steady", "ready"),
                    ("spans", "emit"),
                    ("teardown", "td"),
                ]))) as Box<dyn Target>
            })
            .collect();
        let f = FanoutTarget::new(inners);
        f.provision(&sh).unwrap();
        f.start(&sh).unwrap();
        f.reach_steady(&sh).unwrap();

        // Every instance was driven through the lifecycle.
        let count = |needle: &str| sh.seen.borrow().iter().filter(|c| c.as_str() == needle).count();
        assert_eq!(count("prov"), 3);
        assert_eq!(count("ready"), 3);

        // One aggregate span, named after the inner's own lifecycle span, not
        // three colliding ones.
        let spans = f.spans(&sh).unwrap();
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0]["name"], "boot.vmm_ready");

        f.teardown(&sh).unwrap();
        assert_eq!(count("td"), 3);
    }
}
