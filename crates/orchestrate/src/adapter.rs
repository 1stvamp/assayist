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

use std::collections::BTreeMap;

use assayist_contract::Fragment;
use serde_json::Value;

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
    target.provision(sh)?;
    target.start(sh)?;
    target.reach_steady(sh)?;

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
            .reply("emit-spans", r#"[{"name":"boot.api_to_init","start_unix_nano":1,"end_unix_nano":9}]"#);
        let t = CommandTarget(cset(&[("spans", "emit-spans")]));
        let spans = t.spans(&sh).unwrap();
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0]["name"], "boot.api_to_init");
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
        let plan = plan_gadgets(&entries, 1, Path::new("/tmp")).unwrap();

        let art = execute_run(&sh, &runner, &target, &workload, &plan).unwrap();
        assert_eq!(art.fragments.len(), 1);
        assert_eq!(art.spans.len(), 1);

        // Order: target provision/start/reach_steady, then workload start
        // (gadgets spawn between reach_steady and workload start), then stop,
        // then spans, then teardown.
        let seen = sh.seen.borrow().clone();
        assert_eq!(seen[0], "provision 2"); // params rendered
        assert_eq!(seen[1], "start"); // target start
        assert_eq!(seen[2], "steady");
        assert_eq!(seen[3], "load"); // workload start, after target is steady
        assert_eq!(seen[4], "halt"); // workload stop
        assert_eq!(seen[5], "emit-spans");
        assert_eq!(seen[6], "teardown");
    }
}
