// SPDX-License-Identifier: Apache-2.0
//! Firing capture gadgets and collecting their fragments.
//!
//! Each gadget is a standalone binary that aggregates in-kernel and writes one
//! JSON fragment (`series` + `self_metrics` + `capture_meta`) to a `--out` path
//! over a `--duration` window. The orchestrator does not link them; it launches
//! them as subprocesses.
//!
//! Gadgets must observe the *same* window, so [`capture`] spawns them all first
//! and only then waits on each. Running them one after another would give each
//! its own disjoint window, which would be a confidently wrong measurement. The
//! spawn/wait split sits behind [`GadgetRunner`] so tests inject canned
//! fragments without a BTF host.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};

use assayist_contract::Fragment;

use crate::adapter::render;
use crate::def::CaptureEntry;

/// A resolved gadget launch: which binary, with which args, writing where.
#[derive(Clone, Debug)]
pub struct GadgetInvocation {
    pub gadget: String,
    pub probe: String,
    pub args: Vec<String>,
    pub out_path: PathBuf,
}

/// Turn the def's capture entries into concrete launches. For v0 every gadget
/// gets `--duration` and `--out`; per-gadget cardinality flags (e.g. the kvm
/// gadget's `--per-guest`/`--max-keys`) come from each entry's `args`. Those
/// args are rendered with `vars` (cell params, `{def_dir}`, ...) like the
/// target/workload configs, so a gadget can reference e.g. a `{def_dir}`-relative
/// mem file to measure.
pub fn plan_gadgets(
    entries: &[CaptureEntry],
    duration_secs: u64,
    out_dir: &Path,
    vars: &BTreeMap<String, String>,
) -> Result<Vec<GadgetInvocation>, String> {
    let mut plan = Vec::with_capacity(entries.len());
    for e in entries {
        let gadget = e
            .gadget
            .clone()
            .ok_or_else(|| format!("capture '{}' names no gadget binary to run", e.probe))?;
        let out_path = out_dir.join(format!("{}.frag.json", sanitize(&e.probe)));
        let mut args = vec![
            "--duration".to_string(),
            duration_secs.to_string(),
            "--out".to_string(),
            out_path.to_string_lossy().into_owned(),
        ];
        args.extend(e.args.iter().map(|a| render(a, vars)));
        plan.push(GadgetInvocation { gadget, probe: e.probe.clone(), args, out_path });
    }
    Ok(plan)
}

/// The seam between orchestration and the OS. Two phases so all gadgets start
/// before any is waited on.
pub trait GadgetRunner {
    type Handle;
    fn spawn(&self, inv: &GadgetInvocation) -> Result<Self::Handle, String>;
    fn wait(&self, inv: &GadgetInvocation, handle: Self::Handle) -> Result<Fragment, String>;
    /// Abandon a spawned gadget without collecting it, used to clean up already
    /// running gadgets when a later spawn fails. Default no-op.
    fn kill(&self, _handle: Self::Handle) {}
}

/// Spawn every gadget, then collect every fragment. A failure to spawn or a
/// non-zero exit fails the whole capture: a missing series means the assembled
/// run cannot be trusted, so it is better to refuse than to grade a hole. If a
/// spawn fails midway, the gadgets already spawned are killed rather than left
/// running.
pub fn capture<R: GadgetRunner>(
    plan: &[GadgetInvocation],
    runner: &R,
) -> Result<Vec<Fragment>, String> {
    let mut handles = Vec::with_capacity(plan.len());
    for inv in plan {
        match runner.spawn(inv) {
            Ok(h) => handles.push(h),
            Err(e) => {
                for h in handles {
                    runner.kill(h);
                }
                return Err(e);
            }
        }
    }
    let mut fragments = Vec::with_capacity(plan.len());
    for (inv, handle) in plan.iter().zip(handles) {
        fragments.push(runner.wait(inv, handle)?);
    }
    Ok(fragments)
}

/// Real runner: launches gadget subprocesses.
pub struct SubprocessRunner;

impl GadgetRunner for SubprocessRunner {
    type Handle = Child;

    fn spawn(&self, inv: &GadgetInvocation) -> Result<Child, String> {
        Command::new(&inv.gadget)
            .args(&inv.args)
            .spawn()
            .map_err(|e| format!("launching {} ({}): {e}", inv.gadget, inv.probe))
    }

    fn wait(&self, inv: &GadgetInvocation, mut child: Child) -> Result<Fragment, String> {
        let status = child
            .wait()
            .map_err(|e| format!("waiting on {} ({}): {e}", inv.gadget, inv.probe))?;
        if !status.success() {
            return Err(format!(
                "{} ({}) exited with {}",
                inv.gadget, inv.probe, status
            ));
        }
        let text = std::fs::read_to_string(&inv.out_path).map_err(|e| {
            format!("reading fragment from {}: {e}", inv.out_path.display())
        })?;
        serde_json::from_str(&text)
            .map_err(|e| format!("parsing fragment from {} ({}): {e}", inv.probe, e))
    }

    fn kill(&self, mut child: Child) {
        let _ = child.kill();
        let _ = child.wait();
    }
}

fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::def::Cardinality;
    use std::collections::HashMap;

    /// Returns a canned fragment per probe, so the collect/assemble path runs
    /// without a BTF host.
    struct FakeRunner {
        by_probe: HashMap<String, Fragment>,
    }

    impl GadgetRunner for FakeRunner {
        type Handle = Fragment;
        fn spawn(&self, inv: &GadgetInvocation) -> Result<Fragment, String> {
            self.by_probe
                .get(&inv.probe)
                .cloned()
                .ok_or_else(|| format!("no canned fragment for {}", inv.probe))
        }
        fn wait(&self, _inv: &GadgetInvocation, handle: Fragment) -> Result<Fragment, String> {
            Ok(handle)
        }
    }

    fn entry(probe: &str, gadget: Option<&str>) -> CaptureEntry {
        CaptureEntry {
            probe: probe.to_string(),
            gadget: gadget.map(String::from),
            cardinality: Cardinality { class: "singleton".into(), key_source: None, max_keys: None },
            attach: None,
            hot_path: false,
            args: vec![],
        }
    }

    #[test]
    fn plans_duration_and_out_per_gadget() {
        let entries = vec![entry("kvm_exit", Some("assayist-capture-kvm"))];
        let plan = plan_gadgets(&entries, 30, Path::new("/tmp/x"), &BTreeMap::new()).unwrap();
        assert_eq!(plan.len(), 1);
        assert_eq!(plan[0].gadget, "assayist-capture-kvm");
        assert!(plan[0].args.contains(&"--duration".to_string()));
        assert!(plan[0].args.contains(&"30".to_string()));
        assert_eq!(plan[0].out_path, Path::new("/tmp/x/kvm_exit.frag.json"));
    }

    #[test]
    fn extra_args_are_appended_after_duration_and_out() {
        let mut e = entry("kvm_exit", Some("assayist-capture-kvm"));
        e.args = vec!["--per-guest".into(), "--max-keys".into(), "10000".into()];
        let plan = plan_gadgets(&[e], 30, Path::new("/tmp/x"), &BTreeMap::new()).unwrap();
        assert_eq!(
            plan[0].args,
            vec!["--duration", "30", "--out", "/tmp/x/kvm_exit.frag.json", "--per-guest", "--max-keys", "10000"]
        );
    }

    #[test]
    fn planning_rejects_a_gadgetless_entry() {
        let entries = vec![entry("kvm_exit", None)];
        assert!(plan_gadgets(&entries, 30, Path::new("/tmp"), &BTreeMap::new()).is_err());
    }

    #[test]
    fn capture_collects_fragments_from_all_gadgets() {
        let frag_a = Fragment {
            series: vec![serde_json::json!({"name": "kvm.exit"})],
            self_metrics: vec![serde_json::json!({"probe_id": "kvm_exit"})],
            capture_meta: None,
        };
        let frag_b = Fragment {
            series: vec![serde_json::json!({"name": "block.io"})],
            self_metrics: vec![],
            capture_meta: None,
        };
        let mut by_probe = HashMap::new();
        by_probe.insert("kvm_exit".to_string(), frag_a);
        by_probe.insert("block_rq".to_string(), frag_b);
        let runner = FakeRunner { by_probe };

        let entries = vec![
            entry("kvm_exit", Some("g1")),
            entry("block_rq", Some("g2")),
        ];
        let plan = plan_gadgets(&entries, 10, Path::new("/tmp"), &BTreeMap::new()).unwrap();
        let frags = capture(&plan, &runner).unwrap();
        assert_eq!(frags.len(), 2);
        assert_eq!(frags[0].series.len(), 1);
    }

    #[test]
    fn capture_fails_if_a_gadget_has_no_fragment() {
        let runner = FakeRunner { by_probe: HashMap::new() };
        let plan = plan_gadgets(&[entry("kvm_exit", Some("g1"))], 10, Path::new("/tmp"), &BTreeMap::new()).unwrap();
        assert!(capture(&plan, &runner).is_err());
    }

    #[test]
    fn a_later_spawn_failure_kills_earlier_gadgets() {
        use std::cell::RefCell;

        struct KillFake {
            fail_on: String,
            killed: RefCell<Vec<String>>,
        }
        impl GadgetRunner for KillFake {
            type Handle = String; // the probe name
            fn spawn(&self, inv: &GadgetInvocation) -> Result<String, String> {
                if inv.probe == self.fail_on {
                    Err(format!("spawn {} boom", inv.probe))
                } else {
                    Ok(inv.probe.clone())
                }
            }
            fn wait(&self, _inv: &GadgetInvocation, _h: String) -> Result<Fragment, String> {
                Ok(Fragment::default())
            }
            fn kill(&self, h: String) {
                self.killed.borrow_mut().push(h);
            }
        }

        let runner = KillFake { fail_on: "c".into(), killed: RefCell::new(vec![]) };
        let plan = plan_gadgets(
            &[entry("a", Some("g")), entry("b", Some("g")), entry("c", Some("g"))],
            10,
            Path::new("/tmp"),
            &BTreeMap::new(),
        )
        .unwrap();

        assert!(capture(&plan, &runner).is_err());
        // a and b were spawned before c failed, so both get killed.
        let killed = runner.killed.borrow();
        assert_eq!(killed.as_slice(), &["a".to_string(), "b".to_string()]);
    }
}
