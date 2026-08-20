// SPDX-FileCopyrightText: 2026 Wesley Mason (1stvamp)
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

/// A target's network attribution identity: the host tap it owns and the
/// numbers the attribution map needs. Returned by targets that set up
/// networking; `None` from everything else.
/// Task 4 returns this from the firecracker target; Task 5 consumes it in
/// the run driver.
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(dead_code)]
pub struct NetAttribution {
    pub tap: String,
    pub ifindex: u32,
    pub guest_mac: String,
    pub netns_inum: u32,
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
    /// Snapshot memory files whose page-cache residency should be measured after
    /// the guest reaches steady. Each entry is `(instance_label, mem_file_path)`;
    /// the orchestrator `mincore(2)`s each and emits `resident.snapshot_*` keyed
    /// by the label. This is the per-guest attribution the host-memory delta
    /// cannot give (the delta is system-wide). Adapter-specific, default none.
    fn resident_files(&self) -> Vec<(String, String)> {
        Vec::new()
    }
    /// The tap identities this target set up, one per VM it brought up, in the
    /// order it created them. The run driver registers each and drives the
    /// attribution map for all of them. Empty means no tap, which is the default
    /// so every existing target is unaffected: the adapter stays free of BPF and
    /// sockets, and only a target that actually creates taps reports any. A
    /// fanout reports N, one per inner instance.
    /// Task 5 calls this from the run driver.
    #[allow(dead_code)]
    fn net_attribution(&self, _sh: &dyn Shell) -> Vec<NetAttribution> {
        Vec::new()
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
    /// Handle-to-ULID provenance for the VMs attributed this run, or `None`
    /// when attribution was not enabled. Recorded as additive
    /// `capture_meta.vm_attribution`.
    /// Every call site passes `None` for the session until sub-project 3's
    /// pause/resume hook wires one in and `main` attaches this to the
    /// assembled record, so it goes unread until then.
    #[allow(dead_code)]
    pub vm_attribution: Option<Value>,
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


    fn net_attribution(&self, sh: &dyn Shell) -> Vec<NetAttribution> {
        // Every inner instance owns its own tap, so a fanout reports all of
        // them, in inner order. Without this the fanout took the empty default
        // and an N-VM run had nothing attributed at all.
        self.inners.iter().flat_map(|t| t.net_attribution(sh)).collect()
    }

    fn resident_files(&self) -> Vec<(String, String)> {
        // Key each instance's mem file by its index, so N sandboxes restored
        // from one snapshot get per-guest residency (the file is shared through
        // the page cache, so the numbers show what each faulted in).
        let mut out = Vec::new();
        for (i, t) in self.inners.iter().enumerate() {
            for (_, path) in t.resident_files() {
                out.push((format!("instance{i}"), path));
            }
        }
        out
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


/// Page-cache residency of `path`: (resident_pages, total_pages). mmaps the
/// file MAP_SHARED and calls `mincore(2)`, so it reflects the file's page-cache
/// residency, not this process's private faults. Best-effort: any failure
/// (missing file, mmap/mincore error) returns `None` so a resident probe never
/// fails the run. Mirrors the standalone `capture/resident` gadget.
fn sample_residency(path: &str) -> Option<(u64, u64)> {
    let file = std::fs::File::open(path).ok()?;
    let len = file.metadata().ok()?.len() as usize;
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if page <= 0 {
        return None;
    }
    let page = page as usize;
    if len == 0 {
        return Some((0, 0));
    }
    let pages = len.div_ceil(page);
    let addr = unsafe {
        use std::os::fd::AsRawFd;
        libc::mmap(std::ptr::null_mut(), len, libc::PROT_READ, libc::MAP_SHARED, file.as_raw_fd(), 0)
    };
    if addr == libc::MAP_FAILED {
        return None;
    }
    let mut vec = vec![0u8; pages];
    let rc = unsafe { libc::mincore(addr, len, vec.as_mut_ptr() as *mut _) };
    unsafe { libc::munmap(addr, len) };
    if rc != 0 {
        return None;
    }
    // Residency is bit 0 of each returned byte.
    let resident = vec.iter().filter(|b| *b & 1 == 1).count() as u64;
    Some((resident, pages as u64))
}

/// A synthetic capture fragment carrying per-guest snapshot residency, measured
/// orchestrator-side (like `hostmem_fragment`) rather than by an eBPF gadget.
/// Each `(label, path)` is `mincore`d and emitted as `resident.snapshot_*` keyed
/// by the label, so under fanout each instance gets its own numbers. A single
/// instance keys as a singleton; N > 1 keys `bounded` by guest index. Files that
/// could not be measured are skipped (best effort). Returns `None` when nothing
/// was measurable, so a non-snapshot target adds no series.
fn resident_fragment(samples: &[(String, u64, u64)]) -> Option<Fragment> {
    if samples.is_empty() {
        return None;
    }
    let multi = samples.len() > 1;
    let card = |key_present: bool| {
        if multi && key_present {
            json!({"class": "bounded", "key_source": "guest_index", "max_keys": samples.len()})
        } else {
            json!({"class": "singleton"})
        }
    };
    let mut series = Vec::with_capacity(samples.len() * 3);
    for (label, resident, total) in samples {
        let fraction = if *total > 0 { *resident as f64 / *total as f64 } else { 0.0 };
        let key = (!label.is_empty()).then(|| label.clone());
        let gauge = |name: &str, value: Value| {
            let mut m = serde_json::Map::new();
            m.insert("name".into(), json!(name));
            m.insert("unit".into(), json!("1"));
            m.insert("kind".into(), json!("gauge"));
            m.insert("source".into(), json!("resident"));
            if let Some(k) = &key {
                m.insert("key".into(), json!(k));
            }
            m.insert("cardinality".into(), card(key.is_some()));
            m.insert("data".into(), json!({"value": value, "time_unix_nano": 0}));
            Value::Object(m)
        };
        series.push(gauge("resident.snapshot_resident_pages", json!(resident)));
        series.push(gauge("resident.snapshot_total_pages", json!(total)));
        series.push(gauge("resident.snapshot_fraction", json!(fraction)));
    }
    Some(Fragment {
        series,
        self_metrics: vec![],
        capture_meta: Some(json!({"gadget": "resident", "source": "mincore"})),
    })
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
    mut attrib: Option<&mut crate::netattrib::AttributionSession>,
) -> Result<RunArtifacts, String> {
    // Host memory before the target exists, and after it reaches steady: the
    // delta is the memory cost of preparing and restoring the guest, measured
    // outside the gadget window (which only opens post-steady).
    let mem_before = sample_meminfo(sh);
    target.provision(sh)?;
    target.start(sh)?;
    target.reach_steady(sh)?;
    let mem_after = sample_meminfo(sh);

    // Attribution, when enabled and the target actually set up taps. Register
    // after steady so each tap exists and its ifindex is known, and before the
    // gadgets attach so their first samples are already attributable. Only the
    // handles (not the session borrow) are carried across the gadget spawn/wait
    // below; the session is re-borrowed afterwards to deregister and rewrite.
    let mut attributed: Vec<u64> = Vec::new();
    if let Some(session) = attrib.as_deref_mut() {
        let vms = target.net_attribution(sh);
        if vms.is_empty() {
            // A run that asked for attribution but whose target set up no tap
            // is a config error, not a silent no-op: every later network sample
            // would be unattributable.
            let _ = target.teardown(sh);
            return Err(
                "attribution enabled but the target set up no tap (note: tap networking is cold boot only, so a snapshot-restore def will not have one even with the key set); set `network: tap` on a cold-boot target"
                    .to_string(),
            );
        }
        for na in vms {
            // Each VM gets its own ULID; the handle is the dense id the map and
            // the raw fragments carry.
            let handle = match session.register(
                crate::run::new_run_id(),
                na.tap,
                na.guest_mac,
                na.ifindex,
                na.netns_inum,
            ) {
                Ok(h) => h,
                Err(e) => {
                    for h in &attributed {
                        let _ = session.deregister(*h);
                    }
                    let _ = target.teardown(sh);
                    return Err(e);
                }
            };
            // Recorded before the state command, so a failing `set_state` still
            // removes the entry its `add` just created rather than leaving it
            // for the owner to hold until the window closes.
            attributed.push(handle);
            if let Err(e) = session.set_state(handle, crate::netattrib::LIFECYCLE_RUNNING) {
                for h in &attributed {
                    let _ = session.deregister(*h);
                }
                let _ = target.teardown(sh);
                return Err(e);
            }
        }
    }

    let mut handles = Vec::with_capacity(gadgets.len());
    for inv in gadgets {
        match runner.spawn(inv) {
            Ok(h) => handles.push(h),
            Err(e) => {
                deregister_all(&mut attrib, &attributed);
                let _ = target.teardown(sh);
                return Err(e);
            }
        }
    }

    if let Err(e) = workload.start(sh) {
        deregister_all(&mut attrib, &attributed);
        let _ = target.teardown(sh);
        return Err(e);
    }

    let mut fragments = Vec::with_capacity(gadgets.len());
    for (inv, handle) in gadgets.iter().zip(handles) {
        match runner.wait(inv, handle) {
            Ok(f) => fragments.push(f),
            Err(e) => {
                let _ = workload.stop(sh);
                deregister_all(&mut attrib, &attributed);
                let _ = target.teardown(sh);
                return Err(e);
            }
        }
    }

    let _ = workload.stop(sh);
    let workload_report = workload.report(sh).unwrap_or(Value::Null);
    let spans = target.spans(sh)?;

    // Per-guest snapshot residency, sampled while the guest is still up (so the
    // page cache is warm) and before teardown. Best-effort: unmeasurable files
    // are dropped, so a non-snapshot target adds nothing here.
    let resident: Vec<(String, u64, u64)> = target
        .resident_files()
        .into_iter()
        .filter_map(|(label, path)| sample_residency(&path).map(|(r, t)| (label, r, t)))
        .collect();

    // Deregister before teardown deletes the taps, which is the spec's order
    // ("remove <handle>, delete tap") and matters: ifindex is a recycled kernel
    // resource, so an entry left in the map while its tap goes away is keyed on
    // an index the kernel can hand to a later tap. Teardown's result is held
    // rather than propagated with `?` so the label rewrite and the provenance
    // below happen on the same path whether teardown succeeded or not.
    deregister_all(&mut attrib, &attributed);
    let teardown = target.teardown(sh);

    fragments.push(hostmem_fragment(mem_before, mem_after));
    if let Some(f) = resident_fragment(&resident) {
        fragments.push(f);
    }

    let vm_attribution = match attrib {
        Some(session) if !attributed.is_empty() => {
            let unknown = crate::netattrib::rewrite_vm_id_labels(&mut fragments, &session.table);
            let mut prov = json!({ "vms": session.table.provenance_json() });
            if !unknown.is_empty() {
                // Handles the orchestrator never issued mean a stale map.
                prov["unresolved_handles"] = json!(unknown);
            }
            Some(prov)
        }
        _ => None,
    };

    teardown?;
    Ok(RunArtifacts { fragments, spans, workload_report, vm_attribution })
}

/// Remove every handle this run registered from the owner's map. Best-effort:
/// an abort path already has a failure to report, and a leaked entry keyed on a
/// recyclable ifindex is worse than a dropped error message.
fn deregister_all(
    attrib: &mut Option<&mut crate::netattrib::AttributionSession>,
    handles: &[u64],
) {
    if let Some(session) = attrib.as_deref_mut() {
        for h in handles {
            let _ = session.deregister(*h);
        }
    }
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
    #[derive(Default)]
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

    #[derive(Default)]
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

        let art = execute_run(&sh, &runner, &target, &workload, &plan, None).unwrap();
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
    fn execute_run_without_attribution_reports_none() {
        // The default path is unchanged: no attribution session, no provenance,
        // and every existing caller keeps working.
        let sh = FakeShell::default();
        let runner = FakeRunner::default();
        let target = CommandTarget(CommandSet { commands: BTreeMap::new(), vars: BTreeMap::new() });
        let workload = CommandWorkload(CommandSet { commands: BTreeMap::new(), vars: BTreeMap::new() });
        let art = execute_run(&sh, &runner, &target, &workload, &[], None).unwrap();
        assert!(art.vm_attribution.is_none());
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

    /// A target that only reports resident files, for the fanout aggregation test.
    struct ResidentStub(Vec<(String, String)>);
    impl Target for ResidentStub {
        fn version(&self, _: &dyn Shell) -> String {
            "stub".into()
        }
        fn provision(&self, _: &dyn Shell) -> Result<(), String> {
            Ok(())
        }
        fn start(&self, _: &dyn Shell) -> Result<(), String> {
            Ok(())
        }
        fn reach_steady(&self, _: &dyn Shell) -> Result<(), String> {
            Ok(())
        }
        fn spans(&self, _: &dyn Shell) -> Result<Vec<Value>, String> {
            Ok(vec![])
        }
        fn teardown(&self, _: &dyn Shell) -> Result<(), String> {
            Ok(())
        }
        fn resident_files(&self) -> Vec<(String, String)> {
            self.0.clone()
        }
    }

    /// A target that reports one tap and nothing else, for the fanout
    /// attribution test.
    struct TapStub(NetAttribution);
    impl Target for TapStub {
        fn version(&self, _: &dyn Shell) -> String {
            "tapstub".into()
        }
        fn provision(&self, _: &dyn Shell) -> Result<(), String> {
            Ok(())
        }
        fn start(&self, _: &dyn Shell) -> Result<(), String> {
            Ok(())
        }
        fn reach_steady(&self, _: &dyn Shell) -> Result<(), String> {
            Ok(())
        }
        fn spans(&self, _: &dyn Shell) -> Result<Vec<Value>, String> {
            Ok(vec![])
        }
        fn teardown(&self, _: &dyn Shell) -> Result<(), String> {
            Ok(())
        }
        fn net_attribution(&self, _: &dyn Shell) -> Vec<NetAttribution> {
            vec![self.0.clone()]
        }
    }

    #[test]
    fn fanout_registers_every_inner_tap() {
        // The density case the spec promises: N concurrent VMs, each with its own
        // tap and ifindex, each registered with the owner and each carrying its
        // own ULID. A single-valued SPI made this dead on arrival.
        use crate::netattrib::{fake_owner, sock_path, AttributionSession, ControlClient, HandleTable};

        let path = sock_path("fanout-attrib");
        // add + state per VM, then remove per VM.
        let owner = fake_owner(path.clone(), vec!["ok\n"; 6]);
        let client =
            ControlClient::connect(&path, std::time::Duration::from_secs(2)).expect("connect");
        let mut session = AttributionSession { client, table: HandleTable::new() };

        let na = |tap: &str, ifindex: u32, mac: &str| NetAttribution {
            tap: tap.to_string(),
            ifindex,
            guest_mac: mac.to_string(),
            netns_inum: 0,
        };
        let inners: Vec<Box<dyn Target>> = vec![
            Box::new(TapStub(na("asyq-0", 11, "02:00:00:00:00:00"))),
            Box::new(TapStub(na("asyq-1", 12, "02:00:00:00:00:01"))),
        ];
        let f = FanoutTarget::new(inners);

        let sh = FakeShell::default();
        // The SPI itself reports both, in inner order.
        let reported = f.net_attribution(&sh);
        assert_eq!(reported.len(), 2);
        assert_eq!(reported[0].tap, "asyq-0");
        assert_eq!(reported[1].tap, "asyq-1");

        let runner = FakeRunner::default();
        let workload =
            CommandWorkload(CommandSet { commands: BTreeMap::new(), vars: BTreeMap::new() });
        let art =
            execute_run(&sh, &runner, &f, &workload, &[], Some(&mut session)).expect("run");

        // Two handles registered, so two provenance rows with distinct taps and
        // distinct ULIDs.
        let prov = art.vm_attribution.expect("attribution was enabled");
        let vms = prov["vms"].as_array().expect("vms is an array");
        assert_eq!(vms.len(), 2);
        assert_eq!(vms[0]["handle"], 0);
        assert_eq!(vms[1]["handle"], 1);
        assert_eq!(vms[0]["tap"], "asyq-0");
        assert_eq!(vms[1]["tap"], "asyq-1");
        assert_eq!(vms[0]["ifindex"], 11);
        assert_eq!(vms[1]["ifindex"], 12);
        assert_ne!(vms[0]["vm_id"], vms[1]["vm_id"], "each VM gets its own ULID");
        assert!(prov.get("unresolved_handles").is_none());

        // Both VMs were added, both moved to RUNNING, and both were removed.
        let got = owner.join().expect("owner thread");
        assert_eq!(
            got,
            vec![
                "add 11 0 0",
                "state 0 RUNNING",
                "add 12 1 0",
                "state 1 RUNNING",
                "remove 0",
                "remove 1",
            ]
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn execute_run_errors_when_attribution_is_enabled_but_no_tap_was_set_up() {
        // The message has to name both causes: a missing `network: tap` key, and
        // a def that sets it but restores from a snapshot (tap setup is cold boot
        // only), which would otherwise send the operator back to a key they
        // already set.
        use crate::netattrib::{fake_owner, sock_path, AttributionSession, ControlClient, HandleTable};

        let path = sock_path("no-tap");
        let owner = fake_owner(path.clone(), vec![]);
        let client =
            ControlClient::connect(&path, std::time::Duration::from_secs(2)).expect("connect");
        let mut session = AttributionSession { client, table: HandleTable::new() };

        let sh = FakeShell::default();
        let runner = FakeRunner::default();
        let target = CommandTarget(CommandSet { commands: BTreeMap::new(), vars: BTreeMap::new() });
        let workload =
            CommandWorkload(CommandSet { commands: BTreeMap::new(), vars: BTreeMap::new() });
        let err = match execute_run(&sh, &runner, &target, &workload, &[], Some(&mut session)) {
            Err(e) => e,
            Ok(_) => panic!("no tap while attribution is on is a config error"),
        };
        assert!(err.contains("set up no tap"), "got: {err}");
        assert!(err.contains("cold boot only"), "got: {err}");

        let _ = owner.join();
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn resident_fragment_single_is_singleton_unkeyed() {
        let frag = resident_fragment(&[(String::new(), 30, 100)]).unwrap();
        assert_eq!(frag.series.len(), 3);
        let frac = frag.series.iter().find(|s| s["name"] == "resident.snapshot_fraction").unwrap();
        assert_eq!(frac["data"]["value"].as_f64().unwrap(), 0.30);
        assert_eq!(frac["cardinality"]["class"], "singleton");
        assert!(frac.get("key").is_none());
    }

    #[test]
    fn resident_fragment_multi_keys_per_instance() {
        let frag =
            resident_fragment(&[("instance0".into(), 10, 100), ("instance1".into(), 90, 100)]).unwrap();
        assert_eq!(frag.series.len(), 6);
        let keyed: Vec<_> = frag
            .series
            .iter()
            .filter(|s| s["name"] == "resident.snapshot_resident_pages")
            .collect();
        assert_eq!(keyed.len(), 2);
        assert_eq!(keyed[0]["key"], "instance0");
        assert_eq!(keyed[0]["cardinality"]["class"], "bounded");
        assert_eq!(keyed[0]["cardinality"]["key_source"], "guest_index");
    }

    #[test]
    fn resident_fragment_empty_is_none() {
        assert!(resident_fragment(&[]).is_none());
    }

    #[test]
    fn fanout_keys_resident_files_per_instance() {
        let inners: Vec<Box<dyn Target>> = vec![
            Box::new(ResidentStub(vec![(String::new(), "/snap/mem".into())])),
            Box::new(ResidentStub(vec![(String::new(), "/snap/mem".into())])),
        ];
        let f = FanoutTarget::new(inners);
        let files = f.resident_files();
        assert_eq!(files, vec![
            ("instance0".to_string(), "/snap/mem".to_string()),
            ("instance1".to_string(), "/snap/mem".to_string()),
        ]);
    }

    #[test]
    fn sample_residency_counts_pages_of_a_real_file() {
        // A freshly written temp file: mincore should see a total page count that
        // matches its size, and residency measurement should not error.
        let path = std::env::temp_dir().join(format!("assayist-resident-test-{}", std::process::id()));
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as u64;
        std::fs::write(&path, vec![7u8; (page * 3) as usize]).unwrap();
        let (resident, total) = sample_residency(path.to_str().unwrap()).unwrap();
        std::fs::remove_file(&path).ok();
        assert_eq!(total, 3);
        assert!(resident <= total);
    }

    #[test]
    fn sample_residency_missing_file_is_none() {
        assert!(sample_residency("/no/such/mem/file").is_none());
    }
}
