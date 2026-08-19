// SPDX-FileCopyrightText: 2026 Wesley Mason (1stvamp)
// SPDX-License-Identifier: Apache-2.0
//! Per-VM attribution: dense handles, provenance, and the handle-to-ULID label
//! rewrite.
//!
//! Kernel maps and gadget fragments carry a dense `u64` handle because it is
//! cheap as a map value and as a series label. The self-describing ULID only
//! appears in the assembled run, so this module holds the table that maps one
//! to the other and rewrites `labels.vm_id` before grading.

use std::collections::BTreeMap;

use assayist_contract::Fragment;
use serde_json::{json, Value};

/// Lifecycle states, matching the shared map ABI byte for byte. Fixed by the
/// spec: sub-project 4's eBPF programs read this same value.
/// Task 3's `state_name` consumes these; the pause/resume states stay
/// unreachable from `main` until sub-project 3's hook drives them.
pub const LIFECYCLE_RUNNING: u8 = 0;
#[allow(dead_code)]
pub const LIFECYCLE_PAUSING: u8 = 1;
#[allow(dead_code)]
pub const LIFECYCLE_PAUSED: u8 = 2;
#[allow(dead_code)]
pub const LIFECYCLE_RESUMING: u8 = 3;

/// What the orchestrator knows about one attributed VM. The dense `handle` is
/// what the kernel map and raw fragments carry; `vm_id` is the ULID the
/// assembled run reports.
/// Tasks 3 and 4 consume this.
#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct VmProvenance {
    pub handle: u64,
    pub vm_id: String,
    pub tap: String,
    pub guest_mac: String,
    pub ifindex: u32,
    pub netns_inum: u32,
}

/// A locally administered MAC derived from the handle, so it is deterministic
/// per run and cannot collide between concurrent instances. The `02:` prefix
/// marks the address as locally administered.
/// Tasks 3 and 4 consume this.
#[allow(dead_code)]
pub fn guest_mac_for(handle: u64) -> String {
    let hi = ((handle >> 8) & 0xff) as u8;
    let lo = (handle & 0xff) as u8;
    format!("02:00:00:00:{hi:02x}:{lo:02x}")
}

/// Dense handle assignment plus the handle-to-provenance table. Handles are a
/// per-run counter from zero: they are cheap in a BPF map value and short in a
/// series label, and they are deliberately not stable across runs (the ULID is).
/// Tasks 3 and 4 consume this.
#[derive(Default, Debug)]
#[allow(dead_code)]
pub struct HandleTable {
    by_handle: BTreeMap<u64, VmProvenance>,
    next: u64,
}

impl HandleTable {
    #[allow(dead_code)]
    pub fn new() -> HandleTable {
        HandleTable::default()
    }

    /// Reserve the next handle without recording provenance for it. The
    /// counter always advances, so a reservation that is never (or not yet)
    /// backed by an `insert` still burns that handle number rather than
    /// letting a later, successful registration reuse it.
    fn reserve(&mut self) -> u64 {
        let handle = self.next;
        self.next += 1;
        handle
    }

    /// Record provenance for a handle already reserved via `reserve`.
    fn insert(&mut self, provenance: VmProvenance) {
        self.by_handle.insert(provenance.handle, provenance);
    }

    #[allow(dead_code)]
    pub fn assign(
        &mut self,
        vm_id: String,
        tap: String,
        guest_mac: String,
        ifindex: u32,
        netns_inum: u32,
    ) -> u64 {
        let handle = self.reserve();
        self.insert(VmProvenance { handle, vm_id, tap, guest_mac, ifindex, netns_inum });
        handle
    }

    #[allow(dead_code)]
    pub fn get(&self, handle: u64) -> Option<&VmProvenance> {
        self.by_handle.get(&handle)
    }

    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.by_handle.len()
    }

    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.by_handle.is_empty()
    }

    /// The table as additive `capture_meta.vm_attribution` provenance, so a
    /// dense-handle run is self-describing after the fact. Ascending by handle
    /// (BTreeMap iteration order).
    #[allow(dead_code)]
    pub fn provenance_json(&self) -> Value {
        let rows: Vec<Value> = self
            .by_handle
            .values()
            .map(|p| {
                json!({
                    "handle": p.handle,
                    "vm_id": p.vm_id,
                    "tap": p.tap,
                    "guest_mac": p.guest_mac,
                    "ifindex": p.ifindex,
                    "netns_inum": p.netns_inum,
                })
            })
            .collect();
        Value::Array(rows)
    }
}

/// Rewrite `labels.vm_id` on every series from the dense handle the gadgets
/// emit to the ULID the run reports. Returns the handle strings with no table
/// entry, in first-seen order: a handle the orchestrator never issued means a
/// stale map, so it is surfaced rather than dropped or invented.
/// Tasks 3 and 4 consume this.
#[allow(dead_code)]
pub fn rewrite_vm_id_labels(fragments: &mut [Fragment], table: &HandleTable) -> Vec<String> {
    let mut unknown: Vec<String> = Vec::new();
    for frag in fragments.iter_mut() {
        for s in frag.series.iter_mut() {
            let raw = match s.get("labels").and_then(|l| l.get("vm_id")).and_then(|v| v.as_str()) {
                Some(r) => r.to_string(),
                None => continue,
            };
            match raw.parse::<u64>().ok().and_then(|h| table.get(h)) {
                Some(p) => s["labels"]["vm_id"] = json!(p.vm_id),
                None => {
                    if !unknown.contains(&raw) {
                        unknown.push(raw);
                    }
                }
            }
        }
    }
    unknown
}

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

/// The wire name for a lifecycle state byte, as the owner's protocol expects.
pub fn state_name(state: u8) -> &'static str {
    match state {
        LIFECYCLE_PAUSING => "PAUSING",
        LIFECYCLE_PAUSED => "PAUSED",
        LIFECYCLE_RESUMING => "RESUMING",
        _ => "RUNNING",
    }
}

/// Request/reply client for the owner gadget's control socket. Every command
/// waits for its reply, so a slow owner applies backpressure instead of the
/// orchestrator dropping map updates on the floor.
#[derive(Debug)]
pub struct ControlClient {
    reader: BufReader<UnixStream>,
}

impl ControlClient {
    /// Connect, retrying until `timeout`: the owner is a freshly spawned
    /// subprocess, so its socket may not exist yet.
    #[allow(dead_code)]
    pub fn connect(path: &str, timeout: Duration) -> Result<ControlClient, String> {
        let deadline = Instant::now() + timeout;
        loop {
            match UnixStream::connect(path) {
                Ok(s) => {
                    s.set_read_timeout(Some(Duration::from_secs(5))).ok();
                    return Ok(ControlClient { reader: BufReader::new(s) });
                }
                Err(e) => {
                    if Instant::now() >= deadline {
                        return Err(format!("control socket {path} never accepted: {e}"));
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
            }
        }
    }

    fn command(&mut self, line: &str) -> Result<(), String> {
        self.reader
            .get_mut()
            .write_all(format!("{line}\n").as_bytes())
            .map_err(|e| format!("sending '{line}': {e}"))?;
        self.reader.get_mut().flush().map_err(|e| format!("flushing '{line}': {e}"))?;
        let mut reply = String::new();
        self.reader
            .read_line(&mut reply)
            .map_err(|e| format!("reading reply to '{line}': {e}"))?;
        let reply = reply.trim();
        match reply.strip_prefix("err") {
            Some(msg) => Err(format!("attribution owner rejected '{line}':{msg}")),
            None if reply == "ok" => Ok(()),
            None => Err(format!("unexpected reply to '{line}': {reply:?}")),
        }
    }

    pub fn add(&mut self, ifindex: u32, handle: u64, netns_inum: u32) -> Result<(), String> {
        self.command(&format!("add {ifindex} {handle} {netns_inum}"))
    }

    pub fn state(&mut self, handle: u64, state: u8) -> Result<(), String> {
        self.command(&format!("state {handle} {}", state_name(state)))
    }

    pub fn remove(&mut self, handle: u64) -> Result<(), String> {
        self.command(&format!("remove {handle}"))
    }
}

/// One run's attribution state: the control channel to the owner gadget plus
/// the handle table. Held by the run driver for the length of the run.
pub struct AttributionSession {
    pub client: ControlClient,
    pub table: HandleTable,
}

impl AttributionSession {
    /// Assign a handle to a VM and tell the owner about it. Returns the handle
    /// the gadgets will emit in `labels.vm_id`. `guest_mac` is the MAC the
    /// adapter actually configured on the device, recorded as provenance, not
    /// derived here.
    ///
    /// The handle is reserved before the owner is told, but provenance is
    /// only recorded once the owner accepts it: a rejected or failed `add`
    /// must not leave a table entry for a VM the owner never learned about,
    /// so a later `capture_meta.vm_attribution` cannot claim a registration
    /// that did not happen. The handle number itself is still consumed on
    /// failure, so it is never handed to a later, successful registration.
    pub fn register(
        &mut self,
        vm_id: String,
        tap: String,
        guest_mac: String,
        ifindex: u32,
        netns_inum: u32,
    ) -> Result<u64, String> {
        let handle = self.table.reserve();
        self.client.add(ifindex, handle, netns_inum)?;
        self.table.insert(VmProvenance { handle, vm_id, tap, guest_mac, ifindex, netns_inum });
        Ok(handle)
    }

    pub fn set_state(&mut self, handle: u64, state: u8) -> Result<(), String> {
        self.client.state(handle, state)
    }

    pub fn deregister(&mut self, handle: u64) -> Result<(), String> {
        self.client.remove(handle)
    }
}

#[cfg(test)]
mod tests {
    use assayist_contract::Fragment;
    use serde_json::json;
    use crate::netattrib::{guest_mac_for, rewrite_vm_id_labels, AttributionSession, HandleTable};
    use crate::netattrib::{
        state_name, ControlClient, LIFECYCLE_PAUSED, LIFECYCLE_PAUSING, LIFECYCLE_RESUMING,
        LIFECYCLE_RUNNING,
    };

    fn frag_with_vm_id(vm_id: &str) -> Fragment {
        Fragment {
            series: vec![json!({
                "name": "net.softirq_ns", "unit": "ns", "kind": "counter",
                "source": "softirq",
                "labels": { "vm_id": vm_id, "lifecycle_state": "running" },
                "cardinality": { "class": "bounded", "key_source": "vm_id", "max_keys": 1024 },
                "data": { "value": 7, "start_unix_nano": 0 }
            })],
            self_metrics: vec![],
            capture_meta: None,
        }
    }

    #[test]
    fn handles_are_dense_and_start_at_zero() {
        let mut t = HandleTable::new();
        let a = t.assign("01AAA".into(), "tap0".into(), "02:00:00:00:00:0a".into(), 11, 4026531840);
        let b = t.assign("01BBB".into(), "tap1".into(), "02:00:00:00:00:0b".into(), 12, 4026531841);
        assert_eq!((a, b), (0, 1));
        assert_eq!(t.len(), 2);
        assert_eq!(t.get(a).unwrap().vm_id, "01AAA");
        assert_eq!(t.get(b).unwrap().ifindex, 12);
        assert!(t.get(99).is_none());
    }

    #[test]
    fn guest_mac_is_locally_administered_and_derived_from_the_handle() {
        // 02: prefix marks a locally administered address; the low 16 bits of
        // the handle fill the last two octets.
        assert_eq!(guest_mac_for(0), "02:00:00:00:00:00");
        assert_eq!(guest_mac_for(1), "02:00:00:00:00:01");
        assert_eq!(guest_mac_for(258), "02:00:00:00:01:02");
    }

    #[test]
    fn provenance_json_is_sorted_and_complete() {
        let mut t = HandleTable::new();
        // The MAC is the caller's to supply (the adapter that configures the
        // device), not derived here, so assert it round-trips rather than
        // asserting a value this table computed itself.
        t.assign("01AAA".into(), "tap0".into(), "02:00:00:00:00:0a".into(), 11, 40);
        t.assign("01BBB".into(), "tap1".into(), "02:00:00:00:00:0b".into(), 12, 41);
        let v = t.provenance_json();
        let arr = v.as_array().expect("provenance is an array");
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0]["handle"], 0);
        assert_eq!(arr[0]["vm_id"], "01AAA");
        assert_eq!(arr[0]["tap"], "tap0");
        assert_eq!(arr[0]["guest_mac"], "02:00:00:00:00:0a");
        assert_eq!(arr[0]["ifindex"], 11);
        assert_eq!(arr[0]["netns_inum"], 40);
        assert_eq!(arr[1]["handle"], 1);
        assert_eq!(arr[1]["vm_id"], "01BBB");
    }

    #[test]
    fn rewrite_maps_handle_labels_to_ulids() {
        let mut t = HandleTable::new();
        let h = t.assign("01ULID".into(), "tap0".into(), "02:00:00:00:00:01".into(), 11, 40);
        let mut frags = vec![frag_with_vm_id(&h.to_string())];
        let unknown = rewrite_vm_id_labels(&mut frags, &t);
        assert!(unknown.is_empty(), "nothing unresolved, got {unknown:?}");
        assert_eq!(frags[0].series[0]["labels"]["vm_id"], "01ULID");
        // Other labels are untouched.
        assert_eq!(frags[0].series[0]["labels"]["lifecycle_state"], "running");
    }

    #[test]
    fn rewrite_leaves_unknown_handles_alone_and_reports_them() {
        // A handle the orchestrator never issued means a stale map. Surface it
        // rather than inventing an id or dropping the series.
        let t = HandleTable::new();
        let mut frags = vec![frag_with_vm_id("77")];
        let unknown = rewrite_vm_id_labels(&mut frags, &t);
        assert_eq!(unknown, vec!["77".to_string()]);
        assert_eq!(frags[0].series[0]["labels"]["vm_id"], "77");
    }

    #[test]
    fn rewrite_ignores_series_without_a_vm_id_label() {
        let mut t = HandleTable::new();
        t.assign("01ULID".into(), "tap0".into(), "02:00:00:00:00:01".into(), 11, 40);
        let mut frags = vec![Fragment {
            series: vec![json!({
                "name": "block.io_latency:read", "unit": "ns", "kind": "counter",
                "source": "block_rq_complete", "key": "254:0",
                "cardinality": { "class": "bounded", "key_source": "device", "max_keys": 256 },
                "data": { "value": 1, "start_unix_nano": 0 }
            })],
            self_metrics: vec![],
            capture_meta: None,
        }];
        let unknown = rewrite_vm_id_labels(&mut frags, &t);
        assert!(unknown.is_empty());
        assert!(frags[0].series[0].get("labels").is_none());
    }

    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixListener;
    use std::time::Duration;

    /// A fake owner: accepts one connection, replies to each line from `replies`
    /// in order, and records what it received. Returns the recording handle.
    fn fake_owner(path: String, replies: Vec<&'static str>) -> std::thread::JoinHandle<Vec<String>> {
        let listener = UnixListener::bind(&path).expect("bind fake owner");
        std::thread::spawn(move || {
            let mut got = Vec::new();
            let (s, _) = listener.accept().expect("accept");
            let mut r = BufReader::new(s);
            for reply in replies {
                let mut line = String::new();
                if r.read_line(&mut line).unwrap_or(0) == 0 {
                    break;
                }
                got.push(line.trim().to_string());
                let _ = r.get_mut().write_all(reply.as_bytes());
                let _ = r.get_mut().flush();
            }
            got
        })
    }

    fn sock_path(name: &str) -> String {
        let p = std::env::temp_dir().join(format!("assayist-test-{}-{}.sock", name, std::process::id()));
        let _ = std::fs::remove_file(&p);
        p.to_string_lossy().into_owned()
    }

    #[test]
    fn state_names_match_the_wire_protocol() {
        assert_eq!(state_name(LIFECYCLE_RUNNING), "RUNNING");
        assert_eq!(state_name(LIFECYCLE_PAUSING), "PAUSING");
        assert_eq!(state_name(LIFECYCLE_PAUSED), "PAUSED");
        assert_eq!(state_name(LIFECYCLE_RESUMING), "RESUMING");
    }

    #[test]
    fn client_sends_the_wire_format_and_accepts_ok() {
        let path = sock_path("wire");
        let owner = fake_owner(path.clone(), vec!["ok\n", "ok\n", "ok\n"]);
        let mut c = ControlClient::connect(&path, Duration::from_secs(2)).expect("connect");
        c.add(11, 0, 4026531840).expect("add");
        c.state(0, LIFECYCLE_PAUSED).expect("state");
        c.remove(0).expect("remove");
        let got = owner.join().expect("owner thread");
        assert_eq!(
            got,
            vec!["add 11 0 4026531840", "state 0 PAUSED", "remove 0"]
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn client_surfaces_an_err_reply() {
        let path = sock_path("err");
        let owner = fake_owner(path.clone(), vec!["err no entry for handle 5\n"]);
        let mut c = ControlClient::connect(&path, Duration::from_secs(2)).expect("connect");
        let e = c.remove(5).expect_err("err reply must be an error");
        assert!(e.contains("no entry for handle 5"), "got: {e}");
        let _ = owner.join();
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn connect_times_out_when_no_owner_is_listening() {
        let path = sock_path("absent");
        let e = ControlClient::connect(&path, Duration::from_millis(200))
            .expect_err("no listener means connect fails");
        assert!(e.contains("control socket"), "got: {e}");
    }

    #[test]
    fn session_assigns_and_rewrites_end_to_end() {
        // The whole spine in miniature: a VM is assigned a handle, a gadget
        // emits that handle in labels.vm_id, and assemble turns it into the
        // ULID with provenance alongside.
        let path = sock_path("session");
        let owner = fake_owner(path.clone(), vec!["ok\n", "ok\n"]);
        let client = ControlClient::connect(&path, Duration::from_secs(2)).expect("connect");
        let mut session = AttributionSession { client, table: HandleTable::new() };

        let handle = session
            .register("01ULIDX".into(), "tap9".into(), "02:00:00:00:00:00".into(), 11, 0)
            .expect("register sends add");
        session.set_state(handle, LIFECYCLE_RUNNING).expect("state");

        let mut frags = vec![frag_with_vm_id(&handle.to_string())];
        let unknown = rewrite_vm_id_labels(&mut frags, &session.table);
        assert!(unknown.is_empty());
        assert_eq!(frags[0].series[0]["labels"]["vm_id"], "01ULIDX");
        assert_eq!(session.table.provenance_json()[0]["tap"], "tap9");

        let got = owner.join().expect("owner");
        assert_eq!(got, vec!["add 11 0 0", "state 0 RUNNING"]);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn register_leaves_no_table_entry_when_the_owner_rejects_the_add() {
        // A rejected add must not leave provenance for a VM the owner never
        // actually recorded, or capture_meta.vm_attribution would claim a
        // registration that did not happen.
        let path = sock_path("register-err");
        let owner = fake_owner(path.clone(), vec!["err no room\n"]);
        let client = ControlClient::connect(&path, Duration::from_secs(2)).expect("connect");
        let mut session = AttributionSession { client, table: HandleTable::new() };

        let err = session
            .register("01FAIL".into(), "tap0".into(), "02:00:00:00:00:00".into(), 11, 0)
            .expect_err("owner rejected the add");
        assert!(err.contains("no room"), "got: {err}");
        assert_eq!(session.table.len(), 0);

        let _ = owner.join();
        let _ = std::fs::remove_file(&path);
    }
}
