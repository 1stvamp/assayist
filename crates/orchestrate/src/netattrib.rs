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
/// Task 3 consumes these constants.
#[allow(dead_code)]
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

    #[allow(dead_code)]
    pub fn assign(
        &mut self,
        vm_id: String,
        tap: String,
        ifindex: u32,
        netns_inum: u32,
    ) -> u64 {
        let handle = self.next;
        self.next += 1;
        self.by_handle.insert(
            handle,
            VmProvenance {
                handle,
                vm_id,
                tap,
                guest_mac: guest_mac_for(handle),
                ifindex,
                netns_inum,
            },
        );
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

#[cfg(test)]
mod tests {
    use assayist_contract::Fragment;
    use serde_json::json;
    use crate::netattrib::{guest_mac_for, rewrite_vm_id_labels, HandleTable};

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
        let a = t.assign("01AAA".into(), "tap0".into(), 11, 4026531840);
        let b = t.assign("01BBB".into(), "tap1".into(), 12, 4026531841);
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
        t.assign("01AAA".into(), "tap0".into(), 11, 40);
        t.assign("01BBB".into(), "tap1".into(), 12, 41);
        let v = t.provenance_json();
        let arr = v.as_array().expect("provenance is an array");
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0]["handle"], 0);
        assert_eq!(arr[0]["vm_id"], "01AAA");
        assert_eq!(arr[0]["tap"], "tap0");
        assert_eq!(arr[0]["guest_mac"], "02:00:00:00:00:00");
        assert_eq!(arr[0]["ifindex"], 11);
        assert_eq!(arr[0]["netns_inum"], 40);
        assert_eq!(arr[1]["handle"], 1);
        assert_eq!(arr[1]["vm_id"], "01BBB");
    }

    #[test]
    fn rewrite_maps_handle_labels_to_ulids() {
        let mut t = HandleTable::new();
        let h = t.assign("01ULID".into(), "tap0".into(), 11, 40);
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
        t.assign("01ULID".into(), "tap0".into(), 11, 40);
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
}
