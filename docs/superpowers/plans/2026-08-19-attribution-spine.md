<!--
SPDX-FileCopyrightText: 2026 Wesley Mason (1stvamp)
SPDX-License-Identifier: Apache-2.0
-->

# Attribution Spine Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give every network sample a VM and a lifecycle state to belong to: a bpffs-pinned `vm_by_ifindex` map owned by a new `capture/netattrib` gadget, an orchestrator unix-socket control channel that drives it across the VM lifecycle, firecracker tap networking so a VM has an `ifindex` to attribute on, and a handle-to-ULID label rewrite at assemble.

**Architecture:** The core workspace still cannot link libbpf, so the map lives in a privileged capture-side owner (`capture/netattrib`, pure userspace over libbpf-rs, no `.bpf.c`) and the orchestrator speaks to it over a line-delimited unix socket. The orchestrator assigns each VM a dense `u64` handle (cheap as a map value and a series label) plus a ULID, and rewrites `labels.vm_id` from handle to ULID when the run is assembled. Firecracker tap setup follows the adapter's existing `Shell` pattern (shell commands through `sh.run`), so it is testable through the fake `Shell` exactly like the curl/taskset/fusermount work already there.

**Tech Stack:** Rust (workspace core builds anywhere, no BTF), `libbpf-rs 0.24` + `libbpf-sys 1.4` in the gadget only, `serde_json`, `std::os::unix::net` for the control channel, GitButler (`but`) for commits.

**Spec:** `docs/superpowers/specs/2026-08-19-attribution-spine-design.md` (sub-project 2 of `docs/superpowers/specs/2026-08-19-network-datapath-gadgets-design.md`).

## Global Constraints

- The core workspace (`crates/*`) must keep building on a host with no kernel BTF, no clang, no bpftool. No libbpf dependency may enter `crates/*`. All BPF-adjacent code lives in `capture/netattrib`, which is excluded from the workspace.
- Shared map ABI, fixed by the spec and not to be changed: map name `vm_by_ifindex`, type `BPF_MAP_TYPE_HASH`, key `u32 ifindex`, value `struct vm_ctx { u64 vm_id; u32 netns_inum; u8 lifecycle_state; u8 _pad[3]; }` (16 bytes, `#[repr(C)]`). Lifecycle states: `0 RUNNING, 1 PAUSING, 2 PAUSED, 3 RESUMING`.
- Handle rendering in `labels.vm_id` is the decimal string of a `u64`, no padding, no prefix. This is ABI and is round-trip tested.
- `guest_mac` is locally administered, derived from the handle: `02:00:00:00:<hi>:<lo>` where `hi`/`lo` are the top and bottom bytes of the handle's low 16 bits, lowercase hex.
- Stale pin policy: if the pin path already exists, `netattrib` errors out. It never reclaims or silently reuses a pin from a crashed run.
- Tap networking is gated behind a def config key. Absent, the firecracker adapter behaves exactly as it does today: no tap, `net_attribution()` returns `None`.
- Additive contract only: `capture_meta.vm_attribution` provenance, and reuse of `labels.vm_id` from sub-project 1. No schema change beyond what sub-project 1 landed.
- Prose, comments, and commit messages: no em or en dashes; British spelling; no banned AI-tell words (leverage, robust, seamless, delve, etc.).
- New files carry SPDX headers. Userspace is `Apache-2.0` (`// SPDX-FileCopyrightText: 2026 Wesley Mason (1stvamp)` then `// SPDX-License-Identifier: Apache-2.0`).
- Version control is GitButler. Commit with `but commit <branch> -m "..." --changes <ids>` using ids from `but diff`. Never use `git add`/`git commit`. All commits land on one session branch: `feat/attribution-spine`, created on the first commit with `-c`.
- Commit message convention: `type(scope): summary`.
- Every gadget README has a "Limits" section. Keep that habit.

---

### Task 1: Handle table, provenance, and the label rewrite

The pure-logic core of attribution: assign dense handles, hold the handle-to-provenance table, render provenance for `capture_meta`, and rewrite `labels.vm_id` from handle to ULID across fragments at assemble. No sockets, no subprocesses, no BPF. This is the most valuable here-testable piece and everything else consumes it.

**Files:**
- Create: `crates/orchestrate/src/netattrib.rs`
- Modify: `crates/orchestrate/src/main.rs` (add `mod netattrib;` beside the other module declarations at the top)

**Interfaces:**
- Consumes: `assayist_contract::Fragment` (fields `series: Vec<Value>`, `self_metrics: Vec<Value>`, `capture_meta: Option<Value>`).
- Produces, all used by Tasks 3 and 4:
  - `pub const LIFECYCLE_RUNNING: u8 = 0;` and `LIFECYCLE_PAUSING = 1`, `LIFECYCLE_PAUSED = 2`, `LIFECYCLE_RESUMING = 3`
  - `pub struct VmProvenance { pub handle: u64, pub vm_id: String, pub tap: String, pub guest_mac: String, pub ifindex: u32, pub netns_inum: u32 }`
  - `pub struct HandleTable { /* private */ }` with `pub fn new() -> HandleTable`, `pub fn assign(&mut self, vm_id: String, tap: String, ifindex: u32, netns_inum: u32) -> u64`, `pub fn get(&self, handle: u64) -> Option<&VmProvenance>`, `pub fn len(&self) -> usize`, `pub fn is_empty(&self) -> bool`, `pub fn provenance_json(&self) -> Value` (a JSON array of `{handle, vm_id, tap, guest_mac, ifindex, netns_inum}`, ascending by handle)
  - `pub fn guest_mac_for(handle: u64) -> String`
  - `pub fn rewrite_vm_id_labels(fragments: &mut [Fragment], table: &HandleTable) -> Vec<String>` (returns the handle strings it could not resolve, in first-seen order)

- [ ] **Step 1: Write the failing tests**

Create `crates/orchestrate/src/netattrib.rs` with the SPDX header, a module doc comment, and only a `#[cfg(test)] mod tests` block plus the imports the tests need. Write the file exactly as below (the implementation arrives in Step 3, so the file will not compile yet, which is the point):

```rust
// SPDX-FileCopyrightText: 2026 Wesley Mason (1stvamp)
// SPDX-License-Identifier: Apache-2.0
//! Per-VM attribution: dense handles, provenance, and the handle-to-ULID label
//! rewrite.
//!
//! Kernel maps and gadget fragments carry a dense `u64` handle because it is
//! cheap as a map value and as a series label. The self-describing ULID only
//! appears in the assembled run, so this module holds the table that maps one
//! to the other and rewrites `labels.vm_id` before grading.

#[cfg(test)]
mod tests {
    use super::*;
    use assayist_contract::Fragment;
    use serde_json::json;

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
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p assayist --lib netattrib`
Expected: compile FAIL. Errors name `HandleTable`, `guest_mac_for`, and `rewrite_vm_id_labels` as not found (`cannot find function`/`cannot find struct`), because only the test module exists so far. If instead the error is `file not found for module` or `unresolved module`, add `mod netattrib;` to `crates/orchestrate/src/main.rs` beside the other `mod` declarations first, then re-run to get the intended failure.

- [ ] **Step 3: Write the implementation**

Insert this above the `#[cfg(test)] mod tests` block in `crates/orchestrate/src/netattrib.rs` (keep the SPDX header and module doc at the very top):

```rust
use std::collections::BTreeMap;

use assayist_contract::Fragment;
use serde_json::{json, Value};

/// Lifecycle states, matching the shared map ABI byte for byte. Fixed by the
/// spec: sub-project 4's eBPF programs read this same value.
pub const LIFECYCLE_RUNNING: u8 = 0;
pub const LIFECYCLE_PAUSING: u8 = 1;
pub const LIFECYCLE_PAUSED: u8 = 2;
pub const LIFECYCLE_RESUMING: u8 = 3;

/// What the orchestrator knows about one attributed VM. The dense `handle` is
/// what the kernel map and raw fragments carry; `vm_id` is the ULID the
/// assembled run reports.
#[derive(Clone, Debug)]
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
pub fn guest_mac_for(handle: u64) -> String {
    let hi = ((handle >> 8) & 0xff) as u8;
    let lo = (handle & 0xff) as u8;
    format!("02:00:00:00:{hi:02x}:{lo:02x}")
}

/// Dense handle assignment plus the handle-to-provenance table. Handles are a
/// per-run counter from zero: they are cheap in a BPF map value and short in a
/// series label, and they are deliberately not stable across runs (the ULID is).
#[derive(Default, Debug)]
pub struct HandleTable {
    by_handle: BTreeMap<u64, VmProvenance>,
    next: u64,
}

impl HandleTable {
    pub fn new() -> HandleTable {
        HandleTable::default()
    }

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

    pub fn get(&self, handle: u64) -> Option<&VmProvenance> {
        self.by_handle.get(&handle)
    }

    pub fn len(&self) -> usize {
        self.by_handle.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_handle.is_empty()
    }

    /// The table as additive `capture_meta.vm_attribution` provenance, so a
    /// dense-handle run is self-describing after the fact. Ascending by handle
    /// (BTreeMap iteration order).
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
```

- [ ] **Step 4: Declare the module**

In `crates/orchestrate/src/main.rs`, add `mod netattrib;` alongside the existing module declarations (`mod adapter;`, `mod capture;`, `mod def;`, ...), keeping them alphabetically ordered if they already are.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test -p assayist --lib netattrib`
Expected: PASS, 6 tests.

- [ ] **Step 6: Run the workspace suite and clippy**

Run: `cargo test --workspace`
Expected: PASS, no regressions.

Run: `cargo clippy --workspace --all-targets -- -D warnings`
Expected: exit 0. If clippy flags the unused `LIFECYCLE_*` constants or unused public items (Tasks 3 and 4 consume them), do not delete them and do not add `#[allow(dead_code)]` to the module wholesale; they are `pub` in a binary crate, so if clippy objects add a targeted `#[allow(dead_code)]` on the specific constant block with a one-line comment saying Task 3 consumes them.

- [ ] **Step 7: Commit**

```bash
but diff
but commit feat/attribution-spine -c -m "feat(orchestrate): dense VM handles, provenance, and label rewrite

Adds the pure-logic core of per-VM attribution: a dense u64 handle table
with per-VM provenance (ULID, tap, guest mac, ifindex, netns), the
locally-administered guest mac derivation, capture_meta provenance
rendering, and the rewrite that turns the handle in labels.vm_id into the
ULID the assembled run reports. An unissued handle is surfaced, not
dropped." --changes <netattrib-id>,<main-id>
```

---

### Task 2: `capture/netattrib` gadget

The privileged map owner: creates and pins `vm_by_ifindex`, serves the control socket, writes a fragment. Pure userspace over libbpf-rs, no `.bpf.c` and no `vmlinux.h`, so it needs a libbpf host but not kernel BTF. Excluded from the workspace like every other gadget.

**Files:**
- Create: `capture/netattrib/Cargo.toml`
- Create: `capture/netattrib/src/main.rs`
- Create: `capture/netattrib/README.md`
- Modify: `Cargo.toml` (root: add `capture/netattrib` to the workspace `exclude` list)
- Modify: `mise.toml` (add `netattrib` to the `lint-gadgets` task's gadget loop)
- Modify: `scripts/release.sh` (add `netattrib` to both gadget loops: the clippy loop and the build loop)

**Interfaces:**
- Consumes: the ABI constants from the Global Constraints (map name, `vm_ctx` layout, lifecycle bytes). It does not import from `crates/*`: gadgets are separate crates invoked as subprocesses.
- Produces, relied on by Task 3:
  - binary name `assayist-capture-netattrib`
  - CLI: `--duration <secs>`, `--out <path|->`, `--attrib-map <pin path>` (default `/sys/fs/bpf/assayist/vm_by_ifindex`), `--control <socket path>`, `--max-vms <n>` (default 1024)
  - control protocol, line-delimited ASCII over unix `SOCK_STREAM`, one reply line per command: `add <ifindex> <handle> <netns_inum>` -> `ok`/`err <msg>`; `state <handle> <RUNNING|PAUSING|PAUSED|RESUMING>` -> `ok`/`err <msg>`; `remove <handle>` -> `ok`/`err <msg>`
  - fragment shape: `{"series": [], "self_metrics": [], "capture_meta": {"gadget": "assayist-capture-netattrib", "window_ns": <u64>, "peak_live": <u64>, "final_live": <u64>, "commands": {"add": <u64>, "state": <u64>, "remove": <u64>}, "command_errors": <u64>}}`

- [ ] **Step 1: Write the failing tests**

Create `capture/netattrib/Cargo.toml`:

```toml
# SPDX-FileCopyrightText: 2026 Wesley Mason (1stvamp)
# SPDX-License-Identifier: Apache-2.0
# Excluded from the workspace (see the root Cargo.toml), so metadata is set
# explicitly here rather than inherited. Keep the version in step with the core
# (workspace.package version) when releasing. This gadget creates and pins a BPF
# map from userspace only: no .bpf.c, no CO-RE, so it needs libbpf but not
# kernel BTF.
[package]
name = "assayist-capture-netattrib"
version = "0.1.3"
edition = "2021"
license = "Apache-2.0"
repository = "https://github.com/1stvamp/assayist"
rust-version = "1.97"
description = "Per-VM network attribution map owner (pins vm_by_ifindex) for Assayist"
readme = "README.md"
keywords = ["benchmark", "ebpf", "attribution", "firecracker", "network"]
categories = ["development-tools::profiling"]

[[bin]]
name = "assayist-capture-netattrib"
path = "src/main.rs"

[dependencies]
serde_json = "1"
clap = { version = "4", features = ["derive"] }
anyhow = "1"
libbpf-rs = "0.24"
libbpf-sys = "1.4"
```

Create `capture/netattrib/src/main.rs` containing the SPDX header, the module doc, and only a `#[cfg(test)] mod tests` block with the imports the tests need:

```rust
// SPDX-FileCopyrightText: 2026 Wesley Mason (1stvamp)
// SPDX-License-Identifier: Apache-2.0
//
// Assayist per-VM network attribution map owner.
//
// Creates the shared `vm_by_ifindex` map, pins it on bpffs so the signal
// gadgets can open it read-only, and applies orchestrator-driven updates over a
// unix control socket for the length of the capture window. There is no eBPF
// object here: the map is created from userspace, so this gadget needs libbpf
// but not kernel BTF.
//
// The map value layout below is the shared ABI. Sub-project 4's .bpf.c
// programs declare a matching struct, so changing it is a breaking change to
// the whole gadget set.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vm_ctx_layout_matches_the_shared_abi() {
        // Fixed by the spec: u64 + u32 + u8 + 3 pad = 16 bytes, 8-aligned.
        // Sub-project 4's eBPF programs declare the same struct, so a silent
        // layout change here would silently corrupt their reads.
        assert_eq!(std::mem::size_of::<VmCtx>(), 16);
        assert_eq!(std::mem::align_of::<VmCtx>(), 8);
    }

    #[test]
    fn parses_each_control_command() {
        assert_eq!(
            parse_command("add 11 0 4026531840").unwrap(),
            Command::Add { ifindex: 11, handle: 0, netns_inum: 4026531840 }
        );
        assert_eq!(
            parse_command("state 3 PAUSED").unwrap(),
            Command::State { handle: 3, state: LIFECYCLE_PAUSED }
        );
        assert_eq!(parse_command("remove 7").unwrap(), Command::Remove { handle: 7 });
        // Case-insensitive state names, since the wire is hand-typeable.
        assert_eq!(
            parse_command("state 1 running").unwrap(),
            Command::State { handle: 1, state: LIFECYCLE_RUNNING }
        );
    }

    #[test]
    fn rejects_malformed_commands() {
        for bad in [
            "",
            "add",
            "add 11 0",             // missing netns
            "add x 0 1",            // non-numeric ifindex
            "state 1 SLEEPING",     // unknown state
            "remove",               // missing handle
            "frobnicate 1",         // unknown verb
        ] {
            assert!(parse_command(bad).is_err(), "{bad:?} must be rejected");
        }
    }

    #[test]
    fn state_names_round_trip_to_abi_bytes() {
        assert_eq!(state_from_name("RUNNING").unwrap(), LIFECYCLE_RUNNING);
        assert_eq!(state_from_name("PAUSING").unwrap(), LIFECYCLE_PAUSING);
        assert_eq!(state_from_name("PAUSED").unwrap(), LIFECYCLE_PAUSED);
        assert_eq!(state_from_name("RESUMING").unwrap(), LIFECYCLE_RESUMING);
        assert!(state_from_name("NOPE").is_none());
    }

    #[test]
    fn fragment_reports_occupancy_and_command_counts() {
        let stats = Stats { peak_live: 4, final_live: 2, adds: 4, states: 6, removes: 2, errors: 1 };
        let f = fragment(&stats, 30_000_000_000);
        assert_eq!(f["series"].as_array().unwrap().len(), 0);
        assert_eq!(f["self_metrics"].as_array().unwrap().len(), 0);
        let m = &f["capture_meta"];
        assert_eq!(m["gadget"], "assayist-capture-netattrib");
        assert_eq!(m["window_ns"], 30_000_000_000u64);
        assert_eq!(m["peak_live"], 4);
        assert_eq!(m["final_live"], 2);
        assert_eq!(m["commands"]["add"], 4);
        assert_eq!(m["commands"]["state"], 6);
        assert_eq!(m["commands"]["remove"], 2);
        assert_eq!(m["command_errors"], 1);
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --manifest-path capture/netattrib/Cargo.toml`
Expected: compile FAIL naming `VmCtx`, `parse_command`, `Command`, `state_from_name`, `Stats`, `fragment`, and the `LIFECYCLE_*` constants as not found.

Note: this fetches `libbpf-rs`/`libbpf-sys`, which need libbpf headers present. On a host without them the build fails at the `libbpf-sys` build script instead, which is expected: this gadget is only buildable on a libbpf host. If that happens, record it and continue to Step 3; the maintainer runs this task's suite on the libbpf host.

- [ ] **Step 3: Write the implementation**

Insert above the `#[cfg(test)] mod tests` block in `capture/netattrib/src/main.rs`:

```rust
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use libbpf_rs::{MapCore, MapFlags, MapHandle, MapType};
use serde_json::{json, Value};

/// Lifecycle states, the shared ABI (see the module doc).
pub const LIFECYCLE_RUNNING: u8 = 0;
pub const LIFECYCLE_PAUSING: u8 = 1;
pub const LIFECYCLE_PAUSED: u8 = 2;
pub const LIFECYCLE_RESUMING: u8 = 3;

/// The shared map value. `#[repr(C)]` with explicit padding so the layout is
/// the ABI sub-project 4's eBPF programs compile against.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct VmCtx {
    pub vm_id: u64,
    pub netns_inum: u32,
    pub lifecycle_state: u8,
    pub _pad: [u8; 3],
}

impl VmCtx {
    fn as_bytes(&self) -> [u8; 16] {
        let mut b = [0u8; 16];
        b[0..8].copy_from_slice(&self.vm_id.to_ne_bytes());
        b[8..12].copy_from_slice(&self.netns_inum.to_ne_bytes());
        b[12] = self.lifecycle_state;
        b
    }

    fn from_bytes(b: &[u8]) -> VmCtx {
        VmCtx {
            vm_id: u64::from_ne_bytes(b[0..8].try_into().unwrap()),
            netns_inum: u32::from_ne_bytes(b[8..12].try_into().unwrap()),
            lifecycle_state: b[12],
            _pad: [0; 3],
        }
    }
}

#[derive(Parser, Debug)]
#[command(name = "assayist-capture-netattrib")]
#[command(about = "Owns and pins the per-VM network attribution map, applies orchestrator updates")]
struct Args {
    /// Capture window in seconds. The map stays pinned for this long.
    #[arg(long, default_value_t = 30)]
    duration: u64,

    /// Output path for the AssayRun fragment JSON. "-" for stdout.
    #[arg(long, default_value = "-")]
    out: String,

    /// bpffs path to pin the map at.
    #[arg(long, default_value = "/sys/fs/bpf/assayist/vm_by_ifindex")]
    attrib_map: String,

    /// Unix socket to accept control commands on.
    #[arg(long)]
    control: String,

    /// Cardinality ceiling: max concurrent attributed VMs.
    #[arg(long, default_value_t = 1024)]
    max_vms: u32,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Command {
    Add { ifindex: u32, handle: u64, netns_inum: u32 },
    State { handle: u64, state: u8 },
    Remove { handle: u64 },
}

/// Map a wire state name to its ABI byte. Case-insensitive: the wire is plain
/// text and hand-typeable during debugging.
pub fn state_from_name(name: &str) -> Option<u8> {
    match name.to_ascii_uppercase().as_str() {
        "RUNNING" => Some(LIFECYCLE_RUNNING),
        "PAUSING" => Some(LIFECYCLE_PAUSING),
        "PAUSED" => Some(LIFECYCLE_PAUSED),
        "RESUMING" => Some(LIFECYCLE_RESUMING),
        _ => None,
    }
}

/// Parse one control line. Unknown verbs, missing fields, and unparsable
/// numbers are all errors: the orchestrator gets an `err` reply rather than a
/// silently ignored command.
pub fn parse_command(line: &str) -> Result<Command> {
    let mut f = line.split_whitespace();
    let verb = f.next().ok_or_else(|| anyhow!("empty command"))?;
    match verb {
        "add" => {
            let ifindex: u32 = f.next().ok_or_else(|| anyhow!("add needs an ifindex"))?.parse()?;
            let handle: u64 = f.next().ok_or_else(|| anyhow!("add needs a handle"))?.parse()?;
            let netns_inum: u32 = f.next().ok_or_else(|| anyhow!("add needs a netns_inum"))?.parse()?;
            Ok(Command::Add { ifindex, handle, netns_inum })
        }
        "state" => {
            let handle: u64 = f.next().ok_or_else(|| anyhow!("state needs a handle"))?.parse()?;
            let name = f.next().ok_or_else(|| anyhow!("state needs a state name"))?;
            let state = state_from_name(name).ok_or_else(|| anyhow!("unknown state '{name}'"))?;
            Ok(Command::State { handle, state })
        }
        "remove" => {
            let handle: u64 = f.next().ok_or_else(|| anyhow!("remove needs a handle"))?.parse()?;
            Ok(Command::Remove { handle })
        }
        other => bail!("unknown command '{other}'"),
    }
}

/// Command and occupancy bookkeeping, reported in the fragment.
#[derive(Default, Debug)]
pub struct Stats {
    pub peak_live: u64,
    pub final_live: u64,
    pub adds: u64,
    pub states: u64,
    pub removes: u64,
    pub errors: u64,
}

/// The AssayRun fragment. No series and no self_metrics: this gadget owns a map
/// and attaches no probes, so it has no datapath signal and no eBPF program
/// cost to report. The signal gadgets in sub-project 4 report the
/// unattributed-traffic rate off this same pinned map.
pub fn fragment(stats: &Stats, window_ns: u64) -> Value {
    json!({
        "series": [],
        "self_metrics": [],
        "capture_meta": {
            "gadget": "assayist-capture-netattrib",
            "window_ns": window_ns,
            "peak_live": stats.peak_live,
            "final_live": stats.final_live,
            "commands": {
                "add": stats.adds,
                "state": stats.states,
                "remove": stats.removes,
            },
            "command_errors": stats.errors,
        }
    })
}

/// Create the map and pin it. An existing pin is an error: it means a prior run
/// crashed without cleaning up, and silently reusing it would attribute this
/// run's traffic against stale entries.
fn create_and_pin(pin: &str, max_vms: u32) -> Result<MapHandle> {
    if Path::new(pin).exists() {
        bail!("pin {pin} already exists (stale from a crashed run?); remove it and retry");
    }
    if let Some(dir) = Path::new(pin).parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    let map = MapHandle::create(
        MapType::Hash,
        Some("vm_by_ifindex"),
        std::mem::size_of::<u32>() as u32,
        std::mem::size_of::<VmCtx>() as u32,
        max_vms,
        &Default::default(),
    )
    .context("creating vm_by_ifindex")?;
    map.pin(pin).with_context(|| format!("pinning at {pin}"))?;
    Ok(map)
}

/// Find the map key (ifindex) whose value carries `handle`. The map is keyed by
/// ifindex because that is what the datapath programs have in hand; state
/// updates and removals arrive by handle, so this is the reverse lookup.
fn key_for_handle(map: &MapHandle, handle: u64) -> Option<Vec<u8>> {
    for key in map.keys() {
        if let Ok(Some(v)) = map.lookup(&key, MapFlags::ANY) {
            if VmCtx::from_bytes(&v).vm_id == handle {
                return Some(key);
            }
        }
    }
    None
}

fn apply(map: &MapHandle, cmd: &Command, stats: &mut Stats) -> Result<()> {
    match cmd {
        Command::Add { ifindex, handle, netns_inum } => {
            let v = VmCtx {
                vm_id: *handle,
                netns_inum: *netns_inum,
                lifecycle_state: LIFECYCLE_RUNNING,
                _pad: [0; 3],
            };
            map.update(&ifindex.to_ne_bytes(), &v.as_bytes(), MapFlags::ANY)
                .with_context(|| format!("adding ifindex {ifindex}"))?;
            stats.adds += 1;
        }
        Command::State { handle, state } => {
            let key = key_for_handle(map, *handle)
                .ok_or_else(|| anyhow!("no entry for handle {handle}"))?;
            let cur = map
                .lookup(&key, MapFlags::ANY)?
                .ok_or_else(|| anyhow!("entry for handle {handle} vanished"))?;
            let mut v = VmCtx::from_bytes(&cur);
            v.lifecycle_state = *state;
            map.update(&key, &v.as_bytes(), MapFlags::ANY)?;
            stats.states += 1;
        }
        Command::Remove { handle } => {
            let key = key_for_handle(map, *handle)
                .ok_or_else(|| anyhow!("no entry for handle {handle}"))?;
            map.delete(&key)?;
            stats.removes += 1;
        }
    }
    let live = map.keys().count() as u64;
    stats.final_live = live;
    stats.peak_live = stats.peak_live.max(live);
    Ok(())
}

/// Serve control commands until the window closes. One reply line per command,
/// so a slow owner applies backpressure rather than dropping updates. The
/// listener is non-blocking and polled, because the window is what ends the run,
/// not the peer closing.
fn serve(listener: &UnixListener, map: &MapHandle, stats: &mut Stats, deadline: Instant) {
    listener.set_nonblocking(true).ok();
    let mut peers: Vec<BufReader<UnixStream>> = Vec::new();
    while Instant::now() < deadline {
        match listener.accept() {
            Ok((s, _)) => {
                s.set_nonblocking(false).ok();
                s.set_read_timeout(Some(Duration::from_millis(50))).ok();
                peers.push(BufReader::new(s));
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(_) => {}
        }
        for p in peers.iter_mut() {
            let mut line = String::new();
            match p.read_line(&mut line) {
                Ok(0) => continue,
                Ok(_) => {
                    let reply = match parse_command(line.trim()) {
                        Ok(cmd) => match apply(map, &cmd, stats) {
                            Ok(()) => "ok\n".to_string(),
                            Err(e) => {
                                stats.errors += 1;
                                format!("err {e}\n")
                            }
                        },
                        Err(e) => {
                            stats.errors += 1;
                            format!("err {e}\n")
                        }
                    };
                    let _ = p.get_mut().write_all(reply.as_bytes());
                    let _ = p.get_mut().flush();
                }
                Err(_) => continue,
            }
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn main() -> Result<()> {
    let args = Args::parse();

    let map = create_and_pin(&args.attrib_map, args.max_vms)?;
    let _ = std::fs::remove_file(&args.control);
    let listener = UnixListener::bind(&args.control)
        .with_context(|| format!("binding control socket {}", args.control))?;

    let start = Instant::now();
    let mut stats = Stats::default();
    serve(&listener, &map, &mut stats, start + Duration::from_secs(args.duration));
    let window_ns = start.elapsed().as_nanos() as u64;

    // Release the pin and the socket: the next run creates its own, and a left
    // pin would make that run fail with the stale-pin error.
    let _ = map.unpin(&args.attrib_map);
    let _ = std::fs::remove_file(&args.control);

    let text = serde_json::to_string_pretty(&fragment(&stats, window_ns))?;
    if args.out == "-" {
        println!("{text}");
    } else {
        std::fs::write(&args.out, text).with_context(|| format!("writing {}", args.out))?;
    }
    Ok(())
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --manifest-path capture/netattrib/Cargo.toml`
Expected: PASS, 5 tests.

If `libbpf-rs 0.24`'s `MapHandle::create` signature differs from the call above (the safe wrapper shape varies by point release, as `CLAUDE.local.md` warns), adjust the call to the version in use and keep everything else identical. Do not change the `VmCtx` layout, the map name, the map type, or the protocol to make it compile: those are the fixed ABI. If the crate genuinely cannot express a userspace-created pinned hash map, stop and report that as a blocker rather than inventing a different design.

- [ ] **Step 5: Write the README**

Create `capture/netattrib/README.md`:

```markdown
<!--
SPDX-FileCopyrightText: 2026 Wesley Mason (1stvamp)
SPDX-License-Identifier: Apache-2.0
-->

# assayist-capture-netattrib

Owns the per-VM network attribution map. It creates `vm_by_ifindex`, pins it on
bpffs so the network signal gadgets can open it read-only, and applies
orchestrator-driven updates over a unix control socket for the length of the
capture window.

There is no eBPF object here. The map is created from userspace, so this gadget
needs libbpf but not kernel BTF, which makes it the lightest gadget in the set.

## Build

```sh
cargo build --release --manifest-path capture/netattrib/Cargo.toml
```

## Run

```sh
sudo ./target/release/assayist-capture-netattrib \
  --duration 30 \
  --control /tmp/assayist-netattrib.sock \
  --out netattrib.frag.json
```

The orchestrator normally launches it; run it by hand only for debugging.

## Map ABI

Fixed, and shared with the signal gadgets:

| Property | Value |
|---|---|
| name | `vm_by_ifindex` |
| type | `BPF_MAP_TYPE_HASH` |
| key | `u32 ifindex` |
| value | `struct vm_ctx { u64 vm_id; u32 netns_inum; u8 lifecycle_state; u8 _pad[3]; }` |
| pin | `/sys/fs/bpf/assayist/vm_by_ifindex` (default) |

`vm_id` in the map is the orchestrator's dense per-run handle, not the ULID. The
orchestrator holds the handle to ULID table and rewrites the label when the run
is assembled.

Lifecycle states: `0` RUNNING, `1` PAUSING, `2` PAUSED, `3` RESUMING.

## Control protocol

Line-delimited ASCII over a unix `SOCK_STREAM`, one reply line per command
(`ok` or `err <message>`):

| Command | Effect |
|---|---|
| `add <ifindex> <handle> <netns_inum>` | insert or replace the entry, state RUNNING |
| `state <handle> <RUNNING\|PAUSING\|PAUSED\|RESUMING>` | update that VM's state byte |
| `remove <handle>` | delete the entry |

## Output

An AssayRun fragment with empty `series` and `self_metrics`, and a
`capture_meta` carrying map occupancy (`peak_live`, `final_live`), per-verb
command counts, and `command_errors`.

## Limits

- No datapath probes, so it cannot report an unattributed-traffic rate. That is
  the signal gadgets' job, off this same pinned map.
- It trusts the orchestrator's `add` values. It does not verify that an
  `ifindex` names a real device.
- A `state` or `remove` for an unknown handle replies `err` and counts an
  error. It is not fatal: one stale command must not abandon a run.
- `state` and `remove` scan the map to find the entry for a handle, because the
  map is keyed by ifindex. Fine at the map's bounded size, and it keeps the key
  the datapath programs need.
- An existing pin is an error, never reclaimed. Clear a stale pin by hand
  (`rm /sys/fs/bpf/assayist/vm_by_ifindex`) so a crashed prior run cannot
  silently contaminate this one.
- Needs `CAP_BPF`/`CAP_SYS_ADMIN` to create and pin a map, and a mounted bpffs.
```

- [ ] **Step 6: Register the gadget in the build and lint paths**

In the root `Cargo.toml`, add `"capture/netattrib"` to the workspace `exclude` list beside the other `capture/*` entries.

In `mise.toml`, the `lint-gadgets` task loops `for g in kvm block net ctrlplane resident; do`. Add `netattrib`: `for g in kvm block net ctrlplane resident netattrib; do`.

In `scripts/release.sh`, the same list appears twice (the clippy loop and the build loop). Add `netattrib` to both.

- [ ] **Step 7: Verify the workspace still excludes it and the core still builds**

Run: `cargo build --workspace`
Expected: PASS, and the output does not mention `assayist-capture-netattrib` (it is excluded, so the BTF-free core is unaffected).

Run: `cargo clippy --manifest-path capture/netattrib/Cargo.toml --all-targets -- -D warnings`
Expected: exit 0 on a libbpf host. On a host without libbpf headers this fails in the `libbpf-sys` build script; record that and let the maintainer run it on the libbpf host.

- [ ] **Step 8: Commit**

```bash
but diff
but commit feat/attribution-spine -m "feat(capture): add the netattrib attribution map owner

New gadget that creates the shared vm_by_ifindex map, pins it on bpffs for
the signal gadgets to open read-only, and applies orchestrator-driven
add/state/remove updates over a unix control socket for the capture
window. Pure userspace over libbpf-rs: no .bpf.c and no vmlinux.h, so it
needs libbpf but not kernel BTF. An existing pin is an error rather than
reclaimed, so a crashed prior run cannot contaminate this one." --changes <ids>
```

---

### Task 3: Control-channel client and the `net_attribution` SPI

The orchestrator half: spawn the owner, speak the protocol, and give targets a way to declare their tap identity without pulling BPF or sockets into the adapter. Builds and tests on any host against a fake unix-socket peer.

**Files:**
- Modify: `crates/orchestrate/src/netattrib.rs` (add the client beside Task 1's table)
- Modify: `crates/orchestrate/src/adapter.rs` (add `NetAttribution` and the defaulted `Target::net_attribution` method, near `pinning_layout`/`resident_files` around lines 59-73)

**Interfaces:**
- Consumes from Task 1: `HandleTable`, `LIFECYCLE_*`. From Task 2: the wire protocol and the gadget's CLI flags.
- Produces, relied on by Task 4:
  - `pub struct NetAttribution { pub tap: String, pub ifindex: u32, pub guest_mac: String, pub netns_inum: u32 }` in `adapter.rs`
  - `fn net_attribution(&self, _sh: &dyn Shell) -> Option<NetAttribution> { None }` on `trait Target`
  - in `netattrib.rs`: `pub struct ControlClient { /* private */ }` with `pub fn connect(path: &str, timeout: Duration) -> Result<ControlClient, String>`, `pub fn add(&mut self, ifindex: u32, handle: u64, netns_inum: u32) -> Result<(), String>`, `pub fn state(&mut self, handle: u64, state: u8) -> Result<(), String>`, `pub fn remove(&mut self, handle: u64) -> Result<(), String>`
  - `pub fn state_name(state: u8) -> &'static str`

- [ ] **Step 1: Write the failing tests**

Append to the `#[cfg(test)] mod tests` block in `crates/orchestrate/src/netattrib.rs`:

```rust
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
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p assayist --lib netattrib`
Expected: compile FAIL naming `ControlClient` and `state_name` as not found. Task 1's six tests still pass once it compiles, so the failure is only about the new items.

- [ ] **Step 3: Write the client**

Append to `crates/orchestrate/src/netattrib.rs` (after Task 1's code, before the test module):

```rust
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
pub struct ControlClient {
    reader: BufReader<UnixStream>,
}

impl ControlClient {
    /// Connect, retrying until `timeout`: the owner is a freshly spawned
    /// subprocess, so its socket may not exist yet.
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
```

- [ ] **Step 4: Add the `net_attribution` SPI**

In `crates/orchestrate/src/adapter.rs`, add this struct just above `pub trait Target`:

```rust
/// A target's network attribution identity: the host tap it owns and the
/// numbers the attribution map needs. Returned by targets that set up
/// networking; `None` from everything else.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetAttribution {
    pub tap: String,
    pub ifindex: u32,
    pub guest_mac: String,
    pub netns_inum: u32,
}
```

and add this defaulted method to `trait Target`, beside `pinning_layout` and `resident_files`:

```rust
    /// The tap identity this target set up, if it did. The run driver uses it to
    /// assign a handle and drive the attribution map. Defaulted to `None` so
    /// every existing target is unaffected: the adapter stays free of BPF and
    /// sockets, and only a target that actually creates a tap reports one.
    fn net_attribution(&self, _sh: &dyn Shell) -> Option<NetAttribution> {
        None
    }
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test -p assayist --lib netattrib`
Expected: PASS, 10 tests (Task 1's six plus these four).

- [ ] **Step 6: Run the workspace suite and clippy**

Run: `cargo test --workspace`
Expected: PASS. The new trait method is defaulted, so no existing `impl Target` needs changing.

Run: `cargo clippy --workspace --all-targets -- -D warnings`
Expected: exit 0.

- [ ] **Step 7: Commit**

```bash
but diff
but commit feat/attribution-spine -m "feat(orchestrate): attribution control client and net_attribution SPI

Adds the request/reply client for the netattrib owner's control socket, so
every map update waits for its reply and a slow owner applies backpressure
rather than the orchestrator dropping updates. Adds a defaulted
Target::net_attribution so a target can declare the tap it set up without
the adapter learning about BPF or sockets." --changes <ids>
```

---

### Task 4: Firecracker tap networking

Give a firecracker VM a real host tap, so there is an `ifindex` to attribute on. Follows the adapter's existing `Shell` pattern (shell commands through `sh.run`), which is what makes it testable here through the fake `Shell`. Gated behind a config key so existing defs are untouched.

**Files:**
- Modify: `crates/orchestrate/src/native.rs` (`FirecrackerTarget` struct around lines 96-153; `firecracker_target` constructor around lines 155-220; `provision` around line 351; `teardown` around line 486; add `net_attribution`; tests at the bottom of the file)
- Modify: `docs/config-reference.md` (the firecracker target config table)

**Interfaces:**
- Consumes from Task 3: `adapter::NetAttribution`, `Target::net_attribution`. From Task 1: `netattrib::guest_mac_for`.
- Produces: a firecracker target that, when `network: tap` is set, creates a tap on provision, PUTs `/network-interfaces/eth0`, reads the tap's `ifindex`, deletes the tap on teardown, and returns `Some(NetAttribution)`.

- [ ] **Step 1: Write the failing tests**

Add to the `#[cfg(test)] mod tests` block at the bottom of `crates/orchestrate/src/native.rs`. Match the existing firecracker tests' style (they build a target from a config map and a fake `Shell`, then assert on `sh.saw(...)`); read `firecracker_cold_boot_configures_then_starts` around line 1347 first and reuse its exact helper names and construction:

```rust
    #[test]
    fn firecracker_without_network_creates_no_tap() {
        // The default is unchanged behaviour: no tap, nothing to attribute.
        let sh = FakeShell::default();
        let target = firecracker_target(&fc_config(), &BTreeMap::new(), false);
        target.provision(&sh).unwrap();
        assert!(!sh.saw("/network-interfaces"));
        assert!(!sh.saw("ip tuntap add"));
        assert!(target.net_attribution(&sh).is_none());
    }

    #[test]
    fn firecracker_with_tap_networking_creates_configures_and_reports_it() {
        let sh = FakeShell::default();
        let mut config = fc_config();
        config.insert("network".to_string(), serde_json::json!("tap"));
        let mut vars = BTreeMap::new();
        vars.insert("instance".to_string(), "2".to_string());
        let target = firecracker_target(&config, &vars, false);
        target.provision(&sh).unwrap();

        // Tap created and brought up before the API call that references it.
        assert!(sh.saw("ip tuntap add"), "tap must be created");
        assert!(sh.saw("ip link set"), "tap must be brought up");
        // Firecracker told about the device, with the deterministic mac.
        assert!(sh.saw("/network-interfaces"));
        assert!(sh.saw("host_dev_name"));
        assert!(sh.saw("02:00:00:00:00:02"), "guest mac derives from the instance");

        let attrib = target.net_attribution(&sh).expect("tap networking reports attribution");
        assert_eq!(attrib.guest_mac, "02:00:00:00:00:02");
        assert!(attrib.tap.contains('2'), "tap name carries the instance: {}", attrib.tap);
    }

    #[test]
    fn firecracker_teardown_deletes_the_tap() {
        let sh = FakeShell::default();
        let mut config = fc_config();
        config.insert("network".to_string(), serde_json::json!("tap"));
        let target = firecracker_target(&config, &BTreeMap::new(), false);
        target.provision(&sh).unwrap();
        target.teardown(&sh).unwrap();
        assert!(sh.saw("ip tuntap del"), "teardown must delete the tap it created");
    }
```

If the existing tests use a differently named config helper than `fc_config()` or a different fake shell type than `FakeShell`, use theirs verbatim. Do not introduce a second fake shell.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p assayist --lib native`
Expected: FAIL. `firecracker_without_network_creates_no_tap` fails on `net_attribution` not existing on the concrete type or the tap assertions being unmet; the other two fail because no tap is created.

- [ ] **Step 3: Add the tap fields and constructor wiring**

In the `FirecrackerTarget` struct, add:

```rust
    /// Host tap device for this instance, when the def asks for tap networking
    /// (`network: tap`). `None` leaves the VM with no network interface, which
    /// is the historical behaviour.
    tap: Option<String>,
    /// Deterministic locally-administered guest MAC, derived from the instance
    /// index so concurrent instances cannot collide.
    guest_mac: String,
    /// The tap's ifindex, read from sysfs after the device exists. The
    /// attribution map keys on it.
    tap_ifindex: RefCell<Option<u32>>,
```

In `firecracker_target`, after `let stream_dir = ...`, add:

```rust
    // Tap networking is opt-in. The instance index (already used for the API
    // socket) keeps tap names and MACs unique across concurrent instances.
    let instance: u64 = vars.get("instance").and_then(|s| s.parse().ok()).unwrap_or(0);
    let tap = config.get("network").and_then(|_| {
        matches!(g("network", "").to_lowercase().as_str(), "tap").then(|| {
            format!("asy{}-{}", std::process::id() % 100000, instance)
        })
    });
    let guest_mac = crate::netattrib::guest_mac_for(instance);
```

and in the `FirecrackerTarget { ... }` literal add `tap, guest_mac, tap_ifindex: RefCell::new(None),`.

- [ ] **Step 4: Create the tap in `provision` and configure Firecracker**

In `provision`, after the `/drives/rootfs` PUT (the last API call in the function, around line 435), replace the trailing `self.api(sh, "PUT", "/drives/rootfs", &drive)` expression so the drive result is bound and the network setup follows:

```rust
        self.api(sh, "PUT", "/drives/rootfs", &drive)?;

        // Tap networking, when asked for. Created before the API call that
        // names it, because Firecracker validates the device exists. The
        // ifindex comes from sysfs rather than parsing `ip` output.
        if let Some(tap) = &self.tap {
            sh.run(&format!(
                "ip tuntap del dev '{tap}' mode tap 2>/dev/null; \
                 ip tuntap add dev '{tap}' mode tap && ip link set dev '{tap}' up"
            ))?;
            let idx = sh.run(&format!("cat '/sys/class/net/{tap}/ifindex'"))?;
            *self.tap_ifindex.borrow_mut() = idx.trim().parse().ok();
            let iface = json!({
                "iface_id": "eth0",
                "host_dev_name": tap,
                "guest_mac": self.guest_mac,
            })
            .to_string();
            self.api(sh, "PUT", "/network-interfaces/eth0", &iface)?;
        }
        Ok(())
```

- [ ] **Step 5: Delete the tap in `teardown` and report attribution**

At the end of `teardown`, before its final `Ok(())`, add:

```rust
        // Best-effort tap cleanup: the VM is already gone, and a leaked tap
        // would collide with the next run on this instance index.
        if let Some(tap) = &self.tap {
            let _ = sh.run(&format!("ip tuntap del dev '{tap}' mode tap"));
        }
```

Add the trait method to `impl Target for FirecrackerTarget`:

```rust
    fn net_attribution(&self, _sh: &dyn Shell) -> Option<NetAttribution> {
        let tap = self.tap.clone()?;
        Some(NetAttribution {
            tap,
            ifindex: (*self.tap_ifindex.borrow())?,
            guest_mac: self.guest_mac.clone(),
            // Host netns. Per-VM netns is not used: the tap lives in the host
            // namespace, and netns is recorded for cross-check only.
            netns_inum: 0,
        })
    }
```

Add `NetAttribution` to the `use crate::adapter::{...}` import at the top of `native.rs`.

The `net_attribution` test asserts `Some(..)` after `provision`, so the fake `Shell` must return a parsable ifindex for the sysfs read. If the existing `FakeShell` returns an empty string for every command, extend it minimally so a command containing `/sys/class/net/` returns `"7\n"`, keeping every other command's behaviour identical, and note it in the report.

- [ ] **Step 6: Run the tests to verify they pass**

Run: `cargo test -p assayist --lib native`
Expected: PASS, including the three new tests and every pre-existing firecracker test unchanged.

- [ ] **Step 7: Document the config key**

In `docs/config-reference.md`, add a row to the firecracker target config table:

```markdown
| `network` | `tap` to give the VM a host tap device (created on provision, deleted on teardown) and a deterministic locally-administered MAC. Absent means no network interface, the historical behaviour. Required for per-VM network attribution. | (unset) |
```

- [ ] **Step 8: Run the workspace suite, clippy, and the gate suite**

Run: `cargo test --workspace`
Expected: PASS.

Run: `cargo clippy --workspace --all-targets -- -D warnings`
Expected: exit 0.

Run: `bash scripts/verify-gate.sh`
Expected: exit 0, all six verdicts as before (nothing here touches grading).

- [ ] **Step 9: Commit**

```bash
but diff
but commit feat/attribution-spine -m "feat(orchestrate): firecracker tap networking for attribution

A firecracker VM can now be given a host tap (network: tap), so there is
an ifindex to attribute network samples against. The tap is created before
the API call that names it, its ifindex is read from sysfs, and it is
deleted at teardown so a leaked device cannot collide with the next run.
Absent the config key the adapter behaves exactly as before." --changes <ids>
```

---

### Task 5: Wire attribution into the run and record provenance

Thread the pieces through `execute_run`: spawn nothing new, but drive the control channel around the existing lifecycle, rewrite the labels at assemble, and attach the provenance. This is the task that makes the spine actually do something in a run.

**Files:**
- Modify: `crates/orchestrate/src/adapter.rs` (`execute_run` and `RunArtifacts`, around lines 196-260)
- Modify: `crates/orchestrate/src/main.rs` (the `execute_run` call site around line 707)

**Interfaces:**
- Consumes: Task 1 (`HandleTable`, `rewrite_vm_id_labels`), Task 3 (`ControlClient`, `NetAttribution`, `Target::net_attribution`, `LIFECYCLE_RUNNING`), Task 4 (a firecracker target that reports `Some(NetAttribution)`).
- Produces: `RunArtifacts` gains `pub vm_attribution: Option<Value>`; `execute_run` gains a final parameter `attrib: Option<&mut AttributionSession>`; `pub struct AttributionSession { pub client: ControlClient, pub table: HandleTable }` in `netattrib.rs`.

- [ ] **Step 1: Write the failing tests**

Add to the `#[cfg(test)] mod tests` block in `crates/orchestrate/src/adapter.rs`, beside the existing `execute_run` test around line 642:

```rust
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
```

Add to the `#[cfg(test)] mod tests` block in `crates/orchestrate/src/netattrib.rs`:

```rust
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
            .register("01ULIDX".into(), "tap9".into(), 11, 0)
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
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p assayist --lib`
Expected: FAIL. Compile errors name `AttributionSession`, `register`, `set_state`, `RunArtifacts::vm_attribution`, and `execute_run` taking six arguments.

- [ ] **Step 3: Add `AttributionSession`**

Append to `crates/orchestrate/src/netattrib.rs`, before the test module:

```rust
/// One run's attribution state: the control channel to the owner gadget plus
/// the handle table. Held by the run driver for the length of the run.
pub struct AttributionSession {
    pub client: ControlClient,
    pub table: HandleTable,
}

impl AttributionSession {
    /// Assign a handle to a VM and tell the owner about it. Returns the handle
    /// the gadgets will emit in `labels.vm_id`.
    pub fn register(
        &mut self,
        vm_id: String,
        tap: String,
        ifindex: u32,
        netns_inum: u32,
    ) -> Result<u64, String> {
        let handle = self.table.assign(vm_id, tap, ifindex, netns_inum);
        self.client.add(ifindex, handle, netns_inum)?;
        Ok(handle)
    }

    pub fn set_state(&mut self, handle: u64, state: u8) -> Result<(), String> {
        self.client.state(handle, state)
    }

    pub fn deregister(&mut self, handle: u64) -> Result<(), String> {
        self.client.remove(handle)
    }
}
```

- [ ] **Step 4: Thread attribution through `execute_run`**

In `crates/orchestrate/src/adapter.rs`, add to `RunArtifacts`:

```rust
    /// Handle-to-ULID provenance for the VMs attributed this run, or `None`
    /// when attribution was not enabled. Recorded as additive
    /// `capture_meta.vm_attribution`.
    pub vm_attribution: Option<Value>,
```

Change the signature to take an optional session:

```rust
pub fn execute_run<S: Shell, R: GadgetRunner>(
    sh: &S,
    runner: &R,
    target: &dyn Target,
    workload: &dyn Workload,
    gadgets: &[GadgetInvocation],
    attrib: Option<&mut crate::netattrib::AttributionSession>,
) -> Result<RunArtifacts, String> {
```

After `target.reach_steady(sh)?;` and the `mem_after` sample, register the VM if both a session and a tap exist:

```rust
    // Attribution, when enabled and the target actually set up a tap. Register
    // after steady so the tap exists and its ifindex is known, and before the
    // gadgets attach so their first samples are already attributable.
    let mut attributed: Option<(&mut crate::netattrib::AttributionSession, u64)> = None;
    if let Some(session) = attrib {
        match target.net_attribution(sh) {
            Some(na) => {
                let handle = session.register(
                    crate::run::new_run_id(),
                    na.tap,
                    na.ifindex,
                    na.netns_inum,
                )?;
                session.set_state(handle, crate::netattrib::LIFECYCLE_RUNNING)?;
                attributed = Some((session, handle));
            }
            None => {
                // A run that asked for attribution but whose target set up no
                // tap is a config error, not a silent no-op: every later
                // network sample would be unattributable.
                return Err(
                    "attribution enabled but the target reports no tap; set `network: tap` on the target"
                        .to_string(),
                );
            }
        }
    }
```

Before `target.teardown(sh)?;`, deregister and capture the provenance, then rewrite the labels once the fragments are in hand. Immediately after the `fragments.push(...)` calls that close out the artifacts, add:

```rust
    let vm_attribution = match attributed {
        Some((session, handle)) => {
            let _ = session.deregister(handle);
            let unknown = crate::netattrib::rewrite_vm_id_labels(&mut fragments, &session.table);
            let mut prov = json!({ "vms": session.table.provenance_json() });
            if !unknown.is_empty() {
                // Handles the orchestrator never issued mean a stale map.
                prov["unresolved_handles"] = json!(unknown);
            }
            Some(prov)
        }
        None => None,
    };
```

and add `vm_attribution` to the `RunArtifacts { ... }` literal it returns.

If the borrow checker objects to holding `&mut session` across the gadget wait (the fragments are moved into the rewrite), restructure by keeping only the `handle` in `attributed` and re-borrowing the session after the waits. Do not clone the session, and do not make the field `Option<Value>` public-mutable to dodge it.

- [ ] **Step 5: Update both call sites**

`crates/orchestrate/src/adapter.rs` around line 642 (the existing `execute_run` test): add `, None` as the final argument.

`crates/orchestrate/src/main.rs` around line 707: add `, None` as the final argument for now, so behaviour is unchanged and the pipeline compiles. Wiring the session in from a def flag is sub-project 3's work (it needs the pause/resume hook to be worth switching on); leave a one-line comment saying so:

```rust
                // Attribution is wired in with the pause/resume hook (sub-project 3),
                // which is what makes the lifecycle states worth driving.
                let art = match adapter::execute_run(&shell, &runner, target.as_ref(), workload.as_ref(), &plan, None) {
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `cargo test -p assayist --lib`
Expected: PASS, including `execute_run_without_attribution_reports_none` and `session_assigns_and_rewrites_end_to_end`.

- [ ] **Step 7: Run everything**

Run: `cargo test --workspace`
Expected: PASS.

Run: `cargo clippy --workspace --all-targets -- -D warnings`
Expected: exit 0.

Run: `bash scripts/verify-gate.sh`
Expected: exit 0, six verdicts unchanged.

- [ ] **Step 8: Commit**

```bash
but diff
but commit feat/attribution-spine -m "feat(orchestrate): drive attribution across the run lifecycle

execute_run takes an optional attribution session: it registers the
target's tap after steady and before the gadgets attach, drives the
lifecycle state, deregisters at teardown, rewrites labels.vm_id from the
dense handle to the ULID, and returns the provenance for capture_meta.
Attribution enabled against a target with no tap is a config error rather
than a silent no-op. The pipeline passes None until the pause/resume hook
lands." --changes <ids>
```

---

## Self-Review

**Spec coverage:**
- Shared map ABI (name, type, key, `vm_ctx` layout, lifecycle bytes): Task 2 Step 3 (`VmCtx`, `create_and_pin`), pinned by the layout test in Step 1, documented in the README (Step 5) and the Global Constraints.
- `capture/netattrib` create/pin/serve/fragment, stale-pin error, CLI: Task 2 (all steps).
- Control protocol `add`/`state`/`remove` with `ok`/`err` replies: Task 2 (owner side, Steps 1 and 3), Task 3 (client side, Steps 1 and 3).
- Orchestrator control channel and map lifecycle: Task 3 (`ControlClient`), Task 5 (`AttributionSession`, driven in `execute_run`).
- `net_attribution` SPI defaulted to `None`: Task 3 Step 4.
- Firecracker tap create/configure/ifindex/teardown, gated by config: Task 4 (all steps), documented in Step 7.
- Dense handle plus ULID, decimal handle rendering, handle-to-ULID rewrite, unknown-handle surfacing: Task 1 (table, `rewrite_vm_id_labels`, tests), Task 5 (end-to-end test and wiring).
- `guest_mac` derivation (`02:` locally administered, from the handle): Task 1 (`guest_mac_for`, test), used by Task 4.
- `capture_meta.vm_attribution` provenance: Task 1 (`provenance_json`), Task 5 (attached to `RunArtifacts`).
- Lifecycle ordering (owner before signal gadgets; register after steady, before gadgets attach; remove at teardown): Task 5 Step 4.
- Tap-without-owner is a config error: Task 5 Step 4 (the `None` arm returns an error).
- Core stays BTF-free, gadget excluded from the workspace: Task 2 Steps 6 and 7 (`exclude`, `cargo build --workspace` check), and the Global Constraints.
- Gadget registered in lint and release paths: Task 2 Step 6.
- Spec item deliberately deferred, with the deferral written into the plan: driving the session from a def flag in the A/B pipeline. Task 5 Step 5 passes `None` and says why (it belongs with sub-project 3's pause/resume hook). The spec's step 4 in "Lifecycle and ordering" already marks the pause states as sub-project 3's work, so this matches.
- One reconciliation against the spec, recorded here rather than left implicit: the spec said the adapter would resolve the tap `ifindex` "via rtnetlink (a netlink `RTM_GETLINK` by name, no shelling out to `ip`)". The adapter is uniformly `Shell`-based (curl, taskset, fusermount), and its whole test strategy is the fake `Shell`, so Task 4 reads `/sys/class/net/<tap>/ifindex` through `sh.run` instead. Same value, no new dependency, and it stays testable here. The spec's rtnetlink wording is superseded on that one point.

**Placeholder scan:** none. Every code step carries the code to write. `<...-id>`/`<ids>` in commit commands are change ids the executor reads from `but diff` at that step.

**Type consistency:** `HandleTable::assign(vm_id, tap, ifindex, netns_inum) -> u64` (Task 1) is what `AttributionSession::register` calls (Task 5). `guest_mac_for(u64)` (Task 1) is used by Task 4's constructor. `LIFECYCLE_*` (Task 1) feed `state_name` (Task 3) and the `set_state` call (Task 5); the gadget declares its own copies (Task 2) because it is a separate crate, and the layout test plus the shared-ABI constraint keep them in step. `NetAttribution { tap, ifindex, guest_mac, netns_inum }` (Task 3 Step 4) is exactly what Task 4 returns and what Task 5 destructures. `rewrite_vm_id_labels(&mut [Fragment], &HandleTable) -> Vec<String>` (Task 1) is called with those types in Task 5. `execute_run`'s sixth parameter is `Option<&mut AttributionSession>` in Task 5 Step 4 and both call sites pass `None` in Step 5.

**Scope:** five tasks, each independently testable. Tasks 1, 3, 4, 5 run entirely on this host; Task 2 needs a libbpf host for its own suite and says so at every step where it matters.
