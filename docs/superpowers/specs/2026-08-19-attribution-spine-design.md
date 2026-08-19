<!--
SPDX-FileCopyrightText: 2026 Wesley Mason (1stvamp)
SPDX-License-Identifier: Apache-2.0
-->

# Attribution spine (sub-project 2): design

Status: draft, for review. Parent: `docs/superpowers/specs/2026-08-19-network-datapath-gadgets-design.md` (this is sub-project 2, and it depends on sub-project 1, now merged: `MetricSeries.labels` + `vm_id` key_source). Scope was set at "plumbing plus firecracker tap": the attribution map and its control channel, plus real tap networking on the firecracker adapter so a VM has an `ifindex` to attribute on.

## What this delivers

Every network sample later gadgets emit can be tied back to a specific VM and its lifecycle state. Concretely:

1. A shared, bpffs-pinned `vm_by_ifindex` map that later signal gadgets open read-only.
2. A capture-side owner (`capture/netattrib`) that creates and pins the map, applies orchestrator-driven updates, and reports its bookkeeping.
3. A firecracker VM that actually has a host tap device, so there is an `ifindex` to key on.
4. The orchestrator wiring: assign each VM a dense handle plus a ULID, drive the map over a unix-socket control channel across the VM lifecycle, and rewrite `labels.vm_id` from handle to ULID when the run is assembled.

It does not attach datapath probes or measure traffic. That is sub-project 4. The unattributed-traffic rate lives with the signal gadgets that read the datapath; here the owner reports only map occupancy and command bookkeeping.

## Constraints that shape it

- Core builds anywhere with no BTF: the orchestrator still cannot link libbpf. All BPF-adjacent code stays in `capture/*`. The orchestrator drives the owner over a unix socket and never touches a map.
- `capture/netattrib` creates and pins the map from userspace via libbpf-rs, with no `.bpf.c` object, no CO-RE, no `vmlinux.h`. So it needs a libbpf + bpftool host but not kernel BTF: it is the lightest gadget in the set. Its map value layout is the shared ABI that sub-project 4's `.bpf.c` programs must match byte for byte.
- Tap creation and rtnetlink need `CAP_NET_ADMIN`; the run already runs privileged for eBPF. Tap setup is gated behind a config key so existing no-network defs are untouched.
- Density is the target: the map and control channel handle N concurrent VMs (`FanoutTarget`), each with its own tap and `ifindex`.

## The shared map ABI

```
map name:    vm_by_ifindex
type:        BPF_MAP_TYPE_HASH
max_entries: --max-vms (bounded; the cardinality ceiling)
key:         u32 ifindex
value:       struct vm_ctx {
                 u64 vm_id;            // dense per-run handle, NOT the ULID
                 u32 netns_inum;
                 u8  lifecycle_state;  // 0 RUNNING, 1 PAUSING, 2 PAUSED, 3 RESUMING
                 u8  _pad[3];
             }
```

`netattrib` creates and pins this. Sub-project 4 `.bpf.c` programs declare a matching `struct vm_ctx` and open the pin by path (`BPF_F_...` pinned map). The struct layout, map name, and type are the ABI; changing any of them is a breaking change to the gadget set, so they are fixed here.

`vm_id` in the map is the dense handle, not the ULID. Kernel maps and series stay small; the orchestrator holds the handle to ULID table and does the translation at assemble (see "Handle, ULID, and the label rewrite").

## Component 1: `capture/netattrib`

A privileged owner gadget, pure userspace over libbpf-rs.

- Creates `vm_by_ifindex` with `max_entries = --max-vms`, pins it at `--attrib-map` (default `/sys/fs/bpf/assayist/vm_by_ifindex`). If the pin already exists it is an error (a stale pin from a crashed run is surfaced, not silently reused).
- Listens on a unix `SOCK_STREAM` at `--control` for line-delimited ASCII commands, one per line, each acknowledged:
  - `add <ifindex> <handle> <netns_inum>` inserts or replaces the entry, state RUNNING. Reply `ok` or `err <msg>`.
  - `state <handle> <RUNNING|PAUSING|PAUSED|RESUMING>` updates the state byte of the entry whose value has that handle. Reply `ok`/`err`.
  - `remove <handle>` deletes the entry. Reply `ok`/`err`.
- Runs for `--duration` (the shared capture window) while servicing the socket, then writes an AssayRun fragment to `--out`: `capture_meta` with map occupancy over the window (peak and final live handles), a count of each command applied, and any command errors. Its `series` are empty (no datapath probes); its `self_metrics` are empty (no eBPF programs to cost).

CLI: `--duration`, `--out`, `--attrib-map`, `--control`, `--max-vms`.

Limits: no datapath probes, so it cannot report an unattributed-traffic rate; that is sub-project 4's job off the same pinned map. It trusts the orchestrator's `add` values (it does not verify an `ifindex` names a real device). A `state`/`remove` for an unknown handle is an `err` reply and a counted error, not a fatal.

## Component 2: `crates/orchestrate/src/netattrib.rs`

The control-channel client and map lifecycle. Builds and tests on any host against a fake socket peer.

- Spawns `netattrib` before the capture window opens, waits for the control socket to appear (bounded retry), connects.
- Assigns each VM a dense `u64` handle (a per-run counter) and keeps a `handle -> VmProvenance { vm_id: Ulid, tap, guest_mac, ifindex, netns_inum }` table.
- Sends `add` when a VM's tap exists and its `ifindex` is known, `state RUNNING` at steady, `state PAUSING/PAUSED/RESUMING` when sub-project 3 drives a pause, `remove` at teardown. Every command is request/reply, so a slow owner applies backpressure rather than dropping.
- On window close, stops the owner and reads its fragment.

A new optional method on the `Target` trait (`adapter.rs`) exposes a target's tap identity without pulling the control channel into the adapter:

```rust
struct NetAttribution { tap: String, ifindex: u32, guest_mac: String, netns_inum: u32 }
fn net_attribution(&self, _sh: &dyn Shell) -> Option<NetAttribution> { None }  // default
```

The firecracker target returns `Some(..)` once its tap exists; every other target keeps the `None` default. The run driver, when attribution is enabled, reads it and drives the handle assignment and control commands. The adapter stays free of BPF and sockets.

Limits: attribution is only as fresh as the last command. A tap recreated mid-run without a re-`add` shows as unattributed until re-added. The handle space is per-run; handles are not stable across runs (the ULID is).

## Component 3: firecracker tap networking (`native.rs`)

Slots into the existing lifecycle, which already PUTs `/machine-config`, `/boot-source`, `/drives/rootfs` via the `api()` helper and tears down through `teardown()`.

- `provision()`: after the drive is configured, create a host tap named deterministically per instance (e.g. `asy<run-short>-<n>`), bring it up, and PUT `/network-interfaces/eth0` with `host_dev_name` and a deterministic `guest_mac` derived from the handle. Resolve the tap `ifindex` via rtnetlink (a netlink `RTM_GETLINK` by name, no shelling out to `ip`).
- `teardown()`: delete the tap after the VM is gone.
- Gated behind a config key (`network: tap` or similar). Absent, the adapter behaves exactly as today: no tap, `net_attribution()` returns `None`.

Concurrency: each `FanoutTarget` inner instance owns its own tap; names are unique per instance so N VMs do not collide.

Limits: tap only (the recommended Phase 0 backend); netkit and AF_XDP are the blocked arms in later sub-projects. No in-guest configuration of the interface is done here beyond handing Firecracker the device; the guest image is expected to bring the interface up. Bridging or routing the tap to a real network is out of scope: the tap exists so there is an attributable `ifindex` and a datapath for sub-project 4 to instrument, not to give the VM internet.

## Handle, ULID, and the label rewrite

- The orchestrator assigns each VM a per-VM `Ulid` (self-describing, stable in the output) and a dense `u64` handle (cheap in kernel maps and series).
- Kernel maps and every gadget fragment use the handle: sub-project 4 series carry `labels.vm_id = "<handle>"`.
- At assemble, before grading, the orchestrator rewrites `labels.vm_id` across all fragments from handle to ULID using its table. This is a pure function over the fragment list and the table, and it is where most of this sub-project's here-testable value sits:

```rust
fn rewrite_vm_id_labels(fragments: &mut [Fragment], handle_to_ulid: &BTreeMap<u64, String>);
```

A series whose `labels.vm_id` is a handle with no table entry is left as-is and flagged in `capture_meta` (a handle the orchestrator never issued means a stale map, worth surfacing).

- The AssayRun records the full table as additive `capture_meta.vm_attribution`: an array of `{ handle, vm_id (ULID), tap, guest_mac, ifindex, netns_inum }`. This is the provenance that makes a dense-handle run self-describing after the fact.

Limits: the rewrite is string-keyed on the handle rendering, so the gadget and the orchestrator must agree on how a handle is rendered (decimal, no padding). That agreement is part of the ABI and is asserted by a round-trip test.

## Lifecycle and ordering

1. Run driver opens the attribution phase: spawn `netattrib`, connect the control channel. This happens before the signal gadgets attach, so the pinned map exists when they open it.
2. Each firecracker VM provisions: tap created, `ifindex` resolved, `net_attribution()` now `Some`. The driver assigns a handle, records provenance, sends `add`.
3. At steady state: `state RUNNING`.
4. Sub-project 3 later drives `state PAUSING/PAUSED/RESUMING` around a pause; not implemented here, but the command path is.
5. Teardown: `remove <handle>`, delete tap.
6. Window closes: stop `netattrib`, read its fragment, rewrite labels at assemble, attach `vm_attribution` provenance.

## What is testable here vs on a BTF host

Here (any host, `cargo test`):
- The control-channel protocol and client: framing, request/reply, backpressure, error replies, against a fake unix-socket peer.
- Handle assignment and the `handle -> provenance` table.
- `rewrite_vm_id_labels`: handle to ULID across fragments, including the unknown-handle passthrough-and-flag path.
- The firecracker tap command sequence via the fake `Shell`: `/network-interfaces` PUT with the right `host_dev_name`/`guest_mac`, tap create on provision, tap delete on teardown, and the no-network default (no tap, `net_attribution() == None`).
- rtnetlink `ifindex`-by-name resolution (unit test against a known loopback or a created dummy link where permitted; otherwise a parser test over a captured netlink reply).

BTF/libbpf host (the gadget's own suite):
- `netattrib` creating and pinning the real map, applying `add/state/remove` over the socket, and a sub-project-4-style reader opening the pin and seeing the entries.

## Contract touchpoints

Additive only, no schema change beyond sub-project 1:
- `capture_meta.vm_attribution`: the handle to ULID/tap/mac provenance array (owner fragment and assembled run).
- Reuse of `labels.vm_id` from sub-project 1; the value is a handle in raw fragments and a ULID after the rewrite.

## Open decisions for review

1. Handle rendering in labels: decimal string of a `u64` (leaning this, simplest ABI) vs hex. Whichever, it is fixed as ABI and round-trip tested.
2. `guest_mac` derivation: a locally-administered MAC from the handle (`02:...`), so it is deterministic and collision-free per run. Confirm the prefix.
3. Stale-pin policy: error on an existing pin (leaning this, surfaces a crashed prior run) vs reclaim it. A reclaim hides a real problem, so the default is to error and let the operator clear it.
4. Whether `net_attribution()` returning `Some` should also imply the run driver requires a merged `netattrib` owner (i.e. tap networking without the owner running is a config error, not a silent no-op). Leaning yes: if a VM has a tap for attribution, not running the owner is almost certainly a mistake.
