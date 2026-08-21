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

`netns_inum` is the inode of the network namespace the device lives in. The
orchestrator's firecracker adapter always sends `0`: the tap is created in the
host namespace, not a per-VM one, so the field is there for a cross-check by the
signal gadgets rather than as a lookup key. A future adapter that does put the
tap in its own namespace fills it in without a map change.

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
- SIGTERM and SIGINT end the window early and still unpin and remove the socket,
  so a ctrl-C or a harness kill does not leave a pin that hard-fails every later
  run. A SIGKILL or a hard crash does, and needs the manual `rm` above.
- Needs `CAP_BPF`/`CAP_SYS_ADMIN` to create and pin a map, and a mounted bpffs.
