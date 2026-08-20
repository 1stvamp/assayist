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

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
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

/// Width of the map value on the wire. Derived from the struct rather than
/// written out, so a layout change is a compile error here and in `create`'s
/// `value_size` instead of a runtime size mismatch against the kernel.
const VM_CTX_BYTES: usize = std::mem::size_of::<VmCtx>();

impl VmCtx {
    fn as_bytes(&self) -> [u8; VM_CTX_BYTES] {
        let mut b = [0u8; VM_CTX_BYTES];
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
    // `sz` is libbpf's opts-struct versioning field, and its userspace
    // OPTS_VALID check rejects a zero one before any syscall is made, so a
    // `Default::default()` here fails every run with "bpf_map_create_opts size
    // (0) is too small". Every other field stays at its default.
    let opts = libbpf_sys::bpf_map_create_opts {
        sz: std::mem::size_of::<libbpf_sys::bpf_map_create_opts>() as libbpf_sys::size_t,
        ..Default::default()
    };
    let mut map = MapHandle::create(
        MapType::Hash,
        Some("vm_by_ifindex"),
        std::mem::size_of::<u32>() as u32,
        std::mem::size_of::<VmCtx>() as u32,
        max_vms,
        &opts,
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

/// Set by the SIGTERM/SIGINT handler. Checked by the serve loop so a ctrl-C or
/// a harness kill leaves through the normal cleanup path.
static SHUTDOWN: AtomicBool = AtomicBool::new(false);

extern "C" fn on_signal(_sig: libc::c_int) {
    SHUTDOWN.store(true, Ordering::SeqCst);
}

/// Handle SIGTERM/SIGINT rather than dying on them: the default disposition
/// would leave the pin and the control socket behind, and the stale-pin policy
/// then hard-fails every later run until someone removes the pin by hand. A
/// relaxed store is all the handler does, which is async-signal-safe.
fn install_signal_handlers() {
    unsafe {
        let h = on_signal as *const () as libc::sighandler_t;
        libc::signal(libc::SIGTERM, h);
        libc::signal(libc::SIGINT, h);
    }
}

/// Serve control commands until the window closes. One reply line per command,
/// so a slow owner applies backpressure rather than dropping updates. The
/// listener is non-blocking and polled, because the window is what ends the run,
/// not the peer closing.
fn serve(listener: &UnixListener, map: &MapHandle, stats: &mut Stats, deadline: Instant) {
    listener.set_nonblocking(true).ok();
    let mut peers: Vec<BufReader<UnixStream>> = Vec::new();
    while Instant::now() < deadline && !SHUTDOWN.load(Ordering::SeqCst) {
        // Only an idle iteration sleeps. Sleeping unconditionally put a ~10ms
        // floor under every request/reply command, on the critical path between
        // steady and the signal gadgets attaching.
        let mut worked = false;
        match listener.accept() {
            Ok((s, _)) => {
                s.set_nonblocking(false).ok();
                s.set_read_timeout(Some(Duration::from_millis(50))).ok();
                peers.push(BufReader::new(s));
                worked = true;
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
                    worked = true;
                }
                Err(_) => continue,
            }
        }
        if !worked {
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

fn main() -> Result<()> {
    let args = Args::parse();

    install_signal_handlers();
    let mut map = create_and_pin(&args.attrib_map, args.max_vms)?;
    let _ = std::fs::remove_file(&args.control);
    let listener = match UnixListener::bind(&args.control)
        .with_context(|| format!("binding control socket {}", args.control))
    {
        Ok(l) => l,
        Err(e) => {
            // A failed bind is a mundane config error (bad path, permission
            // denied), not a crashed prior run: unpin so the stale-pin check
            // stays reserved for actual crashes, not a bind typo.
            let _ = map.unpin(&args.attrib_map);
            return Err(e);
        }
    };

    let start = Instant::now();
    let mut stats = Stats::default();
    serve(&listener, &map, &mut stats, start + Duration::from_secs(args.duration));
    let window_ns = start.elapsed().as_nanos() as u64;

    // Release the pin and the socket: the next run creates its own, and a left
    // pin would make that run fail with the stale-pin error. A SIGTERM/SIGINT
    // shutdown falls through here too, so a ctrl-C still writes the fragment for
    // the window it did serve.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vm_ctx_layout_matches_the_shared_abi() {
        // Fixed by the spec: u64 + u32 + u8 + 3 pad = 16 bytes, 8-aligned.
        // Sub-project 4's eBPF programs declare the same struct, so a silent
        // layout change here would silently corrupt their reads. Size and
        // alignment alone would not catch it: swapping netns_inum with
        // lifecycle_state plus its padding keeps both.
        assert_eq!(std::mem::size_of::<VmCtx>(), 16);
        assert_eq!(std::mem::align_of::<VmCtx>(), 8);
        assert_eq!(std::mem::offset_of!(VmCtx, vm_id), 0);
        assert_eq!(std::mem::offset_of!(VmCtx, netns_inum), 8);
        assert_eq!(std::mem::offset_of!(VmCtx, lifecycle_state), 12);
        assert_eq!(std::mem::offset_of!(VmCtx, _pad), 13);
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

    /// The real map, end to end: create, pin, apply each command, check the
    /// bytes the signal gadgets will read, unpin. This is the coverage a pure
    /// unit suite cannot give, because `MapHandle::create` validates its opts in
    /// userspace and then makes a syscall, and both can fail on their own.
    ///
    /// Needs root (CAP_BPF/CAP_SYS_ADMIN) and a mounted bpffs, so it is ignored
    /// by default. Run it with:
    ///   sudo -E cargo test --manifest-path capture/netattrib/Cargo.toml -- --ignored
    #[test]
    #[ignore = "needs root and a mounted bpffs"]
    fn create_pin_apply_and_unpin_against_a_real_map() {
        let dir = format!("/sys/fs/bpf/assayist-test-{}", std::process::id());
        let pin = format!("{dir}/vm_by_ifindex");
        let mut map = create_and_pin(&pin, 16).expect("create and pin");
        assert!(Path::new(&pin).exists(), "the pin must exist after create_and_pin");

        let mut stats = Stats::default();
        apply(&map, &Command::Add { ifindex: 11, handle: 3, netns_inum: 4026531840 }, &mut stats)
            .expect("add");
        let key = 11u32.to_ne_bytes();
        let got = map.lookup(&key, MapFlags::ANY).expect("lookup").expect("entry present");
        assert_eq!(
            got,
            VmCtx {
                vm_id: 3,
                netns_inum: 4026531840,
                lifecycle_state: LIFECYCLE_RUNNING,
                _pad: [0; 3],
            }
            .as_bytes()
        );

        apply(&map, &Command::State { handle: 3, state: LIFECYCLE_PAUSED }, &mut stats)
            .expect("state");
        let got = map.lookup(&key, MapFlags::ANY).expect("lookup").expect("entry present");
        assert_eq!(VmCtx::from_bytes(&got).lifecycle_state, LIFECYCLE_PAUSED);
        assert_eq!(VmCtx::from_bytes(&got).vm_id, 3, "state must not disturb the handle");

        apply(&map, &Command::Remove { handle: 3 }, &mut stats).expect("remove");
        assert!(map.lookup(&key, MapFlags::ANY).expect("lookup").is_none());
        assert_eq!((stats.adds, stats.states, stats.removes), (1, 1, 1));
        assert_eq!((stats.peak_live, stats.final_live), (1, 0));

        map.unpin(&pin).expect("unpin");
        assert!(!Path::new(&pin).exists(), "unpin must remove the pin");
        let _ = std::fs::remove_dir(&dir);
    }
}
