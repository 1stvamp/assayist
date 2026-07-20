// SPDX-FileCopyrightText: 2026 Wesley Mason (1stvamp)
// SPDX-License-Identifier: Apache-2.0
// Assayist tap/virtio-net capture gadget, userspace side. Emits an AssayRun fragment.

use std::ffi::{c_void, CString};
use std::fs;
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
use std::time::Instant;

use anyhow::{bail, Context, Result};
use clap::Parser;
use libbpf_rs::skel::{OpenSkel, SkelBuilder};
use libbpf_rs::{MapCore, TcHookBuilder, TC_EGRESS};
use serde_json::{json, Value};

mod net_skel {
    include!(concat!(env!("OUT_DIR"), "/net.skel.rs"));
}
use net_skel::*;

const SIZE_BUCKETS: usize = 8;
// Must match net.h.
const SIZE_BOUNDS: [u32; 7] = [64, 128, 256, 512, 1024, 1500, 9000];

#[derive(Parser, Debug)]
#[command(name = "assayist-capture-net")]
#[command(about = "Host-side tap/virtio-net capture, emits an AssayRun fragment")]
struct Args {
    #[arg(long, default_value_t = 30)]
    duration: u64,

    /// Interface name prefix to match (e.g. "tap", "fc-"). Repeatable via commas.
    #[arg(long, default_value = "tap")]
    iface_prefix: String,

    /// Explicit interfaces to attach to (repeatable). Overrides prefix matching.
    #[arg(long)]
    iface: Vec<String>,

    /// Also attach tc egress (guest ingress). Off by default.
    #[arg(long, default_value_t = false)]
    tx: bool,

    #[arg(long, default_value_t = 10000)]
    max_keys: u64,

    #[arg(long, default_value_t = 0.01)]
    budget: f64,

    #[arg(long, default_value = "-")]
    out: String,
}

fn enable_run_time_stats() -> Result<OwnedFd> {
    let fd = unsafe { libbpf_sys::bpf_enable_stats(libbpf_sys::BPF_STATS_RUN_TIME) };
    if fd < 0 {
        bail!("bpf_enable_stats(RUN_TIME) failed (need CAP_BPF/CAP_SYS_ADMIN, kernel >= 5.8)");
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn prog_run_stats(fd: i32) -> Result<(u64, u64)> {
    let mut info: libbpf_sys::bpf_prog_info = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libbpf_sys::bpf_prog_info>() as u32;
    let ret = unsafe {
        libbpf_sys::bpf_obj_get_info_by_fd(fd, &mut info as *mut _ as *mut c_void, &mut len)
    };
    if ret != 0 {
        bail!("bpf_obj_get_info_by_fd failed: {ret}");
    }
    Ok((info.run_time_ns, info.run_cnt))
}

fn probe_cost(probe_id: &str, attach_kind: &str, fd: i32, wall_ns: u64, budget: f64) -> Result<Value> {
    let (run_time_ns, run_cnt) = prog_run_stats(fd)?;
    let mean_ns = if run_cnt > 0 { run_time_ns as f64 / run_cnt as f64 } else { 0.0 };
    let steady = if wall_ns > 0 { run_time_ns as f64 / wall_ns as f64 } else { 0.0 };
    Ok(json!({
        "probe_id": probe_id,
        "attach_kind": attach_kind,
        "run_time_ns": run_time_ns,
        "run_cnt": run_cnt,
        "mean_ns": mean_ns,
        "steady_cpu_fraction": steady,
        "over_budget": steady > budget,
        "hot_path": true,
    }))
}

fn if_nametoindex(name: &str) -> Option<u32> {
    let c = CString::new(name).ok()?;
    let idx = unsafe { libc::if_nametoindex(c.as_ptr()) };
    if idx == 0 {
        None
    } else {
        Some(idx)
    }
}

fn if_indextoname(idx: u32) -> String {
    let mut buf = [0u8; libc::IF_NAMESIZE];
    let p = unsafe { libc::if_indextoname(idx, buf.as_mut_ptr() as *mut libc::c_char) };
    if p.is_null() {
        return format!("if{idx}");
    }
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end]).into_owned()
}

/// Resolve the target interface set: explicit list if given, else every
/// interface whose name starts with one of the prefixes.
fn target_ifaces(args: &Args) -> Result<Vec<u32>> {
    if !args.iface.is_empty() {
        let mut v = Vec::new();
        for name in &args.iface {
            match if_nametoindex(name) {
                Some(i) => v.push(i),
                None => bail!("interface not found: {name}"),
            }
        }
        return Ok(v);
    }
    let prefixes: Vec<&str> = args.iface_prefix.split(',').map(|s| s.trim()).collect();
    let mut v = Vec::new();
    for entry in fs::read_dir("/sys/class/net").context("listing /sys/class/net")? {
        let name = entry?.file_name().to_string_lossy().into_owned();
        if prefixes.iter().any(|p| !p.is_empty() && name.starts_with(p)) {
            if let Some(i) = if_nametoindex(&name) {
                v.push(i);
            }
        }
    }
    if v.is_empty() {
        bail!("no interfaces matched prefix '{}'", args.iface_prefix);
    }
    Ok(v)
}

fn parse_if_stat(bytes: &[u8]) -> (u64, u64, u64, u64, [u32; SIZE_BUCKETS], [u32; SIZE_BUCKETS]) {
    // struct if_stat { u64 rx_packets, rx_bytes, tx_packets, tx_bytes;
    //                  u32 rx_size[8]; u32 tx_size[8]; }
    let rd_u64 = |o: usize| u64::from_ne_bytes(bytes[o..o + 8].try_into().unwrap());
    let rx_packets = rd_u64(0);
    let rx_bytes = rd_u64(8);
    let tx_packets = rd_u64(16);
    let tx_bytes = rd_u64(24);
    let mut rx_size = [0u32; SIZE_BUCKETS];
    let mut tx_size = [0u32; SIZE_BUCKETS];
    let base = 32;
    for (i, slot) in rx_size.iter_mut().enumerate() {
        let o = base + i * 4;
        *slot = u32::from_ne_bytes(bytes[o..o + 4].try_into().unwrap());
    }
    let base2 = base + SIZE_BUCKETS * 4;
    for (i, slot) in tx_size.iter_mut().enumerate() {
        let o = base2 + i * 4;
        *slot = u32::from_ne_bytes(bytes[o..o + 4].try_into().unwrap());
    }
    (rx_packets, rx_bytes, tx_packets, tx_bytes, rx_size, tx_size)
}

fn main() -> Result<()> {
    let args = Args::parse();
    let ifaces = target_ifaces(&args)?;
    let _stats_fd = enable_run_time_stats().context("enabling BPF run-time stats")?;

    let skel_builder = NetSkelBuilder::default();
    let mut open_object = MaybeUninit::uninit();
    let open_skel = skel_builder.open(&mut open_object)?;
    let skel = open_skel.load().context("loading eBPF object")?;

    // Attach XDP (RX) to every target interface, sharing the one stats map.
    let mut _xdp_links = Vec::new();
    for &idx in &ifaces {
        let link = skel
            .progs
            .tap_rx
            .attach_xdp(idx as i32)
            .with_context(|| format!("attach_xdp on ifindex {idx}"))?;
        _xdp_links.push(link);
    }

    // Optional tc egress (TX). Sets up clsact and attaches on each interface.
    let mut tc_hooks = Vec::new();
    if args.tx {
        for &idx in &ifaces {
            let mut hook = TcHookBuilder::new(skel.progs.tap_tx.as_fd())
                .ifindex(idx as i32)
                .replace(true)
                .handle(1)
                .priority(1)
                .hook(TC_EGRESS);
            hook.create().ok(); // clsact may already exist; ignore
            hook.attach().with_context(|| format!("tc egress attach on ifindex {idx}"))?;
            tc_hooks.push(hook);
        }
    }

    let start = Instant::now();
    std::thread::sleep(std::time::Duration::from_secs(args.duration));
    let wall_ns = start.elapsed().as_nanos() as u64;

    let card = json!({ "class": "bounded", "key_source": "netdev", "max_keys": args.max_keys });
    let bounds: Vec<u32> = SIZE_BOUNDS.to_vec();

    let mut series: Vec<Value> = Vec::new();
    let stats = &skel.maps.stats;
    for key in stats.keys() {
        let val = match stats.lookup(&key, libbpf_rs::MapFlags::ANY)? {
            Some(v) => v,
            None => continue,
        };
        let ifindex = u32::from_ne_bytes(key[0..4].try_into().unwrap());
        let name = if_indextoname(ifindex);
        let (rxp, rxb, txp, txb, rx_size, tx_size) = parse_if_stat(&val);

        let mut push_dir = |dir: &str, pkts: u64, byts: u64, size: &[u32; SIZE_BUCKETS]| {
            if pkts == 0 {
                return;
            }
            series.push(json!({
                "name": format!("net.tap_{dir}_packets"),
                "unit": "1", "kind": "counter", "source": if dir == "rx" { "tap_rx" } else { "tap_tx" },
                "key": name, "cardinality": card,
                "data": { "value": pkts, "start_unix_nano": 0 }
            }));
            series.push(json!({
                "name": format!("net.tap_{dir}_bytes"),
                "unit": "By", "kind": "counter", "source": if dir == "rx" { "tap_rx" } else { "tap_tx" },
                "key": name, "cardinality": card,
                "data": { "value": byts, "start_unix_nano": 0 }
            }));
            let count: u64 = size.iter().map(|&v| v as u64).sum();
            series.push(json!({
                "name": format!("net.tap_{dir}_packet_size"),
                "unit": "By", "kind": "histogram", "source": if dir == "rx" { "tap_rx" } else { "tap_tx" },
                "key": name, "cardinality": card,
                "data": { "layout": "explicit", "explicit_bounds": bounds, "buckets": size.to_vec(), "count": count }
            }));
        };

        push_dir("rx", rxp, rxb, &rx_size);
        if args.tx {
            push_dir("tx", txp, txb, &tx_size);
        }
    }

    let mut self_metrics = vec![probe_cost(
        "tap_rx", "xdp",
        skel.progs.tap_rx.as_fd().as_raw_fd(), wall_ns, args.budget,
    )?];
    if args.tx {
        self_metrics.push(probe_cost(
            "tap_tx", "tc",
            skel.progs.tap_tx.as_fd().as_raw_fd(), wall_ns, args.budget,
        )?);
    }

    let fragment = json!({
        "series": series,
        "self_metrics": self_metrics,
        "capture_meta": {
            "gadget": "assayist-capture-net",
            "window_ns": wall_ns,
            "interfaces": ifaces.iter().map(|&i| if_indextoname(i)).collect::<Vec<_>>(),
            "tx_enabled": args.tx,
        }
    });

    let text = serde_json::to_string_pretty(&fragment)?;
    if args.out == "-" {
        println!("{text}");
    } else {
        fs::write(&args.out, text).with_context(|| format!("writing {}", args.out))?;
    }
    Ok(())
}
