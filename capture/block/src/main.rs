// SPDX-License-Identifier: Apache-2.0
// Assayist block-IO capture gadget, userspace side. Emits an AssayRun fragment.

use std::ffi::c_void;
use std::fs;
use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::time::Instant;

use anyhow::{bail, Context, Result};
use clap::Parser;
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use libbpf_rs::MapCore;
use serde_json::{json, Value};

mod block_skel {
    include!(concat!(env!("OUT_DIR"), "/block.skel.rs"));
}
use block_skel::*;

const MAX_SLOTS: usize = 40;

#[derive(Parser, Debug)]
#[command(name = "assayist-capture-block")]
#[command(about = "Host-side block-IO latency capture, emits an AssayRun fragment")]
struct Args {
    #[arg(long, default_value_t = 30)]
    duration: u64,
    #[arg(long, default_value_t = 256)]
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

fn probe_cost(probe_id: &str, fd: i32, wall_ns: u64, budget: f64) -> Result<Value> {
    let (run_time_ns, run_cnt) = prog_run_stats(fd)?;
    let mean_ns = if run_cnt > 0 { run_time_ns as f64 / run_cnt as f64 } else { 0.0 };
    let steady = if wall_ns > 0 { run_time_ns as f64 / wall_ns as f64 } else { 0.0 };
    Ok(json!({
        "probe_id": probe_id,
        "attach_kind": "tracepoint",
        "run_time_ns": run_time_ns,
        "run_cnt": run_cnt,
        "mean_ns": mean_ns,
        "steady_cpu_fraction": steady,
        "over_budget": steady > budget,
        "hot_path": true,
    }))
}

fn dev_str(dev: u32) -> String {
    // Linux dev_t packing in tracepoints: major = dev >> 20, minor = dev & 0xFFFFF.
    let major = dev >> 20;
    let minor = dev & 0xFFFFF;
    format!("{major}:{minor}")
}

fn parse_blk_key(bytes: &[u8]) -> (u32, bool) {
    // struct blk_key { u32 dev; u8 is_write; u8 _pad[3]; }
    let dev = u32::from_ne_bytes(bytes[0..4].try_into().unwrap());
    let is_write = bytes[4] != 0;
    (dev, is_write)
}

fn parse_blk_stat(bytes: &[u8]) -> ([u32; MAX_SLOTS], u64, u64) {
    // struct blk_stat { u32 slots[40]; u64 bytes; }
    let mut slots = [0u32; MAX_SLOTS];
    let mut count = 0u64;
    for i in 0..MAX_SLOTS {
        let off = i * 4;
        let v = u32::from_ne_bytes(bytes[off..off + 4].try_into().unwrap());
        slots[i] = v;
        count += v as u64;
    }
    let bytes_off = MAX_SLOTS * 4;
    // account for 8-byte alignment of the u64 that follows the u32 array
    let aligned = (bytes_off + 7) & !7;
    let total_bytes = u64::from_ne_bytes(bytes[aligned..aligned + 8].try_into().unwrap());
    (slots, count, total_bytes)
}

fn main() -> Result<()> {
    let args = Args::parse();
    let _stats_fd = enable_run_time_stats().context("enabling BPF run-time stats")?;

    let mut skel_builder = BlockSkelBuilder::default();
    let mut open_object = MaybeUninit::uninit();
    let open_skel = skel_builder.open(&mut open_object)?;
    let mut skel = open_skel.load().context("loading eBPF object")?;
    skel.attach().context("attaching to block tracepoints")?;

    let start = Instant::now();
    std::thread::sleep(std::time::Duration::from_secs(args.duration));
    let wall_ns = start.elapsed().as_nanos() as u64;

    let mut series: Vec<Value> = Vec::new();
    let stats = &skel.maps.stats;
    for key in stats.keys() {
        let val = match stats.lookup(&key, libbpf_rs::MapFlags::ANY)? {
            Some(v) => v,
            None => continue,
        };
        let (dev, is_write) = parse_blk_key(&key);
        let (slots, count, total_bytes) = parse_blk_stat(&val);
        if count == 0 {
            continue;
        }
        let rw = if is_write { "write" } else { "read" };
        let card = json!({ "class": "bounded", "key_source": "device", "max_keys": args.max_keys });

        series.push(json!({
            "name": format!("block.io_latency:{rw}"),
            "unit": "ns",
            "kind": "histogram",
            "source": "block_rq_complete",
            "key": dev_str(dev),
            "cardinality": card,
            "data": { "layout": "log2", "buckets": slots.to_vec(), "count": count }
        }));
        series.push(json!({
            "name": format!("block.io_bytes:{rw}"),
            "unit": "By",
            "kind": "counter",
            "source": "block_rq_complete",
            "key": dev_str(dev),
            "cardinality": card,
            "data": { "value": total_bytes, "start_unix_nano": 0 }
        }));
    }

    let self_metrics = vec![
        probe_cost("block_rq_issue", skel.progs.handle_issue.as_fd().as_raw_fd(), wall_ns, args.budget)?,
        probe_cost("block_rq_complete", skel.progs.handle_complete.as_fd().as_raw_fd(), wall_ns, args.budget)?,
    ];

    let fragment = json!({
        "series": series,
        "self_metrics": self_metrics,
        "capture_meta": {
            "gadget": "assayist-capture-block",
            "window_ns": wall_ns,
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
