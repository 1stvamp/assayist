// SPDX-FileCopyrightText: 2026 Wesley Mason (1stvamp)
// SPDX-License-Identifier: Apache-2.0
// Assayist block-IO capture gadget, userspace side. Emits an AssayRun fragment.

use std::ffi::c_void;
use std::fs;
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
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

// Must match block.h. The in-kernel histogram is log-linear: MAX_OCTAVES
// power-of-two octaves, each split into SUBSLOTS linear sub-buckets.
const SUBSLOTS: usize = 4;
const MAX_OCTAVES: usize = 40;
const MAX_SLOTS: usize = MAX_OCTAVES * SUBSLOTS;

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
    /// Emit the full log-linear histogram as an explicit-bounds series
    /// (finer tail, so the gate can grade p99). Default collapses to the
    /// coarse log2 layout, whose quantised percentiles the gate treats as
    /// advisory.
    #[arg(long)]
    hires: bool,
    #[arg(long, default_value = "-")]
    out: String,
}

/// Collapse the log-linear sub-buckets back to `MAX_OCTAVES` log2 slots by
/// summing each octave's `SUBSLOTS`. Produces the same octave counts a plain
/// log2 gadget would, so the default output is unchanged.
fn collapse_to_log2(slots: &[u32; MAX_SLOTS]) -> Vec<u32> {
    let mut octaves = vec![0u32; MAX_OCTAVES];
    for (i, &c) in slots.iter().enumerate() {
        octaves[i / SUBSLOTS] += c;
    }
    octaves
}

/// Upper edges of the log-linear buckets, for the explicit layout. Bucket
/// `s = octave * SUBSLOTS + sub` covers `[2^octave * (1 + sub/SUBSLOTS),
/// 2^octave * (1 + (sub+1)/SUBSLOTS))`, so its upper edge is
/// `2^octave * (1 + (sub+1)/SUBSLOTS)`. The contract's explicit layout wants
/// `len(buckets) - 1` bounds (the last bucket is the open-ended overflow), so
/// this returns `MAX_SLOTS - 1` edges.
fn log_linear_bounds() -> Vec<f64> {
    let mut bounds = Vec::with_capacity(MAX_SLOTS - 1);
    for s in 0..MAX_SLOTS - 1 {
        let octave = (s / SUBSLOTS) as u32;
        let sub = (s % SUBSLOTS) as f64;
        let base = (1u64 << octave) as f64;
        bounds.push(base * (1.0 + (sub + 1.0) / SUBSLOTS as f64));
    }
    bounds
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

        let hist_data = if args.hires {
            json!({
                "layout": "explicit",
                "buckets": slots.to_vec(),
                "explicit_bounds": log_linear_bounds(),
                "count": count
            })
        } else {
            json!({ "layout": "log2", "buckets": collapse_to_log2(&slots), "count": count })
        };
        series.push(json!({
            "name": format!("block.io_latency:{rw}"),
            "unit": "ns",
            "kind": "histogram",
            "source": "block_rq_complete",
            "key": dev_str(dev),
            "cardinality": card,
            "data": hist_data
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collapse_sums_each_octave() {
        let mut slots = [0u32; MAX_SLOTS];
        // octave 3, all four sub-buckets; octave 10, one sub-bucket.
        slots[3 * SUBSLOTS] = 1;
        slots[3 * SUBSLOTS + 1] = 2;
        slots[3 * SUBSLOTS + 2] = 3;
        slots[3 * SUBSLOTS + 3] = 4;
        slots[10 * SUBSLOTS + 2] = 5;
        let oct = collapse_to_log2(&slots);
        assert_eq!(oct.len(), MAX_OCTAVES);
        assert_eq!(oct[3], 10);
        assert_eq!(oct[10], 5);
        assert_eq!(oct.iter().sum::<u32>(), 15);
    }

    #[test]
    fn bounds_len_is_one_less_than_buckets() {
        // The contract's explicit layout wants len(buckets) - 1 bounds.
        assert_eq!(log_linear_bounds().len(), MAX_SLOTS - 1);
    }

    #[test]
    fn bounds_are_monotone_and_finer_than_octaves() {
        let b = log_linear_bounds();
        for w in b.windows(2) {
            assert!(w[1] > w[0], "bounds must strictly increase: {w:?}");
        }
        // Octave 3 spans [8, 16); its four sub-bucket upper edges are 10,12,14,16.
        let base = (1u64 << 3) as f64;
        for sub in 0..SUBSLOTS {
            let s = 3 * SUBSLOTS + sub;
            let want = base * (1.0 + (sub as f64 + 1.0) / SUBSLOTS as f64);
            assert!((b[s] - want).abs() < 1e-9, "bound {s} = {} want {want}", b[s]);
        }
    }
}
