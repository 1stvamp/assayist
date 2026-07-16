// SPDX-License-Identifier: Apache-2.0
// Assayist control-plane capture gadget, userspace side. Emits an AssayRun fragment.

use std::collections::HashMap;
use std::ffi::{c_void, CString};
use std::fs;
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
use std::time::Instant;

use anyhow::{bail, Context, Result};
use clap::Parser;
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use libbpf_rs::{MapCore, MapFlags};
use serde_json::{json, Value};

mod ctrlplane_skel {
    include!(concat!(env!("OUT_DIR"), "/ctrlplane.skel.rs"));
}
use ctrlplane_skel::*;

const MAX_SLOTS: usize = 40;

#[derive(Parser, Debug)]
#[command(name = "assayist-capture-ctrlplane")]
#[command(about = "Host-side scheduler-treatment capture for control-plane pods, emits an AssayRun fragment")]
struct Args {
    #[arg(long, default_value_t = 30)]
    duration: u64,

    /// Component cgroup to watch, as name=/cgroup/path (repeatable).
    /// e.g. --cgroup scheduler=/sys/fs/cgroup/kubepods.slice/.../kube-scheduler
    #[arg(long)]
    cgroup: Vec<String>,

    /// Component cgroup by literal id, as name=ID (repeatable). Escape hatch if
    /// path resolution is unavailable. Get the id from `bpftool cgroup tree`.
    #[arg(long)]
    cgroup_id: Vec<String>,

    #[arg(long, default_value_t = 64)]
    max_keys: u64,

    #[arg(long, default_value_t = 0.02)]
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
        "attach_kind": "tp_btf",
        "run_time_ns": run_time_ns,
        "run_cnt": run_cnt,
        "mean_ns": mean_ns,
        "steady_cpu_fraction": steady,
        "over_budget": steady > budget,
        "hot_path": true,
    }))
}

// Resolve a cgroup v2 directory to the id that bpf_get_current_cgroup_id would
// report, via name_to_handle_at. For cgroup2 (kernfs) the handle's first 8
// bytes are the id. This is the technique bcc/bpftrace tools use.
fn cgroup_id_for_path(path: &str) -> Result<u64> {
    #[repr(C)]
    struct FileHandle {
        handle_bytes: u32,
        handle_type: i32,
        f_handle: [u8; 128],
    }
    let cpath = CString::new(path)?;
    let mut fh = FileHandle {
        handle_bytes: 128,
        handle_type: 0,
        f_handle: [0u8; 128],
    };
    let mut mount_id: i32 = 0;
    let ret = unsafe {
        libc::syscall(
            libc::SYS_name_to_handle_at,
            libc::AT_FDCWD,
            cpath.as_ptr(),
            &mut fh as *mut _,
            &mut mount_id as *mut _,
            0,
        )
    };
    if ret != 0 {
        bail!("name_to_handle_at({path}) failed; is it a cgroup2 dir? try --cgroup-id");
    }
    Ok(u64::from_ne_bytes(fh.f_handle[0..8].try_into().unwrap()))
}

/// Parse name=value flags into (name, value) pairs.
fn parse_named(items: &[String]) -> Result<Vec<(String, String)>> {
    let mut v = Vec::new();
    for it in items {
        match it.split_once('=') {
            Some((n, val)) => v.push((n.to_string(), val.to_string())),
            None => bail!("expected name=value, got '{it}'"),
        }
    }
    Ok(v)
}

fn parse_hist(bytes: &[u8]) -> ([u32; MAX_SLOTS], u64) {
    let mut slots = [0u32; MAX_SLOTS];
    let mut count = 0u64;
    for i in 0..MAX_SLOTS {
        let off = i * 4;
        let v = u32::from_ne_bytes(bytes[off..off + 4].try_into().unwrap());
        slots[i] = v;
        count += v as u64;
    }
    (slots, count)
}

fn main() -> Result<()> {
    let args = Args::parse();

    // Build the id -> friendly-name map from both flag styles.
    let mut names: HashMap<u64, String> = HashMap::new();
    for (name, path) in parse_named(&args.cgroup)? {
        let id = cgroup_id_for_path(&path).with_context(|| format!("resolving {name}"))?;
        names.insert(id, name);
    }
    for (name, idstr) in parse_named(&args.cgroup_id)? {
        let id: u64 = idstr.parse().with_context(|| format!("parsing id for {name}"))?;
        names.insert(id, name);
    }
    let filter_enabled = !names.is_empty();
    if !filter_enabled {
        eprintln!("warning: no --cgroup given; capturing all cgroups (high cardinality and cost)");
    }

    let _stats_fd = enable_run_time_stats().context("enabling BPF run-time stats")?;

    let mut skel_builder = CtrlplaneSkelBuilder::default();
    let mut open_object = MaybeUninit::uninit();
    let mut open_skel = skel_builder.open(&mut open_object)?;
    open_skel.maps.rodata_data.filter_enabled = filter_enabled;
    let mut skel = open_skel.load().context("loading eBPF object")?;

    // Populate the allow-list before attaching.
    if filter_enabled {
        for id in names.keys() {
            let k = id.to_ne_bytes();
            let v = [1u8];
            skel.maps.allowed.update(&k, &v, MapFlags::ANY)?;
        }
    }
    skel.attach().context("attaching to sched tracepoints")?;

    let start = Instant::now();
    std::thread::sleep(std::time::Duration::from_secs(args.duration));
    let wall_ns = start.elapsed().as_nanos() as u64;

    let name_for = |id: u64| names.get(&id).cloned().unwrap_or_else(|| id.to_string());
    let card = json!({ "class": "bounded", "key_source": "cgroup_id", "max_keys": args.max_keys });

    let mut series: Vec<Value> = Vec::new();

    // Run-queue latency histograms.
    let runq = &skel.maps.runq;
    for key in runq.keys() {
        let val = match runq.lookup(&key, MapFlags::ANY)? {
            Some(v) => v,
            None => continue,
        };
        let cgid = u64::from_ne_bytes(key[0..8].try_into().unwrap());
        let (slots, count) = parse_hist(&val);
        if count == 0 {
            continue;
        }
        series.push(json!({
            "name": "sched.runqueue_latency",
            "unit": "ns",
            "kind": "histogram",
            "source": "sched_switch",
            "key": name_for(cgid),
            "cardinality": card,
            "data": { "layout": "log2", "buckets": slots.to_vec(), "count": count }
        }));
    }

    // On-CPU time counters.
    let oncpu = &skel.maps.oncpu_ns;
    for key in oncpu.keys() {
        let val = match oncpu.lookup(&key, MapFlags::ANY)? {
            Some(v) => v,
            None => continue,
        };
        let cgid = u64::from_ne_bytes(key[0..8].try_into().unwrap());
        let ns = u64::from_ne_bytes(val[0..8].try_into().unwrap());
        series.push(json!({
            "name": "sched.on_cpu_ns",
            "unit": "ns",
            "kind": "counter",
            "source": "sched_switch",
            "key": name_for(cgid),
            "cardinality": card,
            "data": { "value": ns, "start_unix_nano": 0 }
        }));
    }

    let self_metrics = vec![
        probe_cost("sched_wakeup", skel.progs.on_wakeup.as_fd().as_raw_fd(), wall_ns, args.budget)?,
        probe_cost("sched_wakeup_new", skel.progs.on_wakeup_new.as_fd().as_raw_fd(), wall_ns, args.budget)?,
        probe_cost("sched_switch", skel.progs.on_switch.as_fd().as_raw_fd(), wall_ns, args.budget)?,
    ];

    let fragment = json!({
        "series": series,
        "self_metrics": self_metrics,
        "capture_meta": {
            "gadget": "assayist-capture-ctrlplane",
            "window_ns": wall_ns,
            "filter_enabled": filter_enabled,
            "components": names.values().collect::<Vec<_>>(),
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
