// SPDX-License-Identifier: Apache-2.0
//
// Assayist KVM capture gadget, userspace side.
//
// Loads the eBPF object, enables the kernel's BPF run-time counters so the
// gadget can report its own cost, runs for a fixed window, then reads the
// in-kernel histograms and per-program stats and writes an AssayRun fragment
// ({ series, self_metrics }) that the orchestrator merges into a full run.
//
// The bpf object is GPL (tracing helpers require it). This userspace file is
// Apache-2.0. The compiled skeleton is generated at build time by libbpf-cargo.

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

mod kvm_skel {
    include!(concat!(env!("OUT_DIR"), "/kvm.skel.rs"));
}
use kvm_skel::*;

const MAX_SLOTS: usize = 40;

#[derive(Parser, Debug)]
#[command(name = "assayist-capture-kvm")]
#[command(about = "Host-side KVM exit-handling latency capture, emits an AssayRun fragment")]
struct Args {
    /// Capture window in seconds.
    #[arg(long, default_value_t = 30)]
    duration: u64,

    /// Key histograms per guest (by cgroup id). Off = aggregate across guests.
    #[arg(long, default_value_t = false)]
    per_guest: bool,

    /// Cardinality budget: max distinct cgroup keys per reason (density ceiling).
    #[arg(long, default_value_t = 10000)]
    max_keys: u64,

    /// Observer-effect budget as a fraction of one core. Over this => over_budget.
    #[arg(long, default_value_t = 0.01)]
    budget: f64,

    /// Output path for the AssayRun fragment JSON. "-" for stdout.
    #[arg(long, default_value = "-")]
    out: String,
}

// --- raw exit-reason -> name tables (best-effort, numeric fallback) ----------
// Names are a convenience only; the numeric reason is always what the histogram
// is keyed on. Intel (VMX) and AMD (SVM) use different exit-code spaces, so we
// pick the table from the CPU vendor. Unknown codes fall back to reason_<n>.

fn cpu_vendor() -> &'static str {
    match fs::read_to_string("/proc/cpuinfo") {
        Ok(s) if s.contains("AuthenticAMD") => "amd",
        Ok(s) if s.contains("GenuineIntel") => "intel",
        _ => "unknown",
    }
}

fn vmx_reason(r: u32) -> Option<&'static str> {
    Some(match r {
        0 => "EXCEPTION_NMI",
        1 => "EXTERNAL_INTERRUPT",
        2 => "TRIPLE_FAULT",
        7 => "INTERRUPT_WINDOW",
        12 => "HLT",
        18 => "VMCALL",
        28 => "CR_ACCESS",
        30 => "IO_INSTRUCTION",
        31 => "MSR_READ",
        32 => "MSR_WRITE",
        44 => "APIC_ACCESS",
        48 => "EPT_VIOLATION",
        49 => "EPT_MISCONFIG",
        52 => "PREEMPTION_TIMER",
        _ => return None,
    })
}

fn svm_reason(r: u32) -> Option<&'static str> {
    Some(match r {
        0x060 => "INTR",
        0x061 => "NMI",
        0x078 => "HLT",
        0x07b => "IOIO",
        0x07c => "MSR",
        0x081 => "VMMCALL",
        0x400 => "NPF", // nested page fault
        _ => return None,
    })
}

fn reason_name(vendor: &str, r: u32) -> String {
    let named = match vendor {
        "amd" => svm_reason(r),
        "intel" => vmx_reason(r),
        _ => None,
    };
    named.map(|s| s.to_string()).unwrap_or_else(|| format!("reason_{r}"))
}

// --- BPF run-time stats ------------------------------------------------------

/// Enable the kernel's per-program run-time accounting. Returns an fd that must
/// stay open for the counters to keep incrementing; dropping it disables stats.
fn enable_run_time_stats() -> Result<OwnedFd> {
    let fd = unsafe { libbpf_sys::bpf_enable_stats(libbpf_sys::BPF_STATS_RUN_TIME) };
    if fd < 0 {
        bail!("bpf_enable_stats(RUN_TIME) failed (need CAP_BPF/CAP_SYS_ADMIN and kernel >= 5.8)");
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// (run_time_ns, run_cnt) for a loaded program fd.
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

fn probe_cost(
    probe_id: &str,
    fd: i32,
    wall_ns: u64,
    budget: f64,
    hot_path: bool,
) -> Result<Value> {
    let (run_time_ns, run_cnt) = prog_run_stats(fd)?;
    let mean_ns = if run_cnt > 0 {
        run_time_ns as f64 / run_cnt as f64
    } else {
        0.0
    };
    // Fraction of one core spent inside this program over the window.
    let steady = if wall_ns > 0 {
        run_time_ns as f64 / wall_ns as f64
    } else {
        0.0
    };
    Ok(json!({
        "probe_id": probe_id,
        "attach_kind": "tracepoint",
        "run_time_ns": run_time_ns,
        "run_cnt": run_cnt,
        "mean_ns": mean_ns,
        "steady_cpu_fraction": steady,
        "over_budget": steady > budget,
        "hot_path": hot_path,
    }))
}

// --- histogram readout -------------------------------------------------------

fn parse_hist_key(bytes: &[u8]) -> (u64, u32) {
    // struct hist_key { u64 cgroup_id; u32 exit_reason; u32 _pad; }
    let cgroup_id = u64::from_ne_bytes(bytes[0..8].try_into().unwrap());
    let exit_reason = u32::from_ne_bytes(bytes[8..12].try_into().unwrap());
    (cgroup_id, exit_reason)
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
    let vendor = cpu_vendor();

    // Enable self-accounting before load so we capture the whole window.
    let _stats_fd = enable_run_time_stats().context("enabling BPF run-time stats")?;

    let mut skel_builder = KvmSkelBuilder::default();
    let mut open_object = MaybeUninit::uninit();
    let mut open_skel = skel_builder.open(&mut open_object)?;
    open_skel.maps.rodata_data.per_guest = args.per_guest;

    let mut skel = open_skel.load().context("loading eBPF object")?;
    skel.attach().context("attaching to kvm tracepoints")?;

    let start = Instant::now();
    std::thread::sleep(std::time::Duration::from_secs(args.duration));
    let wall_ns = start.elapsed().as_nanos() as u64;

    // Read histograms. One series per (reason) in singleton mode, or per
    // (reason, cgroup) in per-guest mode with cgroup id as the series key.
    let mut series: Vec<Value> = Vec::new();
    let mut overflow = false;
    let hists = &skel.maps.hists;
    let max_entries = hists.info()?.info.max_entries as u64;
    let mut live_keys = 0u64;

    for key in hists.keys() {
        let val = match hists.lookup(&key, libbpf_rs::MapFlags::ANY)? {
            Some(v) => v,
            None => continue,
        };
        live_keys += 1;
        let (cgroup_id, exit_reason) = parse_hist_key(&key);
        let (slots, count) = parse_hist(&val);
        if count == 0 {
            continue;
        }

        let cardinality = if args.per_guest {
            json!({ "class": "bounded", "key_source": "cgroup_id", "max_keys": args.max_keys })
        } else {
            json!({ "class": "singleton" })
        };

        let mut s = json!({
            "name": format!("kvm.exit_handling_latency:{}", reason_name(vendor, exit_reason)),
            "unit": "ns",
            "kind": "histogram",
            "source": "kvm_exit",
            "cardinality": cardinality,
            "data": {
                "layout": "log2",
                "buckets": slots.to_vec(),
                "count": count,
            }
        });
        if args.per_guest {
            s["key"] = json!(cgroup_id.to_string());
        }
        series.push(s);
    }

    // If the map filled, distinct keys pressed against max_entries; flag it so
    // the gate can mark affected metrics contaminated rather than trust a
    // truncated picture.
    if live_keys >= max_entries {
        overflow = true;
    }

    let self_metrics = vec![
        probe_cost("kvm_exit", skel.progs.handle_kvm_exit.as_fd().as_raw_fd(), wall_ns, args.budget, true)?,
        probe_cost("kvm_entry", skel.progs.handle_kvm_entry.as_fd().as_raw_fd(), wall_ns, args.budget, true)?,
    ];

    let fragment = json!({
        "series": series,
        "self_metrics": self_metrics,
        "capture_meta": {
            "gadget": "assayist-capture-kvm",
            "window_ns": wall_ns,
            "cpu_vendor": vendor,
            "per_guest": args.per_guest,
            "cardinality_overflow": overflow,
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
