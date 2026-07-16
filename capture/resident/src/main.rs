// SPDX-License-Identifier: Apache-2.0
//! Snapshot residency capture: how much of a snapshot's memory file is resident
//! in the host page cache. It mmaps the file and calls mincore(2) at the end of
//! the window, emitting resident/total pages and the resident fraction as an
//! AssayRun fragment. Unlike the other gadgets it is pure userspace (no eBPF, no
//! BTF), so it builds and runs anywhere.
//!
//! This is the ground-truth working set: how much of the snapshot actually
//! faulted into cache. For a file-backed restore it is the set shared through
//! the page cache (so concurrent instances of one snapshot count it once); a
//! userfaultfd restore that copies pages into each guest's own anonymous memory
//! leaves those copies off the file, so this measures the shared/file residency,
//! not per-guest private memory. It complements the host-memory delta: the delta
//! is the machine cost, this is what the snapshot itself has resident.

use std::fs::{self, File};
use std::os::fd::AsRawFd;
use std::thread::sleep;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use clap::Parser;
use serde_json::json;

#[derive(Parser, Debug)]
#[command(about = "Snapshot residency capture (mincore on a mem file)")]
struct Args {
    /// Capture window in seconds; residency is sampled once at the end.
    #[arg(long, default_value_t = 30)]
    duration: u64,
    /// The snapshot memory file to measure.
    #[arg(long)]
    mem: String,
    /// Output path for the AssayRun fragment JSON. "-" for stdout.
    #[arg(long, default_value = "-")]
    out: String,
}

/// Resident and total page counts for `path`, via mmap + mincore.
fn residency(path: &str) -> Result<(u64, u64, i64)> {
    let file = File::open(path).with_context(|| format!("open {path}"))?;
    let len = file.metadata().with_context(|| format!("stat {path}"))?.len() as usize;
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if page <= 0 {
        bail!("bad page size");
    }
    let page = page as usize;
    if len == 0 {
        return Ok((0, 0, page as i64));
    }
    let pages = len.div_ceil(page);
    // MAP_SHARED so the mapping reflects the file's page-cache residency rather
    // than this process's private faults.
    let addr = unsafe {
        libc::mmap(std::ptr::null_mut(), len, libc::PROT_READ, libc::MAP_SHARED, file.as_raw_fd(), 0)
    };
    if addr == libc::MAP_FAILED {
        bail!("mmap {path}: {}", std::io::Error::last_os_error());
    }
    let mut vec = vec![0u8; pages];
    let rc = unsafe { libc::mincore(addr, len, vec.as_mut_ptr() as *mut _) };
    let err = std::io::Error::last_os_error();
    unsafe { libc::munmap(addr, len) };
    if rc != 0 {
        bail!("mincore {path}: {err}");
    }
    // The residency bit is bit 0 of each byte.
    let resident = vec.iter().filter(|b| *b & 1 == 1).count() as u64;
    Ok((resident, pages as u64, page as i64))
}

fn gauge(name: &str, value: serde_json::Value) -> serde_json::Value {
    json!({
        "name": name,
        "unit": "1",
        "kind": "gauge",
        "source": "resident",
        "cardinality": {"class": "singleton"},
        "data": {"value": value, "time_unix_nano": 0},
    })
}

fn main() -> Result<()> {
    let args = Args::parse();
    let window_ns = args.duration.saturating_mul(1_000_000_000);
    sleep(Duration::from_secs(args.duration));

    let (resident, total, page) = residency(&args.mem)?;
    let fraction = if total > 0 { resident as f64 / total as f64 } else { 0.0 };

    let fragment = json!({
        "series": [
            gauge("resident.snapshot_resident_pages", json!(resident)),
            gauge("resident.snapshot_total_pages", json!(total)),
            gauge("resident.snapshot_fraction", json!(fraction)),
        ],
        "self_metrics": [],
        "capture_meta": {
            "gadget": "assayist-capture-resident",
            "mem": args.mem,
            "page_size": page,
            "window_ns": window_ns,
        },
    });

    let text = serde_json::to_string_pretty(&fragment)?;
    if args.out == "-" {
        println!("{text}");
    } else {
        fs::write(&args.out, text).with_context(|| format!("writing {}", args.out))?;
    }
    Ok(())
}
