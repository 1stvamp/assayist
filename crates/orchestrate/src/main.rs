// SPDX-License-Identifier: Apache-2.0
// assayist: the orchestrator. Reads a benchmark def, prepares the host, runs the
// target + workload, fires capture gadgets, assembles graded AssayRuns, and
// hands the A/B groups to the gate.
//
// Subcommands:
//   run     full A/B pipeline: N repeats per group per cell, capture, assemble, gate.
//   capture single capture: fire the gadgets once and assemble one graded run.
//   inspect read-only: parse/validate/expand a def and observe the host.
//
// Host prep applies with `run --apply-prep` (writes governor/SMT/THP via
// `apply_tuning` and refuses the run if readback != requested); without it `run`
// observes the host read-only. With `host_prep.pin_threads` the firecracker
// target pins vCPU threads and records the per-run `pinning_layout`, so a
// fully-prepped, pinned run on an extended-fact host can grade `reproducible`.

mod adapter;
mod capture;
mod def;
mod gate;
mod hostprep;
mod native;
mod run;

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::ExitCode;

use adapter::{Target, Workload};
use assayist_contract::Grade;
use def::BenchmarkDef;

/// Pick a target adapter by name. `firecracker` is the native adapter; anything
/// else falls back to the command adapter (shell templates from the def).
/// `pin_threads` comes from `host_prep`; only the native target acts on it.
fn select_target(def: &BenchmarkDef, vars: BTreeMap<String, String>, pin_threads: bool) -> Box<dyn Target> {
    match def.target.adapter.as_str() {
        "firecracker" => Box::new(native::firecracker_target(&def.target.config, &vars, pin_threads)),
        "qemu" => Box::new(native::qemu_target(&def.target.config, &vars, pin_threads)),
        _ => Box::new(adapter::command_target(def, vars)),
    }
}

/// How many sandboxes to bring up concurrently. `instances` may come from a
/// parameterise cell (so it can be the `compare` axis) or the target config.
fn instances_of(def: &BenchmarkDef, vars: &BTreeMap<String, String>) -> u32 {
    vars.get("instances")
        .cloned()
        .or_else(|| match def.target.config.get("instances") {
            Some(serde_json::Value::String(s)) => Some(s.clone()),
            Some(other) => Some(other.to_string()),
            None => None,
        })
        .and_then(|s| s.parse().ok())
        .unwrap_or(1)
        .max(1)
}

/// Build the run's target. One instance is the plain adapter target; N > 1 wraps
/// N of them (each with a distinct `{instance}` var, so their sockets/dirs do
/// not collide) in a `FanoutTarget`, which is where concurrency lives so every
/// adapter gets it. When pinning is on, each instance gets a distinct `cpu_base`
/// (instance i starts at i * vcpu) so concurrent sandboxes pin to disjoint CPUs;
/// `taskset` fails the run if that would need more CPUs than exist.
fn build_target(def: &BenchmarkDef, vars: BTreeMap<String, String>, pin_threads: bool) -> Box<dyn Target> {
    let n = instances_of(def, &vars);
    if n <= 1 {
        return select_target(def, vars, pin_threads);
    }
    let vcpu: u32 = vars
        .get("vcpu")
        .cloned()
        .or_else(|| match def.target.config.get("vcpu") {
            Some(serde_json::Value::String(s)) => Some(s.clone()),
            Some(other) => Some(other.to_string()),
            None => None,
        })
        .and_then(|s| s.parse().ok())
        .unwrap_or(1)
        .max(1);
    let inners = (0..n)
        .map(|i| {
            let mut v = vars.clone();
            v.insert("instance".to_string(), i.to_string());
            if pin_threads {
                v.insert("cpu_base".to_string(), (i * vcpu).to_string());
            }
            select_target(def, v, pin_threads)
        })
        .collect();
    Box::new(adapter::FanoutTarget::new(inners))
}

/// Pick a workload driver by name. `fio*` and `wrk*` are native adapters;
/// anything else falls back to the command adapter.
fn select_workload(def: &BenchmarkDef, vars: BTreeMap<String, String>) -> Box<dyn Workload> {
    match def.workload.driver.as_str() {
        d if d == "fio" || d.starts_with("fio-") => {
            Box::new(native::fio_workload(&def.workload.config, &vars))
        }
        d if d == "wrk" || d.starts_with("wrk") => {
            Box::new(native::wrk_workload(&def.workload.config, &vars))
        }
        "vsock" => Box::new(native::vsock_workload(&def.workload.config, &vars)),
        _ => Box::new(adapter::command_workload(def, vars)),
    }
}

fn usage() -> ExitCode {
    eprintln!("usage:");
    eprintln!("  assayist run <def.yaml> [--repeat N] [--a-sut SHA] [--b-sut SHA] [--out DIR] [--duration N] [--allow-ungraded] [--apply-prep]");
    eprintln!("      full A/B pipeline: capture N runs per group per cell, assemble, and gate.");
    eprintln!("      --apply-prep writes host tuning to sysfs (needs root); default observes read-only.");
    eprintln!("  assayist capture <def.yaml> [--duration N] [--out PATH] [--sut-sha SHA] [--work-dir DIR]");
    eprintln!("      fire the def's capture gadgets once and assemble one graded AssayRun.");
    eprintln!("  assayist inspect <def.yaml>");
    eprintln!("      parse, validate, expand a def and observe the host (read-only).");
    eprintln!("  assayist export <run.json> [--signal both|traces|metrics] [--out PATH]");
    eprintln!("      transform an assembled AssayRun into OTLP/JSON.");
    eprintln!("  assayist import <otlp.json> [--out PATH]");
    eprintln!("      transform an OTLP/JSON document into an AssayRun (grade: valid).");
    ExitCode::from(64) // EX_USAGE
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("run") => run_cmd(&args[1..]),
        Some("capture") => capture_cmd(&args[1..]),
        Some("inspect") => match args.get(1) {
            Some(path) => inspect(path),
            None => usage(),
        },
        Some("export") => export_cmd(&args[1..]),
        Some("import") => import_cmd(&args[1..]),
        _ => usage(),
    }
}

// ---------------------------------------------------------------------------
// export: AssayRun JSON -> OTLP/JSON.
// ---------------------------------------------------------------------------

fn export_cmd(args: &[String]) -> ExitCode {
    let mut run_path: Option<String> = None;
    let mut signal = "both".to_string();
    let mut out = "-".to_string();
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        let mut next = || {
            i += 1;
            args.get(i).cloned().ok_or_else(|| format!("missing value after {arg}"))
        };
        match arg.as_str() {
            "--signal" => match next() {
                Ok(s) => signal = s,
                Err(e) => {
                    eprintln!("{e}");
                    return usage();
                }
            },
            "--out" => match next() {
                Ok(s) => out = s,
                Err(e) => {
                    eprintln!("{e}");
                    return usage();
                }
            },
            other if other.starts_with("--") => {
                eprintln!("unknown flag {other}");
                return usage();
            }
            other => {
                if run_path.is_some() {
                    eprintln!("unexpected argument {other}");
                    return usage();
                }
                run_path = Some(other.to_string());
            }
        }
        i += 1;
    }
    let Some(path) = run_path else {
        eprintln!("export needs a <run.json> path");
        return usage();
    };

    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("reading {path}: {e}");
            return ExitCode::from(1);
        }
    };
    let run: assayist_contract::AssayRun = match serde_json::from_str(&text) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("parsing AssayRun from {path}: {e}");
            return ExitCode::from(1);
        }
    };

    // Histograms and probe-cost points carry no timestamp in the contract, so
    // stamp export time onto them.
    let now_nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let doc = match signal.as_str() {
        "both" => assayist_otlp::export_at(&run, now_nanos),
        "traces" => assayist_otlp::export_traces(&run),
        "metrics" => assayist_otlp::export_metrics_at(&run, now_nanos),
        other => {
            eprintln!("unknown --signal '{other}' (want both, traces, or metrics)");
            return usage();
        }
    };

    let json = match serde_json::to_string_pretty(&doc) {
        Ok(j) => j,
        Err(e) => {
            eprintln!("serialising OTLP: {e}");
            return ExitCode::from(1);
        }
    };
    if out == "-" {
        println!("{json}");
    } else if let Err(e) = std::fs::write(&out, json) {
        eprintln!("writing {out}: {e}");
        return ExitCode::from(1);
    }
    ExitCode::from(0)
}

// ---------------------------------------------------------------------------
// import: OTLP/JSON -> AssayRun JSON.
// ---------------------------------------------------------------------------

fn import_cmd(args: &[String]) -> ExitCode {
    let mut in_path: Option<String> = None;
    let mut out = "-".to_string();
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        match arg.as_str() {
            "--out" => {
                i += 1;
                match args.get(i) {
                    Some(v) => out = v.clone(),
                    None => {
                        eprintln!("missing value after --out");
                        return usage();
                    }
                }
            }
            other if other.starts_with("--") => {
                eprintln!("unknown flag {other}");
                return usage();
            }
            other => {
                if in_path.is_some() {
                    eprintln!("unexpected argument {other}");
                    return usage();
                }
                in_path = Some(other.to_string());
            }
        }
        i += 1;
    }
    let Some(path) = in_path else {
        eprintln!("import needs an <otlp.json> path");
        return usage();
    };

    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("reading {path}: {e}");
            return ExitCode::from(1);
        }
    };
    let doc: serde_json::Value = match serde_json::from_str(&text) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("parsing OTLP from {path}: {e}");
            return ExitCode::from(1);
        }
    };
    let run = match assayist_otlp::import(&doc) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("importing OTLP: {e}");
            return ExitCode::from(1);
        }
    };

    let json = match serde_json::to_string_pretty(&run) {
        Ok(j) => j,
        Err(e) => {
            eprintln!("serialising run: {e}");
            return ExitCode::from(1);
        }
    };
    if out == "-" {
        println!("{json}");
    } else if let Err(e) = std::fs::write(&out, json) {
        eprintln!("writing {out}: {e}");
        return ExitCode::from(1);
    }
    ExitCode::from(0)
}

// ---------------------------------------------------------------------------
// inspect: read-only parse/validate/expand + host observation.
// ---------------------------------------------------------------------------

fn inspect(path: &str) -> ExitCode {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("reading {path}: {e}");
            return ExitCode::from(1);
        }
    };

    let (def, sha) = match def::parse(&text) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(1);
        }
    };

    if let Err(errs) = def::validate(&def) {
        eprintln!("benchmark def rejected at load ({} problem(s)):", errs.len());
        for e in &errs {
            eprintln!("  - {e}");
        }
        return ExitCode::from(1);
    }

    let cells = def::expand_cells(&def);

    println!("benchmark: {}", def.name);
    println!("benchmark_def_sha: {sha}");
    println!("target: {} {}", def.target.adapter, def.target.version);
    println!("workload: {}", def.workload.driver);
    println!("gate mode: {}", def.gate.mode);
    println!("tenancy: {}", def.tenancy);
    println!("parameterisation cells: {}", cells.len());
    for c in &cells {
        println!("  {} -> {}", &c.params_hash[..12], c.params);
    }
    println!("capture gadgets: {}", def.capture.len());
    for c in &def.capture {
        let g = c.gadget.as_deref().unwrap_or("(unspecified)");
        println!("  {} via {} [{}]", c.probe, g, c.cardinality.class);
    }

    let prep = hostprep::HostPrep::from_value(&def.host_prep);
    println!();
    match hostprep::observe(&hostprep::LinuxHost::new(), &prep, &def.tenancy) {
        Ok(fp) => {
            println!("host (observed, not applied):");
            println!("  {} / {} / {}", fp.hostname, fp.kernel_version, fp.os_release);
            println!(
                "  {} ({} logical, {} physical cores), smt={}",
                fp.cpu_model, fp.cpu_count_logical, fp.cpu_count_physical, fp.smt_enabled
            );
            println!("  governor={} thp={} kvm={}", fp.cpu_governor, fp.thp_setting, fp.kvm_present);
            let would_be = if fp.has_extended() { Grade::Reproducible } else { Grade::Valid };
            println!("  extended fields present: {}", fp.has_extended());
            if prep.knobs.to_value() != serde_json::json!({}) {
                println!(
                    "  requested tuning: {} | matches now: {}",
                    prep.knobs.to_value(),
                    fp.tuning_consistent()
                );
            }
            println!("  fingerprint would grade: {would_be:?} (before host prep applies)");
        }
        Err(e) => eprintln!("host observation skipped: {e}"),
    }
    ExitCode::from(0)
}

// ---------------------------------------------------------------------------
// capture: one capture, one assembled run.
// ---------------------------------------------------------------------------

struct CaptureArgs {
    def_path: String,
    duration: u64,
    out: String,
    sut_sha: String,
    work_dir: Option<PathBuf>,
}

fn parse_capture_args(args: &[String]) -> Result<CaptureArgs, String> {
    let mut def_path: Option<String> = None;
    let mut ca = CaptureArgs {
        def_path: String::new(),
        duration: 30,
        out: "-".into(),
        sut_sha: "unknown".into(),
        work_dir: None,
    };
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        let mut next = || {
            i += 1;
            args.get(i).cloned().ok_or_else(|| format!("missing value after {arg}"))
        };
        match arg.as_str() {
            "--duration" => ca.duration = next()?.parse().map_err(|_| "bad --duration")?,
            "--out" => ca.out = next()?,
            "--sut-sha" => ca.sut_sha = next()?,
            "--work-dir" => ca.work_dir = Some(PathBuf::from(next()?)),
            other if other.starts_with("--") => return Err(format!("unknown flag {other}")),
            other => {
                if def_path.is_some() {
                    return Err(format!("unexpected argument {other}"));
                }
                def_path = Some(other.to_string());
            }
        }
        i += 1;
    }
    ca.def_path = def_path.ok_or("capture needs a <def.yaml> path")?;
    Ok(ca)
}

fn capture_cmd(args: &[String]) -> ExitCode {
    let ca = match parse_capture_args(args) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{e}");
            return usage();
        }
    };

    let (def, sha) = match load_def(&ca.def_path) {
        Ok(v) => v,
        Err(code) => return code,
    };

    let prep = hostprep::HostPrep::from_value(&def.host_prep);
    let fingerprint = match hostprep::observe(&hostprep::LinuxHost::new(), &prep, &def.tenancy) {
        Ok(fp) => fp,
        Err(e) => {
            eprintln!("cannot build fingerprint: {e}");
            return ExitCode::from(1);
        }
    };

    let cells = def::expand_cells(&def);
    let (params, params_hash) = cells
        .first()
        .map(|c| (c.params.clone(), c.params_hash.clone()))
        .unwrap_or_else(|| (serde_json::json!({}), def::params_hash(&serde_json::json!({}))));

    let work_dir = ca
        .work_dir
        .unwrap_or_else(|| std::env::temp_dir().join(format!("assayist-{}", std::process::id())));
    if let Err(e) = std::fs::create_dir_all(&work_dir) {
        eprintln!("creating work dir {}: {e}", work_dir.display());
        return ExitCode::from(1);
    }

    let mut vars = adapter::vars(&params, &ca.sut_sha);
    if let Some(dir) = std::path::Path::new(&ca.def_path)
        .canonicalize()
        .ok()
        .and_then(|p| p.parent().map(std::path::Path::to_path_buf))
    {
        vars.insert("def_dir".to_string(), dir.to_string_lossy().into_owned());
    }

    let plan = match capture::plan_gadgets(&def.capture, ca.duration, &work_dir, &vars) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(1);
        }
    };
    eprintln!(
        "firing {} gadget(s) for {}s (fragments in {})",
        plan.len(),
        ca.duration,
        work_dir.display()
    );
    let fragments = match capture::capture(&plan, &capture::SubprocessRunner) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("capture failed: {e}");
            return ExitCode::from(1);
        }
    };

    // Real adapter/workload versions from the tools themselves (a `--version`
    // query, no provisioning), rather than the 0.0.0 placeholder.
    let shell = adapter::SystemShell;
    let target = select_target(&def, vars.clone(), prep.pin_threads);
    let workload = select_workload(&def, vars);
    let versions = run::AdapterVersions {
        target: target.version(&shell),
        workload: workload.version(&shell),
    };
    let identity = run::build_identity(&def, params, params_hash, &sha, &ca.sut_sha, &versions);
    let gate = run::build_gate_context(&def, "");
    let assay = run::assemble(run::new_run_id(), identity, fingerprint, gate, &fragments, vec![]);

    eprintln!("run {} graded: {:?}", assay.run_id, assay.grade);

    let json = match serde_json::to_string_pretty(&assay) {
        Ok(j) => j,
        Err(e) => {
            eprintln!("serialising run: {e}");
            return ExitCode::from(1);
        }
    };
    if ca.out == "-" {
        println!("{json}");
    } else if let Err(e) = std::fs::write(&ca.out, json) {
        eprintln!("writing {}: {e}", ca.out);
        return ExitCode::from(1);
    }
    ExitCode::from(0)
}

// ---------------------------------------------------------------------------
// run: full A/B pipeline.
// ---------------------------------------------------------------------------

struct RunArgs {
    def_path: String,
    repeat: u32,
    a_sut: String,
    b_sut: String,
    out_dir: PathBuf,
    duration: u64,
    allow_ungraded: bool,
    apply_prep: bool,
}

fn parse_run_args(args: &[String]) -> Result<RunArgs, String> {
    let mut def_path: Option<String> = None;
    let mut ra = RunArgs {
        def_path: String::new(),
        repeat: 3,
        a_sut: "unknown-a".into(),
        b_sut: "unknown-b".into(),
        out_dir: PathBuf::from("assayist-out"),
        duration: 30,
        allow_ungraded: false,
        apply_prep: false,
    };
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        let mut next = || {
            i += 1;
            args.get(i).cloned().ok_or_else(|| format!("missing value after {arg}"))
        };
        match arg.as_str() {
            "--repeat" => ra.repeat = next()?.parse().map_err(|_| "bad --repeat")?,
            "--a-sut" => ra.a_sut = next()?,
            "--b-sut" => ra.b_sut = next()?,
            "--out" => ra.out_dir = PathBuf::from(next()?),
            "--duration" => ra.duration = next()?.parse().map_err(|_| "bad --duration")?,
            "--allow-ungraded" => ra.allow_ungraded = true,
            "--apply-prep" => ra.apply_prep = true,
            other if other.starts_with("--") => return Err(format!("unknown flag {other}")),
            other => {
                if def_path.is_some() {
                    return Err(format!("unexpected argument {other}"));
                }
                def_path = Some(other.to_string());
            }
        }
        i += 1;
    }
    ra.def_path = def_path.ok_or("run needs a <def.yaml> path")?;
    if ra.repeat == 0 {
        return Err("--repeat must be > 0".into());
    }
    Ok(ra)
}

fn run_cmd(args: &[String]) -> ExitCode {
    let ra = match parse_run_args(args) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{e}");
            return usage();
        }
    };

    let (def, sha) = match load_def(&ra.def_path) {
        Ok(v) => v,
        Err(code) => return code,
    };

    let cells = def::expand_cells(&def);
    let prep = hostprep::HostPrep::from_value(&def.host_prep);
    let host = hostprep::LinuxHost::new();
    let has_knobs = prep.knobs.to_value() != serde_json::json!({});
    if has_knobs && !ra.apply_prep {
        eprintln!(
            "note: --apply-prep not set, so host prep is observed not applied. requested tuning {} is recorded but not enforced; runs grade `invalid` if the host does not already match.",
            prep.knobs.to_value()
        );
    }
    // Apply host prep (mutates sysfs, needs root) only when asked; otherwise
    // observe the current state read-only.
    let fp_result = if ra.apply_prep {
        hostprep::prepare(&host, &prep, &def.tenancy)
    } else {
        hostprep::observe(&host, &prep, &def.tenancy)
    };
    let fingerprint = match fp_result {
        Ok(fp) => fp,
        Err(e) => {
            eprintln!("cannot build fingerprint: {e}");
            return ExitCode::from(1);
        }
    };
    if ra.apply_prep && !fingerprint.tuning_consistent() {
        eprintln!(
            "host prep did not take: requested {} but host reports {}. refusing the run.",
            fingerprint.tuning_requested, fingerprint.tuning_readback
        );
        return ExitCode::from(1);
    }

    if let Err(e) = std::fs::create_dir_all(&ra.out_dir) {
        eprintln!("creating out dir {}: {e}", ra.out_dir.display());
        return ExitCode::from(1);
    }

    let shell = adapter::SystemShell;
    let runner = capture::SubprocessRunner;

    let mut a_files: Vec<PathBuf> = Vec::new();
    let mut b_files: Vec<PathBuf> = Vec::new();

    // Directory of the def file, exposed to config templates as `{def_dir}` so a
    // committed def can reference assets by repo-relative path rather than a
    // machine-specific absolute one.
    let def_dir = std::path::Path::new(&ra.def_path)
        .canonicalize()
        .ok()
        .and_then(|p| p.parent().map(std::path::Path::to_path_buf))
        .map(|d| d.to_string_lossy().into_owned())
        .unwrap_or_default();

    // Groups A and B. With `compare` set, they are the two values of that
    // parameterise dimension (validated to be exactly two), and any other
    // dimensions form cells within each group. Without it, both groups run every
    // cell and differ only by SUT sha (the legacy build-vs-build A/B).
    let groups: Vec<(&str, &str, Vec<&def::Cell>)> = match &def.compare {
        Some(dim) => {
            let values = &def.parameterise[dim];
            [("a", ra.a_sut.as_str(), &values[0]), ("b", ra.b_sut.as_str(), &values[1])]
                .into_iter()
                .map(|(label, sut, v)| {
                    let sel = cells.iter().filter(|c| c.params.get(dim) == Some(v)).collect();
                    (label, sut, sel)
                })
                .collect()
        }
        None => vec![
            ("a", ra.a_sut.as_str(), cells.iter().collect()),
            ("b", ra.b_sut.as_str(), cells.iter().collect()),
        ],
    };

    for &(group, sut, ref group_cells) in &groups {
        for (ci, cell) in group_cells.iter().enumerate() {
            for i in 0..ra.repeat {
                let mut vars = adapter::vars(&cell.params, sut);
                if !def_dir.is_empty() {
                    vars.insert("def_dir".to_string(), def_dir.clone());
                }
                let target = build_target(&def, vars.clone(), prep.pin_threads);
                let workload = select_workload(&def, vars.clone());

                let work_dir = ra.out_dir.join("frags").join(format!("{group}-{ci}-{i}"));
                if let Err(e) = std::fs::create_dir_all(&work_dir) {
                    eprintln!("creating work dir {}: {e}", work_dir.display());
                    return ExitCode::from(1);
                }
                let plan = match capture::plan_gadgets(&def.capture, ra.duration, &work_dir, &vars) {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!("{e}");
                        return ExitCode::from(1);
                    }
                };

                let art = match adapter::execute_run(&shell, &runner, target.as_ref(), workload.as_ref(), &plan) {
                    Ok(a) => a,
                    Err(e) => {
                        eprintln!("run {group}[cell {ci} #{i}] failed: {e}");
                        return ExitCode::from(1);
                    }
                };
                if !art.workload_report.is_null() {
                    eprintln!("  workload report {group}[{ci}#{i}]: {}", art.workload_report);
                }

                let versions = run::AdapterVersions {
                    target: target.version(&shell),
                    workload: workload.version(&shell),
                };
                let identity = run::build_identity(
                    &def,
                    cell.params.clone(),
                    cell.params_hash.clone(),
                    &sha,
                    sut,
                    &versions,
                );
                let gate_ctx = run::build_gate_context(&def, "");
                // Re-read the fingerprint per run (read-only; prep, if any, was
                // applied once before the loop). A host that drifts between the A
                // and B builds then shows up in that run's own fingerprint rather
                // than being masked by a single snapshot taken up front. The
                // thread-pinning layout is this run's own, folded in on top, so a
                // fully-prepped and pinned run can grade `reproducible`.
                let mut fp = match hostprep::observe(&host, &prep, &def.tenancy) {
                    Ok(f) => f,
                    Err(e) => {
                        eprintln!("re-reading fingerprint for {group}[cell {ci} #{i}]: {e}");
                        return ExitCode::from(1);
                    }
                };
                if let Some(layout) = target.pinning_layout() {
                    fp.pinning_layout = Some(layout);
                }
                let mut assay = run::assemble(
                    run::new_run_id(),
                    identity,
                    fp,
                    gate_ctx,
                    &art.fragments,
                    art.spans,
                );
                if !art.workload_report.is_null() {
                    assay.workload_report = Some(art.workload_report);
                }

                let path = ra.out_dir.join(format!("{group}_{ci}_{i}.json"));
                let json = match serde_json::to_string_pretty(&assay) {
                    Ok(j) => j,
                    Err(e) => {
                        eprintln!("serialising run: {e}");
                        return ExitCode::from(1);
                    }
                };
                if let Err(e) = std::fs::write(&path, json) {
                    eprintln!("writing {}: {e}", path.display());
                    return ExitCode::from(1);
                }
                match group {
                    "a" => a_files.push(path),
                    _ => b_files.push(path),
                }
            }
        }
    }

    eprintln!(
        "assembled {} A runs and {} B runs in {}",
        a_files.len(),
        b_files.len(),
        ra.out_dir.display()
    );

    let thresholds = gate::GateThresholds {
        p_threshold: def.gate.p_threshold.unwrap_or(0.01),
        noise_threshold: def.gate.noise_threshold.unwrap_or(0.05),
        resamples: def.gate.resamples.unwrap_or(10_000),
        ignore: def.gate.ignore.clone(),
        allow_ungraded: ra.allow_ungraded,
    };
    let bin = gate::resolve_gate_bin();
    let outcome = match gate::run_gate(&bin, &def.gate.mode, &a_files, &b_files, &thresholds) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(1);
        }
    };

    if let Err(e) = gate::write_outcome(&ra.out_dir, &outcome.outcome) {
        eprintln!("warning: {e}");
    }
    eprintln!("gate verdict: {} (exit {})", outcome.verdict, outcome.exit_code);

    let code = outcome.exit_code.clamp(0, 255) as u8;
    ExitCode::from(code)
}

/// Read, parse, and validate a def, mapping any failure to an exit code.
fn load_def(path: &str) -> Result<(def::BenchmarkDef, String), ExitCode> {
    let text = std::fs::read_to_string(path).map_err(|e| {
        eprintln!("reading {path}: {e}");
        ExitCode::from(1)
    })?;
    let (def, sha) = def::parse(&text).map_err(|e| {
        eprintln!("{e}");
        ExitCode::from(1)
    })?;
    if let Err(errs) = def::validate(&def) {
        eprintln!("benchmark def rejected at load ({} problem(s)):", errs.len());
        for e in &errs {
            eprintln!("  - {e}");
        }
        return Err(ExitCode::from(1));
    }
    Ok((def, sha))
}
