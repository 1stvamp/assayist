// SPDX-License-Identifier: Apache-2.0
// assayist-gate: consume AssayRun records, return a verdict.
//
// Usage:
//   assayist-gate --mode ab_permutation --a a1.json a2.json --b b1.json b2.json [opts]
//   assayist-gate --mode longitudinal_drift --baseline base*.json --candidate cand*.json
//   assayist-gate --mode subsystem_triad --a ... --b ...
//
// Options: --p-threshold --noise-threshold --min-effect --resamples --drift-k
//          --seed --ignore <substr> (repeatable) --allow-ungraded
//          --strict-single-cell --out <path|->

mod gate;
mod reduce;
mod stats;

use std::fs;
use std::process::ExitCode;

use serde_json::Value;

use gate::Config;

struct Args {
    mode: String,
    a: Vec<String>,
    b: Vec<String>,
    baseline: Vec<String>,
    candidate: Vec<String>,
    out: String,
    cfg: Config,
}

fn parse_args() -> Result<Args, String> {
    let mut a = Args {
        mode: "ab_permutation".into(),
        a: Vec::new(),
        b: Vec::new(),
        baseline: Vec::new(),
        candidate: Vec::new(),
        out: "-".into(),
        cfg: Config::default(),
    };
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    // Which multi-value list the bare positional args currently feed into.
    let mut cur: Option<&str> = None;
    while i < argv.len() {
        let arg = &argv[i];
        let mut next = || {
            i += 1;
            argv.get(i).cloned().ok_or_else(|| format!("missing value after {arg}"))
        };
        match arg.as_str() {
            "--mode" => { a.mode = next()?; cur = None; }
            "--a" => cur = Some("a"),
            "--b" => cur = Some("b"),
            "--baseline" => cur = Some("baseline"),
            "--candidate" => cur = Some("candidate"),
            "--out" => { a.out = next()?; cur = None; }
            "--p-threshold" => { a.cfg.p_threshold = next()?.parse().map_err(|_| "bad --p-threshold")?; cur = None; }
            "--noise-threshold" => { a.cfg.noise_threshold = next()?.parse().map_err(|_| "bad --noise-threshold")?; cur = None; }
            "--min-effect" => { a.cfg.min_effect = next()?.parse().map_err(|_| "bad --min-effect")?; cur = None; }
            "--resamples" => { a.cfg.resamples = next()?.parse().map_err(|_| "bad --resamples")?; cur = None; }
            "--drift-k" => { a.cfg.drift_k = next()?.parse().map_err(|_| "bad --drift-k")?; cur = None; }
            "--seed" => { a.cfg.seed = next()?.parse().map_err(|_| "bad --seed")?; cur = None; }
            "--ignore" => { a.cfg.ignore.push(next()?); cur = None; }
            "--allow-ungraded" => { a.cfg.allow_ungraded = true; cur = None; }
            "--strict-single-cell" => { a.cfg.strict_single_cell = true; cur = None; }
            other => {
                if other.starts_with("--") {
                    return Err(format!("unknown flag {other}"));
                }
                match cur {
                    Some("a") => a.a.push(other.to_string()),
                    Some("b") => a.b.push(other.to_string()),
                    Some("baseline") => a.baseline.push(other.to_string()),
                    Some("candidate") => a.candidate.push(other.to_string()),
                    _ => return Err(format!("stray argument {other}")),
                }
            }
        }
        i += 1;
    }
    Ok(a)
}

fn load(paths: &[String]) -> Result<Vec<Value>, String> {
    let mut out = Vec::new();
    for p in paths {
        let text = fs::read_to_string(p).map_err(|e| format!("reading {p}: {e}"))?;
        let v: Value = serde_json::from_str(&text).map_err(|e| format!("parsing {p}: {e}"))?;
        out.push(v);
    }
    Ok(out)
}

fn run() -> Result<Value, String> {
    let args = parse_args()?;
    match args.mode.as_str() {
        "ab_permutation" => {
            let a = load(&args.a)?;
            let b = load(&args.b)?;
            if a.is_empty() || b.is_empty() {
                return Err("ab_permutation needs --a and --b run files".into());
            }
            gate::ab(&a, &b, &args.cfg)
        }
        "longitudinal_drift" => {
            let base = load(&args.baseline)?;
            let cand = load(&args.candidate)?;
            if base.is_empty() || cand.is_empty() {
                return Err("longitudinal_drift needs --baseline and --candidate".into());
            }
            gate::drift(&base, &cand, &args.cfg)
        }
        "subsystem_triad" => {
            let a = load(&args.a)?;
            let b = load(&args.b)?;
            if a.is_empty() || b.is_empty() {
                return Err("subsystem_triad needs --a and --b run files".into());
            }
            gate::triad(&a, &b, &args.cfg)
        }
        m => Err(format!("unknown mode '{m}'")),
    }
    .map(|result| {
        // Attach the mode for downstream clarity if not present.
        result
    })
    .and_then(|result| {
        let out = args.out.clone();
        let text = serde_json::to_string_pretty(&result).map_err(|e| e.to_string())?;
        if out == "-" {
            println!("{text}");
        } else {
            fs::write(&out, text).map_err(|e| format!("writing {out}: {e}"))?;
        }
        Ok(result)
    })
}

fn main() -> ExitCode {
    match run() {
        Ok(result) => {
            let verdict = result
                .get("outcome")
                .and_then(|o| o.get("verdict"))
                .and_then(|v| v.as_str())
                .unwrap_or("pass");
            // Exit code carries the verdict for CI: 0 pass, 2 fail, 3 contaminated.
            match verdict {
                "pass" => ExitCode::from(0),
                "fail" => ExitCode::from(2),
                "contaminated" => ExitCode::from(3),
                _ => ExitCode::from(0),
            }
        }
        Err(e) => {
            eprintln!("gate error: {e}");
            ExitCode::from(1)
        }
    }
}
