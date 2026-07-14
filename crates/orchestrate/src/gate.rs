// SPDX-License-Identifier: Apache-2.0
//! Handing the assembled A/B groups to the gate.
//!
//! The gate is a separate binary (`assayist-gate`), invoked as a subprocess with
//! the two groups of run files and the def's thresholds. Its exit code carries
//! the verdict for CI (0 pass, 1 error, 2 fail, 3 contaminated), so the
//! orchestrator propagates it rather than re-deriving one.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

/// Resolve the gate binary: an explicit `ASSAYIST_GATE`, else a sibling of the
/// current executable (the usual cargo/target and installed layouts put both
/// binaries side by side), else bare `assayist-gate` on `PATH`.
pub fn resolve_gate_bin() -> String {
    if let Ok(p) = std::env::var("ASSAYIST_GATE") {
        return p;
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let sibling = dir.join("assayist-gate");
            if sibling.exists() {
                return sibling.to_string_lossy().into_owned();
            }
        }
    }
    "assayist-gate".to_string()
}

pub struct GateThresholds {
    pub p_threshold: f64,
    pub noise_threshold: f64,
    pub resamples: u64,
    pub ignore: Vec<String>,
    pub allow_ungraded: bool,
}

pub struct GateOutput {
    pub outcome: Value,
    pub verdict: String,
    pub exit_code: i32,
}

/// Invoke the gate over the two groups. Returns the parsed outcome and the
/// gate's own exit code. A gate *error* (exit 1) is surfaced as `Err`; a
/// pass/fail/contaminated verdict comes back as `Ok` with the code, because
/// those are results to propagate, not failures to invoke.
#[allow(clippy::too_many_arguments)]
pub fn run_gate(
    bin: &str,
    mode: &str,
    a: &[PathBuf],
    b: &[PathBuf],
    thresholds: &GateThresholds,
) -> Result<GateOutput, String> {
    let mut cmd = Command::new(bin);
    cmd.arg("--mode").arg(mode);
    cmd.arg("--a");
    for f in a {
        cmd.arg(f);
    }
    cmd.arg("--b");
    for f in b {
        cmd.arg(f);
    }
    cmd.arg("--p-threshold").arg(thresholds.p_threshold.to_string());
    cmd.arg("--noise-threshold").arg(thresholds.noise_threshold.to_string());
    cmd.arg("--resamples").arg(thresholds.resamples.to_string());
    for ig in &thresholds.ignore {
        cmd.arg("--ignore").arg(ig);
    }
    if thresholds.allow_ungraded {
        cmd.arg("--allow-ungraded");
    }

    let out = cmd
        .output()
        .map_err(|e| format!("launching gate `{bin}`: {e}"))?;
    let code = out.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&out.stdout);

    if code == 1 {
        return Err(format!(
            "gate error: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }

    let outcome: Value = serde_json::from_str(stdout.trim()).unwrap_or(Value::Null);
    let verdict = outcome
        .get("outcome")
        .and_then(|o| o.get("verdict"))
        .and_then(|v| v.as_str())
        .map(String::from)
        .unwrap_or_else(|| match code {
            0 => "pass".into(),
            2 => "fail".into(),
            3 => "contaminated".into(),
            _ => "unknown".into(),
        });

    Ok(GateOutput { outcome, verdict, exit_code: code })
}

/// Write the gate outcome next to the run files.
pub fn write_outcome(dir: &Path, outcome: &Value) -> Result<PathBuf, String> {
    let path = dir.join("outcome.json");
    let text = serde_json::to_string_pretty(outcome).map_err(|e| e.to_string())?;
    std::fs::write(&path, text).map_err(|e| format!("writing {}: {e}", path.display()))?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_prefers_env_override() {
        // Safe: we only read it back, never exec.
        std::env::set_var("ASSAYIST_GATE", "/custom/assayist-gate");
        assert_eq!(resolve_gate_bin(), "/custom/assayist-gate");
        std::env::remove_var("ASSAYIST_GATE");
    }
}
