// SPDX-License-Identifier: Apache-2.0
//! Host preparation and fingerprinting.
//!
//! Reproducibility lives or dies on the host fingerprint, so this module builds
//! it and enforces the contract's tuning rule: what host prep asked for must
//! equal what the host reported back, else the run is a lie and gets thrown out
//! (`Grade::Invalid`).
//!
//! System access sits behind the [`Host`] trait so tests inject a fake and never
//! touch the real machine. [`LinuxHost`] reads `/proc` and `/sys`. Applying
//! tuning (`apply_tuning`) writes to sysfs and needs root, so it is deliberately
//! kept out of any read-only path: the `assayist run` demo uses [`observe`],
//! which reads current state and never mutates.

use assayist_contract::Fingerprint;
use serde::Serialize;
use serde_json::Value;

/// The globally-verifiable tuning knobs: governor, SMT, THP. Each is set only
/// when the def asked for it, and read back with the same shape, so a
/// requested-vs-readback comparison is meaningful. `pin_threads` is not here: it
/// is not a global sysfs value, it is a directive the target adapter carries out
/// and records into `pinning_layout` (done by the firecracker target).
#[derive(Serialize, Clone, Debug, Default, PartialEq)]
pub struct TuningKnobs {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_governor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub smt: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thp: Option<String>,
}

impl TuningKnobs {
    pub fn to_value(&self) -> Value {
        serde_json::to_value(self).unwrap_or(Value::Null)
    }

    /// The knobs the def actually set, so readback can mirror exactly these.
    fn requested_fields(&self) -> RequestedFields {
        RequestedFields {
            governor: self.cpu_governor.is_some(),
            smt: self.smt.is_some(),
            thp: self.thp.is_some(),
        }
    }
}

struct RequestedFields {
    governor: bool,
    smt: bool,
    thp: bool,
}

/// Parsed `host_prep` block. `knobs` are the verifiable tuning; `pin_threads` is
/// carried separately for the target adapter (consumed in the run-loop stage).
#[derive(Clone, Debug, Default)]
pub struct HostPrep {
    pub knobs: TuningKnobs,
    #[allow(dead_code)] // read by the target adapter (stage 4)
    pub pin_threads: bool,
}

impl HostPrep {
    /// Parse from the def's `host_prep` Value. Tolerant of YAML's scalar quirks:
    /// `smt: off` deserialises to the string "off", so booleans accept
    /// on/off/yes/no/true/false as well as native bools.
    pub fn from_value(v: &Value) -> HostPrep {
        HostPrep {
            knobs: TuningKnobs {
                cpu_governor: v.get("cpu_governor").and_then(as_string),
                smt: v.get("smt").and_then(as_bool),
                thp: v.get("thp").and_then(as_string),
            },
            pin_threads: v.get("pin_threads").and_then(as_bool).unwrap_or(false),
        }
    }
}

/// Non-tuning host facts, mapped onto the fingerprint's core and extended fields.
#[derive(Clone, Debug)]
pub struct Facts {
    pub hostname: String,
    pub kernel_version: String,
    pub os_release: String,
    pub cpu_model: String,
    pub cpu_count_logical: u32,
    pub cpu_count_physical: u32,
    pub smt_enabled: bool,
    pub cpu_governor: String,
    pub thp_setting: String,
    pub total_memory_bytes: u64,
    pub kvm_present: bool,
    // Extended (optional; absence keeps a run `valid` rather than `reproducible`).
    pub numa_topology: Option<Value>,
    pub mitigations: Option<Value>,
    pub microcode_version: Option<String>,
    pub nested_virt: Option<bool>,
}

/// Abstraction over the host so tests do not touch the real machine.
pub trait Host {
    fn facts(&self) -> Result<Facts, String>;
    /// Read back only the knobs the request set, so shapes line up for the
    /// consistency check.
    fn read_tuning(&self, want: &TuningKnobs) -> Result<TuningKnobs, String>;
    /// Mutating: write governor/SMT/THP to sysfs. Needs root. Only called on the
    /// apply path (`assayist run --apply-prep`), never from a read-only one.
    fn apply_tuning(&self, want: &TuningKnobs) -> Result<(), String>;
}

/// Assemble a fingerprint from facts, the requested tuning, and what the host
/// reported back. Grading is the contract's job: `Fingerprint::tuning_consistent`
/// and `has_extended` drive it once this is folded into an `AssayRun`.
pub fn build_fingerprint(
    facts: &Facts,
    requested: &TuningKnobs,
    readback: &TuningKnobs,
    tenancy: &str,
    pinning_layout: Option<Value>,
) -> Fingerprint {
    Fingerprint {
        hostname: facts.hostname.clone(),
        kernel_version: facts.kernel_version.clone(),
        os_release: facts.os_release.clone(),
        cpu_model: facts.cpu_model.clone(),
        cpu_count_logical: facts.cpu_count_logical,
        cpu_count_physical: facts.cpu_count_physical,
        smt_enabled: facts.smt_enabled,
        cpu_governor: facts.cpu_governor.clone(),
        thp_setting: facts.thp_setting.clone(),
        total_memory_bytes: facts.total_memory_bytes,
        kvm_present: facts.kvm_present,
        tenancy: tenancy.to_string(),
        tuning_requested: requested.to_value(),
        tuning_readback: readback.to_value(),
        numa_topology: facts.numa_topology.clone(),
        pinning_layout,
        mitigations: facts.mitigations.clone(),
        microcode_version: facts.microcode_version.clone(),
        nested_virt: facts.nested_virt,
    }
}

/// Read-only: current facts plus a readback of the requested knobs, with no
/// mutation. This is what `assayist run` uses to show observed host state.
pub fn observe(host: &dyn Host, prep: &HostPrep, tenancy: &str) -> Result<Fingerprint, String> {
    let facts = host.facts()?;
    let readback = host.read_tuning(&prep.knobs)?;
    Ok(build_fingerprint(&facts, &prep.knobs, &readback, tenancy, None))
}

/// Mutating: apply the requested tuning, read it back, and build the fingerprint.
/// The caller must check `tuning_consistent()` before admitting a gated run.
/// Needs root (writes sysfs). Called by `assayist run --apply-prep`. The caller
/// must check `tuning_consistent()` before admitting a gated run.
pub fn prepare(host: &dyn Host, prep: &HostPrep, tenancy: &str) -> Result<Fingerprint, String> {
    host.apply_tuning(&prep.knobs)?;
    let facts = host.facts()?;
    let readback = host.read_tuning(&prep.knobs)?;
    Ok(build_fingerprint(&facts, &prep.knobs, &readback, tenancy, None))
}

fn as_string(v: &Value) -> Option<String> {
    v.as_str().map(|s| s.to_string())
}

fn as_bool(v: &Value) -> Option<bool> {
    match v {
        Value::Bool(b) => Some(*b),
        Value::String(s) => match s.to_ascii_lowercase().as_str() {
            "on" | "yes" | "true" | "1" => Some(true),
            "off" | "no" | "false" | "0" => Some(false),
            _ => None,
        },
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// LinuxHost: real reads from /proc and /sys.
// ---------------------------------------------------------------------------

pub struct LinuxHost;

impl LinuxHost {
    pub fn new() -> LinuxHost {
        LinuxHost
    }
}

impl Default for LinuxHost {
    fn default() -> Self {
        LinuxHost::new()
    }
}

impl Host for LinuxHost {
    fn facts(&self) -> Result<Facts, String> {
        let cpuinfo = read_trim("/proc/cpuinfo").unwrap_or_default();
        let (logical, physical) = cpu_counts(&cpuinfo);
        Ok(Facts {
            hostname: read_trim("/proc/sys/kernel/hostname")
                .ok_or("cannot read hostname")?,
            kernel_version: read_trim("/proc/sys/kernel/osrelease")
                .ok_or("cannot read kernel version")?,
            os_release: os_pretty_name().unwrap_or_else(|| "unknown".to_string()),
            cpu_model: cpuinfo_field(&cpuinfo, "model name")
                .unwrap_or_else(|| "unknown".to_string()),
            cpu_count_logical: logical,
            cpu_count_physical: physical,
            smt_enabled: read_trim("/sys/devices/system/cpu/smt/active")
                .map(|s| s == "1")
                .unwrap_or(false),
            cpu_governor: read_trim(
                "/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor",
            )
            .unwrap_or_else(|| "unknown".to_string()),
            thp_setting: thp_active().unwrap_or_else(|| "unknown".to_string()),
            total_memory_bytes: meminfo_total_bytes().ok_or("cannot read MemTotal")?,
            kvm_present: std::path::Path::new("/dev/kvm").exists(),
            numa_topology: numa_topology(),
            mitigations: mitigations(),
            microcode_version: cpuinfo_field(&cpuinfo, "microcode"),
            nested_virt: nested_virt(),
        })
    }

    fn read_tuning(&self, want: &TuningKnobs) -> Result<TuningKnobs, String> {
        let f = want.requested_fields();
        Ok(TuningKnobs {
            cpu_governor: if f.governor {
                read_trim("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor")
            } else {
                None
            },
            smt: if f.smt {
                read_trim("/sys/devices/system/cpu/smt/active").map(|s| s == "1")
            } else {
                None
            },
            thp: if f.thp { thp_active() } else { None },
        })
    }

    fn apply_tuning(&self, want: &TuningKnobs) -> Result<(), String> {
        if let Some(gov) = &want.cpu_governor {
            set_governor(gov)?;
        }
        if let Some(smt) = &want.smt {
            set_smt(*smt)?;
        }
        if let Some(thp) = &want.thp {
            write_sysfs("/sys/kernel/mm/transparent_hugepage/enabled", thp)?;
        }
        Ok(())
    }
}

fn write_sysfs(path: &str, value: &str) -> Result<(), String> {
    std::fs::write(path, value).map_err(|e| format!("writing '{value}' to {path}: {e}"))
}

/// Write the governor to every online CPU's cpufreq node. A host with no cpufreq
/// (common in VMs) has no `scaling_governor` files, so requesting a governor
/// there is an error: the run cannot claim the tuning took.
fn set_governor(gov: &str) -> Result<(), String> {
    let mut wrote = 0;
    let dir = std::fs::read_dir("/sys/devices/system/cpu").map_err(|e| format!("listing cpus: {e}"))?;
    for entry in dir.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let is_cpu_n = name
            .strip_prefix("cpu")
            .map(|n| !n.is_empty() && n.chars().all(|c| c.is_ascii_digit()))
            .unwrap_or(false);
        if !is_cpu_n {
            continue;
        }
        let path = format!("/sys/devices/system/cpu/{name}/cpufreq/scaling_governor");
        if std::path::Path::new(&path).exists() {
            write_sysfs(&path, gov)?;
            wrote += 1;
        }
    }
    if wrote == 0 {
        return Err("no cpufreq scaling_governor present; cannot set the CPU governor".into());
    }
    Ok(())
}

fn set_smt(on: bool) -> Result<(), String> {
    let path = "/sys/devices/system/cpu/smt/control";
    if !std::path::Path::new(path).exists() {
        return Err("SMT control not available (/sys/devices/system/cpu/smt/control missing)".into());
    }
    write_sysfs(path, if on { "on" } else { "off" })
}

fn read_trim(path: &str) -> Option<String> {
    std::fs::read_to_string(path).ok().map(|s| s.trim().to_string())
}

fn cpuinfo_field(cpuinfo: &str, key: &str) -> Option<String> {
    cpuinfo.lines().find_map(|l| {
        let (k, v) = l.split_once(':')?;
        if k.trim() == key {
            Some(v.trim().to_string())
        } else {
            None
        }
    })
}

/// Logical = count of `processor` lines. Physical = distinct (physical id, core
/// id) pairs, falling back to logical when those fields are absent (containers,
/// some arches).
fn cpu_counts(cpuinfo: &str) -> (u32, u32) {
    let logical = cpuinfo
        .lines()
        .filter(|l| l.split_once(':').map(|(k, _)| k.trim() == "processor").unwrap_or(false))
        .count() as u32;

    let mut cores = std::collections::HashSet::new();
    let mut phys: Option<String> = None;
    let mut core: Option<String> = None;
    for l in cpuinfo.lines() {
        if let Some((k, v)) = l.split_once(':') {
            match k.trim() {
                "physical id" => phys = Some(v.trim().to_string()),
                "core id" => core = Some(v.trim().to_string()),
                "processor" => {
                    phys = None;
                    core = None;
                }
                _ => {}
            }
        }
        if l.trim().is_empty() {
            if let (Some(p), Some(c)) = (&phys, &core) {
                cores.insert(format!("{p}:{c}"));
            }
        }
    }
    if let (Some(p), Some(c)) = (&phys, &core) {
        cores.insert(format!("{p}:{c}"));
    }

    let physical = if cores.is_empty() { logical } else { cores.len() as u32 };
    (logical.max(1), physical.max(1))
}

fn os_pretty_name() -> Option<String> {
    let text = std::fs::read_to_string("/etc/os-release").ok()?;
    for l in text.lines() {
        if let Some(v) = l.strip_prefix("PRETTY_NAME=") {
            return Some(v.trim_matches('"').to_string());
        }
    }
    None
}

/// THP `enabled` reads like `always madvise [never]`; the active setting is the
/// bracketed token.
fn thp_active() -> Option<String> {
    let text = read_trim("/sys/kernel/mm/transparent_hugepage/enabled")?;
    text.split_whitespace()
        .find_map(|t| t.strip_prefix('[').and_then(|t| t.strip_suffix(']')))
        .map(|s| s.to_string())
}

fn meminfo_total_bytes() -> Option<u64> {
    let text = std::fs::read_to_string("/proc/meminfo").ok()?;
    for l in text.lines() {
        if let Some(rest) = l.strip_prefix("MemTotal:") {
            let kb: u64 = rest.split_whitespace().next()?.parse().ok()?;
            return Some(kb * 1024);
        }
    }
    None
}

fn numa_topology() -> Option<Value> {
    let dir = std::fs::read_dir("/sys/devices/system/node").ok()?;
    let mut nodes = serde_json::Map::new();
    for entry in dir.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if let Some(id) = name.strip_prefix("node") {
            if id.chars().all(|c| c.is_ascii_digit()) {
                let cpulist = read_trim(&format!("/sys/devices/system/node/{name}/cpulist"))
                    .unwrap_or_default();
                nodes.insert(name.clone(), Value::String(cpulist));
            }
        }
    }
    if nodes.is_empty() {
        None
    } else {
        Some(Value::Object(nodes))
    }
}

fn mitigations() -> Option<Value> {
    let dir = std::fs::read_dir("/sys/devices/system/cpu/vulnerabilities").ok()?;
    let mut map = serde_json::Map::new();
    for entry in dir.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if let Some(v) = read_trim(&format!(
            "/sys/devices/system/cpu/vulnerabilities/{name}"
        )) {
            map.insert(name, Value::String(v));
        }
    }
    if map.is_empty() {
        None
    } else {
        Some(Value::Object(map))
    }
}

fn nested_virt() -> Option<bool> {
    for path in [
        "/sys/module/kvm_intel/parameters/nested",
        "/sys/module/kvm_amd/parameters/nested",
    ] {
        if let Some(v) = read_trim(path) {
            return Some(matches!(v.as_str(), "Y" | "1"));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    struct FakeHost {
        facts: Facts,
        readback: TuningKnobs,
    }

    impl Host for FakeHost {
        fn facts(&self) -> Result<Facts, String> {
            Ok(self.facts.clone())
        }
        fn read_tuning(&self, _want: &TuningKnobs) -> Result<TuningKnobs, String> {
            Ok(self.readback.clone())
        }
        fn apply_tuning(&self, _want: &TuningKnobs) -> Result<(), String> {
            Ok(())
        }
    }

    fn facts(extended: bool) -> Facts {
        Facts {
            hostname: "lab".into(),
            kernel_version: "6.11.0".into(),
            os_release: "Ubuntu 26.04".into(),
            cpu_model: "Ryzen".into(),
            cpu_count_logical: 16,
            cpu_count_physical: 8,
            smt_enabled: false,
            cpu_governor: "performance".into(),
            thp_setting: "never".into(),
            total_memory_bytes: 1 << 37,
            kvm_present: true,
            numa_topology: if extended { Some(json!({"node0": "0-15"})) } else { None },
            mitigations: if extended { Some(json!({"mds": "Not affected"})) } else { None },
            microcode_version: if extended { Some("0xa60120c".into()) } else { None },
            nested_virt: if extended { Some(false) } else { None },
        }
    }

    #[test]
    fn parses_host_prep_with_yaml_off_string() {
        let hp = HostPrep::from_value(&json!({
            "cpu_governor": "performance",
            "smt": "off",
            "thp": "never",
            "pin_threads": true
        }));
        assert_eq!(hp.knobs.cpu_governor.as_deref(), Some("performance"));
        assert_eq!(hp.knobs.smt, Some(false));
        assert_eq!(hp.knobs.thp.as_deref(), Some("never"));
        assert!(hp.pin_threads);
    }

    #[test]
    fn tuning_requested_only_carries_set_knobs() {
        let hp = HostPrep::from_value(&json!({"cpu_governor": "performance"}));
        assert_eq!(hp.knobs.to_value(), json!({"cpu_governor": "performance"}));
    }

    #[test]
    fn matching_readback_is_consistent() {
        let hp = HostPrep::from_value(&json!({"cpu_governor": "performance", "smt": "off"}));
        let host = FakeHost {
            facts: facts(true),
            readback: TuningKnobs {
                cpu_governor: Some("performance".into()),
                smt: Some(false),
                thp: None,
            },
        };
        let fp = observe(&host, &hp, "single_tenant").unwrap();
        assert!(fp.tuning_consistent());
        // observe passes no pinning_layout (the target adapter fills it in a
        // later stage), so a read-only observation is never extended-complete.
        assert!(!fp.has_extended());
    }

    #[test]
    fn build_fingerprint_with_pinning_is_extended_complete() {
        let requested = TuningKnobs::default();
        let fp = build_fingerprint(
            &facts(true),
            &requested,
            &requested,
            "single_tenant",
            Some(json!({"vcpu0": 2})),
        );
        assert!(fp.has_extended());
        assert!(fp.tuning_consistent());
    }

    #[test]
    fn diverging_readback_is_inconsistent() {
        let hp = HostPrep::from_value(&json!({"cpu_governor": "performance"}));
        let host = FakeHost {
            facts: facts(true),
            // Host reports powersave: prep did not take, the run is a lie.
            readback: TuningKnobs {
                cpu_governor: Some("powersave".into()),
                smt: None,
                thp: None,
            },
        };
        let fp = observe(&host, &hp, "single_tenant").unwrap();
        assert!(!fp.tuning_consistent());
    }

    #[test]
    fn missing_extended_facts_are_not_reproducible_grade() {
        let hp = HostPrep::default();
        let host = FakeHost { facts: facts(false), readback: TuningKnobs::default() };
        let fp = observe(&host, &hp, "single_tenant").unwrap();
        assert!(!fp.has_extended());
    }

    #[test]
    fn cpu_counts_from_cpuinfo() {
        let cpuinfo = "\
processor\t: 0
physical id\t: 0
core id\t: 0

processor\t: 1
physical id\t: 0
core id\t: 1

processor\t: 2
physical id\t: 0
core id\t: 0

processor\t: 3
physical id\t: 0
core id\t: 1
";
        // 4 logical, 2 physical cores (SMT pairs share a core id).
        let (logical, physical) = cpu_counts(cpuinfo);
        assert_eq!(logical, 4);
        assert_eq!(physical, 2);
    }
}
