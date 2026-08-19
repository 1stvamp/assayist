// SPDX-FileCopyrightText: 2026 Wesley Mason (1stvamp)
// SPDX-License-Identifier: Apache-2.0
//! Native reference adapters: a firecracker microVM target and an fio workload.
//!
//! A def author selects `target.adapter: firecracker` / `workload.driver: fio`
//! (or `fio-*`) and gets the real lifecycle: firecracker boot/snapshot/restore
//! spans and a structured fio report, without hand-writing the shell templates
//! the command adapter needs. Settings come from the def's `target.config` /
//! `workload.config` maps; string values may reference cell params as `{name}`.
//!
//! Both drive their tool through the [`Shell`](crate::adapter::Shell) seam
//! (firecracker via `curl --unix-socket`, fio via its CLI) so the API
//! sequencing and output parsing are unit-testable without a KVM host. The seam
//! is shell rather than a direct unix-socket client purely for that reason: the
//! curl calls are the same requests a socket client would send, and every other
//! adapter in the crate already goes through `Shell`.
//!
//! Limits: the `boot.vmm_ready` span measures the InstanceStart API round-trip
//! (including the curl control-path hop), not the guest reaching userspace init:
//! without an in-guest agent the host cannot observe guest-init, and adding one
//! would break the agentless vantage. It shares its name with the qemu/CH
//! adapters' equivalent marker, so a cross-VMM boot compare lines up. Measured
//! run-to-run CoV is high (tens of percent, control-path jitter), so the noise
//! gate usually treats it as advisory rather than gating on it; that is the
//! intended behaviour (see issue #14). `reach_steady` runs an optional
//! author-supplied `readiness` shell probe. Teardown kills firecracker by
//! matching the api-sock path, so do not share one sock path across concurrent
//! runs.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::{json, Map, Value};

use crate::adapter::{render, NetAttribution, Shell, Target, Workload};

/// Read a config key, render `{param}` refs, fall back to `default`.
fn cfg(
    config: &BTreeMap<String, Value>,
    vars: &BTreeMap<String, String>,
    key: &str,
    default: &str,
) -> String {
    match config.get(key) {
        Some(Value::String(s)) => render(s, vars),
        Some(other) => other.to_string(),
        None => default.to_string(),
    }
}

fn now_nanos() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

fn span(name: &str, parent: Option<&str>, start: u64, end: u64) -> Value {
    let mut m = Map::new();
    m.insert("name".into(), json!(name));
    if let Some(p) = parent {
        m.insert("parent".into(), json!(p));
    }
    m.insert("start_unix_nano".into(), json!(start));
    m.insert("end_unix_nano".into(), json!(end));
    Value::Object(m)
}

/// First token that looks like a version (`v?<digit>...`) in a tool's
/// `--version` output, else the whole trimmed first line.
fn version_token(out: &str) -> String {
    let first = out.lines().next().unwrap_or("").trim();
    first
        .split_whitespace()
        .find(|t| {
            let t = t.strip_prefix('v').unwrap_or(t);
            t.chars().next().is_some_and(|c| c.is_ascii_digit())
        })
        .map(str::to_string)
        .unwrap_or_else(|| first.to_string())
}

// --- firecracker target -----------------------------------------------------

/// A firecracker microVM. Two modes, chosen by config:
/// - cold boot (default): configure machine/boot-source/drives, then
///   `InstanceStart`, recording `boot.vmm_ready`.
/// - restore (`from_snapshot` set): `snapshot/load` with `resume_vm`, recording
///   `restore.resume_to_steady`; `start` is then a no-op.
///
/// With `snapshot_out` set, `reach_steady` also pauses, creates a full
/// snapshot, and resumes, recording `snapshot.create`.
pub struct FirecrackerTarget {
    bin: String,
    sock: String,
    vcpu: String,
    mem_mib: String,
    smt: bool,
    kernel: String,
    rootfs: String,
    boot_args: String,
    /// (snapshot_path, mem_file): restore mode.
    from_snapshot: Option<(String, String)>,
    /// (snapshot_path, mem_file): snapshot the running VM at steady state.
    snapshot_out: Option<(String, String)>,
    readiness: Option<String>,
    /// Shell command run in restore mode after the API server is up but before
    /// `snapshot/load`, outside the measured span. Lets a def set the page-cache
    /// state the restore starts from: drop caches for a cold baseline, or warm a
    /// captured working set (e.g. `bpfoliod prefetch`) so resume faults hit cache.
    pre_restore: Option<String>,
    /// Memory backend for restore: "File" (default) mmaps the mem file, so
    /// concurrent instances share resident pages through the page cache; "Uffd"
    /// serves guest memory from an external userfaultfd handler, so each instance
    /// gets its own anonymous copy (no page-cache dedup). The REAP baseline.
    mem_backend: String,
    /// Command template launching the userfaultfd handler for `mem_backend:
    /// uffd`, backgrounded before `snapshot/load`. Rendered with `{uffd_uds}`
    /// (the socket Firecracker connects to) and `{mem_file}`, e.g.
    /// `bpfolio-reap --uds {uffd_uds} --mem {mem_file} ondemand`.
    uffd_handler: Option<String>,
    /// Streaming restore (M-stream): when set, the mem file is served from a
    /// per-instance FUSE mount backed by this source URL (`file://…` or
    /// `http(s)://…`), and the File restore loads against the mounted file rather
    /// than a local one. The mount is brought up before `snapshot/load` and
    /// unmounted at teardown. Pages are shared across concurrent instances the
    /// same way a local File restore shares them (one mount per instance).
    stream_source: Option<String>,
    /// The bpfoliod binary that provides `stream-mount`/`stream-prefetch`.
    stream_bin: String,
    /// Working-set metadata for streaming prewarm (`stream-prefetch`).
    stream_wsmeta: String,
    /// Whether to prewarm the working set from the source into the mount (inside
    /// the pre-restore window) before loading. False = pure demand-fault over the
    /// mount, the streaming baseline.
    stream_prefetch: bool,
    /// The FUSE mountpoint for this instance's stream restore, unique per target
    /// (a per-construction nonce): rapidly remounting the *same* path within one
    /// process can leave the kernel FUSE connection half-alive so the next mount
    /// never appears, so each repeat gets a fresh path.
    stream_dir: String,
    /// Pin each vCPU thread to a dedicated logical CPU and record the layout.
    pin_threads: bool,
    /// First logical CPU this instance's vCPUs pin to: `fc_vcpu n` -> CPU
    /// `cpu_base + n`. The orchestrator sets a distinct base per concurrent
    /// instance (via the `cpu_base` var) so they do not all land on CPU 0.
    cpu_base: u32,
    /// Host tap device for this instance, when the def asks for tap networking
    /// (`network: tap`). `None` leaves the VM with no network interface, which
    /// is the historical behaviour.
    tap: Option<String>,
    /// Deterministic locally-administered guest MAC, derived from the instance
    /// index so concurrent instances cannot collide.
    guest_mac: String,
    /// The tap's ifindex, read from sysfs after the device exists. The
    /// attribution map keys on it.
    tap_ifindex: RefCell<Option<u32>>,
    spans: RefCell<Vec<Value>>,
    pinning: RefCell<Option<Value>>,
}

pub fn firecracker_target(
    config: &BTreeMap<String, Value>,
    vars: &BTreeMap<String, String>,
    pin_threads: bool,
) -> FirecrackerTarget {
    let g = |k: &str, d: &str| cfg(config, vars, k, d);
    // vcpu/mem come from the parameterisation cell when present.
    let vcpu = vars.get("vcpu").cloned().unwrap_or_else(|| g("vcpu", "1"));
    let mem_mib = vars.get("mem_mib").cloned().unwrap_or_else(|| g("mem_mib", "128"));
    let smt = matches!(g("smt", "false").as_str(), "true" | "on" | "1");
    let pid = std::process::id();
    // The default socket carries the per-instance index (empty for a lone
    // instance) so concurrent instances of one def do not collide on it. A def
    // that sets `api_sock` for N > 1 should template `{instance}` itself.
    let inst = vars.get("instance").map(|i| format!("-{i}")).filter(|_| vars.contains_key("instance"));
    let sock = g("api_sock", &format!("/tmp/assayist-fc-{pid}{}.sock", inst.unwrap_or_default()));

    let from_snapshot = match (config.get("from_snapshot"), config.get("mem_file")) {
        (Some(_), _) => Some((g("from_snapshot", ""), g("mem_file", ""))),
        _ => None,
    };
    let snapshot_out = config
        .get("snapshot_out")
        .map(|_| (g("snapshot_out", ""), g("snapshot_mem", "")));
    let readiness = config.get("readiness").map(|_| g("readiness", ""));
    let pre_restore = config.get("pre_restore").map(|_| g("pre_restore", ""));
    let mem_backend = match g("mem_backend", "File").to_lowercase().as_str() {
        "uffd" => "Uffd".to_string(),
        _ => "File".to_string(),
    };
    let uffd_handler = config.get("uffd_handler").map(|_| g("uffd_handler", ""));
    let stream_source = config
        .get("stream_source")
        .map(|_| g("stream_source", ""))
        .filter(|s| !s.trim().is_empty());
    // Treat "stream"/"true"/"on" as prewarm; anything else (e.g. "nostream") is
    // pure demand-fault. Lets a def drive the A/B with a single {mode} value.
    let stream_prefetch = matches!(g("stream_prefetch", "false").to_lowercase().as_str(), "stream" | "true" | "on");
    let stream_dir = format!("{}.stream.{}", sock, now_nanos());

    // Tap networking is opt-in. The instance index (already used for the API
    // socket) keeps tap names and MACs unique across concurrent instances.
    let instance: u64 = vars.get("instance").and_then(|s| s.parse().ok()).unwrap_or(0);
    let tap = matches!(g("network", "").to_lowercase().as_str(), "tap")
        .then(|| format!("asy{}-{}", std::process::id() % 100000, instance));
    let guest_mac = crate::netattrib::guest_mac_for(instance);

    FirecrackerTarget {
        bin: g("bin", "firecracker"),
        sock,
        vcpu,
        mem_mib,
        smt,
        kernel: g("kernel", ""),
        rootfs: g("rootfs", ""),
        boot_args: g("boot_args", "console=ttyS0 reboot=k panic=1"),
        from_snapshot,
        snapshot_out,
        readiness,
        pre_restore,
        mem_backend,
        uffd_handler,
        stream_source,
        stream_bin: g("stream_bin", "bpfoliod"),
        stream_wsmeta: g("stream_wsmeta", ""),
        stream_prefetch,
        stream_dir,
        pin_threads,
        cpu_base: vars.get("cpu_base").and_then(|s| s.parse().ok()).unwrap_or(0),
        tap,
        guest_mac,
        tap_ifindex: RefCell::new(None),
        spans: RefCell::new(Vec::new()),
        pinning: RefCell::new(None),
    }
}

impl FirecrackerTarget {
    fn api(&self, sh: &dyn Shell, method: &str, path: &str, body: &str) -> Result<(), String> {
        let cmd = format!(
            "curl -fsS --unix-socket '{}' -X {method} 'http://localhost{path}' \
             -H 'Content-Type: application/json' -d '{body}'",
            self.sock
        );
        sh.run(&cmd).map(|_| ())
    }

    /// Launch the firecracker API server in a fresh, wiped scratch cwd (see the
    /// vsock note in `provision`), recording its pid for teardown.
    fn launch_cmd(&self) -> String {
        format!(
            "rm -f '{sock}' '{sock}.pid'; wd='{sock}.d'; rm -rf \"$wd\"; mkdir -p \"$wd\"; \
             ( cd \"$wd\" && exec '{bin}' --api-sock '{sock}' ) >'{sock}.log' 2>&1 & \
             echo $! > '{sock}.pid'; \
             for _ in $(seq 1 100); do [ -S '{sock}' ] && exit 0; sleep 0.05; done; \
             echo 'firecracker api socket did not appear' >&2; exit 1",
            sock = self.sock,
            bin = self.bin,
        )
    }

    /// The socket Firecracker's `Uffd` backend connects to, derived from the API
    /// socket so it is unique per instance.
    fn uffd_uds(&self) -> String {
        format!("{}.uffd", self.sock)
    }

    /// Launch the userfaultfd handler in the background and wait for its socket,
    /// so it is listening before `snapshot/load`. The handler template is
    /// rendered with `{uffd_uds}` and `{mem_file}`; its pid is recorded for
    /// teardown.
    fn launch_uffd_cmd(&self, handler: &str, uds: &str, mem: &str) -> String {
        let mut v = BTreeMap::new();
        v.insert("uffd_uds".to_string(), uds.to_string());
        v.insert("mem_file".to_string(), mem.to_string());
        let handler = render(handler, &v);
        format!(
            "rm -f '{uds}' '{uds}.pid'; ( {handler} ) >'{uds}.log' 2>&1 & \
             echo $! > '{uds}.pid'; \
             for _ in $(seq 1 200); do [ -S '{uds}' ] && exit 0; sleep 0.05; done; \
             echo 'uffd handler socket did not appear' >&2; exit 1"
        )
    }

    /// Launch `bpfoliod stream-mount` in the background: a FUSE mount at
    /// `stream_dir` exposing `mem`, backed by `source`, sized from the real mem
    /// file. Waits for the mounted file to appear so it is ready before
    /// `snapshot/load`; records the pid for teardown.
    fn launch_stream_cmd(&self, source: &str, mem: &str) -> String {
        let dir = &self.stream_dir;
        // Repeats reuse this per-instance path, so first fully retire any prior
        // mount: kill the old daemon and wait for it to exit, then lazy-unmount
        // and wipe the dir. A lingering daemon or half-torn-down FUSE mount makes
        // the fresh stream-mount fail to appear.
        format!(
            "d='{dir}'; \
             if [ -f \"$d.pid\" ]; then op=\"$(cat \"$d.pid\")\"; kill \"$op\" 2>/dev/null; \
               for _ in $(seq 1 150); do kill -0 \"$op\" 2>/dev/null || break; sleep 0.02; done; fi; \
             fusermount3 -uz \"$d\" 2>/dev/null; rm -rf \"$d\" '{dir}.pid' '{dir}.log'; mkdir -p \"$d\"; \
             sz=$(stat -c%s '{mem}'); \
             ( exec '{bin}' stream-mount '{source}' \"$d\" --size-bytes \"$sz\" --name mem ) >'{dir}.log' 2>&1 & \
             mp=$!; echo \"$mp\" > '{dir}.pid'; \
             for _ in $(seq 1 500); do [ -e \"$d/mem\" ] && exit 0; sleep 0.02; done; \
             kill \"$mp\" 2>/dev/null; fusermount3 -uz \"$d\" 2>/dev/null; \
             echo 'stream mount did not appear (see {dir}.log)' >&2; exit 1",
            bin = self.stream_bin,
        )
    }

    /// Prewarm the working set from `source` into the mounted file with
    /// `stream-prefetch`, before the timed load. Run only when `stream_prefetch`.
    fn stream_prefetch_cmd(&self, source: &str) -> String {
        format!(
            "'{bin}' stream-prefetch '{source}' --mem '{dir}/mem' --wsmeta '{ws}'",
            bin = self.stream_bin,
            dir = self.stream_dir,
            ws = self.stream_wsmeta,
        )
    }

    /// Time a fallible API step and record it as a span.
    fn timed(
        &self,
        name: &str,
        parent: Option<&str>,
        f: impl FnOnce() -> Result<(), String>,
    ) -> Result<(), String> {
        let start = now_nanos();
        f()?;
        let end = now_nanos();
        self.spans.borrow_mut().push(span(name, parent, start, end));
        Ok(())
    }

    /// Shell that pins each firecracker vCPU thread to a logical CPU
    /// (`fc_vcpu <n>` -> CPU `cpu_base + n`) via `taskset` and prints the applied
    /// layout as JSON on stdout. It reads the pid recorded at launch, so it must
    /// run after the VM has started (threads exist). A vcpu whose `taskset` fails
    /// aborts the run: a run that asked to pin and could not must not claim it
    /// did (e.g. when concurrent instances would need more CPUs than exist).
    fn pin_cmd(&self) -> String {
        format!(
            "pid=$(cat '{sock}.pid'); layout=''; base={base}; \
             for t in /proc/$pid/task/*; do \
               comm=$(cat \"$t/comm\" 2>/dev/null); \
               case \"$comm\" in \"fc_vcpu \"*) \
                 n=${{comm#fc_vcpu }}; tid=${{t##*/}}; cpu=$((base + n)); \
                 taskset -pc \"$cpu\" \"$tid\" >/dev/null 2>&1 || {{ echo \"pin vcpu $n -> cpu $cpu failed\" >&2; exit 7; }}; \
                 layout=\"$layout,\\\"vcpu$n\\\":$cpu\"; \
               ;; esac; \
             done; \
             printf '{{%s}}' \"${{layout#,}}\"",
            sock = self.sock,
            base = self.cpu_base,
        )
    }
}

impl Target for FirecrackerTarget {
    fn version(&self, sh: &dyn Shell) -> String {
        match sh.run(&format!("'{}' --version", self.bin)) {
            Ok(out) => version_token(&out),
            Err(_) => "firecracker".to_string(),
        }
    }

    fn provision(&self, sh: &dyn Shell) -> Result<(), String> {
        // Each firecracker runs in a fresh, wiped scratch cwd. A restored
        // snapshot can carry a vsock device whose host-side uds is a *relative*
        // path (Firecracker resolves it against cwd); without an isolated, wiped
        // cwd a leftover socket from the previous repeat makes the next
        // `snapshot/load` fail with EADDRINUSE, and N concurrent instances would
        // collide on one path. Def paths are absolute, so cd does not affect
        // kernel/rootfs/snapshot resolution. The pid goes to a file so teardown
        // can kill by pid rather than matching the command line (which would also
        // match the shell running the command and SIGTERM itself).
        sh.run(&self.launch_cmd())?;

        if let Some((snap, mem)) = &self.from_snapshot {
            // Streaming (M-stream): bring the FUSE mount up first, so the load and
            // any prewarm run against the mounted mem file rather than the local
            // one. The mount must be listening before snapshot/load reads it.
            let mem_path = if let Some(source) = &self.stream_source {
                sh.run(&self.launch_stream_cmd(source, mem))?;
                format!("{}/mem", self.stream_dir)
            } else {
                mem.clone()
            };
            // Set the page-cache state the restore starts from (drop caches for a
            // cold baseline, or warm a captured working set). Run before the
            // timed load so the prewarm cost is not charged to restore latency.
            if let Some(cmd) = &self.pre_restore {
                if !cmd.trim().is_empty() {
                    sh.run(cmd)?;
                }
            }
            // Streaming prewarm: pull the working set from the source into the
            // mount before loading (else the load pure-demand-faults over it).
            if let Some(source) = &self.stream_source {
                if self.stream_prefetch {
                    sh.run(&self.stream_prefetch_cmd(source))?;
                }
            }
            // Pick the memory backend. Uffd serves guest RAM from an external
            // handler (launched here, listening before load); File mmaps the mem
            // file (the mounted one under streaming). The handler must be up
            // before snapshot/load connects to it.
            let backend = if self.mem_backend == "Uffd" {
                let handler = self
                    .uffd_handler
                    .as_deref()
                    .filter(|h| !h.trim().is_empty())
                    .ok_or("mem_backend: uffd needs a uffd_handler command")?;
                let uds = self.uffd_uds();
                sh.run(&self.launch_uffd_cmd(handler, &uds, mem))?;
                json!({"backend_type": "Uffd", "backend_path": uds})
            } else {
                json!({"backend_type": "File", "backend_path": mem_path})
            };
            // Restore mode: load resumes the VM; that is the measured span.
            let body = json!({
                "snapshot_path": snap,
                "mem_backend": backend,
                "resume_vm": true,
            })
            .to_string();
            return self.timed("restore.resume_to_steady", None, || {
                self.api(sh, "PUT", "/snapshot/load", &body)
            });
        }

        // Cold-boot config.
        let machine = json!({
            "vcpu_count": self.vcpu.parse::<u64>().unwrap_or(1),
            "mem_size_mib": self.mem_mib.parse::<u64>().unwrap_or(128),
            "smt": self.smt,
        })
        .to_string();
        self.api(sh, "PUT", "/machine-config", &machine)?;

        let boot = json!({"kernel_image_path": self.kernel, "boot_args": self.boot_args}).to_string();
        self.api(sh, "PUT", "/boot-source", &boot)?;

        let drive = json!({
            "drive_id": "rootfs",
            "path_on_host": self.rootfs,
            "is_root_device": true,
            "is_read_only": false,
        })
        .to_string();
        self.api(sh, "PUT", "/drives/rootfs", &drive)?;

        // Tap networking, when asked for. Created before the API call that
        // names it, because Firecracker validates the device exists. The
        // ifindex comes from sysfs rather than parsing `ip` output.
        if let Some(tap) = &self.tap {
            sh.run(&format!(
                "ip tuntap del dev '{tap}' mode tap 2>/dev/null; \
                 ip tuntap add dev '{tap}' mode tap && ip link set dev '{tap}' up"
            ))?;
            let idx = sh.run(&format!("cat '/sys/class/net/{tap}/ifindex'"))?;
            let ifindex: u32 = idx
                .trim()
                .parse()
                .map_err(|e| format!("parsing tap '{tap}' ifindex '{}': {e}", idx.trim()))?;
            *self.tap_ifindex.borrow_mut() = Some(ifindex);
            let iface = json!({
                "iface_id": "eth0",
                "host_dev_name": tap,
                "guest_mac": self.guest_mac,
            })
            .to_string();
            self.api(sh, "PUT", "/network-interfaces/eth0", &iface)?;
        }
        Ok(())
    }

    fn start(&self, sh: &dyn Shell) -> Result<(), String> {
        // In restore mode the VM is already resumed by snapshot/load.
        if self.from_snapshot.is_some() {
            return Ok(());
        }
        self.timed("boot.vmm_ready", None, || {
            self.api(sh, "PUT", "/actions", r#"{"action_type":"InstanceStart"}"#)
        })
    }

    fn reach_steady(&self, sh: &dyn Shell) -> Result<(), String> {
        if let Some(cmd) = &self.readiness {
            if !cmd.trim().is_empty() {
                sh.run(cmd)?;
            }
        }
        // Pin vCPU threads once they exist (post start/resume) and record the
        // layout so a fully-prepped run can grade `reproducible`.
        if self.pin_threads {
            let out = sh.run(&self.pin_cmd())?;
            let layout: Value = serde_json::from_str(out.trim())
                .map_err(|e| format!("parsing pinning layout '{}': {e}", out.trim()))?;
            match layout.as_object() {
                Some(m) if !m.is_empty() => *self.pinning.borrow_mut() = Some(layout),
                _ => return Err("pin_threads requested but no fc_vcpu threads were pinned".into()),
            }
        }
        // Snapshot the steady-state VM if asked.
        if let Some((snap, mem)) = &self.snapshot_out {
            self.api(sh, "PATCH", "/vm", r#"{"state":"Paused"}"#)?;
            let body = json!({
                "snapshot_type": "Full",
                "snapshot_path": snap,
                "mem_file_path": mem,
            })
            .to_string();
            self.timed("snapshot.create", None, || {
                self.api(sh, "PUT", "/snapshot/create", &body)
            })?;
            self.api(sh, "PATCH", "/vm", r#"{"state":"Resumed"}"#)?;
        }
        Ok(())
    }

    fn spans(&self, _sh: &dyn Shell) -> Result<Vec<Value>, String> {
        Ok(self.spans.borrow().clone())
    }

    fn teardown(&self, sh: &dyn Shell) -> Result<(), String> {
        // Best effort: kill the API server by the pid recorded at launch, then
        // remove the socket/pid/log/scratch. `rm -rf` is last and always
        // succeeds, so a stale or missing pid is not fatal. Killing by pid (not
        // by command-line match) avoids SIGTERMing the shell that runs this very
        // command.
        // Also stop the uffd handler and unmount the stream FUSE mount if either
        // was set up (harmless no-ops otherwise: the pidfiles/mount do not exist
        // and `rm -rf` always succeeds). The mount is unmounted before its dir is
        // removed, and its daemon killed.
        // For a stream mount, firecracker mmaps the FUSE-backed mem, so unmount
        // has to wait for it to exit or fusermount3 reports the mount busy and
        // the dir cannot be removed. Kill it, wait for it to release, then lazy-
        // unmount (-uz detaches even if a straggler holds it). A trailing `true`
        // keeps teardown best-effort: leftover cleanup must not fail the run.
        let cmd = format!(
            "[ -f '{sock}.pid' ] && kill \"$(cat '{sock}.pid')\" 2>/dev/null; \
             [ -f '{uds}.pid' ] && kill \"$(cat '{uds}.pid')\" 2>/dev/null; \
             if [ -f '{sock}.pid' ]; then p=\"$(cat '{sock}.pid')\"; \
               for _ in $(seq 1 150); do kill -0 \"$p\" 2>/dev/null || break; sleep 0.02; done; fi; \
             fusermount3 -uz '{stream}' 2>/dev/null; \
             [ -f '{stream}.pid' ] && kill \"$(cat '{stream}.pid')\" 2>/dev/null; \
             rm -rf '{sock}' '{sock}.log' '{sock}.pid' '{sock}.d' '{uds}' '{uds}.log' '{uds}.pid' \
             '{stream}' '{stream}.log' '{stream}.pid'; \
             true",
            sock = self.sock,
            uds = self.uffd_uds(),
            stream = self.stream_dir,
        );
        sh.run(&cmd)?;

        // Best-effort tap cleanup: the VM is already gone, and a leaked tap
        // would collide with the next run on this instance index.
        if let Some(tap) = &self.tap {
            let _ = sh.run(&format!("ip tuntap del dev '{tap}' mode tap"));
        }
        Ok(())
    }

    fn pinning_layout(&self) -> Option<Value> {
        self.pinning.borrow().clone()
    }

    fn net_attribution(&self, _sh: &dyn Shell) -> Option<NetAttribution> {
        let tap = self.tap.clone()?;
        Some(NetAttribution {
            tap,
            ifindex: (*self.tap_ifindex.borrow())?,
            guest_mac: self.guest_mac.clone(),
            // Host netns. Per-VM netns is not used: the tap lives in the host
            // namespace, and netns is recorded for cross-check only.
            netns_inum: 0,
        })
    }


    fn resident_files(&self) -> Vec<(String, String)> {
        // Only a restore has a snapshot mem file to measure residency of; a cold
        // boot has none. The label is empty for a lone instance (fanout keys it
        // per instance).
        match &self.from_snapshot {
            Some((_, mem_file)) if !mem_file.is_empty() => vec![(String::new(), mem_file.clone())],
            _ => Vec::new(),
        }
    }
}

// --- qemu target ------------------------------------------------------------

/// A QEMU/KVM full-VM target (cold boot). It launches `qemu-system` with a QMP
/// control socket and times the VM up to that socket appearing
/// (`boot.vmm_ready`): the VMM is initialised and about to run the guest. Like
/// the firecracker adapter's `boot.vmm_ready`, this is a host-observable
/// marker, not guest userspace init, which an agentless vantage cannot see; an
/// optional `readiness` command bridges to a guest-ready signal when the def has
/// one. Concurrency, host-memory, and residency capture all work through the
/// generic paths, so N-sandbox QEMU runs come for free.
///
/// v0 is cold boot only: QEMU snapshot/restore (savevm/migration) and vCPU
/// pinning are not wired yet.
pub struct QemuTarget {
    bin: String,
    sock: String,
    vcpu: String,
    mem_mib: String,
    kernel: String,
    rootfs: String,
    boot_args: String,
    extra: String,
    readiness: Option<String>,
    pin_threads: bool,
    spans: RefCell<Vec<Value>>,
}

pub fn qemu_target(
    config: &BTreeMap<String, Value>,
    vars: &BTreeMap<String, String>,
    pin_threads: bool,
) -> QemuTarget {
    let g = |k: &str, d: &str| cfg(config, vars, k, d);
    let vcpu = vars.get("vcpu").cloned().unwrap_or_else(|| g("vcpu", "1"));
    let mem_mib = vars.get("mem_mib").cloned().unwrap_or_else(|| g("mem_mib", "128"));
    let pid = std::process::id();
    let inst = vars.get("instance").map(|i| format!("-{i}")).filter(|_| vars.contains_key("instance"));
    let sock = g("qmp_sock", &format!("/tmp/assayist-qemu-{pid}{}.sock", inst.unwrap_or_default()));
    QemuTarget {
        bin: g("bin", "qemu-system-x86_64"),
        sock,
        vcpu,
        mem_mib,
        kernel: g("kernel", ""),
        rootfs: g("rootfs", ""),
        boot_args: g("boot_args", "console=ttyS0 reboot=k panic=1 root=/dev/vda ro"),
        extra: g("extra_args", ""),
        readiness: config.get("readiness").map(|_| g("readiness", "")),
        pin_threads,
        spans: RefCell::new(Vec::new()),
    }
}

impl QemuTarget {
    /// Launch qemu-system in a fresh scratch cwd (wiped per launch, as the
    /// firecracker adapter does) with a QMP unix socket, backgrounded, recording
    /// its pid and waiting for the socket to appear.
    fn launch_cmd(&self) -> String {
        format!(
            "rm -f '{sock}' '{sock}.pid'; wd='{sock}.d'; rm -rf \"$wd\"; mkdir -p \"$wd\"; \
             ( cd \"$wd\" && exec '{bin}' -enable-kvm -m '{mem}' -smp '{vcpu}' \
               -kernel '{kernel}' -append '{boot_args}' \
               -drive file='{rootfs}',format=raw,if=virtio,readonly=on \
               -qmp unix:'{sock}',server,nowait -display none -serial none -no-reboot {extra} \
             ) >'{sock}.log' 2>&1 & \
             echo $! > '{sock}.pid'; \
             for _ in $(seq 1 250); do [ -S '{sock}' ] && exit 0; sleep 0.02; done; \
             echo 'qemu qmp socket did not appear' >&2; exit 1",
            sock = self.sock,
            bin = self.bin,
            mem = self.mem_mib,
            vcpu = self.vcpu,
            kernel = self.kernel,
            boot_args = self.boot_args,
            rootfs = self.rootfs,
            extra = self.extra,
        )
    }
}

impl Target for QemuTarget {
    fn version(&self, sh: &dyn Shell) -> String {
        match sh.run(&format!("'{}' --version", self.bin)) {
            Ok(out) => version_token(&out),
            Err(_) => "qemu".to_string(),
        }
    }

    fn provision(&self, sh: &dyn Shell) -> Result<(), String> {
        // The measured span is QEMU coming up to its control socket.
        let start = now_nanos();
        sh.run(&self.launch_cmd())?;
        let end = now_nanos();
        self.spans.borrow_mut().push(span("boot.vmm_ready", None, start, end));
        Ok(())
    }

    fn start(&self, _sh: &dyn Shell) -> Result<(), String> {
        // QEMU boots the guest at launch; nothing to start.
        Ok(())
    }

    fn reach_steady(&self, sh: &dyn Shell) -> Result<(), String> {
        if self.pin_threads {
            return Err("pin_threads is not supported for the qemu target yet".into());
        }
        if let Some(cmd) = &self.readiness {
            if !cmd.trim().is_empty() {
                sh.run(cmd)?;
            }
        }
        Ok(())
    }

    fn spans(&self, _sh: &dyn Shell) -> Result<Vec<Value>, String> {
        Ok(self.spans.borrow().clone())
    }

    fn teardown(&self, sh: &dyn Shell) -> Result<(), String> {
        let cmd = format!(
            "[ -f '{sock}.pid' ] && kill \"$(cat '{sock}.pid')\" 2>/dev/null; \
             rm -rf '{sock}' '{sock}.log' '{sock}.pid' '{sock}.d'",
            sock = self.sock
        );
        sh.run(&cmd).map(|_| ())
    }
}

/// A Cloud Hypervisor full-VM target (cold boot). Like the QEMU adapter it
/// launches the VMM with a control socket and times the VM up to that socket
/// appearing (`boot.vmm_ready`). Cloud Hypervisor boots the guest immediately
/// when the VM config is passed on the command line, and the `--api-socket`
/// opens the same moment, so the marker is the VMM initialising and handing off
/// to the guest, not guest userspace init (the agentless vantage cannot see
/// that; an optional `readiness` command bridges to a guest-ready signal). It
/// direct-boots an uncompressed `vmlinux`, the same kernel image the firecracker
/// adapter uses, so a firecracker-vs-CH compare shares kernel and rootfs.
/// Concurrency, host-memory, and residency capture all ride the generic paths.
///
/// v0 is cold boot only: CH snapshot/restore and vCPU pinning are not wired yet.
pub struct CloudHypervisorTarget {
    bin: String,
    sock: String,
    vcpu: String,
    mem_mib: String,
    kernel: String,
    rootfs: String,
    cmdline: String,
    extra: String,
    readiness: Option<String>,
    pin_threads: bool,
    spans: RefCell<Vec<Value>>,
}

pub fn ch_target(
    config: &BTreeMap<String, Value>,
    vars: &BTreeMap<String, String>,
    pin_threads: bool,
) -> CloudHypervisorTarget {
    let g = |k: &str, d: &str| cfg(config, vars, k, d);
    let vcpu = vars.get("vcpu").cloned().unwrap_or_else(|| g("vcpu", "1"));
    let mem_mib = vars.get("mem_mib").cloned().unwrap_or_else(|| g("mem_mib", "128"));
    let pid = std::process::id();
    let inst = vars.get("instance").map(|i| format!("-{i}")).filter(|_| vars.contains_key("instance"));
    let sock = g("api_sock", &format!("/tmp/assayist-chv-{pid}{}.sock", inst.unwrap_or_default()));
    CloudHypervisorTarget {
        bin: g("bin", "cloud-hypervisor"),
        sock,
        vcpu,
        mem_mib,
        kernel: g("kernel", ""),
        rootfs: g("rootfs", ""),
        cmdline: g("cmdline", "console=ttyS0 reboot=k panic=1 root=/dev/vda ro"),
        extra: g("extra_args", ""),
        readiness: config.get("readiness").map(|_| g("readiness", "")),
        pin_threads,
        spans: RefCell::new(Vec::new()),
    }
}

impl CloudHypervisorTarget {
    /// Launch cloud-hypervisor in a fresh scratch cwd (wiped per launch, as the
    /// firecracker and qemu adapters do), backgrounded, recording its pid and
    /// waiting for the api socket to appear. Guest console is routed into the
    /// log so a failed boot is visible.
    fn launch_cmd(&self) -> String {
        format!(
            "rm -f '{sock}' '{sock}.pid'; wd='{sock}.d'; rm -rf \"$wd\"; mkdir -p \"$wd\"; \
             ( cd \"$wd\" && exec '{bin}' --api-socket '{sock}' \
               --kernel '{kernel}' --cmdline '{cmdline}' \
               --disk path='{rootfs}',readonly=on \
               --cpus boot='{vcpu}' --memory size='{mem}'M \
               --serial tty --console off {extra} \
             ) >'{sock}.log' 2>&1 & \
             echo $! > '{sock}.pid'; \
             for _ in $(seq 1 250); do [ -S '{sock}' ] && exit 0; sleep 0.02; done; \
             echo 'cloud-hypervisor api socket did not appear' >&2; exit 1",
            sock = self.sock,
            bin = self.bin,
            kernel = self.kernel,
            cmdline = self.cmdline,
            rootfs = self.rootfs,
            vcpu = self.vcpu,
            mem = self.mem_mib,
            extra = self.extra,
        )
    }
}

impl Target for CloudHypervisorTarget {
    fn version(&self, sh: &dyn Shell) -> String {
        match sh.run(&format!("'{}' --version", self.bin)) {
            Ok(out) => version_token(&out),
            Err(_) => "cloud-hypervisor".to_string(),
        }
    }

    fn provision(&self, sh: &dyn Shell) -> Result<(), String> {
        // The measured span is CH coming up to its control socket.
        let start = now_nanos();
        sh.run(&self.launch_cmd())?;
        let end = now_nanos();
        self.spans.borrow_mut().push(span("boot.vmm_ready", None, start, end));
        Ok(())
    }

    fn start(&self, _sh: &dyn Shell) -> Result<(), String> {
        // CH boots the guest at launch; nothing to start.
        Ok(())
    }

    fn reach_steady(&self, sh: &dyn Shell) -> Result<(), String> {
        if self.pin_threads {
            return Err("pin_threads is not supported for the cloud-hypervisor target yet".into());
        }
        if let Some(cmd) = &self.readiness {
            if !cmd.trim().is_empty() {
                sh.run(cmd)?;
            }
        }
        Ok(())
    }

    fn spans(&self, _sh: &dyn Shell) -> Result<Vec<Value>, String> {
        Ok(self.spans.borrow().clone())
    }

    fn teardown(&self, sh: &dyn Shell) -> Result<(), String> {
        // Unlike firecracker/qemu, Cloud Hypervisor does not exit when the guest
        // resets: it keeps rebooting the guest and holds a flock on
        // `<api-socket>.lock`. So we must wait for it to actually die before the
        // next run reuses the socket, else CH-b fails with ApiSocketInUse while
        // CH-a is still winding down (it can be slow to answer SIGTERM while the
        // vcpu spins). SIGTERM, wait bounded for exit, SIGKILL as a backstop,
        // then remove the socket, lock, pid, log, and scratch. `rm -rf` is last
        // and always succeeds, so a stale or missing pid is not fatal.
        let cmd = format!(
            "p=\"$(cat '{sock}.pid' 2>/dev/null)\"; \
             if [ -n \"$p\" ]; then kill \"$p\" 2>/dev/null; \
               for _ in $(seq 1 250); do kill -0 \"$p\" 2>/dev/null || break; sleep 0.02; done; \
               kill -9 \"$p\" 2>/dev/null; fi; \
             rm -rf '{sock}' '{sock}.lock' '{sock}.log' '{sock}.pid' '{sock}.d'",
            sock = self.sock
        );
        sh.run(&cmd).map(|_| ())
    }
}


/// A unikernel target: boots a single self-contained unikernel image under
/// QEMU/KVM and times it up to a QMP control socket appearing as
/// `boot.vmm_ready`, the same host-observable marker the qemu and CH adapters
/// use. A unikernel is the archetypal agentless guest (one address space, no
/// userspace to log into), which is exactly the vantage assayist is built for:
/// the kvm/net gadgets see its exits and packets host-side. Two boot styles:
/// `disk` (a raw disk image, e.g. Nanos/ops output; the default) and `kernel`
/// (a multiboot/PVH kernel image via `-kernel`, e.g. Unikraft). An optional
/// `hostfwd` maps a host port to a guest port so a `readiness` probe can reach
/// the guest, the only agentless way to confirm it is actually serving.
///
/// v0 is cold boot only: no snapshot/restore, no vCPU pinning.
pub struct UnikernelTarget {
    bin: String,
    sock: String,
    mem_mib: String,
    image: String,
    disk_boot: bool,
    boot_args: String,
    hostfwd: String,
    extra: String,
    readiness: Option<String>,
    pin_threads: bool,
    spans: RefCell<Vec<Value>>,
}

pub fn unikernel_target(
    config: &BTreeMap<String, Value>,
    vars: &BTreeMap<String, String>,
    pin_threads: bool,
) -> UnikernelTarget {
    let g = |k: &str, d: &str| cfg(config, vars, k, d);
    let mem_mib = vars.get("mem_mib").cloned().unwrap_or_else(|| g("mem_mib", "256"));
    let pid = std::process::id();
    let inst = vars.get("instance").map(|i| format!("-{i}")).filter(|_| vars.contains_key("instance"));
    let sock = g("qmp_sock", &format!("/tmp/assayist-uk-{pid}{}.sock", inst.unwrap_or_default()));
    // `disk` (raw disk image, the Nanos/ops shape) is the default; `kernel`
    // boots a multiboot/PVH image via -kernel (the Unikraft shape).
    let disk_boot = !matches!(g("boot_style", "disk").as_str(), "kernel");
    UnikernelTarget {
        bin: g("bin", "qemu-system-x86_64"),
        sock,
        mem_mib,
        image: g("image", ""),
        disk_boot,
        boot_args: g("boot_args", ""),
        hostfwd: g("hostfwd", ""),
        extra: g("extra_args", ""),
        readiness: config.get("readiness").map(|_| g("readiness", "")),
        pin_threads,
        spans: RefCell::new(Vec::new()),
    }
}

impl UnikernelTarget {
    /// Launch qemu in a fresh scratch cwd (wiped per launch, as the firecracker
    /// and qemu adapters do) booting the unikernel image, backgrounded, with a
    /// QMP socket, recording its pid and waiting for the socket to appear.
    fn launch_cmd(&self) -> String {
        let boot = if self.disk_boot {
            format!(
                "-drive file='{img}',format=raw,if=none,id=hd0 -device virtio-blk-pci,drive=hd0",
                img = self.image
            )
        } else {
            format!("-kernel '{img}' -append '{args}'", img = self.image, args = self.boot_args)
        };
        // Optional user-mode networking with a host->guest port forward, so a
        // readiness probe can reach the agentless guest.
        let net = if self.hostfwd.trim().is_empty() {
            String::new()
        } else {
            format!("-netdev user,id=n0,hostfwd={} -device virtio-net-pci,netdev=n0", self.hostfwd)
        };
        format!(
            "rm -f '{sock}' '{sock}.pid'; wd='{sock}.d'; rm -rf \"$wd\"; mkdir -p \"$wd\"; \
             ( cd \"$wd\" && exec '{bin}' -machine q35 -enable-kvm -cpu host -m '{mem}' \
               {boot} {net} \
               -qmp unix:'{sock}',server,nowait -nographic -serial file:'{sock}.serial' -no-reboot {extra} \
             ) >'{sock}.log' 2>&1 & \
             echo $! > '{sock}.pid'; \
             for _ in $(seq 1 250); do [ -S '{sock}' ] && exit 0; sleep 0.02; done; \
             echo 'unikernel qmp socket did not appear' >&2; exit 1",
            sock = self.sock,
            bin = self.bin,
            mem = self.mem_mib,
            boot = boot,
            net = net,
            extra = self.extra,
        )
    }
}

impl Target for UnikernelTarget {
    fn version(&self, sh: &dyn Shell) -> String {
        match sh.run(&format!("'{}' --version", self.bin)) {
            Ok(out) => version_token(&out),
            Err(_) => "qemu".to_string(),
        }
    }

    fn provision(&self, sh: &dyn Shell) -> Result<(), String> {
        // The measured span is qemu coming up to its control socket, about to
        // run the unikernel.
        let start = now_nanos();
        sh.run(&self.launch_cmd())?;
        let end = now_nanos();
        self.spans.borrow_mut().push(span("boot.vmm_ready", None, start, end));
        Ok(())
    }

    fn start(&self, _sh: &dyn Shell) -> Result<(), String> {
        // The VMM boots the unikernel at launch; nothing to start.
        Ok(())
    }

    fn reach_steady(&self, sh: &dyn Shell) -> Result<(), String> {
        if self.pin_threads {
            return Err("pin_threads is not supported for the unikernel target yet".into());
        }
        // A unikernel has no in-guest agent, so the only steady signal is
        // host-observable: an author-supplied probe against a forwarded port.
        if let Some(cmd) = &self.readiness {
            if !cmd.trim().is_empty() {
                sh.run(cmd)?;
            }
        }
        Ok(())
    }

    fn spans(&self, _sh: &dyn Shell) -> Result<Vec<Value>, String> {
        Ok(self.spans.borrow().clone())
    }

    fn teardown(&self, sh: &dyn Shell) -> Result<(), String> {
        let cmd = format!(
            "[ -f '{sock}.pid' ] && kill \"$(cat '{sock}.pid')\" 2>/dev/null; \
             rm -rf '{sock}' '{sock}.log' '{sock}.serial' '{sock}.pid' '{sock}.d'",
            sock = self.sock
        );
        sh.run(&cmd).map(|_| ())
    }
}

// --- fio workload -----------------------------------------------------------

/// An fio job run to completion inside the capture window. `start` runs fio with
/// `--output-format=json` and stashes the output; `report` parses it into a
/// compact per-direction summary (iops, bandwidth, completion-latency mean and
/// p99). fio runs synchronously in `start` because the gadgets are already
/// spawned by then (see `adapter::execute_run`), so they observe its window.
pub struct FioWorkload {
    bin: String,
    args: Vec<String>,
    out: RefCell<Option<Value>>,
}

pub fn fio_workload(
    config: &BTreeMap<String, Value>,
    vars: &BTreeMap<String, String>,
) -> FioWorkload {
    let g = |k: &str, d: &str| cfg(config, vars, k, d);
    let args = vec![
        format!("--name={}", g("name", "assayist")),
        format!("--filename={}", g("filename", "/tmp/assayist-fio.dat")),
        format!("--rw={}", g("rw", "randread")),
        format!("--bs={}", g("bs", "4k")),
        format!("--iodepth={}", g("iodepth", "32")),
        format!("--numjobs={}", g("numjobs", "1")),
        format!("--ioengine={}", g("ioengine", "libaio")),
        format!("--direct={}", g("direct", "1")),
        format!("--size={}", g("size", "1G")),
        format!("--runtime={}", g("runtime", "30")),
        "--time_based".to_string(),
        "--output-format=json".to_string(),
    ];
    FioWorkload { bin: g("bin", "fio"), args, out: RefCell::new(None) }
}

impl Workload for FioWorkload {
    fn version(&self, sh: &dyn Shell) -> String {
        match sh.run(&format!("'{}' --version", self.bin)) {
            Ok(out) => version_token(&out),
            Err(_) => "fio".to_string(),
        }
    }

    fn start(&self, sh: &dyn Shell) -> Result<(), String> {
        let quoted: Vec<String> = self.args.iter().map(|a| format!("'{a}'")).collect();
        let out = sh.run(&format!("'{}' {}", self.bin, quoted.join(" ")))?;
        let parsed: Value = serde_json::from_str(out.trim())
            .map_err(|e| format!("parsing fio json output: {e}"))?;
        *self.out.borrow_mut() = Some(parsed);
        Ok(())
    }

    fn stop(&self, _sh: &dyn Shell) -> Result<(), String> {
        // fio ran to completion in `start`; nothing to stop.
        Ok(())
    }

    fn report(&self, _sh: &dyn Shell) -> Result<Value, String> {
        match self.out.borrow().as_ref() {
            Some(v) => Ok(fio_summary(v)),
            None => Ok(Value::Null),
        }
    }
}

/// Reduce fio JSON to a compact summary. Liberal: missing fields become null,
/// and it reads either `clat_ns` (modern) or `clat` for latency. The report is
/// opaque provenance (no grading/gating effect), so being tolerant is right.
fn fio_summary(v: &Value) -> Value {
    let job = v.get("jobs").and_then(|j| j.get(0));
    let dir = |name: &str| -> Value {
        let d = job.and_then(|j| j.get(name));
        let iops = d.and_then(|d| d.get("iops")).cloned().unwrap_or(Value::Null);
        let bw_kb = d.and_then(|d| d.get("bw")).cloned().unwrap_or(Value::Null);
        let clat = d.and_then(|d| d.get("clat_ns").or_else(|| d.get("clat")));
        let lat_mean = clat.and_then(|c| c.get("mean")).cloned().unwrap_or(Value::Null);
        let lat_p99 = clat
            .and_then(|c| c.get("percentile"))
            .and_then(|p| p.get("99.000000"))
            .cloned()
            .unwrap_or(Value::Null);
        json!({"iops": iops, "bw_kb_s": bw_kb, "clat_ns_mean": lat_mean, "clat_ns_p99": lat_p99})
    };
    json!({
        "driver": "fio",
        "fio_version": v.get("fio version").or_else(|| v.get("fio_version")).cloned().unwrap_or(Value::Null),
        "read": dir("read"),
        "write": dir("write"),
    })
}

// --- wrk workload -----------------------------------------------------------

/// An HTTP load test run to completion inside the capture window. Like fio,
/// `start` runs wrk synchronously (the gadgets are already spawned) and stashes
/// its stdout; `report` parses the text summary into requests/sec, transfer/sec,
/// average/max latency, and total requests. wrk has no native JSON output, so
/// the parse is text-based and liberal (missing fields become null). The report
/// is opaque provenance, no grading effect.
pub struct WrkWorkload {
    bin: String,
    args: Vec<String>,
    out: RefCell<Option<String>>,
}

pub fn wrk_workload(
    config: &BTreeMap<String, Value>,
    vars: &BTreeMap<String, String>,
) -> WrkWorkload {
    let g = |k: &str, d: &str| cfg(config, vars, k, d);
    let mut args = vec![
        format!("-t{}", g("threads", "2")),
        format!("-c{}", g("connections", "10")),
        format!("-d{}s", g("duration", "30")),
        "--latency".to_string(),
    ];
    // Optional constant request rate (wrk2-style) and Lua script.
    if config.contains_key("rate") {
        args.push(format!("-R{}", g("rate", "")));
    }
    if config.contains_key("script") {
        args.push(format!("-s{}", g("script", "")));
    }
    args.push(g("url", "http://127.0.0.1:8080/"));
    WrkWorkload { bin: g("bin", "wrk"), args, out: RefCell::new(None) }
}

impl Workload for WrkWorkload {
    fn version(&self, sh: &dyn Shell) -> String {
        // wrk prints its version to stderr and exits non-zero, so `run` reports
        // an error; fall back to the driver name rather than a bogus version.
        match sh.run(&format!("'{}' --version 2>&1", self.bin)) {
            Ok(out) => version_token(&out),
            Err(_) => "wrk".to_string(),
        }
    }

    fn start(&self, sh: &dyn Shell) -> Result<(), String> {
        let quoted: Vec<String> = self.args.iter().map(|a| format!("'{a}'")).collect();
        let out = sh.run(&format!("'{}' {}", self.bin, quoted.join(" ")))?;
        *self.out.borrow_mut() = Some(out);
        Ok(())
    }

    fn stop(&self, _sh: &dyn Shell) -> Result<(), String> {
        // wrk ran to completion in `start`; nothing to stop.
        Ok(())
    }

    fn report(&self, _sh: &dyn Shell) -> Result<Value, String> {
        match self.out.borrow().as_ref() {
            Some(text) => Ok(wrk_summary(text)),
            None => Ok(Value::Null),
        }
    }
}

/// Parse wrk's text summary. Liberal: any field it cannot find stays null.
fn wrk_summary(text: &str) -> Value {
    // "Requests/sec:  8123.40" / "Transfer/sec:   1.23MB"
    let after_colon = |label: &str| -> Option<String> {
        text.lines()
            .find(|l| l.trim_start().starts_with(label))
            .and_then(|l| l.split(':').nth(1))
            .map(|s| s.trim().to_string())
    };
    let req_per_sec = after_colon("Requests/sec")
        .and_then(|s| s.parse::<f64>().ok())
        .map(|f| json!(f))
        .unwrap_or(Value::Null);
    let transfer_per_sec = after_colon("Transfer/sec").map(Value::String).unwrap_or(Value::Null);

    // "    Latency   1.23ms   0.45ms   10.50ms   80.00%": avg is the first
    // whitespace token after the "Latency" label.
    let latency_field = |label: &str, idx: usize| -> Value {
        text.lines()
            .find(|l| l.trim_start().starts_with(label))
            .and_then(|l| l.trim_start().strip_prefix(label))
            .and_then(|rest| rest.split_whitespace().nth(idx))
            .map(|s| Value::String(s.to_string()))
            .unwrap_or(Value::Null)
    };

    // "  81234 requests in 10.00s, 12.34MB read"
    let total_requests = text
        .lines()
        .find(|l| l.contains("requests in"))
        .and_then(|l| l.split_whitespace().next())
        .and_then(|s| s.parse::<u64>().ok())
        .map(|n| json!(n))
        .unwrap_or(Value::Null);

    json!({
        "driver": "wrk",
        "requests_per_sec": req_per_sec,
        "transfer_per_sec": transfer_per_sec,
        "latency_avg": latency_field("Latency", 0),
        "latency_max": latency_field("Latency", 2),
        "total_requests": total_requests,
    })
}

// --- vsock workload ---------------------------------------------------------

/// Drives an agentless guest over Firecracker's host-side vsock socket. For each
/// invocation it opens the uds, issues the Firecracker `CONNECT <port>`
/// handshake, optionally sends a payload, and drains the guest's response to EOF.
/// The connection itself is the invocation (that is how a snapshot-restored
/// function server is triggered), so this exercises the guest's working set
/// inside the capture window rather than letting it sit idle. `report` gives the
/// invocation count, error count, and a latency summary; timings are wall-clock
/// round-trips measured host-side.
///
/// The uds is the firecracker adapter's per-run vsock path. Because the adapter
/// runs each restore in a `{api_sock}.d` scratch cwd and the guest's uds is
/// relative (`fn.vsock`), a def coordinates the two: set a fixed `api_sock` on
/// the target and point `uds` at `{that}.d/{relative-name}`.
pub struct VsockWorkload {
    uds: String,
    port: u32,
    invocations: u32,
    payload: Vec<u8>,
    timeout: Duration,
    latencies_ns: RefCell<Vec<u128>>,
    errors: RefCell<u32>,
}

pub fn vsock_workload(
    config: &BTreeMap<String, Value>,
    vars: &BTreeMap<String, String>,
) -> VsockWorkload {
    let g = |k: &str, d: &str| cfg(config, vars, k, d);
    VsockWorkload {
        uds: g("uds", ""),
        port: g("port", "5252").parse().unwrap_or(5252),
        invocations: g("invocations", "50").parse().unwrap_or(50),
        payload: g("payload", "").into_bytes(),
        timeout: Duration::from_millis(g("timeout_ms", "5000").parse().unwrap_or(5000)),
        latencies_ns: RefCell::new(Vec::new()),
        errors: RefCell::new(0),
    }
}

impl VsockWorkload {
    /// One invocation: connect, CONNECT handshake, optional payload, drain the
    /// response to EOF. Returns the host-side round-trip.
    fn invoke_once(&self) -> Result<Duration, String> {
        let t0 = Instant::now();
        let mut stream =
            UnixStream::connect(&self.uds).map_err(|e| format!("connect {}: {e}", self.uds))?;
        stream.set_read_timeout(Some(self.timeout)).map_err(|e| format!("read timeout: {e}"))?;
        stream.set_write_timeout(Some(self.timeout)).map_err(|e| format!("write timeout: {e}"))?;
        writeln!(stream, "CONNECT {}", self.port).map_err(|e| format!("CONNECT: {e}"))?;
        let mut reader =
            BufReader::new(stream.try_clone().map_err(|e| format!("clone stream: {e}"))?);
        // Firecracker replies "OK <host_port>\n" once the guest accepts.
        let mut line = String::new();
        reader.read_line(&mut line).map_err(|e| format!("read OK: {e}"))?;
        if !line.starts_with("OK ") {
            return Err(format!("vsock CONNECT {} rejected: {line:?}", self.port));
        }
        if !self.payload.is_empty() {
            stream.write_all(&self.payload).map_err(|e| format!("write payload: {e}"))?;
        }
        // The guest treats the connection as the request, writes its response,
        // then closes: draining to EOF makes the round-trip include the
        // working-set touch.
        let mut resp = Vec::new();
        reader.read_to_end(&mut resp).map_err(|e| format!("read response: {e}"))?;
        Ok(t0.elapsed())
    }
}

impl Workload for VsockWorkload {
    fn version(&self, _sh: &dyn Shell) -> String {
        "vsock".to_string()
    }

    fn start(&self, _sh: &dyn Shell) -> Result<(), String> {
        if self.uds.trim().is_empty() {
            return Err("vsock workload needs a 'uds' (the firecracker host vsock socket)".into());
        }
        // Retry the first invocation until the guest is accepting or the timeout
        // is up: a just-resumed guest may not have re-bound its listener yet.
        // Once it answers, the remaining invocations run back to back.
        let deadline = Instant::now() + self.timeout;
        let mut last_err = String::new();
        let first = loop {
            match self.invoke_once() {
                Ok(d) => break Some(d),
                Err(e) => {
                    last_err = e;
                    if Instant::now() >= deadline {
                        break None;
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
            }
        };
        match first {
            Some(d) => self.latencies_ns.borrow_mut().push(d.as_nanos()),
            None => return Err(format!("vsock first invocation failed: {last_err}")),
        }
        for _ in 1..self.invocations {
            match self.invoke_once() {
                Ok(d) => self.latencies_ns.borrow_mut().push(d.as_nanos()),
                Err(_) => *self.errors.borrow_mut() += 1,
            }
        }
        Ok(())
    }

    fn stop(&self, _sh: &dyn Shell) -> Result<(), String> {
        Ok(())
    }

    fn report(&self, _sh: &dyn Shell) -> Result<Value, String> {
        Ok(vsock_summary(&self.latencies_ns.borrow(), *self.errors.borrow(), self.invocations))
    }
}

/// Summarise vsock invocation round-trips. Percentiles are nearest-rank on the
/// sorted samples; an all-failed run reports zero invocations and the error count.
fn vsock_summary(latencies_ns: &[u128], errors: u32, requested: u32) -> Value {
    if latencies_ns.is_empty() {
        return json!({"driver": "vsock", "invocations": 0, "requested": requested, "errors": errors});
    }
    let mut sorted = latencies_ns.to_vec();
    sorted.sort_unstable();
    let n = sorted.len();
    let sum: u128 = sorted.iter().sum();
    let pct = |p: f64| -> u64 {
        let idx = ((p * (n as f64 - 1.0)).round() as usize).min(n - 1);
        sorted[idx] as u64
    };
    json!({
        "driver": "vsock",
        "invocations": n,
        "requested": requested,
        "errors": errors,
        "latency_avg_ns": (sum / n as u128) as u64,
        "latency_p50_ns": pct(0.50),
        "latency_p99_ns": pct(0.99),
        "latency_max_ns": sorted[n - 1] as u64,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::HashMap;

    struct FakeShell {
        seen: RefCell<Vec<String>>,
        replies: HashMap<String, String>,
    }
    impl FakeShell {
        fn new() -> FakeShell {
            FakeShell { seen: RefCell::new(vec![]), replies: HashMap::new() }
        }
        fn reply(mut self, needle: &str, out: &str) -> FakeShell {
            self.replies.insert(needle.to_string(), out.to_string());
            self
        }
        fn saw(&self, needle: &str) -> bool {
            self.seen.borrow().iter().any(|c| c.contains(needle))
        }
        fn first_containing(&self, needle: &str) -> Option<String> {
            self.seen.borrow().iter().find(|c| c.contains(needle)).cloned()
        }
    }
    impl Shell for FakeShell {
        fn run(&self, cmd: &str) -> Result<String, String> {
            self.seen.borrow_mut().push(cmd.to_string());
            for (needle, out) in &self.replies {
                if cmd.contains(needle) {
                    return Ok(out.clone());
                }
            }
            Ok(String::new())
        }
    }

    fn config(pairs: &[(&str, Value)]) -> BTreeMap<String, Value> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.clone())).collect()
    }

    fn vars(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn version_token_extracts_the_number() {
        assert_eq!(version_token("Firecracker v1.7.0\nfoo"), "v1.7.0");
        assert_eq!(version_token("fio-3.36"), "fio-3.36");
        assert_eq!(version_token("fio 3.36"), "3.36");
    }

    #[test]
    fn firecracker_cold_boot_configures_then_starts() {
        let cfg = config(&[
            ("kernel", json!("/k/vmlinux")),
            ("rootfs", json!("/k/rootfs.ext4")),
        ]);
        let t = firecracker_target(&cfg, &vars(&[("vcpu", "2"), ("mem_mib", "512")]), false);
        let sh = FakeShell::new();

        t.provision(&sh).unwrap();
        t.start(&sh).unwrap();
        t.reach_steady(&sh).unwrap();

        assert!(sh.saw("--api-sock"));
        assert!(sh.saw("/machine-config"));
        assert!(sh.saw("\"vcpu_count\":2"));
        assert!(sh.saw("\"mem_size_mib\":512"));
        assert!(sh.saw("/boot-source"));
        assert!(sh.saw("/k/vmlinux"));
        assert!(sh.saw("/drives/rootfs"));
        assert!(sh.saw("InstanceStart"));

        let spans = t.spans(&sh).unwrap();
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0]["name"], "boot.vmm_ready");
        assert!(spans[0]["end_unix_nano"].as_u64() >= spans[0]["start_unix_nano"].as_u64());
    }

    #[test]
    fn firecracker_restore_mode_loads_and_skips_start() {
        let cfg = config(&[
            ("from_snapshot", json!("/s/snap")),
            ("mem_file", json!("/s/mem")),
        ]);
        let t = firecracker_target(&cfg, &vars(&[]), false);
        let sh = FakeShell::new();

        t.provision(&sh).unwrap();
        t.start(&sh).unwrap();

        assert!(sh.saw("/snapshot/load"));
        assert!(sh.saw("\"resume_vm\":true"));
        assert!(!sh.saw("InstanceStart"));
        assert!(!sh.saw("/machine-config"));

        let spans = t.spans(&sh).unwrap();
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0]["name"], "restore.resume_to_steady");
    }

    #[test]
    fn firecracker_resident_files_only_for_restore() {
        // A restore exposes its snapshot mem file for residency; a cold boot has
        // none.
        let restore = firecracker_target(
            &config(&[("from_snapshot", json!("/s/snap")), ("mem_file", json!("/s/mem"))]),
            &vars(&[]),
            false,
        );
        assert_eq!(restore.resident_files(), vec![(String::new(), "/s/mem".to_string())]);

        let cold = firecracker_target(
            &config(&[("kernel", json!("/k")), ("rootfs", json!("/r"))]),
            &vars(&[]),
            false,
        );
        assert!(cold.resident_files().is_empty());
    }

    #[test]
    fn firecracker_default_socket_carries_the_instance_index() {
        let base = firecracker_target(&config(&[("from_snapshot", json!("/s"))]), &vars(&[]), false);
        let sh = FakeShell::new();
        base.provision(&sh).unwrap();
        assert!(sh.seen.borrow().iter().any(|c| c.contains("assayist-fc-") && !c.contains(".sock-")));

        let mut v = vars(&[]);
        v.insert("instance".into(), "2".into());
        let inst = firecracker_target(&config(&[("from_snapshot", json!("/s"))]), &v, false);
        let sh2 = FakeShell::new();
        inst.provision(&sh2).unwrap();
        // The per-instance socket is discriminated so concurrent instances of
        // one def do not collide.
        assert!(sh2.seen.borrow().iter().any(|c| c.contains("-2.sock")));
    }

    #[test]
    fn firecracker_uffd_launches_handler_and_loads_uffd_backend() {
        let cfg = config(&[
            ("from_snapshot", json!("/s/snap")),
            ("mem_file", json!("/s/mem")),
            ("api_sock", json!("/tmp/p.sock")),
            ("mem_backend", json!("uffd")),
            ("uffd_handler", json!("reap --uds {uffd_uds} --mem {mem_file} ondemand")),
        ]);
        let t = firecracker_target(&cfg, &vars(&[]), false);
        let sh = FakeShell::new();
        t.provision(&sh).unwrap();

        let seen = sh.seen.borrow();
        // The handler is launched on the derived uffd socket, with mem_file
        // substituted, before the snapshot load...
        assert!(seen.iter().any(|c| c.contains("reap --uds /tmp/p.sock.uffd --mem /s/mem ondemand")));
        // ...and the load uses the Uffd backend pointing at that socket.
        assert!(seen.iter().any(|c| c.contains("/snapshot/load") && c.contains("\"backend_type\":\"Uffd\"") && c.contains("/tmp/p.sock.uffd")));
    }

    #[test]
    fn firecracker_uffd_without_handler_is_an_error() {
        let cfg = config(&[
            ("from_snapshot", json!("/s/snap")),
            ("mem_file", json!("/s/mem")),
            ("mem_backend", json!("uffd")),
        ]);
        let t = firecracker_target(&cfg, &vars(&[]), false);
        let sh = FakeShell::new();
        assert!(t.provision(&sh).unwrap_err().contains("uffd_handler"));
    }

    #[test]
    fn firecracker_streaming_mounts_then_loads_against_the_mount() {
        // Prewarm arm: mount the FUSE source, stream-prefetch, then load File
        // against the mounted mem (not the local one).
        let cfg = config(&[
            ("from_snapshot", json!("/s/snap")),
            ("mem_file", json!("/s/mem")),
            ("stream_source", json!("file:///s/mem")),
            ("stream_bin", json!("/b/bpfoliod")),
            ("stream_wsmeta", json!("/s/reap.wsmeta")),
            ("stream_prefetch", json!("stream")),
        ]);
        let t = firecracker_target(&cfg, &vars(&[]), false);
        let sh = FakeShell::new();
        t.provision(&sh).unwrap();

        assert!(sh.saw("stream-mount"), "should launch the FUSE mount");
        assert!(sh.saw("stream-prefetch"), "prewarm arm should stream-prefetch");
        // The load's mem backend path is the mounted file, not the local mem.
        let load = sh.first_containing("/snapshot/load").expect("loaded");
        assert!(load.contains(".stream.") && load.contains("/mem"), "load should target the mounted mem: {load}");
    }

    #[test]
    fn firecracker_streaming_demand_arm_skips_prefetch() {
        let cfg = config(&[
            ("from_snapshot", json!("/s/snap")),
            ("mem_file", json!("/s/mem")),
            ("stream_source", json!("file:///s/mem")),
            ("stream_bin", json!("/b/bpfoliod")),
            ("stream_prefetch", json!("nostream")),
        ]);
        let t = firecracker_target(&cfg, &vars(&[]), false);
        let sh = FakeShell::new();
        t.provision(&sh).unwrap();
        assert!(sh.saw("stream-mount"), "demand arm still mounts");
        assert!(!sh.saw("stream-prefetch"), "demand arm must not prewarm");
    }

    #[test]
    fn qemu_provision_launches_kvm_and_records_boot_span() {
        let cfg = config(&[
            ("kernel", json!("/k/vmlinux")),
            ("rootfs", json!("/r/root.ext4")),
            ("qmp_sock", json!("/tmp/q.sock")),
        ]);
        let t = qemu_target(&cfg, &vars(&[("vcpu", "2"), ("mem_mib", "512")]), false);
        let sh = FakeShell::new();
        t.provision(&sh).unwrap();
        t.start(&sh).unwrap();

        let launch = sh.first_containing("qmp").expect("launched");
        assert!(launch.contains("-enable-kvm"));
        assert!(launch.contains("-smp '2'") && launch.contains("-m '512'"));
        assert!(launch.contains("-kernel '/k/vmlinux'"));
        assert!(launch.contains("file='/r/root.ext4'"));
        assert!(launch.contains("-qmp unix:'/tmp/q.sock'"));

        let spans = t.spans(&sh).unwrap();
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0]["name"], "boot.vmm_ready");
    }

    #[test]
    fn qemu_default_socket_carries_the_instance_index() {
        let mut v = vars(&[]);
        v.insert("instance".into(), "3".into());
        let t = qemu_target(&config(&[("kernel", json!("/k"))]), &v, false);
        let sh = FakeShell::new();
        t.provision(&sh).unwrap();
        assert!(sh.seen.borrow().iter().any(|c| c.contains("-3.sock")));
    }

    #[test]
    fn qemu_pinning_is_rejected_for_now() {
        let t = qemu_target(&config(&[("kernel", json!("/k"))]), &vars(&[]), true);
        let sh = FakeShell::new();
        t.provision(&sh).unwrap();
        assert!(t.reach_steady(&sh).unwrap_err().contains("pin_threads"));
    }

    #[test]
    fn ch_provision_launches_vmm_and_records_boot_span() {
        let cfg = config(&[
            ("kernel", json!("/k/vmlinux")),
            ("rootfs", json!("/r/root.ext4")),
            ("api_sock", json!("/tmp/ch.sock")),
        ]);
        let t = ch_target(&cfg, &vars(&[("vcpu", "2"), ("mem_mib", "512")]), false);
        let sh = FakeShell::new();
        t.provision(&sh).unwrap();
        t.start(&sh).unwrap();

        let launch = sh.first_containing("api-socket").expect("launched");
        assert!(launch.contains("--api-socket '/tmp/ch.sock'"));
        assert!(launch.contains("--cpus boot='2'") && launch.contains("--memory size='512'M"));
        assert!(launch.contains("--kernel '/k/vmlinux'"));
        assert!(launch.contains("--disk path='/r/root.ext4',readonly=on"));

        let spans = t.spans(&sh).unwrap();
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0]["name"], "boot.vmm_ready");
    }

    #[test]
    fn ch_default_socket_carries_the_instance_index() {
        let mut v = vars(&[]);
        v.insert("instance".into(), "3".into());
        let t = ch_target(&config(&[("kernel", json!("/k"))]), &v, false);
        let sh = FakeShell::new();
        t.provision(&sh).unwrap();
        assert!(sh.seen.borrow().iter().any(|c| c.contains("-3.sock")));
    }

    #[test]
    fn ch_pinning_is_rejected_for_now() {
        let t = ch_target(&config(&[("kernel", json!("/k"))]), &vars(&[]), true);
        let sh = FakeShell::new();
        t.provision(&sh).unwrap();
        assert!(t.reach_steady(&sh).unwrap_err().contains("pin_threads"));
    }

    #[test]
    fn unikernel_disk_boot_uses_a_raw_virtio_drive() {
        let cfg = config(&[("image", json!("/img/hello-uk")), ("qmp_sock", json!("/tmp/uk.sock"))]);
        let t = unikernel_target(&cfg, &vars(&[("mem_mib", "256")]), false);
        let sh = FakeShell::new();
        t.provision(&sh).unwrap();
        t.start(&sh).unwrap();

        let launch = sh.first_containing("qmp").expect("launched");
        assert!(launch.contains("-drive file='/img/hello-uk',format=raw"));
        assert!(launch.contains("virtio-blk-pci"));
        assert!(!launch.contains("-kernel"));
        assert!(launch.contains("-qmp unix:'/tmp/uk.sock'"));

        let spans = t.spans(&sh).unwrap();
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0]["name"], "boot.vmm_ready");
    }

    #[test]
    fn unikernel_kernel_boot_uses_dash_kernel() {
        let cfg = config(&[
            ("image", json!("/img/unikraft")),
            ("boot_style", json!("kernel")),
            ("boot_args", json!("netdev.ip=...")),
        ]);
        let t = unikernel_target(&cfg, &vars(&[]), false);
        let sh = FakeShell::new();
        t.provision(&sh).unwrap();
        let launch = sh.first_containing("qmp").expect("launched");
        assert!(launch.contains("-kernel '/img/unikraft'"));
        assert!(launch.contains("-append 'netdev.ip=...'"));
        assert!(!launch.contains("virtio-blk-pci"));
    }

    #[test]
    fn unikernel_hostfwd_adds_user_networking() {
        let with = unikernel_target(
            &config(&[("image", json!("/i")), ("hostfwd", json!("tcp::18080-:8080"))]),
            &vars(&[]),
            false,
        );
        let sh = FakeShell::new();
        with.provision(&sh).unwrap();
        let launch = sh.first_containing("qmp").expect("launched");
        assert!(launch.contains("hostfwd=tcp::18080-:8080"));
        assert!(launch.contains("virtio-net-pci"));

        // No hostfwd => no networking flags.
        let without = unikernel_target(&config(&[("image", json!("/i"))]), &vars(&[]), false);
        let sh2 = FakeShell::new();
        without.provision(&sh2).unwrap();
        assert!(!sh2.first_containing("qmp").unwrap().contains("netdev"));
    }

    #[test]
    fn unikernel_default_socket_carries_the_instance_index() {
        let mut v = vars(&[]);
        v.insert("instance".into(), "2".into());
        let t = unikernel_target(&config(&[("image", json!("/i"))]), &v, false);
        let sh = FakeShell::new();
        t.provision(&sh).unwrap();
        assert!(sh.seen.borrow().iter().any(|c| c.contains("-2.sock")));
    }

    #[test]
    fn unikernel_pinning_is_rejected_for_now() {
        let t = unikernel_target(&config(&[("image", json!("/i"))]), &vars(&[]), true);
        let sh = FakeShell::new();
        t.provision(&sh).unwrap();
        assert!(t.reach_steady(&sh).unwrap_err().contains("pin_threads"));
    }

    #[test]
    fn firecracker_pre_restore_runs_before_load_not_in_span() {
        let cfg = config(&[
            ("from_snapshot", json!("/s/snap")),
            ("mem_file", json!("/s/mem")),
            ("pre_restore", json!("warm-the-working-set")),
        ]);
        let t = firecracker_target(&cfg, &vars(&[]), false);
        let sh = FakeShell::new();
        t.provision(&sh).unwrap();

        let seen = sh.seen.borrow();
        let warm = seen.iter().position(|c| c.contains("warm-the-working-set"));
        let load = seen.iter().position(|c| c.contains("/snapshot/load"));
        assert!(warm.is_some() && load.is_some(), "both ran");
        assert!(warm < load, "prewarm runs before the load");
        // The prewarm is outside the timed span: only the load is a span.
        let spans = t.spans(&sh).unwrap();
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0]["name"], "restore.resume_to_steady");
    }

    #[test]
    fn firecracker_launches_in_a_wiped_scratch_cwd() {
        // A vsock-bearing snapshot binds a relative host uds; each restore must
        // run in a fresh, wiped cwd so a leftover socket cannot collide.
        let cfg = config(&[("kernel", json!("/k/vmlinux")), ("rootfs", json!("/r/rootfs"))]);
        let t = firecracker_target(&cfg, &vars(&[]), false);
        let sh = FakeShell::new();
        t.provision(&sh).unwrap();
        let launch = sh.first_containing("--api-sock").expect("launch ran");
        assert!(launch.contains("rm -rf \"$wd\""), "scratch cwd is wiped: {launch}");
        assert!(launch.contains("cd \"$wd\""), "fc runs in scratch cwd: {launch}");

        t.teardown(&sh).unwrap();
        assert!(sh.saw(".sock.d"), "teardown removes the scratch dir");
    }

    #[test]
    fn firecracker_snapshot_out_pauses_creates_resumes() {
        let cfg = config(&[
            ("kernel", json!("/k/vmlinux")),
            ("rootfs", json!("/k/rootfs.ext4")),
            ("snapshot_out", json!("/s/snap")),
            ("snapshot_mem", json!("/s/mem")),
        ]);
        let t = firecracker_target(&cfg, &vars(&[]), false);
        let sh = FakeShell::new();

        t.provision(&sh).unwrap();
        t.start(&sh).unwrap();
        t.reach_steady(&sh).unwrap();

        assert!(sh.saw("\"state\":\"Paused\""));
        assert!(sh.saw("/snapshot/create"));
        assert!(sh.saw("\"state\":\"Resumed\""));

        let names: Vec<String> =
            t.spans(&sh).unwrap().iter().map(|s| s["name"].as_str().unwrap().to_string()).collect();
        assert!(names.contains(&"boot.vmm_ready".to_string()));
        assert!(names.contains(&"snapshot.create".to_string()));
    }

    #[test]
    fn firecracker_pins_vcpu_threads_and_records_layout() {
        let cfg = config(&[
            ("kernel", json!("/k/vmlinux")),
            ("rootfs", json!("/k/rootfs.ext4")),
            ("api_sock", json!("/tmp/p.sock")),
        ]);
        let t = firecracker_target(&cfg, &vars(&[("vcpu", "2")]), true);
        // The pin command reads the launch pidfile and tasksets threads; the
        // fake returns the layout it "applied".
        let sh = FakeShell::new().reply("taskset", r#"{"vcpu0":0,"vcpu1":1}"#);

        t.provision(&sh).unwrap();
        t.start(&sh).unwrap();
        t.reach_steady(&sh).unwrap();

        assert!(sh.saw("taskset"));
        assert!(sh.saw("/tmp/p.sock.pid"));
        assert!(sh.saw("fc_vcpu"));
        assert_eq!(t.pinning_layout(), Some(json!({"vcpu0": 0, "vcpu1": 1})));
    }

    #[test]
    fn firecracker_cpu_base_offsets_the_pinning() {
        // A concurrent instance is given a cpu_base so its vCPUs pin above the
        // earlier instances' CPUs instead of colliding on CPU 0.
        let cfg = config(&[("kernel", json!("/k/v")), ("rootfs", json!("/k/r"))]);
        let t = firecracker_target(&cfg, &vars(&[("vcpu", "2"), ("cpu_base", "4")]), true);
        let sh = FakeShell::new().reply("taskset", r#"{"vcpu0":4,"vcpu1":5}"#);
        t.provision(&sh).unwrap();
        t.start(&sh).unwrap();
        t.reach_steady(&sh).unwrap();
        assert!(sh.saw("base=4"), "pin command carries the cpu base");
        assert_eq!(t.pinning_layout(), Some(json!({"vcpu0": 4, "vcpu1": 5})));
    }

    #[test]
    fn firecracker_no_pin_records_no_layout() {
        let cfg = config(&[("kernel", json!("/k/v")), ("rootfs", json!("/k/r"))]);
        let t = firecracker_target(&cfg, &vars(&[]), false);
        let sh = FakeShell::new();
        t.provision(&sh).unwrap();
        t.start(&sh).unwrap();
        t.reach_steady(&sh).unwrap();
        assert!(!sh.saw("taskset"));
        assert_eq!(t.pinning_layout(), None);
    }

    #[test]
    fn firecracker_pin_with_no_vcpu_threads_errors() {
        let cfg = config(&[("kernel", json!("/k/v")), ("rootfs", json!("/k/r"))]);
        let t = firecracker_target(&cfg, &vars(&[]), true);
        // No vcpu threads found -> pin command prints an empty object.
        let sh = FakeShell::new().reply("taskset", "{}");
        t.provision(&sh).unwrap();
        t.start(&sh).unwrap();
        assert!(t.reach_steady(&sh).is_err());
    }

    #[test]
    fn firecracker_teardown_kills_by_pidfile_not_cmdline() {
        let t = firecracker_target(&config(&[("api_sock", json!("/tmp/x.sock"))]), &vars(&[]), false);
        let sh = FakeShell::new();
        t.teardown(&sh).unwrap();
        // Kills by the recorded pid and cleans up; must NOT match on the
        // command line (that would SIGTERM the shell running the command).
        assert!(sh.saw("/tmp/x.sock.pid"));
        assert!(sh.saw("kill"));
        assert!(sh.saw("rm -rf '/tmp/x.sock'"));
        assert!(!sh.saw("pkill"));
    }

    #[test]
    fn fio_start_builds_command_and_reports_summary() {
        let out = r#"{
            "fio version": "fio-3.36",
            "jobs": [{
                "jobname": "assayist",
                "read": {"iops": 25600.5, "bw": 102400,
                         "clat_ns": {"mean": 3000.0, "percentile": {"99.000000": 9000}}},
                "write": {"iops": 0.0, "bw": 0,
                          "clat_ns": {"mean": 0.0, "percentile": {"99.000000": 0}}}
            }]
        }"#;
        let cfg = config(&[
            ("filename", json!("/dev/{dev}")),
            ("rw", json!("randread")),
            ("bs", json!("8k")),
        ]);
        let w = fio_workload(&cfg, &vars(&[("dev", "nvme0n1")]));
        let sh = FakeShell::new().reply("--output-format=json", out);

        w.start(&sh).unwrap();
        w.stop(&sh).unwrap();

        assert!(sh.saw("--filename=/dev/nvme0n1")); // param rendered
        assert!(sh.saw("--bs=8k"));
        assert!(sh.saw("--rw=randread"));

        let rep = w.report(&sh).unwrap();
        assert_eq!(rep["driver"], "fio");
        assert_eq!(rep["fio_version"], "fio-3.36");
        assert_eq!(rep["read"]["iops"], 25600.5);
        assert_eq!(rep["read"]["bw_kb_s"], 102400);
        assert_eq!(rep["read"]["clat_ns_mean"], 3000.0);
        assert_eq!(rep["read"]["clat_ns_p99"], 9000);
    }

    #[test]
    fn fio_report_is_null_before_a_run() {
        let w = fio_workload(&config(&[]), &vars(&[]));
        let sh = FakeShell::new();
        assert_eq!(w.report(&sh).unwrap(), Value::Null);
    }

    #[test]
    fn fio_version_falls_back_when_unavailable() {
        let w = fio_workload(&config(&[]), &vars(&[]));
        // FakeShell returns empty string (never errors), so version_token yields "".
        let sh = FakeShell::new().reply("--version", "fio-3.36");
        assert_eq!(w.version(&sh), "fio-3.36");
    }

    #[test]
    fn wrk_start_builds_command_and_reports_summary() {
        let out = "Running 10s test @ http://127.0.0.1:8080/\n\
             \x20 2 threads and 10 connections\n\
             \x20 Thread Stats   Avg      Stdev     Max   +/- Stdev\n\
             \x20   Latency     1.23ms    0.45ms   10.50ms   80.00%\n\
             \x20   Req/Sec     4.10k     0.50k     5.00k    75.00%\n\
             \x20 Latency Distribution\n\
             \x20    50%    1.10ms\n\
             \x20 81234 requests in 10.00s, 12.34MB read\n\
             Requests/sec:   8123.40\n\
             Transfer/sec:      1.23MB\n";
        let cfg = config(&[
            ("url", json!("http://{host}:8080/")),
            ("threads", json!("4")),
            ("connections", json!("100")),
            ("duration", json!("5")),
        ]);
        let w = wrk_workload(&cfg, &vars(&[("host", "10.0.0.5")]));
        // Reply keyed on a substring of the wrk command line (the rendered url).
        let sh = FakeShell::new().reply("http://10.0.0.5:8080/", out);

        w.start(&sh).unwrap();
        w.stop(&sh).unwrap();

        assert!(sh.saw("-t4"));
        assert!(sh.saw("-c100"));
        assert!(sh.saw("-d5s"));
        assert!(sh.saw("http://10.0.0.5:8080/")); // param rendered

        let rep = w.report(&sh).unwrap();
        assert_eq!(rep["driver"], "wrk");
        assert_eq!(rep["requests_per_sec"], 8123.40);
        assert_eq!(rep["transfer_per_sec"], "1.23MB");
        assert_eq!(rep["latency_avg"], "1.23ms");
        assert_eq!(rep["latency_max"], "10.50ms");
        assert_eq!(rep["total_requests"], 81234);
    }

    #[test]
    fn wrk_report_is_null_before_a_run() {
        let w = wrk_workload(&config(&[("url", json!("http://x/"))]), &vars(&[]));
        let sh = FakeShell::new();
        assert_eq!(w.report(&sh).unwrap(), Value::Null);
    }

    #[test]
    fn wrk_rate_and_script_are_optional_flags() {
        let base = wrk_workload(&config(&[("url", json!("http://x/"))]), &vars(&[]));
        let sh = FakeShell::new();
        base.start(&sh).unwrap();
        assert!(!sh.saw("-R"));
        assert!(!sh.saw("-s"));

        let withopts = wrk_workload(
            &config(&[("url", json!("http://x/")), ("rate", json!("2000")), ("script", json!("/s.lua"))]),
            &vars(&[]),
        );
        let sh2 = FakeShell::new();
        withopts.start(&sh2).unwrap();
        assert!(sh2.saw("-R2000"));
        assert!(sh2.saw("-s/s.lua"));
    }

    #[test]
    fn vsock_summary_reports_percentiles_and_average() {
        // 10 samples 1000..10000 ns.
        let lat: Vec<u128> = (1..=10).map(|i| i as u128 * 1000).collect();
        let r = vsock_summary(&lat, 2, 12);
        assert_eq!(r["invocations"], 10);
        assert_eq!(r["requested"], 12);
        assert_eq!(r["errors"], 2);
        assert_eq!(r["latency_avg_ns"], 5500);
        assert_eq!(r["latency_max_ns"], 10000);
        assert_eq!(r["latency_p50_ns"], 6000); // nearest-rank idx round(0.5*9)=5 -> 6000
        assert_eq!(r["latency_p99_ns"], 10000);
    }

    #[test]
    fn vsock_summary_with_no_samples_is_zero() {
        let r = vsock_summary(&[], 5, 5);
        assert_eq!(r["invocations"], 0);
        assert_eq!(r["errors"], 5);
        assert!(r.get("latency_avg_ns").is_none());
    }

    #[test]
    fn vsock_start_without_uds_is_an_error() {
        let w = vsock_workload(&config(&[("port", json!("5252"))]), &vars(&[]));
        let sh = FakeShell::new();
        let err = w.start(&sh).unwrap_err();
        assert!(err.contains("uds"), "{err}");
    }

    fn fc_config() -> BTreeMap<String, Value> {
        config(&[("kernel", json!("/k/vmlinux")), ("rootfs", json!("/k/rootfs.ext4"))])
    }

    #[test]
    fn firecracker_without_network_creates_no_tap() {
        // The default is unchanged behaviour: no tap, nothing to attribute.
        let sh = FakeShell::new();
        let target = firecracker_target(&fc_config(), &BTreeMap::new(), false);
        target.provision(&sh).unwrap();
        assert!(!sh.saw("/network-interfaces"));
        assert!(!sh.saw("ip tuntap add"));
        assert!(target.net_attribution(&sh).is_none());
    }

    #[test]
    fn firecracker_with_tap_networking_creates_configures_and_reports_it() {
        let sh = FakeShell::new().reply("/sys/class/net/", "7\n");
        let mut cfg = fc_config();
        cfg.insert("network".to_string(), json!("tap"));
        let mut v = vars(&[]);
        v.insert("instance".to_string(), "2".to_string());
        let target = firecracker_target(&cfg, &v, false);
        target.provision(&sh).unwrap();

        // Tap created and brought up before the API call that references it.
        assert!(sh.saw("ip tuntap add"), "tap must be created");
        assert!(sh.saw("ip link set"), "tap must be brought up");
        // Firecracker told about the device, with the deterministic mac.
        assert!(sh.saw("/network-interfaces"));
        assert!(sh.saw("host_dev_name"));
        assert!(sh.saw("02:00:00:00:00:02"), "guest mac derives from the instance");

        let attrib = target.net_attribution(&sh).expect("tap networking reports attribution");
        assert_eq!(attrib.guest_mac, "02:00:00:00:00:02");
        assert!(attrib.tap.contains('2'), "tap name carries the instance: {}", attrib.tap);
    }

    #[test]
    fn firecracker_teardown_deletes_the_tap() {
        // provision's own tap command already contains a guard `ip tuntap del`
        // (it clears a possible stale device before `add`), so a bare
        // `sh.saw("ip tuntap del")` after teardown would pass even if teardown
        // issued no delete at all. Count occurrences instead: teardown must add
        // exactly one more over what provision already left behind.
        let sh = FakeShell::new().reply("/sys/class/net/", "7\n");
        let mut cfg = fc_config();
        cfg.insert("network".to_string(), json!("tap"));
        let target = firecracker_target(&cfg, &BTreeMap::new(), false);
        target.provision(&sh).unwrap();

        let before = sh.seen.borrow().iter().filter(|c| c.contains("ip tuntap del")).count();
        target.teardown(&sh).unwrap();
        let after = sh.seen.borrow().iter().filter(|c| c.contains("ip tuntap del")).count();
        assert_eq!(after, before + 1, "teardown must issue its own tap delete, not just reuse provision's guard delete");
    }
}
