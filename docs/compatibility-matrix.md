# Compatibility matrix

The eBPF gadgets are CO-RE (compile once, run everywhere) via BTF, so field
offsets relocate across kernels automatically. What does not relocate is a
field or struct that gets renamed or removed. Those are listed here per gadget,
with the kernel floor and the failure mode. CO-RE fails loudly at load if a
relocation cannot be resolved (it does not read garbage), so a break shows up
as a clear load error, not a wrong number.

The `resident` gadget is the exception to everything below: it is pure userspace
(mmap + `mincore`), no BPF and no BTF, so none of the kernel-floor or capability
requirements here apply to it. It builds and runs on any Linux with a `/proc`.
This matrix covers the four eBPF gadgets only.

## Shared floor (the eBPF gadgets)

| Requirement | Kernel | Note |
|---|---|---|
| BTF (`CONFIG_DEBUG_INFO_BTF=y`) | 5.2+ practically | Needed for CO-RE and `tp_btf`. |
| BPF ring buffer | 5.8 | Not currently used by these gadgets (all aggregate in maps), listed for future. |
| `bpf_enable_stats(RUN_TIME)` | 5.8 | Powers the self-metrics (`ProbeCost`). Without it, cost fields read zero. |
| `CAP_BPF` + `CAP_PERFMON` | 5.8 | Else run as root. |

## assayist-capture-kvm

| Dependency | Kernel | Failure mode |
|---|---|---|
| `trace_event_raw_kvm_exit.exit_reason` (CO-RE) | broad | Load error if the field is renamed. The one field this gadget depends on. |
| `tracepoint/kvm/kvm_exit`, `kvm_entry` | broad | Standard KVM tracepoints. |
| VMX vs SVM exit-code space | n/a | Numeric `exit_reason` differs by vendor; the loader picks the name table from `/proc/cpuinfo` (Intel VMX vs AMD SVM), numeric fallback otherwise. |

`kvm_entry` reads no formatted field (keys on the current tid), so it is immune
to tracepoint layout changes.

## assayist-capture-block

| Dependency | Kernel | Failure mode |
|---|---|---|
| `trace_event_raw_block_rq` (issue: `dev`, `sector`, `bytes`, `rwbs`) | broad | Load error if renamed. |
| `trace_event_raw_block_rq_completion` (`dev`, `sector`) | current naming | Pre-4.x used a different struct name; load error on very old kernels. |

## assayist-capture-net

| Dependency | Kernel | Failure mode |
|---|---|---|
| `xdp_md.ingress_ifindex`, `xdp_md.data`/`data_end` | broad | Core XDP context. |
| tun/tap XDP support | ~4.14 | XDP attach on the tap fails without it. Native where supported, else generic (slower). |
| `__sk_buff.ifindex`/`len` (tc egress) | broad | Only used with `--tx`. |
| clsact qdisc for tc egress | 4.5 | `--tx` sets it up; existing clsact reused. |

## assayist-capture-ctrlplane

| Dependency | Kernel | Failure mode |
|---|---|---|
| `tp_btf/sched_wakeup`, `sched_wakeup_new`, `sched_switch` | broad | `BPF_PROG` reads args by position; `sched_switch` gained a `prev_state` arg ~5.14 which is ignored safely. |
| `task_struct -> cgroups -> dfl_cgrp -> kn -> id` (CO-RE) | 5.5 | cgroup v2 id. Load error if the chain changes. |
| `name_to_handle_at` cgroup id (userspace) | cgroup v2 | Assumes the kernfs handle's first 8 bytes are the id. If wrong, use `--cgroup-id` with a literal from `bpftool cgroup tree`. |

## How to extend

When you bring up a gadget on a new kernel, run it once against a known
workload and confirm the numbers are sane. If a CO-RE relocation fails at load,
the error names the field; add a note here and, if needed, a `bpf_core_read`
fallback keyed on kernel version.
