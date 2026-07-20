# QEMU, Cloud Hypervisor, and unikernels

The host-side capture plane is VMM-agnostic: the same kvm gadget captures a full
VM, a Cloud Hypervisor guest, or a unikernel unchanged, because it watches KVM on
the host. These three adapters cold-boot their guests and time up to a
host-observable readiness marker (`boot.vmm_ready`), the same span name the
firecracker adapter records for InstanceStart. Per-key config is in
[`../config-reference.md`](../config-reference.md).

## Full VMs (QEMU)

`target.adapter: qemu` cold-boots a QEMU/KVM full VM (`-kernel`/`-drive`, a QMP
control socket), timing the VM up to that socket appearing as `boot.vmm_ready`.
That is a host-observable marker, not guest userspace init, which the agentless
vantage cannot see; an optional `readiness` command bridges to a guest-ready
signal. It is v0: cold boot only (QEMU savevm/migration restore and vCPU pinning
are not wired yet).

```yaml
target:
  adapter: qemu
  config:
    kernel: "{def_dir}/../vmlinux"
    rootfs: "{def_dir}/../rootfs.ext4"
    boot_args: "console=ttyS0 root=/dev/vda ro"
```

The same kvm gadget captured a QEMU guest's exits (HLT, MSR_WRITE, CR_ACCESS,
...) unchanged. A full VM is chattier than a microVM, so on this host the kvm
probe ran just over its default 0.01-core budget and the run graded
`contaminated`, the observer-effect check doing its job; raise the gadget's
`--budget` for a full VM. Concurrency (`instances`), the host-memory delta, and
residency all work through the generic paths, so N-sandbox QEMU runs come for
free.

## Full VMs (Cloud Hypervisor)

`target.adapter: cloud-hypervisor` (alias `chv`) cold-boots a Cloud Hypervisor
VM, timing it up to its `--api-socket` appearing as `boot.vmm_ready`, the same
host-observable marker the qemu adapter uses. It direct-boots an uncompressed
`vmlinux`, the same kernel image the firecracker adapter takes, so a
firecracker-vs-CH or qemu-vs-CH compare shares kernel and rootfs. It is v0: cold
boot only (CH snapshot/restore and vCPU pinning are not wired yet).

```yaml
target:
  adapter: cloud-hypervisor
  config:
    bin: "{def_dir}/../cloud-hypervisor"
    kernel: "{def_dir}/../vmlinux-guest"
    rootfs: "{def_dir}/../rootfs.ext4"
    cmdline: "console=ttyS0 root=/dev/vda ro"
```

**Note**: the boot-args key here is `cmdline`, not `boot_args`. Unlike
firecracker and qemu, CH does not exit when the guest resets: it keeps rebooting
the guest and holds a flock on `<api-socket>.lock`, so teardown waits for the
process to die before the next run reuses the socket (else a repeat run fails with
`ApiSocketInUse`). Validated: CH v53.0 booted the firecracker `vmlinux` + `.ext4`
rootfs, `boot.vmm_ready` ~47ms, and the kvm gadget captured its exits
(IO_INSTRUCTION, EPT_VIOLATION, HLT, MSR_WRITE, ...) unchanged, a third VMM
through the same capture plane.

## Unikernels

`target.adapter: unikernel` boots a single self-contained unikernel image under
QEMU/KVM, timing it up to a QMP socket appearing as `boot.vmm_ready`. A unikernel
is the archetypal agentless guest, one address space with no userspace to log
into, which is exactly the vantage assayist is built for: the kvm/net gadgets see
it host-side without an in-guest agent. Two boot styles: `disk` (a raw disk
image, e.g. Nanos/`ops` output; the default) and `kernel` (a multiboot/PVH image
via `-kernel`, e.g. Unikraft). An optional `hostfwd` maps a host port to a guest
port so a `readiness` probe can reach the guest, the only agentless way to confirm
it is actually serving.

```yaml
target:
  adapter: unikernel
  config:
    image: /path/to/unikernel-image      # raw disk (Nanos) by default
    hostfwd: "tcp::18080-:8080"           # optional host->guest port forward
    readiness: "curl -sf --max-time 1 http://127.0.0.1:18080/ >/dev/null"
```

Validated: a Nanos unikernel (a static Go HTTP server, built with `ops`) booted
under qemu-kvm, `boot.vmm_ready` ~52ms, the readiness probe reached its forwarded
port, and the kvm gadget captured its exits (MSR_WRITE, HLT, IO_INSTRUCTION,
...). It is far quieter than a full-VM or microVM boot (~1.5k exits vs tens of
thousands), the small single-purpose guest showing through the capture. v0 is
cold boot only (no snapshot/restore, no vCPU pinning).
