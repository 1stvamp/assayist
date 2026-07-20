# Guides

Worked walkthroughs of the feature surface, one topic each. For the exhaustive
key/flag list see [`../config-reference.md`](../config-reference.md); for the
record shape see [`../contract-v0.md`](../contract-v0.md).

- [`comparing-configs.md`](comparing-configs.md): the `compare` A/B axis, so one
  `assayist run` gates a stock config against a variant (not two builds).
- [`snapshot-restore.md`](snapshot-restore.md): the firecracker restore path,
  the feature set bpfolio exercises: driving an agentless guest over vsock, the
  host-memory delta, per-guest snapshot residency, concurrent sandboxes, file vs
  userfaultfd backends, and streaming restore over a FUSE mount.
- [`other-vmms.md`](other-vmms.md): cold-booting full VMs (qemu, cloud-hypervisor)
  and unikernels through the same VMM-agnostic capture plane.
