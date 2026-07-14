# assayist-capture-net

Host-side per-tap packet and byte counters plus packet-size histograms, emitted as an AssayRun fragment.

Each Firecracker microVM owns a tap, so the interface is a reliable per-guest key at density. Counting runs at XDP (RX) and optionally tc egress (TX), sharing one per-ifindex map, so a single program set covers thousands of taps.

## What it captures

- `net.tap_rx_packets` / `net.tap_rx_bytes`: monotonic counters, keyed by interface name.
- `net.tap_rx_packet_size`: explicit-bucket histogram (bounds 64/128/256/512/1024/1500/9000 bytes).
- `net.tap_tx_*`: the same for egress, only when `--tx` is set.
- `self_metrics`: XDP program cost as `attach_kind: xdp`, tc program as `attach_kind: tc`.

## Direction

Stated from the tap's point of view, because that is what the kernel hooks see:

- **tap RX** (XDP) = host receives on the tap = **guest egress** (guest sent it).
- **tap TX** (tc egress) = host transmits on the tap = **guest ingress** (headed into the guest).

So `net.tap_rx_bytes` is how much the guest is sending. Keep this mapping in mind reading the numbers.

## Run

```
# XDP RX only, every interface named tap*
sudo ./target/release/assayist-capture-net --duration 30 --iface-prefix tap

# both directions, explicit interfaces
sudo ./target/release/assayist-capture-net --tx --iface fc-tap0 --iface fc-tap1 --out net-fragment.json
```

Build and kernel requirements match the other gadgets (BTF kernel, clang + bpftool, `vmlinux.h` generated once). The tap driver needs XDP support (tun/tap has it on modern kernels).

## Limits (be honest)

- **XDP on tap** attaches in native mode where the tap supports it, else generic (slower). If attach fails, check the tap driver and kernel. The gadget does not silently fall back without telling you.
- **tc egress setup** creates a clsact qdisc on each interface. `--tx` is off by default because it touches qdisc state; only turn it on when you want guest-ingress numbers. Existing clsact is reused, not clobbered.
- **Size, not latency.** This gadget counts and sizes packets; it does not measure per-packet or RTT latency (that needs flow tracking, a separate concern). Throughput = bytes / window from the counters.
- **cgroup vs tap.** Per-guest keying assumes one tap per guest, which holds for Firecracker. A bridged or shared-interface setup collapses guests onto one key.

## Licence

eBPF object GPL-2.0, userspace Apache-2.0, same split as the other gadgets.
