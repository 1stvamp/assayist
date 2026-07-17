#!/usr/bin/env bash
# Assemble a release tarball for distribution: the assayist orchestrator plus
# every capture gadget, under bin/, so a consumer can pull it with one mise
# entry (github backend). The eBPF gadgets are CO-RE, so a binary
# built here relocates against the host's /sys/kernel/btf/vmlinux at load and
# runs on any same-arch BTF host, no rebuild.
#
# Binaries must already be built:
#   cargo build --release            # assayist (orchestrator) + assayist-gate
#   for g in kvm block net ctrlplane resident; do
#     cargo build --release --manifest-path "capture/$g/Cargo.toml"
#   done
#
# Env: DIST (output dir, default ./dist).
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
arch="$(uname -m)"
name="assayist-${arch}-linux"
dist="${DIST:-$root/dist}"
stage="$dist/.stage"

# The orchestrator (assayist) shells out to the gate (assayist-gate) for the A/B
# permutation, so both workspace binaries ship, plus every capture gadget.
core="assayist assayist-gate"
gadgets="kvm block net ctrlplane resident"

# Fail early with a clear message if a binary is missing, rather than shipping a
# partial tarball.
missing=0
for b in $core; do
  [ -x "$root/target/release/$b" ] || { echo "missing target/release/$b" >&2; missing=1; }
done
for g in $gadgets; do
  [ -x "$root/capture/$g/target/release/assayist-capture-$g" ] ||
    { echo "missing capture/$g/target/release/assayist-capture-$g" >&2; missing=1; }
done
[ "$missing" -eq 0 ] || { echo "build the release binaries first (see this script's header)" >&2; exit 1; }

rm -rf "$stage"
mkdir -p "$stage/bin"
for b in $core; do
  cp "$root/target/release/$b" "$stage/bin/"
done
for g in $gadgets; do
  cp "$root/capture/$g/target/release/assayist-capture-$g" "$stage/bin/"
done

# Archive root is `bin/` (no arch-named wrapper dir), so a consumer's
# `bin_path = "bin"` is portable across arches.
tar -C "$stage" -czf "$dist/$name.tar.gz" bin
( cd "$dist" && sha256sum "$name.tar.gz" > "$name.tar.gz.sha256" )
rm -rf "$stage"

echo "packaged $dist/$name.tar.gz"
tar -tzf "$dist/$name.tar.gz"
