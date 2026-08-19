#!/usr/bin/env bash
# Cut a release from a BTF + KVM host: build the orchestrator, the gate, and
# every capture gadget, package them (scripts/package-release.sh), create the GitHub
# release with the tarball. Consumers then pull the whole set with one mise
# entry (github backend); see the README.
#
# Releases are cut locally, not in CI, because the gadgets compile against this
# host's BTF and stock GitHub runners have no KVM tracepoint structs
# (trace_event_raw_kvm_exit) in their kernel BTF. Any BTF-enabled host with KVM,
# clang, and bpftool can cut one; the resulting binaries are CO-RE and run on any
# same-arch BTF host.
#
# Usage: scripts/release.sh vX.Y.Z     (or VERSION=vX.Y.Z scripts/release.sh)
#        DRY_RUN=1 scripts/release.sh vX.Y.Z    # build + package, no publish
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

version="${1:-${VERSION:-}}"
[ -n "$version" ] || { echo "usage: $0 vX.Y.Z" >&2; exit 1; }
case "$version" in v*) ;; *) version="v$version" ;; esac

echo "building orchestrator + gate..."
cargo build --release
# Lint the gadgets before building them for release. They are excluded from the
# workspace, so CI's `cargo clippy --workspace` never sees them; this is where
# gadget warnings get caught (set -e aborts the release on any).
echo "linting capture gadgets (clippy -D warnings)..."
for g in kvm block net ctrlplane resident netattrib; do
  cargo clippy --manifest-path "capture/$g/Cargo.toml" --all-targets -- -D warnings
done
echo "building capture gadgets..."
for g in kvm block net ctrlplane resident netattrib; do
  cargo build --release --manifest-path "capture/$g/Cargo.toml"
done

bash scripts/package-release.sh

if [ "${DRY_RUN:-0}" = 1 ]; then
  echo "DRY_RUN set: built dist/, skipping the GitHub release"
  exit 0
fi

echo "creating GitHub release $version..."
gh release create "$version" \
  dist/assayist-*.tar.gz dist/assayist-*.tar.gz.sha256 \
  --title "$version" --generate-notes
echo "released $version"
