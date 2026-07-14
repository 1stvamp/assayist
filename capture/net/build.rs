// SPDX-License-Identifier: Apache-2.0
use std::env;
use std::path::PathBuf;

use libbpf_cargo::SkeletonBuilder;

const SRC: &str = "src/bpf/net.bpf.c";

fn main() {
    let mut out = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR must be set by cargo"));
    out.push("net.skel.rs");

    SkeletonBuilder::new()
        .source(SRC)
        // Generate vmlinux.h once:
        //   bpftool btf dump file /sys/kernel/btf/vmlinux format c > src/bpf/vmlinux.h
        .build_and_generate(&out)
        .expect("bpf skeleton build failed (need clang, bpftool, and a BTF vmlinux.h)");

    println!("cargo:rerun-if-changed={SRC}");
    println!("cargo:rerun-if-changed=src/bpf/net.h");
    println!("cargo:rerun-if-changed=src/bpf/vmlinux.h");
}
