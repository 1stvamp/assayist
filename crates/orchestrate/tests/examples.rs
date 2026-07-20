// SPDX-FileCopyrightText: 2026 Wesley Mason (1stvamp)
// SPDX-License-Identifier: Apache-2.0
//! Guard: every committed `examples/*.assay.yaml` must parse, validate, and
//! expand cleanly. `assayist inspect` does exactly that (and observes the host
//! read-only), so we run it over each example and assert it succeeds. This is
//! what catches a def-vs-parser drift like a capture entry growing a key the
//! parser does not accept, before it reaches a doc or a consumer.
//!
//! It drives the real binary rather than the parser directly, because the crate
//! is a binary with no library target (same as the pipeline test).

#![cfg(unix)]

use std::path::PathBuf;
use std::process::Command;

fn examples_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples")
}

#[test]
fn committed_example_defs_parse_and_validate() {
    let bin = PathBuf::from(env!("CARGO_BIN_EXE_assayist"));
    let dir = examples_dir();

    let mut checked = 0;
    for entry in std::fs::read_dir(&dir).expect("read examples dir") {
        let path = entry.expect("dir entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("yaml") {
            continue;
        }
        if !path.to_string_lossy().ends_with(".assay.yaml") {
            continue;
        }
        let out = Command::new(&bin)
            .arg("inspect")
            .arg(&path)
            .output()
            .expect("run assayist inspect");
        assert!(
            out.status.success(),
            "inspect failed for {}:\n{}",
            path.display(),
            String::from_utf8_lossy(&out.stderr)
        );
        checked += 1;
    }

    assert!(checked > 0, "no *.assay.yaml examples found in {}", dir.display());
}
