# CLAUDE.md (Assayist)

Project instructions for an agent working in this repo. Complements the global `~/.claude/CLAUDE.md`; where they overlap, the global one wins on personal style.

## Voice (for any prose: READMEs, docs, comments, commits)

- BLUF: lead with the answer, no preamble.
- No em dashes or en dashes anywhere. Use colons, parentheses, commas, full stops.
- British spelling (serialise, behaviour, aggregate, licence as noun).
- Banned vocabulary: leverage, robust, seamless, delve, passionate, and similar AI-smell words. No balanced-antithesis constructions, no neat closing one-liners, no metaphor flourishes.
- Terse and technically precise. Parenthetical asides are fine.
- Name what a thing will NOT do, honestly. Every gadget README has a "Limits" section; keep that habit.

## Engineering stance

- Root-cause before patch. If a fix needs a design change, say so and make it, do not paper over.
- Measure, do not assert. The whole project's credibility rests on the observer-effect self-metrics being real. Never claim low overhead without the `ProbeCost` numbers to back it.
- Prefer working outputs over clarifying questions. If a reasonable assumption unblocks you, state it inline and proceed.
- Verify against primary sources (kernel docs, project repos, papers), not aggregators.
- Do not reproduce external copyrighted text; cite sources by name.

## Contract discipline (most important)

- The metric contract (`docs/contract-v0.md`, `contract/assay-run.schema.json`) is load-bearing and expensive to change once published. Read it before touching the schema.
- On unreleased v0, additive changes (new enum values, new optional fields) are fine and expected as gadgets reveal needed vocabulary. Retyping or removing a field is a breaking change; avoid it.
- Producer strict, consumer liberal: the orchestrator and `contract` crate build runs strictly (missing core fingerprint field = error). The gate reads runs liberally (tolerant JSON) so it can grade a slightly-off record rather than refuse it. Keep this split.
- Every `MetricSeries` must declare a cardinality class; there is no `unbounded`. Reject unbounded at load, not at write.

## Work tracking

- Track all outstanding work, bugs, and deferred scope as GitHub issues on this repo (`gh issue create` / `gh issue list`), not in a checked-in file. There is no `TODO.md` and no `HANDOFF.md`; do not recreate them.
- When you flag a bug or defer scope, open an issue: a clear title, and a body that states the problem, where it lives (file/path), and any workaround already in place. Reference or close the issue from the commit or PR that resolves it.
- Session pickup / handoff notes are ephemeral: keep them in the conversation, do not commit them to the repo.

## Build model

- Workspace core (`crates/contract`, `crates/gate`, `crates/orchestrate`, `crates/otlp`) builds anywhere: `cargo build`, `cargo test`. Keep tests green.
- eBPF gadgets (`capture/*`) are excluded from the workspace. They need a BTF-enabled Linux host with clang + bpftool. Generate `vmlinux.h` once per host (see each gadget README). The orchestrator invokes them as subprocess binaries emitting JSON fragments, not as linked crates.
- Gadget userspace targets libbpf-rs 0.24; the prog-info call goes through libbpf-sys directly because the safe wrapper shape varies by version. Expect minor API drift on other point releases.

## Licence

- Userspace: Apache-2.0. eBPF objects (`capture/*/src/bpf/*.bpf.c`): GPL-2.0 (tracing helpers require it). Per-file SPDX headers are authoritative. Keep them on every new file.
- The two LICENSE files carry the canonical Apache-2.0 and GPL-2.0 texts (filled). Keep them verbatim; the split is expressed per-file via SPDX headers, not by editing the licence texts.

## Testing

- `cargo test` across the core must stay green.
- The gate has a reproducible scenario suite: `scripts/verify-gate.sh` regenerates synthetic runs and checks all six verdicts and exit codes. Run it after touching the gate.
