---
category: performance
last_reviewed: 2026-08-22
---

## Pattern: Measure Analyzer Hot Paths Before Rewriting Semantics

**Context:** Use this when `scripts/test-performance.sh` points at analyzer runtime, especially the `src.*` scenarios.

**Evidence:** On 2026-05-17, `src.json` median time moved from about `0.4789s` before optimization to `0.1571s` on the final default harness run. The largest wins came from caching static regex compilation and replacing repeated per-match prefix line scans. On 2026-05-22, replacing repeated dead-code identifier regex rescans with a project identifier count index in `src/project/mod.rs` (search: `identifier_counts`) and `src/analyse_project/dead_code.rs` moved the final harness to `src.json` median `0.1340s` and `large-corpus.json` median `0.1387s` with no finding identity diff for the targeted rule.

**Approach:** First isolate whether the cost moves with rule/config toggles, then prefer behavior-preserving mechanical optimizations such as caching static `Regex` values with `OnceLock` in `src/built_in_rules/mod.rs` (search: `static CYCLOMATIC_COMPLEXITY_REGEX`), replacing repeated prefix scans with a per-source line-start index in `src/parser/mod.rs` (search: `fn byte_line_from_starts`), and pre-indexing project-wide facts when a rule asks the same question for many candidates. Preserve fingerprints by diffing sorted finding identity rows before and after the change. Re-run `GRUFF_PERF_ITERS=3 bash scripts/test-performance.sh` for before/after evidence and a focused self-scan such as `cargo run --quiet -- analyse src --format json --fail-on none --no-baseline`. Keep failed experiments out of the diff: a later attempt to reuse one masked Rust source across function blocks raised `src.*` median time and RSS, so measurement should decide whether allocation-sharing ideas stay.

## Pattern: Degrade deep source analysis and bind its performance baseline

**Created:** 2026-08-22

**Evidence:** ACTUAL_MEASURED

**Context:** Rust's scan cost grew about 2.5 times per synthetic file-size doubling and exceeded the 120-second calibration ceiling at 4 MB. Bounding deep work prevents that failure mode, but skipping the file would also drop raw-text secret checks.

**Approach:** Apply the paired line/byte test in `src/project/mod.rs` (search: `bounded_deep_scan_diagnostic`) only to Rust source. Produce an analysis unit with source text, `bounded_deep_scan: true`, and a non-fatal diagnostic but no parsed Rust syntax. Text rules consult that state in `src/built_in_rules/text_rules.rs` while AST-backed and non-text custom rules decline the unit. Keep config/CLI precedence atomic in `src/config.rs` (search: `apply_deep_scan_budget_override`).

**Measurement integrity:** `scripts/test-performance.sh` rebuilds with `cargo build --release --locked`, records host, Git, runtime-source, release-binary, and harness identities, and writes `scripts/performance-baselines/linux-x86_64.json`. Its runtime-source and binary digests match the source-bound M11 cohort build.

**Verification:** `src/tests/scenarios/smoke.rs` (search: `deep_scan_budget_honours_both_boundaries_disable_and_source_classification`) protects both bounds, disable behavior, and source classification; `src/tests/config_and_selectors/config.rs` (search: `deep_scan_budget_loads_valid_config_and_cli_wins_atomically`) protects precedence.
