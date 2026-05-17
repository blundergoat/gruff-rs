---
category: performance
last_reviewed: 2026-05-17
---

## Pattern: Measure Analyzer Hot Paths Before Rewriting Semantics

**Context:** Use this when `scripts/test-performance.sh` points at analyzer runtime, especially the `src.*` scenarios.

**Evidence:** On 2026-05-17, `src.json` median time moved from about `0.4789s` before optimization to `0.1571s` on the final default harness run. The largest wins came from caching static regex compilation and replacing repeated per-match prefix line scans.

**Approach:** First isolate whether the cost moves with rule/config toggles, then prefer behavior-preserving mechanical optimizations such as caching static `Regex` values with `OnceLock` in `src/main.rs` (search: `static CYCLOMATIC_COMPLEXITY_REGEX`) and replacing repeated prefix scans with a per-source line-start index (search: `fn byte_line_from_starts`) before changing rule semantics, fingerprints, schemas, fixtures, or baselines. Re-run `GRUFF_PERF_ITERS=3 bash scripts/test-performance.sh` for before/after evidence and a focused self-scan such as `cargo run --quiet -- analyse src --format json --fail-on none --no-baseline`. Keep failed experiments out of the diff: a later attempt to reuse one masked Rust source across function blocks raised `src.*` median time and RSS, so measurement should decide whether allocation-sharing ideas stay.
