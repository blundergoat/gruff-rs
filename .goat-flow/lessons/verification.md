---
category: verification
last_reviewed: 2026-05-22
---

## Lesson: Shell Wrapper Path Resolution Must Pass Shellcheck

**Created:** 2026-05-16

When adding POSIX shell entrypoint wrappers, do not copy the `CDPATH= cd ...`
idiom without checking it. Shellcheck reports SC1007 because the assignment-like
prefix is easy to misread.

Use a command-substitution form that clears `CDPATH` inside the subshell:
`SCRIPT_DIR="$(unset CDPATH; cd -- "$(dirname -- "$PRG")" && pwd)"`.

## Lesson: Analyzer Fixes Need A Focused Re-Scan

**Created:** 2026-05-16

When fixing findings reported by gruff itself, run a focused analyzer scan before
declaring victory. A performance fix can move code enough to create a different
finding, such as a function-length error from adding local setup inside the
target function.

If a fix introduces setup data, prefer module-level constants or small helpers
over adding bulky local tables to an already near-threshold function.

## Lesson: Calibration Fixes Must Update Fixture Contracts

**Created:** 2026-05-16

When changing analyzer rule semantics, rerun the full unit suite after targeted
calibration tests. A desired rule behavior change can invalidate fixture-count
contracts, and the first failing assertion may poison the shared analysis lock
so later failures look unrelated.

After fixing the first semantic mismatch, rerun the full suite before diagnosing
the lock-poison follow-on failures.

## Lesson: Negative Performance Experiments Must Be Reverted

**Created:** 2026-05-17

When optimizing analyzer hot paths, measure each candidate with
`GRUFF_PERF_ITERS=3 bash scripts/test-performance.sh` before keeping it. A
plausible allocation-sharing change can regress both wall time and RSS.

If a candidate makes the `src.*` scenarios slower or noisier, revert only that
candidate and keep the measured wins. Finish with `bash scripts/preflight-checks.sh` plus a
default `bash scripts/test-performance.sh` run so the final diff has both
correctness and performance evidence.

## Lesson: Clippy Shape Failures Deserve Design Fixes

**Created:** 2026-05-18

When a late verification pass catches a structural Clippy failure, do not add an
allow just to finish the milestone. In M31, threading suppression state pushed
`src/analysis.rs` (search: `fn build_report`) over the argument-count limit; bundling
the summaries and SARIF-only suppressed findings into a small state struct kept
the pipeline explicit and lint-clean.

## Lesson: Regex Match Starts Can Hide Useful Source Lines

**Created:** 2026-05-18

When testing regex-driven findings, include patterns with leading whitespace
such as `(?m)^\s*//`. Rust `regex` treats `\s` as newline-capable, so the match
may start before the visible token and report the wrong line if the analyzer
uses `match.start()` directly.

For source diagnostics, compute the displayed line from the first
non-whitespace byte inside the match when that exists, then rerun the focused
scope test before continuing with broader gates.

## Lesson: New Scenario Tests Can Trip Dogfood File-Length Gates

**Created:** 2026-05-22

When adding scenario coverage to an already large test module, check the
project dogfood thresholds before assuming the full suite is enough. In M52, a
new discovery glob test made `src/tests/scenarios/smoke.rs` exceed the
`size.file-length` warning threshold even though the Rust tests passed.

Prefer a focused scenario module such as `src/tests/scenarios/discovery.rs`
when new coverage is cohesive. Then rerun `bash scripts/preflight-checks.sh` so
the dogfood scan proves the repository still clears its own quality gate.
