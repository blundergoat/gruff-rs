---
category: verification
last_reviewed: 2026-05-17
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
candidate and keep the measured wins. Finish with `bash scripts/check.sh` plus a
default `bash scripts/test-performance.sh` run so the final diff has both
correctness and performance evidence.
