---
category: verification
last_reviewed: 2026-05-24
---

## Lesson: New Rules Need A Deep Scan Against An External Repo Before Shipping

**Created:** 2026-05-24

Calibration fixtures prove a rule fires on the shape it was designed for and stays silent on a controlled negative. They cannot reveal what shapes the rule *also* fires on in real codebases — code idioms the rule author never considered. Before declaring a new default-on rule ready, run it against at least one repository outside the gruff-rs source tree and classify every finding TP/FP by reading the source.

**Concrete example (this repo, 2026-05-24):** Ten new rules landed with passing calibration and a clean dogfood scan on gruff-rs itself (14 total findings, all reviewable). A second scan against a sibling Tauri project (`/home/devgoat/projects/devgoat`) surfaced 130 findings from the same rules, including:

- 30 `security.path-traversal-candidate` findings, ~30% false positives from idioms gruff-rs's own code didn't exercise (hardcoded loop iterators over `["a", "b", "c"]`, sanitised filenames named `safe`, internal `&Path` utility helpers).
- 66 `docs.missing-param-doc` findings on `#[tauri::command]` functions whose rustdoc described the *action* (user-facing summary) without enumerating params by identifier.
- A semantic false positive class where rustdoc describes a parameter by what-it-represents ("WSL UNC path") rather than by its identifier (`working_dir`).

None of these patterns existed in gruff-rs's own source. Calibration was green; dogfood was acceptable. The rules looked ready. They weren't.

**How to apply:**

- After calibration passes for a new default-on rule, pick at least one external Rust repository (a Tauri app, a library crate, a CLI tool — something with code idioms gruff-rs doesn't have) and run the rule's selector against it.
- Read every finding the new rule produced — open the file, look at 3-5 lines of context, decide TP/FP. Don't trust counts; trust source inspection.
- For each FP class, decide: (a) tighten the rule, (b) accept and document the FP shape, or (c) delete the rule. "Accept" only when the FP rate stays under ~10% on the external repo.
- The two-stage shape (calibration + external scan) catches false positives that calibration alone misses, because calibration fixtures are written by the same person who wrote the rule. External code is the cheapest source of patterns the author didn't think of.

**Why:** Calibration proves a rule does what its author intended; an external scan reveals what the rule *also* does that the author didn't intend. Shipping without the second step ships hidden noise that erodes user trust in every other finding.

**How to apply:** For every new default-on rule, add a one-line note to the rule's `Created:` PR description: "External scan: <repo path>, <N> findings, <X> TPs / <Y> FPs / <Z> ambiguous." If <Y> exceeds 10% of <N>, tighten the rule or downgrade it to non-default-on before merge.

## Lesson: When A Self-Scan Says Zero, Confirm The Rule Still Fires Somewhere

**Created:** 2026-05-24

After tightening a rule to eliminate false positives, a "zero findings on dogfood" result is ambiguous: either the FPs were correctly suppressed, or the rule's pattern-matching was broken so it now matches nothing. Confirm the rule still fires on its calibration positive case before declaring victory.

**Concrete example (this repo, 2026-05-24):** While tightening `modernisation.manual-contains` to require either a deref (`*x == y`) or RHS-ref (`x == &y`) shape, the regex went from broad to narrow in one edit. Dogfood went from 4 findings to 0, which could mean "the 4 FPs are gone" *or* "the regex is now broken." Running `cargo test rule_calibration_matrix_covers_every_rule -- --nocapture` confirmed the calibration positive case (`*item == target`) still fires, validating that the zero-finding result was the FP fix, not a regression.

**How to apply:**

- After every rule-tightening change, run the calibration matrix test before celebrating a zero-finding dogfood result.
- If both green: the FP fix worked. If the calibration positive case now fails: the regex was over-tightened — restore the necessary pattern coverage.
- The `rule_calibration_matrix_covers_every_rule` test catches this asymmetry by checking `positive_fired == true && negative_fired == false` for every rule.

**Why:** Pattern-matching rules can silently lose their pattern when calibration changes. The matrix is the contract; trust it over dogfood counts.

**How to apply:** Tightening a regex → run calibration matrix as the first verification command, dogfood as the second. Never declare a tightening done from dogfood alone.

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

## Lesson: Rule Helpers Must Pass Dogfood Shape Gates

**Created:** 2026-05-23

When adding analyzer rules, run a focused dogfood scan before final preflight if
the implementation introduces new helpers in `src/built_in_rules/` (search:
`analyse_weak_crypto`). In M55, Rust tests and calibration passed, but
`cargo run --quiet -- analyse . --format json --fail-on none --no-baseline`
reported a new `size.parameter-count` warning for a helper that threaded file,
line-start, findings, dedupe, primitive, and byte-index parameters separately.

Prefer a small context/reporter struct for repeated finding construction, then
rerun the dogfood scan at the same threshold before treating the verification
failure as closed.

## Lesson: Cargo Test Accepts One Name Filter Before Harness Args

**Created:** 2026-05-24

When running multiple focused Rust tests, do not pass several test names to one
`cargo test` command. Cargo accepts a single test-name filter before `--`; an
extra name is parsed as an unexpected argument and does not run either intended
set.

Run separate focused commands, use a shared substring filter, or run the module
or full suite when the desired tests do not share a stable name prefix.

## Lesson: Keep JSON Smoke Assertions One File At A Time

**Created:** 2026-05-24

When verifying CLI JSON round trips, avoid clever `jq input` pipelines across
several files. It is easy to consume the wrong stream position and turn a valid
product check into a jq error.

Assign each expected value from a separate `jq -r` read, then use shell `test`
assertions before printing the compact summary.

## Lesson: Verify Cargo Subcommand Binaries Both Ways

**Created:** 2026-05-24

When a script resolves a Cargo subcommand binary path directly, test that direct
binary invocation separately from `cargo <subcommand>`. `cargo audit` dispatches
through Cargo, but the installed `cargo-audit` binary needs the explicit
`audit` subcommand when invoked by path.

For tool-root smoke tests, run the exact path form the script will use, such as
`/tmp/tool-root/bin/cargo-audit audit`, before treating the Cargo-dispatched
form as equivalent.
