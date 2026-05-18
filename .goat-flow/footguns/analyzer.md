---
category: analyzer
last_reviewed: 2026-05-18
---

## Footgun: Fixture Findings Are Intentional

**Status:** active | **Created:** 2026-05-13 | **Evidence:** ACTUAL_MEASURED

`fixtures/sample.rs` (search: `let api_key =`) intentionally includes secret-looking strings, command execution, a long parameter list, and a weak test. Do not "fix" this file as ordinary bad code unless the replacement still proves the analyzer reports those rule families.

The non-obvious failure mode is losing analyzer coverage while making the repository appear cleaner. The smoke command `cargo run -- analyse fixtures --format json --fail-on none` currently reports findings from this fixture.

## Footgun: Code-Shape Rules Can Scan Fixture Strings

**Status:** active | **Created:** 2026-05-13 | **Evidence:** ACTUAL_MEASURED

`src/main.rs` (search: `fn strip_rust_string_literals`) masks Rust string literals before code-shape checks such as complexity, unwrap, process command, unsafe, and test-quality scans. Secret scanners intentionally still inspect raw text.

Without that split, self-scan can report rule examples embedded inside unit-test fixture strings as if they were real analyzer code. M03 caught this when test-quality checks flagged raw fixture snippets in `src/main.rs` tests.

## Resolved Entries

## Footgun: Report Exclusions Are Not Discovery Ignores

**Status:** resolved | **Created:** 2026-05-16 | **Resolved:** 2026-05-18 | **Evidence:** ACTUAL_MEASURED
**hallucination-risk:** high
**Symptoms:** Adding a richer exclusion DSL by widening `paths.ignore` can hide committed files from security and sensitive-data rules instead of only suppressing reviewed findings.
**Why it happened:** `src/main.rs` (search: `config.ignored_paths = string_array(ignore, "paths.ignore")`) treats `paths.ignore` as discovery-time policy. ADR-004 also separates Git ignore rules from gruff config ignores, while M23 research in `.goat-flow/scratchpad/related-projects/golangci-lint/STUDY.md` (search: `Exclusions hide reported issues but do not skip analysis`) identified report-level exclusions as a different layer.
**Resolution:** `src/main.rs` (search: `apply_report_exclusions`) adds top-level `exclude` entries that run after exact baselines and before patch filtering. They require reasons, record suppression counts, and filter `AnalysisReport.findings` without changing source discovery.
**Prevention:** Keep `paths.ignore` for "do not read" policy. Use top-level `exclude` for reviewed report suppressions with reasons and counts.

## Footgun: Diff Mode Currently Executes Git

**Status:** resolved | **Created:** 2026-05-16 | **Resolved:** 2026-05-18 | **Evidence:** ACTUAL_MEASURED
**hallucination-risk:** high
**Symptoms:** Treating `--diff` as a pure report filter could accidentally preserve or expand a trust-boundary violation.
**Why it happened:** `src/main.rs` (search: `fn changed_files`) shells out to `git diff --name-only` and accepts an arbitrary mode/ref argument. M23 research in `.goat-flow/scratchpad/related-projects/semgrep/STUDY.md` (search: `Baseline setup executes Git`) and `.goat-flow/scratchpad/related-projects/golangci-lint/STUDY.md` (search: `New-code-only mode is a line-level diff filter`) showed that safer new-code filtering can be modeled from patch data after analysis instead of executing Git during ordinary scans.
**Resolution:** `src/main.rs` (search: `DiffSelection::Patch`) adds `--diff-patch` as the safe no-execute path and gates the Git-backed mode behind explicit `--diff-git-unsafe`, with a `diff-git-unsafe` run diagnostic when that path is used.
**Prevention:** Keep patch-input line filtering as the default diff route. If direct Git/ref diff needs more behavior, add a separate trust-boundary ADR covering hooks, external diff drivers, path normalization, timeouts, and failure diagnostics.

## Footgun: Dashboard Scans Change Process Cwd

**Status:** resolved | **Created:** 2026-05-13 | **Resolved:** 2026-05-13 | **Evidence:** ACTUAL_MEASURED

Before M04, dashboard `/scan` changed the process working directory before calling `run_analysis`, then restored the previous directory afterward.

M04 replaced that with `src/main.rs` (search: `fn run_analysis_in_project`) and `src/main.rs` (search: `fn dashboard_response`), so dashboard scans pass an explicit project root and do not mutate cwd. Regression coverage lives in `src/main.rs` (search: `dashboard_scan_preserves_cwd_and_report_paths`).

## Footgun: Rust Parsing Was Regex And Brace Counting

**Status:** resolved | **Created:** 2026-05-13 | **Resolved:** 2026-05-13 | **Evidence:** ACTUAL_MEASURED

Before M01, `src/main.rs` (search: `fn rust_function_blocks`) extracted functions with a regex and brace-depth scan, and `parse_diagnostics` only checked delimiter balance.

M01 replaced that path with `src/main.rs` (search: `fn parse_source_file`) using `syn::parse_file` and `src/main.rs` (search: `fn rust_function_blocks`) walking the parsed AST. The regression proof is `cargo run --quiet -- analyse src --format json --fail-on none` exiting 0 with zero diagnostics and `cargo test` passing parser fixtures for raw strings, macros, impl methods, test attributes, and invalid Rust.
