---
category: analyzer
last_reviewed: 2026-05-23
---

## Footgun: Fixture Findings Are Intentional

**Status:** active | **Created:** 2026-05-13 | **Evidence:** ACTUAL_MEASURED

`fixtures/sample.rs` (search: `let api_key =`) intentionally includes secret-looking strings, command execution, a long parameter list, and a weak test. Do not "fix" this file as ordinary bad code unless the replacement still proves the analyzer reports those rule families.

The non-obvious failure mode is losing analyzer coverage while making the repository appear cleaner. The smoke command `cargo run -- analyse fixtures --format json --fail-on none` currently reports findings from this fixture.

## Footgun: Code-Shape Rules Can Scan Fixture Strings

**Status:** active | **Created:** 2026-05-13 | **Evidence:** ACTUAL_MEASURED

`src/parser.rs` (search: `fn strip_rust_string_literals`) masks Rust string literals before code-shape checks such as complexity, unwrap, process command, unsafe, and test-quality scans. Secret scanners intentionally still inspect raw text.

Without that split, self-scan can report rule examples embedded inside unit-test fixture strings as if they were real analyzer code. M03 caught this when test-quality checks flagged raw fixture snippets in analyzer source tests.

**Char-literal subtlety (M33, 2026-05-18):** Earlier versions of the masker handled `"..."` and `r#"..."#` but did NOT recognise Rust character literals such as `'"'`. The first occurrence of `trim_matches('"')` flipped the masker into string mode at the `"` inside the char literal, then every later `"` toggled the wrong state, leaving downstream string contents (notably `concat!("std::process::Command::new(\"sh\")...")` test fixtures) partially unmasked and triggering `security.process-command` on fixture text. The fix added `fn char_literal_end` and a char-literal pass in `strip_rust_string_literals`. Regression coverage: `src/tests/regression_milestones.rs` (search: `m33_process_command_silent_after_char_literal_quote`).

## Footgun: Per-Rule Guards In `analyse_waste_line` Must Stay Symmetric

**Status:** active | **Created:** 2026-05-19 | **Evidence:** OBSERVED

`src/built_in_rules/analyzers_b.rs` (search: `fn analyse_waste_line`) hosts both `waste.unwrap-expect` and `waste.unnecessary-clone-candidate` as sibling `if`-blocks against the same `line`. The unwrap branch has carried `&& !line.contains("#[test]") && !self.line_is_in_test_context(line_number)` since M33; the clone branch (added later) silently omitted both guards, so self-scan reported clones inside `#[cfg(test)] mod tests` and `#[test]` fns as production waste advisories (e.g. baseline-roundtrip test setup at search `write_baseline(&baseline_path, &[selected.findings[0].clone()])` and SARIF test scaffolding at search `let mut sorted_rule_ids = sarif_rule_ids.clone();`).

The non-obvious failure mode is that adding a NEW line rule to `analyse_waste_line` (or any future "per-rule branch under one wrapper" file-scan helper) inherits NOTHING from its neighbours — every branch must restate its own test-context, comment-mask, and consumer-exemption guards. There is no compiler signal when a guard goes missing; only a self-scan delta against test-context lines surfaces it.

Regression coverage: `src/tests/regression_milestones.rs` (search: `m38_unnecessary_clone_candidate_skips_test_context`). When adding a new sibling rule under `analyse_waste_line` or any analogous dispatcher, copy the guard list from the most-restrictive existing branch and add a per-rule negative test that probes a `.clone()`-shaped pattern inside both a `#[test]` fn and a non-`#[test]` helper fn inside `#[cfg(test)] mod tests`.

## Footgun: Same-Line Findings Can Dedupe Together

**Status:** active | **Created:** 2026-05-22 | **Evidence:** OBSERVED

`src/report.rs` (search: `hasher.update(symbol.clone().unwrap_or_default().as_bytes())`) derives finding fingerprints from rule id, file path, line, and symbol. `sensitive-data.hardcoded-env-value` findings in `src/built_in_rules/secret_rules.rs` (search: `analyse_env_like_secrets`) currently carry `symbol: None`, so two env-style secret matches for the same file and line collapse during `sort_and_dedupe_findings`.

The non-obvious failure mode is testing multi-secret JSON on one physical line and expecting one finding per key. Unless a rule intentionally changes symbol/fingerprint identity, put multi-match regression fixtures on separate lines or assert at least one same-line finding rather than exact per-key cardinality.

## Footgun: Workflow Text Rules Need List-Item Syntax

**Status:** active | **Created:** 2026-05-23 | **Evidence:** OBSERVED

`src/built_in_rules/text_rules.rs` (search: `fn analyse_ci_github_event_shell_interpolation`) scans GitHub Actions YAML as deterministic text, not with a YAML parser. Workflow shell steps commonly appear as list-item mappings (`- run: ...`), not only as bare `run:` keys, so key-oriented string checks can miss the most common positive shape.

M54 calibration first caught this as `ci.github-event-shell-interpolation: positive=MISS negative=silent`. Regression coverage now lives in `src/tests/calibration/cases_c.rs` (search: `ci.github-event-shell-interpolation`) and `src/tests/scenarios/calibration_extras.rs` (search: `calibration_security_rubric_improvements_have_false_positive_guards`). When adding workflow text rules without a YAML parser, include both `run:` and `- run:` positive/negative fixtures, plus a block scalar case if continuation lines matter.

## Resolved Entries

## Footgun: Report Exclusions Are Not Discovery Ignores

**Status:** resolved | **Created:** 2026-05-16 | **Resolved:** 2026-05-18 | **Evidence:** ACTUAL_MEASURED
**hallucination-risk:** high
**Symptoms:** Adding a richer exclusion DSL by widening `paths.ignore` can hide committed files from security and sensitive-data rules instead of only suppressing reviewed findings.
**Why it happened:** `src/config_loader/mod.rs` (search: `config.ignored_paths = string_array(ignore, "paths.ignore")`) treats `paths.ignore` as discovery-time policy. ADR-004 also separates Git ignore rules from gruff config ignores, while M23 research in `.goat-flow/scratchpad/related-projects/golangci-lint/STUDY.md` (search: `Exclusions hide reported issues but do not skip analysis`) identified report-level exclusions as a different layer.
**Resolution:** `src/analysis.rs` (search: `apply_report_exclusions`) adds top-level `exclude` entries that run after exact baselines and before patch filtering. They require reasons, record suppression counts, and filter `AnalysisReport.findings` without changing source discovery.
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

M04 replaced that with `src/analysis.rs` (search: `fn run_analysis_in_project`) and `src/dashboard.rs` (search: `fn dashboard_response`), so dashboard scans pass an explicit project root and do not mutate cwd. Regression coverage lives in `src/tests/renderers.rs` (search: `dashboard_scan_preserves_cwd_and_report_paths`).

## Footgun: Rust Parsing Was Regex And Brace Counting

**Status:** resolved | **Created:** 2026-05-13 | **Resolved:** 2026-05-13 | **Evidence:** ACTUAL_MEASURED

Before M01, `src/built_in_rules/analyzers_c.rs` (search: `fn rust_function_blocks`) extracted functions with a regex and brace-depth scan, and `parse_diagnostics` only checked delimiter balance.

M01 replaced that path with `src/project/mod.rs` (search: `fn parse_source_file`) using `syn::parse_file` and `src/built_in_rules/analyzers_c.rs` (search: `fn rust_function_blocks`) walking the parsed AST. The regression proof is `cargo run --quiet -- analyse src --format json --fail-on none` exiting 0 with zero diagnostics and `cargo test` passing parser fixtures for raw strings, macros, impl methods, test attributes, and invalid Rust.
