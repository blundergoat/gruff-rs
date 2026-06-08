---
category: analyzer
last_reviewed: 2026-06-07
---

## Footgun: Bare-Bare Equality Closures Look Like `.contains()` But Often Aren't

**Status:** active | **Created:** 2026-05-24 | **Evidence:** ACTUAL_MEASURED

`src/built_in_rules/modernisation_rules.rs` (search: `fn analyse_manual_contains`) flags `iter().any(|x| x == y)` shapes that should use `.contains(&y)`. The shape that *looks* equivalent isn't always: when the iterator yields `&String` and the comparison target is `&str`, the closure compiles via `PartialEq<&str> for String`, but `[String]::contains` needs `&String` — `.contains(&y)` would not compile without an allocation.

Concrete instances from 2026-05-24 self-scan:

- `src/built_in_rules/naming_rules.rs` (search: `extra_placeholders.iter().any`) — `extra_placeholders: Vec<String>`, `name: &str`. The bare-bare shape is the only one the type system accepts cheaply.
- `src/config_loader/mod.rs` (search: `allowed.iter().any`) — `allowed: &[&str]`, `key: &String`. Same cross-type compare problem.

The non-obvious failure mode is matching every `iter().any(|x| ARG == OTHER)` shape and producing findings the user can't safely auto-fix. The rule was first written that way and flagged both type-compatible cases (where `.contains()` is a clean swap) and cross-type cases (where it isn't).

Calibrate by requiring an explicit dereference or reference token: `iter().any(|x| *x == y)` (deref pattern, items are `&T` comparing to `T`) or `iter().any(|x| x == &y)` (RHS-ref pattern, items are `&T` comparing to `&T`). Bare `|x| x == y` stays silent because the only way that compiles is through `PartialEq` cross-type impls, where `.contains()` likely needs an allocation. Regression coverage: `src/tests/calibration/cases_pillar_expansion.rs` (search: `modernisation.manual-contains`) uses `*item == target` so the deref shape stays detected.

## Footgun: Candidate Security Rules Must Recognise Idiomatic Defence Patterns

**Status:** active | **Created:** 2026-05-24 | **Evidence:** ACTUAL_MEASURED

`src/built_in_rules/path_traversal_rules.rs` (search: `fn analyse_path_traversal_candidate`) flags filesystem path construction from non-literal identifiers. A first cut that only inspected the call site and a safe-arg name list produced ~30% false-positive rate on real codebases. The patterns that look unsafe at the call site but are actually defended:

- **Path-typed parameters in utility helpers**: `fn absolutize(root: &Path, path: &Path) -> PathBuf { root.join(path) }`. The `path` argument cannot carry an unconstrained string segment — it was already path-typed upstream.
- **Validate-then-trust pattern**: `default_root.join(requested).canonicalize()?` followed by `.starts_with(default_root)`. The join is dangerous in isolation but resolved and re-checked immediately after.
- **Identifier names that signal validation**: `safe`, `sanitized`, `normalized`, `validated`, `file_name` — common in code that has just finished validating.
- **Test infrastructure**: paths constructed inside `tests/` directories are not attack surfaces.

The non-obvious failure mode is shipping a candidate rule whose recall is high but whose precision collapses on idiomatic Rust. Users either silence it project-wide or stop reading its findings.

Calibrate with three guards before emitting the finding (kept in `path_traversal_finding_is_suppressed`): (1) safe-arg list restricted to validation-outcome and base-path-convention names (no slot-describing names like `dir`, `parent`, `target`); (2) lookback for the argument's declaration in a nearby fn signature typed as `&Path` / `&PathBuf` / `impl AsRef<Path>`; (3) forward window check for `.canonicalize()` AND `.starts_with(` within 25 lines after the join. Regression: dogfood scan moved from 10 findings on this repo to 0 after these three guards landed, while the calibration positive case (untyped `&str` parameter, no validation) still fires.

## Footgun: Fixture Findings Are Intentional

**Status:** active | **Created:** 2026-05-13 | **Evidence:** ACTUAL_MEASURED

`fixtures/sample.rs` (search: `let api_key =`) intentionally includes secret-looking strings, command execution, a long parameter list, and a weak test. Do not "fix" this file as ordinary bad code unless the replacement still proves the analyzer reports those rule families.

The non-obvious failure mode is losing analyzer coverage while making the repository appear cleaner. The smoke command `cargo run -- analyse fixtures --format json --fail-on none` currently reports findings from this fixture.

## Footgun: Code-Shape Rules Can Scan Fixture Strings

**Status:** active | **Created:** 2026-05-13 | **Evidence:** ACTUAL_MEASURED

`src/parser/mod.rs` (search: `fn strip_rust_string_literals`) masks Rust string literals before code-shape checks such as complexity, unwrap, process command, unsafe, and test-quality scans. Secret scanners intentionally still inspect raw text.

Without that split, self-scan can report rule examples embedded inside unit-test fixture strings as if they were real analyzer code. M03 caught this when test-quality checks flagged raw fixture snippets in analyzer source tests.

**Char-literal subtlety (M33, 2026-05-18):** Earlier versions of the masker handled `"..."` and `r#"..."#` but did NOT recognise Rust character literals such as `'"'`. The first occurrence of `trim_matches('"')` flipped the masker into string mode at the `"` inside the char literal, then every later `"` toggled the wrong state, leaving downstream string contents (notably `concat!("std::process::Command::new(\"sh\")...")` test fixtures) partially unmasked and triggering `security.process-command` on fixture text. The fix added `fn char_literal_end` and a char-literal pass in `strip_rust_string_literals`. Regression coverage: `src/tests/rule_behaviours/false_positive_guards.rs` (search: `process_command_silent_after_char_literal_quote`).

## Footgun: Per-Rule Guards In `analyse_waste_line` Must Stay Symmetric

**Status:** active | **Created:** 2026-05-19 | **Evidence:** OBSERVED

`src/built_in_rules/behavior_rules.rs` (search: `fn analyse_waste_line`) hosts both `waste.unwrap-expect` and `waste.unnecessary-clone-candidate` as sibling `if`-blocks against the same `line`. The unwrap branch has carried `&& !line.contains("#[test]") && !self.line_is_in_test_context(line_number)` since M33; the clone branch (added later) silently omitted both guards, so self-scan reported clones inside `#[cfg(test)] mod tests` and `#[test]` fns as production waste advisories (e.g. baseline-roundtrip test setup at search `write_baseline(&baseline_path, &[selected.findings[0].clone()])` and SARIF test scaffolding at search `let mut sorted_rule_ids = sarif_rule_ids.clone();`).

The non-obvious failure mode is that adding a NEW line rule to `analyse_waste_line` (or any future "per-rule branch under one wrapper" file-scan helper) inherits NOTHING from its neighbours — every branch must restate its own test-context, comment-mask, and consumer-exemption guards. There is no compiler signal when a guard goes missing; only a self-scan delta against test-context lines surfaces it.

Regression coverage: `src/tests/rule_behaviours/false_positive_guards.rs` (search: `unnecessary_clone_candidate_skips_test_context`). When adding a new sibling rule under `analyse_waste_line` or any analogous dispatcher, copy the guard list from the most-restrictive existing branch and add a per-rule negative test that probes a `.clone()`-shaped pattern inside both a `#[test]` fn and a non-`#[test]` helper fn inside `#[cfg(test)] mod tests`.

## Footgun: Same-Line Findings Can Dedupe Together

**Status:** active | **Created:** 2026-05-22 | **Evidence:** OBSERVED

`src/report.rs` (search: `hasher.update(symbol.clone().unwrap_or_default().as_bytes())`) derives finding fingerprints from rule id, file path, line, and symbol. `sensitive-data.hardcoded-env-value` findings in `src/built_in_rules/secret_rules.rs` (search: `analyse_env_like_secrets`) currently carry `symbol: None`, so two env-style secret matches for the same file and line collapse during `sort_and_dedupe_findings`.

The non-obvious failure mode is testing multi-secret JSON on one physical line and expecting one finding per key. Unless a rule intentionally changes symbol/fingerprint identity, put multi-match regression fixtures on separate lines or assert at least one same-line finding rather than exact per-key cardinality.

## Footgun: Workflow Text Rules Need List-Item Syntax

**Status:** active | **Created:** 2026-05-23 | **Evidence:** OBSERVED

`src/built_in_rules/text_rules.rs` (search: `fn analyse_ci_github_event_shell_interpolation`) scans GitHub Actions YAML as deterministic text, not with a YAML parser. Workflow shell steps commonly appear as list-item mappings (`- run: ...`), not only as bare `run:` keys, so key-oriented string checks can miss the most common positive shape.

M54 calibration first caught this as `ci.github-event-shell-interpolation: positive=MISS negative=silent`. Regression coverage now lives in `src/tests/calibration/security_size_test_waste_cases.rs` (search: `ci.github-event-shell-interpolation`) and `src/tests/scenarios/calibration_extras.rs` (search: `calibration_security_rubric_improvements_have_false_positive_guards`). When adding workflow text rules without a YAML parser, include both `run:` and `- run:` positive/negative fixtures, plus a block scalar case if continuation lines matter.

2026-06-05 extension: event detection has the same YAML-shape trap. `src/built_in_rules/text_rules.rs` (search: `fn workflow_line_contains_event`) originally matched `on: [pull_request]`, mapping keys (`on:\n  pull_request:`), and list items, but missed scalar events (`on: pull_request` / `on: pull_request_target`). That made `security.github-actions-secrets-in-pr` and `security.github-actions-pull-request-target` silent for a common valid workflow form. Regression coverage: `src/tests/rule_behaviours/release_noise_guards.rs` (search: `github_actions_security_events_accept_scalar_on_values`).

**How to apply:** every new GitHub Actions text rule needs fixtures for scalar, mapping, and list event syntax where event gating matters. Prefer a real YAML parser only if the rule needs nesting semantics; otherwise keep the text matcher deterministic but enumerate common YAML surface forms.

## Footgun: check-ignore Needs Hierarchical Gitignore Context

**Status:** active | **Created:** 2026-06-05 | **Evidence:** OBSERVED

`src/check_ignore.rs` (search: `pub(crate) fn run_check_ignore`) is the hook-facing contract for "would gruff ignore this path?" The discovery walk gets hierarchical `.gitignore` handling from `ignore::WalkBuilder`, but a direct path query has no traversal context unless `check-ignore` rebuilds it. A matcher built only from project-root `.gitignore` silently misses nested policies such as `src/.gitignore`.

Concrete instance from the 0.3.0 release check: `git check-ignore src/generated.rs` returned ignored for a temp repo with `src/.gitignore` containing `generated.rs`; `gruff-rs analyse` produced no findings for that file; `gruff-rs check-ignore --format json src/generated.rs` returned `"ignored": false` because the old query matcher loaded only the root `.gitignore`. Fixed by `src/check_ignore.rs` (search: `pub(crate) fn gitignore_for_path`) walking ancestors from project root to the queried path's parent and adding each `.gitignore` to the same `ignore` crate builder. Regression coverage: `src/tests/scenarios/discovery.rs` (search: `check_ignore_gitignore_matcher_loads_nested_gitignore_files`).

**How to apply:** any direct ignore query must reconstruct the path's ignore hierarchy before answering. Do not replace this with an ad hoc glob matcher; use the same `ignore` crate semantics as discovery, and include a nested `.gitignore` regression whenever `check-ignore` changes.

## Footgun: Dead-Code Reference Masking Must Preserve Structured Attribute References

**Status:** active | **Created:** 2026-05-23 | **Evidence:** OBSERVED

`src/parser/mod.rs` (search: `fn rust_code_reference_source`) masks arbitrary comments and strings before dead-code reference counting, then appends only structured references such as `serde(default = "function_name")`. Comments and ordinary prose strings should not keep private functions alive, but serde default function strings are real call sites from generated deserialization code.

The non-obvious failure mode is treating all string-literal references as equally fake. Over-masking fixes comment/prose false negatives but can make valid serde defaults look unused; under-masking makes comments and fixture strings hide genuinely dead functions. Regression coverage: `src/tests/rule_behaviours/rubric_false_positive_guards.rs` (search: `dead_code_unused_private_function_recognises_indirect_references`) and `src/tests/project_tests/dead_code.rs` (search: `project_dead_code_ignores_comment_mentions_and_test_cfg_helpers`).

## Footgun: Secret-Key Case Sensitivity Depends On File Kind

**Status:** active | **Created:** 2026-05-23 | **Evidence:** OBSERVED

`src/built_in_rules/secret_rules.rs` (search: `fn config_like_secret_regex`) intentionally allows lowercase secret-like keys only for structured config formats such as YAML, JSON, TOML, `.env`, and properties files. Rust source and prose/script-like text stay uppercase-only for `sensitive-data.hardcoded-env-value`, because lowercase identifiers such as `secret_access_key`, `secret_json`, `touches_secret`, and detector variable names are usually runtime values or scanner implementation details rather than committed secret assignments.

The non-obvious failure mode is globally removing `(?i)` to fix false positives, which breaks real structured config coverage such as `database_password: yaml-secret-123`. The opposite mistake is making every text file case-insensitive, which reintroduces shell, Markdown, and Rust variable false positives. Regression coverage: `src/tests/scenarios/calibration_extras.rs` (search: `calibration_hardcoded_env_value_detects_structured_config_keys`) and `src/tests/rule_behaviours/rubric_false_positive_guards.rs` (search: `sensitive_data_rules_skip_common_placeholder_and_detector_contexts`).

## Footgun: Process Command Needs Risk Signals

**Status:** active | **Created:** 2026-05-23 | **Evidence:** OBSERVED

`src/built_in_rules/behavior_rules.rs` (search: `fn analyse_process_commands`) reports `security.process-command` only when `process_command_risk_signals` finds a concrete risk shape such as shell execution, dynamic executable, dynamic arguments, environment changes, or working-directory changes. Reporting every `Command::new(...)` constructor creates release-blocking noise for fixed executable helpers and cleanup commands.

The non-obvious failure mode is treating "process object constructed" as equivalent to "security-relevant process execution." Builder helpers that return `Command` and fixed cleanup commands such as `taskkill /PID <pid> /F /T` should stay silent, while dynamic shell execution must still fire. Regression coverage: `src/tests/rule_behaviours/release_noise_guards.rs` (search: `process_command_skips_builders_and_fixed_pid_cleanup`) and `src/tests/scenarios/calibration_extras.rs` (search: `calibration_security_process_command_detects_code_not_fixture_text`).

## Footgun: Loop-Scoped Rules Must Mask Comments

**Status:** active | **Created:** 2026-05-23 | **Evidence:** OBSERVED

`src/built_in_rules/perf_rules.rs` (search: `fn analyse_performance_block`) must feed comment-masked Rust text into `loop_pattern_count_filtered`. Function blocks include doc comments before the `fn` line, so words like `for` or `while` in rustdoc can otherwise create a fake loop scope and make later `format!` or `.clone()` calls look like `performance.format-in-loop` / `performance.clone-in-loop`.

The non-obvious failure mode is masking strings but not comments for loop-scoped performance checks. That keeps line/token patterns visible enough to match `format!`, while doc text such as "Load favorites for a workspace" flips the loop state. Regression coverage: `src/tests/rule_behaviours/rubric_false_positive_guards.rs` (search: `performance_loop_rules_ignore_loop_words_in_comments`).

## Footgun: Assertion Unwrap Exemptions Need Receiver Context

**Status:** active | **Created:** 2026-05-23 | **Evidence:** OBSERVED

`src/built_in_rules/test_rules.rs` (search: `fn body_contains_only_assertion_subject_unwraps`) exempts `test-quality.unwrap-in-test` only when every `.unwrap()` is inside an assertion macro and the unwrap receiver is a call result. A broad "inside assert macro" exemption hides setup variables such as `assert_eq!(v.unwrap(), 2)`, which existing regression coverage expects to remain visible.

The non-obvious failure mode is treating all assertion unwraps as equivalent. Unwrapping a direct function call in an assertion can be the subject under test; unwrapping a local variable inside an assertion can still hide setup intent. Regression coverage: `src/tests/rule_behaviours/false_positive_guards.rs` (search: `unwrap_expect_skips_cfg_test_module`) and `src/tests/rule_behaviours/rubric_false_positive_guards.rs` (search: `unwrap_in_test_skips_assertion_subject_but_reports_setup_unwrap`).

## Footgun: Test-Quality Assertion Rules Must Mask Comments

**Status:** active | **Created:** 2026-06-03 | **Evidence:** OBSERVED

`src/built_in_rules/blocks.rs` (search: `let searchable_body = strip_rust_string_literals(&block.body);`) passes a string-masked but comment-preserved body into `analyse_test_assertions`. `src/built_in_rules/helpers.rs` (search: `fn has_trivial_assertion`) then runs assertion regexes over that comment-preserved body. Unlike `long_test_effective_line_count` in `src/built_in_rules/test_rules.rs` (search: `strip_rust_comments_after_string_mask(&strip_rust_string_literals(&block.body))`), the trivial-assertion path does not strip comments before matching.

Concrete review probes from 2026-06-03 showed the failure mode: `let x = 5; // assert_eq!(x, 5); assert_eq!(x + 1, 6);` produced `test-quality.trivial-assertion`, and even fully commented-out `// let ghost = 5; // assert_eq!(ghost, 5);` produced the same finding. This is a false positive, not a harmless implementation detail, because gruff findings are commands to change code in hook mode.

When adding or widening test-quality assertion regexes, feed them a comment-masked view unless the rule intentionally reads comments. Regression coverage should include both a commented-out assertion after a real binding and a fully commented-out binding-plus-assertion pair. String and raw-string probes are still required separately because `src/parser/mod.rs` (search: `fn strip_rust_string_literals`) masks those before comments are considered.

## Footgun: Regex Shadow Windows Miss Rust Binding Patterns

**Status:** active | **Created:** 2026-06-03 | **Evidence:** OBSERVED

`src/built_in_rules/helpers.rs` (search: `fn literal_is_asserted_before_shadow`) treats shadowing as a textual `let name` occurrence. That catches `let x = ...` but misses valid Rust binding patterns such as `let (x) = ...`, destructuring, and some scope-sensitive cases. The helper is used by `has_literal_binding_tautology` (search: `has_literal_binding_tautology(source)`), so a missed shadow can make the rule attribute a later assertion to an older literal initializer.

Concrete review probe from 2026-06-03: `let x = 5; let (x) = (6); assert_eq!(x, 5);` produced `test-quality.trivial-assertion`. The asserted `x` is the parenthesized shadow binding, so this is a false positive. A related false negative also exists: `let x = 5; { let x = 6; assert_eq!(x + 1, 7); } assert_eq!(x, 5);` stayed silent because the inner `let x` cut off the scan window for the outer binding even though the later outer assertion is a tautology.

Any future "binding then later use before shadow" rule should either use syntax-aware local analysis or carry explicit negative probes for parenthesized bindings, destructuring, inner-scope shadows, and commented shadows. If regex remains the local choice, document the supported binding grammar and prefer false negatives over false positives.

## Footgun: Text-Pattern Rules Self-Fire On Their Own Sentinel Values

**Status:** active | **Created:** 2026-05-24 | **Evidence:** ACTUAL_MEASURED

Rules that scan raw source text for literal patterns (`sensitive-data.*`, `security.hardcoded-bind-all-interfaces`, `security.weak-crypto`, etc.) cannot distinguish "this byte sequence appears in production source" from "this byte sequence appears in the rule's own implementation code." If the rule author writes a literal sentinel, default, or example value in the rule body, the dogfood scan will report the rule's own file as a finding.

Concrete instance from 2026-05-24: `analyse_hardcoded_bind_all_interfaces` was first written with `let addr = capture.name("addr").map_or("", |m| m.as_str()).unwrap_or("0.0.0.0");` — the `.unwrap_or("0.0.0.0")` placed a literal `"0.0.0.0"` in the rule's source, exactly matching the rule's own quoted-IP regex. Dogfood scan flagged `src/built_in_rules/network_security_rules.rs` with `security.hardcoded-bind-all-interfaces`. Same trap nearly hit `sensitive-data.pii-test-fixture` — its placeholder list contained `"example.com"` etc. inside a `matches!` pattern; the strings were safe only because none contained `@` in source-line context, so the email regex didn't match them.

The non-obvious failure mode is that the rule appears correct (calibration passes, external scan looks clean) until you scan the rule's own crate. By then the sentinel value is baked into a public API or fallback.

**How to apply:**

- Before writing a text-pattern rule, list every literal value that will appear in the rule body: regex patterns, fallback defaults, example strings in error messages, allowlist entries. Each one is a self-fire risk.
- Prefer regex captures over literal fallbacks: if the named capture is guaranteed by the regex contract, early-return on `.name().is_none()` instead of using `.unwrap_or("sentinel")`.
- For exemption lists in source: put the placeholder values in `matches!` patterns (where they appear as bare identifiers between `|` separators, not as quoted strings in context the regex sees), or load them from a non-source location.
- After every new text-pattern rule, run `cargo run --quiet -- analyse src/built_in_rules/<new_rule_file>.rs --format json --fail-on none --no-baseline` as the first verification. If the rule fires on its own file, fix it before calibration.

Regression coverage for this specific case: `src/tests/calibration/cases_pillar_expansion.rs` (search: `security.hardcoded-bind-all-interfaces`); the positive case is a Rust fn returning a `"0.0.0.0:8080"` literal, the negative returns `"127.0.0.1:8080"`. Calibration would not have caught the self-fire because calibration runs in a tempdir; only dogfood revealed it. Pairs with [[rule-precision]] for the broader candidate-rule defence pattern.

## Footgun: Candidate Taint Rules Can Taint Their Own Predicate Booleans

**Status:** active | **Created:** 2026-05-31 | **Evidence:** ACTUAL_MEASURED

`src/built_in_rules/network_security_rules.rs` (search: `fn analyse_template_injection_xss`) uses a bounded same-function taint model. A first cut treated every function parameter as tainted and propagated taint through any local binding whose RHS mentioned a tainted name. The rule then self-fired on its own helper because `fn template_sink_argument(line: &str, ...)` has a tainted `line` parameter, `let has_sink = line.contains("Html(format!") ...` became a tainted local, and the later `if !has_sink` line looked like an unescaped template sink candidate.

The non-obvious failure mode is that candidate taint rules can create findings from detector-control booleans, not from user data. This is different from literal self-fire: calibration fixtures still pass, but dogfood reports the analyzer source as a security finding.

Calibrate taint propagation so predicate/control bindings (`has_`, `is_`, `should_`, `matches_`, etc.) do not become tainted sink arguments, and keep source scans in the verification loop after every taint-style rule. The current guard lives in `src/built_in_rules/network_security_rules.rs` (search: `fn binding_name_is_predicate`). The same verification pass also caught `serde_yaml::from_str` in analyzer config parsing; local config/YAML parsing should stay silent unless the source evidence is actually request/env-derived.

## Footgun: Wrapper-Module Fan-Out Hits 8 When Adding New Rule Files

**Status:** active | **Created:** 2026-05-24 | **Evidence:** ACTUAL_MEASURED

`src/built_in_rules/rust_block_rules.rs` and `src/built_in_rules/rust_other_rules.rs` are wrapper modules that mount per-rule sub-files via `#[path = "..."] mod ...;`. The `architecture.module-fan-out` rule fires on files declaring more than 8 child modules. As the rule catalogue grows past 80, adding a single new built-in rule file to one of these wrappers can push it from 8 → 9 child modules and break dogfood.

Concrete instance from 2026-05-24: adding `network_security_rules.rs` to `rust_other_rules.rs` pushed its mount count to 9. Bumping the threshold would silence the rule everywhere; combining unrelated rules into one file (e.g. `network_security_rules` into `path_traversal_rules`) would create misleading file names. The right fix was moving an existing module (`dead_code`) from `rust_other_rules` to `rust_block_rules` — `dead_code` analysis operates per-item, not per-line, so it semantically fits the block-rules wrapper anyway.

The non-obvious failure mode is treating the wrapper organisation as fixed. The split is: `rust_block_rules` for per-`FunctionBlock` analyzers, `rust_other_rules` for per-file / per-line analyzers. When fan-out tension appears, look for modules in the wrong wrapper before reaching for the threshold dial or for file-merging.

2026-06-07 extension: the rule also fires on the top-level `src/built_in_rules/mod.rs` itself, not only the two wrappers — it sat at exactly 8 direct `mod` declarations. Extracting a cohesive concern out of an over-long top-level module to clear `size.file-length` (here, splitting the `sensitive-data.pii-test-fixture` rule out of `secret_rules.rs`) tripped fan-out when the extraction was added as a 9th top-level sibling in `mod.rs`. Fix: nest the new sub-file under its semantic owner via `#[path]` instead of adding a top-level sibling — `secret_rules.rs` mounts it with `#[path = "pii_rules.rs"] mod pii_rules;` and re-exports the entry point (search: `pub(crate) use pii_rules::analyse_pii_test_fixture;`), mirroring how `behavior_rules.rs` nests `tls_sql` (search: `#[path = "behavior_rules/tls_sql.rs"]`). The file stays flat in the directory; only the module tree gains a level. Re-classification therefore also covers "nest under the owning module", not just "move between the two wrappers".

**How to apply:**

- Before adding a new built-in rule file, check `wc -l src/built_in_rules/rust_block_rules.rs src/built_in_rules/rust_other_rules.rs` and count the `#[path]` declarations. If the wrapper is already at 7 or 8, the next addition will break the rule.
- Prefer re-classification (move a module to the wrapper that semantically fits) over threshold bumping or file merging.
- Count fan-out on `mod.rs` too, not only the wrappers. When splitting a top-level module (e.g. `secret_rules`, `text_rules`), nest the extracted file under its semantic owner via `#[path = "..."] mod ...;` rather than adding a new top-level sibling — a `sensitive-data.*` sub-file belongs under `secret_rules`, not beside it.
- The decision criterion: does the rule's analyzer operate on a `FunctionBlock` argument, or on `&SourceFile` + `&str source`? The former goes in `rust_block_rules`, the latter in `rust_other_rules`.

Regression coverage: this footgun re-fires every time the catalogue grows and a new rule file lands. No dedicated regression test — dogfood scan catches it.

## Footgun: Complexity Scanners Count Control-Flow Keywords In Comments

**Status:** active | **Created:** 2026-05-30 | **Evidence:** ACTUAL_MEASURED

`src/built_in_rules/blocks.rs` (search: `let searchable_body = strip_rust_string_literals`) feeds the complexity scanners — `fn analyse_block_complexity` (cyclomatic via `CYCLOMATIC_COMPLEXITY_REGEX`), `fn approximate_npath`, `fn max_nesting_depth`, and cognitive — a body with string literals masked but COMMENTS intact. Control-flow words (`if`, `for`, `match`, `while`, `loop`, `&&`, `||`, `?`) inside `//` and `///` comments are therefore counted as real decisions. This is the complexity-pillar twin of "Loop-Scoped Rules Must Mask Comments" above: the perf rules already comment-mask; the complexity rules do not.

Concrete instance (2026-05-30, external scan): a private `validate_script_path` with THREE flat `if` guards and ZERO loops reported `complexity.npath` 128. The branch-keyword count came back as 7 = 3 real `if` + 4 occurrences of the word "for" inside its comments ("Check **for** path traversal", "a script path **for** security"). NPath exponentiates (2^7 = 128 > threshold 100) so it crossed the line, while `complexity.cyclomatic` only summed (7 + 1 = 8 <= 10) and stayed silent — which is why npath fired alone on clean, well-documented code.

The non-obvious failure mode: the more faithfully an agent follows the doc-comment mandate (`.goat-flow/decisions/ADR-015-mission-agent-code-governance.md`), the more control-flow prose its comments carry, and the more the complexity metrics inflate — the analyzer penalises the documentation it requires. `?`-dense idiomatic error handling also reads higher than its real decision complexity.

**How to apply:**

- Fix: derive a comment-masked body for the complexity scanners — reuse `strip_rust_comments_after_string_mask` (search in `src/built_in_rules/modernisation_rules.rs`) over the string-masked body, localized to `analyse_block_complexity` so the perf / error-handling / concurrency rules that share `searchable_body` are unaffected. Tracked by milestone M00c.
- `?` (error-propagation) counts toward cyclomatic but reads linearly; weight it deliberately (M00c).
- `complexity.npath` was removed entirely (M00) because exponentiation made this inflation cross threshold while adding no signal cyclomatic / cognitive / nesting don't already carry.
- Regression coverage to add when fixed: a complexity calibration case whose body contains control-flow words only in comments and stays silent.

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
**Why it happened:** `src/diff.rs` (search: `fn changed_files`) shells out to `git diff --name-only` and accepts an arbitrary mode/ref argument. M23 research in `.goat-flow/scratchpad/related-projects/semgrep/STUDY.md` (search: `Baseline setup executes Git`) and `.goat-flow/scratchpad/related-projects/golangci-lint/STUDY.md` (search: `New-code-only mode is a line-level diff filter`) showed that safer new-code filtering can be modeled from patch data after analysis instead of executing Git during ordinary scans.
**Resolution:** `src/main.rs` (search: `DiffSelection::Patch`) adds `--diff-patch` as the safe no-execute path and gates the Git-backed mode behind explicit `--diff-git-unsafe`, with a `diff-git-unsafe` run diagnostic when that path is used.
**Prevention:** Keep patch-input line filtering as the default diff route. If direct Git/ref diff needs more behavior, add a separate trust-boundary ADR covering hooks, external diff drivers, path normalization, timeouts, and failure diagnostics.

## Footgun: Dashboard Scans Change Process Cwd

**Status:** resolved | **Created:** 2026-05-13 | **Resolved:** 2026-05-13 | **Evidence:** ACTUAL_MEASURED

Before M04, dashboard `/scan` changed the process working directory before calling `run_analysis`, then restored the previous directory afterward.

M04 replaced that with `src/analysis.rs` (search: `fn run_analysis_in_project`) and `src/dashboard.rs` (search: `fn dashboard_response`), so dashboard scans pass an explicit project root and do not mutate cwd. Regression coverage lives in `src/tests/renderers/dashboard.rs` (search: `dashboard_scan_preserves_cwd_and_report_paths`).

## Footgun: Rust Parsing Was Regex And Brace Counting

**Status:** resolved | **Created:** 2026-05-13 | **Resolved:** 2026-05-13 | **Evidence:** ACTUAL_MEASURED

Before M01, `src/built_in_rules/comment_item_and_blocks.rs` (search: `fn rust_function_blocks`) extracted functions with a regex and brace-depth scan, and `parse_diagnostics` only checked delimiter balance.

M01 replaced that path with `src/project/mod.rs` (search: `fn parse_source_file`) using `syn::parse_file` and `src/built_in_rules/comment_item_and_blocks.rs` (search: `fn rust_function_blocks`) walking the parsed AST. The regression proof is `cargo run --quiet -- analyse src --format json --fail-on none` exiting 0 with zero diagnostics and `cargo test` passing parser fixtures for raw strings, macros, impl methods, test attributes, and invalid Rust.
