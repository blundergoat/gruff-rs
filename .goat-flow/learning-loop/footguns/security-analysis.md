---
category: security-analysis
last_reviewed: 2026-07-13
---

## Footgun: Candidate Security Rules Must Recognise Idiomatic Defence Patterns

**Status:** active | **Created:** 2026-05-24 | **Evidence:** ACTUAL_MEASURED

`src/built_in_rules/path_traversal_rules.rs` (search: `fn analyse_path_traversal_candidate`) flags filesystem path construction from non-literal identifiers. A first cut that only inspected the call site and a safe-arg name list produced ~30% false-positive rate on real codebases. The patterns that look unsafe at the call site but are actually defended:

- **Path-typed parameters in utility helpers**: `fn absolutize(root: &Path, path: &Path) -> PathBuf { root.join(path) }`. The `path` argument cannot carry an unconstrained string segment — it was already path-typed upstream.
- **Validate-then-trust pattern**: `default_root.join(requested).canonicalize()?` followed by `.starts_with(default_root)`. The join is dangerous in isolation but resolved and re-checked immediately after.
- **Identifier names that signal validation**: `safe`, `sanitized`, `normalized`, `validated`, `file_name` — common in code that has just finished validating.
- **Test infrastructure**: paths constructed inside `tests/` directories are not attack surfaces.

The non-obvious failure mode is shipping a candidate rule whose recall is high but whose precision collapses on idiomatic Rust. Users either silence it project-wide or stop reading its findings.

Calibrate with three guards before emitting the finding (kept in `path_traversal_finding_is_suppressed`): (1) safe-arg list restricted to validation-outcome and base-path-convention names (no slot-describing names like `dir`, `parent`, `target`); (2) lookback for the argument's declaration in a nearby fn signature typed as `&Path` / `&PathBuf` / `impl AsRef<Path>`; (3) forward window check for `.canonicalize()` AND `.starts_with(` within 25 lines after the join. Regression: dogfood scan moved from 10 findings on this repo to 0 after these three guards landed, while the calibration positive case (untyped `&str` parameter, no validation) still fires.

## Footgun: Secret-Key Case Sensitivity Depends On File Kind

**Status:** active | **Created:** 2026-05-23 | **Evidence:** OBSERVED

`src/built_in_rules/secret_rules.rs` (search: `fn config_like_secret_regex`) intentionally allows lowercase secret-like keys only for structured config formats such as YAML, JSON, TOML, `.env`, and properties files. Rust source and prose/script-like text stay uppercase-only for `sensitive-data.hardcoded-env-value`, because lowercase identifiers such as `secret_access_key`, `secret_json`, `touches_secret`, and detector variable names are usually runtime values or scanner implementation details rather than committed secret assignments.

The non-obvious failure mode is globally removing `(?i)` to fix false positives, which breaks real structured config coverage such as `database_password: yaml-secret-123`. The opposite mistake is making every text file case-insensitive, which reintroduces shell, Markdown, and Rust variable false positives. Regression coverage: `src/tests/scenarios/calibration_extras.rs` (search: `calibration_hardcoded_env_value_detects_structured_config_keys`) and `src/tests/rule_behaviours/rubric_false_positive_guards.rs` (search: `sensitive_data_rules_skip_common_placeholder_and_detector_contexts`).

## Footgun: Process Command Needs Risk Signals

**Status:** active | **Created:** 2026-05-23 | **Evidence:** OBSERVED

`src/built_in_rules/behavior_rules.rs` (search: `fn analyse_process_commands`) reports `security.process-command` only when `process_command_risk_signals` finds a concrete risk shape such as shell execution, dynamic executable, dynamic arguments, environment changes, or working-directory changes. Reporting every `Command::new(...)` constructor creates release-blocking noise for fixed executable helpers and cleanup commands.

The non-obvious failure mode is treating "process object constructed" as equivalent to "security-relevant process execution." Builder helpers that return `Command` and fixed cleanup commands such as `taskkill /PID <pid> /F /T` should stay silent, while dynamic shell execution must still fire. Regression coverage: `src/tests/rule_behaviours/release_noise_guards.rs` (search: `process_command_skips_builders_and_fixed_pid_cleanup`) and `src/tests/scenarios/calibration_extras.rs` (search: `calibration_security_process_command_detects_code_not_fixture_text`).

## Footgun: Candidate Taint Rules Can Taint Their Own Predicate Booleans

**Status:** active | **Created:** 2026-05-31 | **Evidence:** ACTUAL_MEASURED

`src/built_in_rules/network_security_rules.rs` (search: `fn analyse_template_injection_xss`) uses a bounded same-function taint model. A first cut treated every function parameter as tainted and propagated taint through any local binding whose RHS mentioned a tainted name. The rule then self-fired on its own helper because `fn template_sink_argument(line: &str, ...)` has a tainted `line` parameter, `let has_sink = line.contains("Html(format!") ...` became a tainted local, and the later `if !has_sink` line looked like an unescaped template sink candidate.

The non-obvious failure mode is that candidate taint rules can create findings from detector-control booleans, not from user data. This is different from literal self-fire: calibration fixtures still pass, but dogfood reports the analyzer source as a security finding.

Calibrate taint propagation so predicate/control bindings (`has_`, `is_`, `should_`, `matches_`, etc.) do not become tainted sink arguments, and keep source scans in the verification loop after every taint-style rule. The current guard lives in `src/built_in_rules/network_security_rules.rs` (search: `fn binding_name_is_predicate`). The same verification pass also caught `serde_yaml::from_str` in analyzer config parsing; local config/YAML parsing should stay silent unless the source evidence is actually request/env-derived.

## Footgun: A Rule Exemption That Counts Only Named Placeholders Hides Positional Injection

**Status:** active | **Created:** 2026-06-14 | **Evidence:** ACTUAL_MEASURED

`src/built_in_rules/behavior_rules/tls_sql.rs` (search: `fn fixed_placeholder_arity_is_safe`) exempts `security.sql-dynamic-query` for the safe IN-clause idiom: a `let placeholders = repeat_n("?", n).join(",")` list bound through `params_from_iter`. The original exemption extracted only NAMED placeholders from the `format!` template, so positional `{}` and indexed `{0}` placeholders were invisible to it. `format!("... WHERE status = {} AND id IN ({placeholders})", status)` had its only *named* placeholder (`placeholders`) proven safe, the `all(...)` check passed, and the rule silently dropped a real injection sink. Positional `{}` is the most common `format!` form, so the gap masked the dominant shape, not an edge case.

The non-obvious failure mode is a security false-NEGATIVE introduced by a precision exemption: the placeholder enumerator filtered to simple identifiers and dropped non-identifier placeholders instead of treating them as un-proven. An exemption is itself a rule, and a skip predicate must enumerate EVERY placeholder and require all of them to be proven safe - never just the ones it can name.

Fix: `fn placeholder_arg_names` now returns every placeholder token (positional `{}` -> empty string, indexed `{0}` -> digits) and `fixed_placeholder_arity_is_safe` requires each to be a simple identifier AND a proven `?` list. Regression coverage: `src/tests/rule_behaviours/sql_dynamic_query_guards.rs` (search: `sql_dynamic_query_rejects_value_interpolation_beside_placeholder_list`) probes both positional `{}` and indexed `{0}`. Pairs with [[rule-precision]]: an exemption's false negatives cost as much as the rule's false positives.

## Footgun: High-Entropy Inert Skip Was Tuned To One Model-ID Shape, Not A Safe Principle

**Status:** active | **Created:** 2026-06-14 | **Evidence:** ACTUAL_MEASURED

`src/built_in_rules/helpers.rs` (search: `fn is_structured_high_entropy_non_secret`) skips inert high-entropy strings so `sensitive-data.high-entropy-string` (error severity) does not fire on base64 alphabets, word slugs, and model identifiers. The original model-ID recogniser demanded a `provider/Family/Model` slash structure with all-uppercase-or-digit version codes. Real model catalogues carry far more variety, so it missed bare names with no slash (`Llama-4-Maverick-17B-128E-Instruct-FP8`), single-slash ids, and lowercase size codes (`480b`, `a35b`). A scan of an AI-tooling repo's catalogue (`goose .../canonical_models.json`) produced ~92 error-severity false positives from model identifiers alone, and no real leaked credential was present among the 173 high-entropy hits across five repos.

The non-obvious failure mode is an error-severity secret rule whose inert-skip is enumerated from the author's example shapes: it looks correct on fixtures and floods on real data, and because it is error severity it FAILS a hook/CI gate on model-name strings - the false-positive-as-command-to-change-correct-code problem this tool exists to avoid. A structured-non-secret skip must be defined by a *safe separating principle*, not a hand-tuned shape.

Fix: `fn is_separated_identifier_slug` recognises any separator-delimited slug where every segment is short and alphanumeric and at least two are word-like, but refuses the skip when any non-word segment exceeds 6 chars - because a real secret is either contiguous (one segment), carries base64 padding (`+`/`=`), or hides a long high-entropy run, none of which pass. This removed 100 of 101 model-catalogue FPs across five external repos with zero collateral on any other rule, while every real-secret fixture stayed flagged. Regression coverage: `src/built_in_rules/helpers.rs` (search: `high_entropy_skips_model_identifiers_without_masking_secrets`) asserts the model IDs skip AND that opaque tokens / separated secret blobs keep flagging. Residual: a CamelCase name with a short acronym tail whose non-word segment exceeds 6 chars (`WizardLM-2-8x22B`) still flags; closing it would loosen the safety bound, so it is left. Pairs with [[rule-precision]].

## Footgun: Text Proof/Evidence Helpers Match Names Too Loosely

**Status:** active | **Created:** 2026-06-14 | **Evidence:** ACTUAL_MEASURED

Several rules "prove" a value safe, or find "evidence" it is risky, by scanning nearby source text for a binding or function. Done with `starts_with`, substring `find`, or `rfind("\nfn ")`, those matches are too loose in two recurring ways - they ignore word boundaries and they cross function boundaries - and the failure is a silent false negative in a SECURITY rule.

Concrete instances (2026-06-14, PR review): `src/built_in_rules/behavior_rules/tls_sql.rs` (search: `fn placeholder_binding_is_fixed_question_list`) scoped its fixed-`?` proof window with `rfind("\nfn ")`, which only matches a bare `fn` at column zero - so for `pub fn`/`async fn`/`impl` methods (the common case) the window spilled into earlier functions and a helper's `let placeholders = ...join(",")` vouched for an untrusted `placeholders` parameter elsewhere. Same file, `line_is_name_binding` used `starts_with("let {name}")`, so `placeholders` was proven by an unrelated `placeholders_safe` binding. The identical shape lived in `src/built_in_rules/path_traversal_rules.rs` (search: `fn window_has_receiver_path_binding`): a plain `find("let {receiver}")` let a `files_backup` binding vouch for a `files` receiver, and `let mut` bindings were missed entirely.

Fix pattern: scope the window to the ENCLOSING function (reuse `is_function_start_line` to find the start, not `rfind("\nfn ")`), and require a non-identifier char after a name match so `x` does not match `x_suffix`; cover both `let` and `let mut`. Regression coverage: `src/tests/rule_behaviours/sql_dynamic_query_guards.rs` (search: `sql_dynamic_query_proof_is_scoped_to_current_function_and_exact_name`) and `src/tests/rule_behaviours/mission_retune_guards.rs` (search: `path_traversal_reaches_accessor_receivers_and_let_mut_bindings`).

When adding any "look at nearby text for a binding/usage named X" helper, default to word-boundary checks and current-function scope, and add a negative fixture with a prefix-collision name (`X_safe`) plus a `let mut` binding. Pairs with [[rule-precision]].

## Footgun: Clearing Git Env Vars Does Not Fully Neutralise The Subprocess

**Status:** active | **Created:** 2026-06-14 | **Evidence:** OBSERVED

`src/changed_region.rs` (search: `fn git_command`) hardens the diff subprocess by removing `GIT_EXTERNAL_DIFF` and pointing config/hooks at `/dev/null`. That does NOT stop `git diff` from running an external diff driver configured by the repository's OWN committed `diff.external` (or a `.gitattributes` `diff=<driver>` mapping) - attacker-controlled data in an untrusted tree. Env hygiene neutralises the environment, not the repo's committed config.

The diff path is opt-in behind `--diff-git-unsafe` (ADR-019), but `.goat-flow/architecture.md` claims the diff subprocess "does not execute arbitrary code", so the gap also makes a committed claim untrue. Fix: pass `--no-ext-diff` on every `git diff` invocation (`src/changed_region.rs` search: `fn git_diff_patch`) - it disables both global `diff.external` and attribute-driven drivers. `--no-ext-diff` is a diff/log option, so it cannot live in the shared `git_command` builder (cat-file/ls-tree reject it); add it per diff arg vector.

When hardening any subprocess against an untrusted tree, enumerate the ways the tree's OWN committed files (config, attributes, hooks, ignore files) can change behaviour, not just environment variables. Pairs with ADR-019.
