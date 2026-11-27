---
category: config
last_reviewed: 2026-11-25
---

## Footgun: Stripping `paths.ignore` Defaults From `.gruff-rs.yaml`

**Status:** active | **Created:** 2026-05-24 | **Evidence:** OBSERVED

`.gruff-rs.yaml` (search: `paths:`) ships with discovery-time ignores for agent, CI, fixture, and vendor directories. Commit `2a5cc31` (search commit message: `update gruff-rs configuration and rules to enhance maintainability checks`) collapsed that list to just `target/**`, `node_modules/**`, and four lockfiles. The trimmed config silently pulled `.claude/**`, `.codex/**`, `.github/**`, `.goat-flow/**`, `.agents/**`, `.antigravitycli/**`, `fixtures/**`, and `tests/fixtures/**` back into the scan surface.

When this was first recorded the dogfood scan covered only `src/`, so the regression was invisible there. The dogfood scan now analyses the repository root (`scripts/preflight-checks.sh` search: `bin/gruff-rs analyse . --format text --no-baseline`), so a trimmed list pulls these directories straight into it. The dashboard and every other `gruff-rs analyse .` run are affected the same way: they descend into agent-skill markdown, CI YAML, calibration fixture configs, and analyzer fixture sources, producing dozens of advisory and error findings that are pure noise.

Two-part fix, both must stay in sync:
1. `.gruff-rs.yaml` `paths.ignore` must contain the agent/CI/fixture set this repo cares about (`.agents/**`, `.antigravitycli/**`, `.claude/**`, `.codex/**`, `.github/**`, `.goat-flow/**`, `fixtures/**`, `tests/fixtures/**`) on top of `target/**`, `node_modules/**`, and the lockfile globs.
2. `src/init.rs` (search: `DEFAULT_IGNORE_PATTERNS`) is the generator that `gruff-rs init` emits into new repos. The five universally-applicable agent/CI dirs (`.agents/**`, `.claude/**`, `.codex/**`, `.github/**`, `.goat-flow/**`) belong in that constant so freshly-initialised projects do not inherit the same trap.

When modifying `paths.ignore` in `.gruff-rs.yaml` or `DEFAULT_IGNORE_PATTERNS` in `src/init.rs`, do not remove the agent / CI / fixture entries. Always diff against the committed version and treat removal as a destructive change that needs explicit user approval. Add new ignores; do not silently prune.

Regression coverage:
- `src/tests/config_and_selectors/init_command.rs` (search: `default_config_round_trips_through_load_config`) now asserts the five agent/CI ignore prefixes (`.agents/`, `.claude/`, `.codex/`, `.github/`, `.goat-flow/`) appear in the rendered default.
- `src/tests/config_and_selectors/init_command.rs` (search: `init_preserves_existing_ignore_entries_on_regenerate`) writes a fake existing config with a custom `paths.ignore` entry and asserts the regenerated body retains it (and deduplicates entries that overlap with defaults).
- `src/tests/config_and_selectors/init_command.rs` (search: `read_existing_ignore_patterns_returns_empty_for_missing_or_malformed`) pins the graceful-degrade behaviour so `--force` can still repair a broken file.

The runtime defense lives in `src/init.rs` (search: `fn read_existing_ignore_patterns`). On every `gruff-rs init` invocation, the renderer reads the existing file's `paths.ignore` and unions it with `DEFAULT_IGNORE_PATTERNS` before writing - `--force` no longer wipes user customizations of the ignore list. Missing / malformed YAML / missing `paths.ignore` all degrade silently to an empty list with a stderr warning, so the regenerate path still works against a corrupted config.

**Scope caveat:** `--force` preserves four sections today: `paths.ignore` (`src/init.rs` search: `fn read_existing_ignore_patterns`), the `failOn` thresholds (`src/init.rs` search: `fn read_existing_fail_on`), the scalar `minimumSeverity` display floor (`src/init.rs` search: `fn read_existing_display_floor`), and `deepScanBudget` (`src/init.rs` search: `fn read_existing_deep_scan_budget`). Everything else is lost. `allowlists:` and `rules:` thresholds return to their defaults, and `sensitiveExclusions:` returns as a commented example. The renderer emits no `exclude:`, `custom_rules:` or `gate:` block, so those are dropped entirely. The preservation helpers share a `read_existing_yaml` reader (search: `fn read_existing_yaml`) so error-handling stays uniform. Extending preservation to a new section means adding a sibling `read_existing_<section>` plus a new parameter on `render_default_config` (search: `pub(crate) fn render_default_config`) — do not silently broaden the scope without an explicit ask.

## Footgun: Default-Allowlist Constants Duplicate Between config.rs And init.rs

**Status:** active | **Created:** 2026-05-25 | **Evidence:** OBSERVED

`src/config.rs` (search: `pub(crate) const DEFAULT_ABBREVIATIONS`) holds the compiled-in default that `Config::default()` uses to populate `accepted_abbreviations`. `src/init.rs` (search: `for abbreviation in DEFAULT_ABBREVIATIONS`) renders the same list into the YAML body that `gruff-rs init` writes to disk. Before 0.1.2 each module had its own private 16-entry constant — byte-identical but unlinked.

The PR that grew the list from 6 to 16 entries kept both copies in sync by accident; the next agent expanding only one would silently break the contract that compiled-in defaults and the freshly-`init`-generated YAML match. Unlike `DEFAULT_IGNORE_PATTERNS` (which intentionally has different runtime / on-disk shapes — empty `Vec` at runtime via `Config::default()`, populated YAML on disk via `init.rs` — see the previous footgun for why), `accepted_abbreviations` MUST match across both surfaces.

The non-obvious failure mode is that drift is invisible to the test suite: `Config::default()` unit tests and `init`-output snapshot tests each pass independently. For this list the fix has landed. `src/init.rs` imports the one constant (search: `use crate::config::{Config, DeepScanBudget, DEFAULT_ABBREVIATIONS`), and `src/tests/config_and_selectors/init_command.rs` (search: `assert_eq!(DEFAULT_ABBREVIATIONS, FAMILY_ABBREVIATIONS)`) also pins it to the family list. The trap remains for the next shared default that someone adds as two copies.

**How to apply:**

- Defaults that must match between `Config::default()` and the `init`-emitted YAML belong as one `pub(crate) const` in `src/config.rs`. `init.rs` imports it.
- Direction matters: `init.rs` depends on `config.rs`, never the reverse — `config.rs` is foundational and should not pull from CLI-subcommand modules.
- When adding a new allowlist / override-list config field that `init.rs` also needs to emit, factor the const out before adding both copies.
- See ../patterns/architecture.md "Default Config Constants Are Defined Once" for the prescriptive form.

## Footgun: Rule Option Names Do Not Imply Their Semantics

**Status:** active | **Created:** 2026-05-26 | **Evidence:** OBSERVED

A rule option's NAME is not enough to know what setting it does. `naming.placeholder-identifier.options.extraPlaceholders` sounds like an allow-list ("extra tokens this rule will tolerate") but is actually a BLOCK-list extension: any name added to it triggers the rule MORE, not less. When this was written, `naming.generic-function.options.extraGenericNames` had the same misleading shape and `naming.boolean-prefix.options.predicatePrefixes` was the inverse, a real allow-list. Both rules were retired in commit `b389054` (search commit message: `retire low-accuracy built-in rules`), and `extraPlaceholders` is the surviving example.

The OptionDefinition.description field encodes the truth (`src/rules/idiom_security_size_test_definitions.rs` search: `Additional placeholder identifiers rejected by naming.placeholder-identifier`), but those descriptions read past quickly when the option name alone seems self-explanatory. The 0.1.2 M05 first pass populated `false_positive_shapes` mitigations that told users to add their intentional names to the blocklist option, which would have made the false positive worse.

**Where the failure mode surfaces:**
- `false_positive_shapes` metadata in rule metadata shards under `src/rules/` (search: `FalsePositiveShape`).
- Per-rule remediation strings in `src/built_in_rules/naming_rules.rs` (search: `remediation: Some`).
- `list-rules <rule_id>` detail-card mitigations in `src/rules_detail.rs` (search: `fn render_false_positive_block`).

**How to apply:**
- Before writing a mitigation that names an option, read the option's `description` field. If the description says "rejected by" / "blocked by", it's a blocklist - tell the user to use `paths.ignore` or `rules.<id>.enabled: false` instead.
- Before writing a mitigation that names an option, check the rule's consumer code (`config.string_array_option(...)`). If the option value is checked with `contains` and a hit FIRES the rule, it's a blocklist.
- When designing a NEW option, prefer names that unambiguously encode direction: `allowed*` / `accepted*` / `extra*Allow*` for allow-lists; `denied*` / `rejected*` / `extra*Block*` / `additional*Reject*` for blocklists. Do not name an option `extra<thing>` when the semantics are "additional rejections" - that name reads as allow-list to consumers.
- The safest universal hatch for an intentional false positive is `paths.ignore` (when the call lives in fixtures, generated code, or a test harness) or `rules.<id>.enabled: false` (project-wide opt-out). Both are unambiguous.

## Footgun: Required-Field Config Schema Bumps Break Every Test Fixture

**Status:** active | **Created:** 2026-05-26 | **Evidence:** OBSERVED

0.1.2 M08a introduced the required `schemaVersion: gruff-rs.config.v1` field in `src/config_loader/mod.rs` (search: `fn apply_config_value`, look for the `missing the required` error). Configs that omit it are rejected with `Run gruff-rs init --force to regenerate`. The change is intentional - per the `feedback-no-bc-ceremony` memory, gruff-rs has no external users to migrate.

The non-obvious failure mode is the test suite. Every test that writes a fixture YAML and calls `load_config` started failing in lockstep: ~95 of 143 tests on first cargo test after the validator landed. The failures are spread across `src/tests/config_and_selectors/`, `src/tests/scenarios/`, `src/tests/project_tests/`, `src/tests/rule_behaviours/`, and `src/tests/renderers/` — the surface is wide because almost every behavioural test writes some inline config.

The fix is centralised in `src/tests/mod.rs` (search: `fn write_config`). The helper auto-prepends `schemaVersion: gruff-rs.config.v1\n` to any body that does not already contain `schemaVersion`, and emits a JSON-style merged form when the body starts with `{` (some smoke tests write JSON-syntax YAML at the root). Every test that needs to assert on the absence of `schemaVersion` (e.g. `config_rejects_missing_schema_version`) bypasses the helper and calls `fs::write` directly.

**How to apply:**
- When adding a NEW required field to the config schema, audit every YAML writer in the test surface BEFORE landing the validator change. `rg -n 'fs::write.*\.yaml|write_config' src/tests/ scripts/preflight-checks.sh` enumerates the write sites; only `src/tests/mod.rs` `write_config` is the central one.
- The auto-prepend belongs in `write_config`, not in individual tests - the latter rots the moment a new required field arrives.
- Smoke tests in `scripts/preflight-checks.sh` are NOT covered by `write_config`. Each `cat >"$config_file" <<'YAML'` heredoc that writes a config needs its own `schemaVersion: gruff-rs.config.v1` line on the first content line.
- The `null` mapping case matters: `gruff-rs init`'s default template emits `failOn:` with every entry commented (`src/init.rs` search: `# failOn controls per-subcommand fail thresholds.`), which YAML parses as null. The `failOn` handler, which kept its pre-rename name `apply_minimum_severity_section` (`src/config_loader/mod.rs` search: `if value.is_null()`), treats null as no-op so round-trip works. Future required-shape blocks need the same null-as-empty fall-through if they ship a commented-only default template.

Regression coverage:
- `src/tests/config_and_selectors/config.rs` (search: `fn config_rejects_missing_schema_version`) asserts the load-time error wording.
- `src/tests/config_and_selectors/config.rs` (search: `fn config_rejects_wrong_schema_version`) asserts an unknown version value is rejected with the same useful-error shape.
- `src/tests/config_and_selectors/config.rs` (search: `fn config_accepts_schema_version_and_records_it`) confirms the round-trip through `Config.schema_version`.

## Footgun: A Second Suppression Channel Reindexes The Shared `suppressions[]` Counter

**Status:** active | **Created:** 2026-08-22 | **Evidence:** ACTUAL_MEASURED
**Decision changed:** Before adding any new configuration-driven suppression channel, decide what `suppressions[].index` means and fix the recount before writing the matcher.
**Trigger phase:** ACT

`report.suppressions[]` was built for exactly one channel. `src/analysis.rs` (search: `fn initial_suppression_summaries`) set each row's `index` to its position in `config.exclusions`, which was also its position in the published array, and `src/diff.rs` (search: `pub(crate) fn recount_suppressions`) relied on that coincidence by recounting through the row's own `index`. The 0.6.0 `sensitiveExclusions` section (FAMILY-CONTRACT.md section 13a) is a second channel publishing into the same array, and the coincidence breaks the moment both sections carry entries: `exclude[0]` and `sensitiveExclusions[0]` are two different rows with the same `index`.

Two readings of `index` are both defensible and they pull opposite ways. Array-position indexes keep the positional recount working but make an audit row uncorrelatable with the config entry a validation diagnostic names, because a diagnostic can only name `sensitiveExclusions[0]`. Section-local indexes correlate, and they match the family reference row `{"index": 0, ...}`, but they make `index` alone ambiguous. The shipped choice is section-local, with `src/report.rs` (search: `pub(crate) config_key: &'static str`) carrying the owning config key as a `#[serde(skip)]` field so the pair identifies a row. `recount_suppressions` now matches on that pair, and `src/render/text.rs` (search: `summary.config_key`) labels each row `exclude[N]` or `sensitiveExclusions[N]` instead of a hardcoded `exclude[` prefix.

**Portability question this raises for the family (M03 review candidate).** rs is the only port that already had a reason-bearing `exclude[]`, so it is the only port where `suppressions[].index` carries pre-0.6.0 meaning. go, php, py and ts build the array from nothing and will naturally emit section-local indexes with no second channel to disambiguate against - which means four ports can satisfy the published shape without ever meeting the ambiguity, and the family then has one port whose `index` needs a companion field to be unique and four whose does not. Either `index` is contracted as section-local and the family adds a serialized owner key when a second channel appears, or the contract states that `suppressions[]` may carry only one channel per port. That question is open. This port answered it locally and did not change the published key set, because four other ports copy the rs row verbatim.

Two item budgets also constrain where the new code can live, and both fire as advisory findings in the dogfood scan (`scripts/preflight-checks.sh` search: `dogfood_scan`):

- `src/config.rs` and `src/report.rs` each sat at exactly 25 public items, the `architecture.large-module` threshold. Adding the resolved config type to `src/config.rs`, and an enum plus its `impl` to `src/report.rs`, pushed both over. The resolved type therefore lives with its parser in `src/config_loader/sensitive_exclusions.rs` (search: `pub(crate) struct SensitiveExclusionRule`), following how `Gate` lives in `src/gate.rs` rather than in `config.rs`, and the enum became a plain `&'static str` field.
- `src/tests/config_and_selectors/mod.rs` sat at 8 child modules, the `architecture.module-fan-out` threshold. The new test module is mounted under its semantic owner instead of as a ninth sibling: `src/tests/config_and_selectors/exclusions.rs` (search: `#[path = "sensitive_exclusions.rs"]`), the same nesting fix already recorded for the `built_in_rules` wrappers.

A third trap is specific to writing these tests: a rule id used only inside an inline format argument is invisible to `dead-code.unused-private-item-candidate`, because `src/parser/mod.rs` (search: `fn strip_rust_string_literals`) masks string literals before reference scanning. A constant referenced only as `format!("{JWT_RULE_ID} ...")` reports as an unused private item. Reference such a constant outside a format string, or inline the literal.

Regression coverage:
- `src/tests/config_and_selectors/sensitive_exclusions.rs` (search: `fn ordinary_exclusions_and_sensitive_exclusions_coexist`) asserts both channels publish rows, each with its own section-local index and config key, and that text output labels both.
- `src/tests/config_and_selectors/sensitive_exclusions.rs` (search: `fn assert_removed_scopes`) differences a no-config baseline run against the configured run, so an unintended sibling suppression fails the case rather than silently hiding a finding.

## Footgun: Selector Helpers Shared Between Config Loading And CLI Flags Leak Config Hints

**Status:** active | **Created:** 2026-11-25 | **Evidence:** ACTUAL_MEASURED
**Decision changed:** Before editing selector or unknown-rule diagnostics in `src/config_loader/`, check whether CLI commands reuse the same helper and gate config-migration advice to config paths and retired rule IDs only.
**Trigger phase:** ACT
**Caught at:** VERIFY

**Prevention:** Gate `gruff-rs migrate-config` hints in `src/config_loader/selectors.rs` (search: `fn is_config_selector_path`) so only config paths (`rules.select[...]`, `rules.ignore[...]`, `exclude[...].rule`) emit migration advice, never CLI paths such as `rules --selector` in `src/main.rs` (search: `fn render_rule_list`). Keep non-retired unknown-rule diagnostics unchanged across `src/config_loader/rule_settings.rs` (search: `fn insert_rule_setting`), `src/config_loader/mod.rs` (search: `fn ensure_rule_supports_threshold`), and `src/config_loader/sensitive_exclusions.rs` (search: `fn parse_sensitive_rule_id`), because contract tests assert exact wording on typos. When `src/migrate_config.rs` (search: `fn drop_retired_selector_list`) removes retired IDs from a non-empty `rules.select`, refuse migration rather than emptying the list and silently widening analysis to every built-in rule.

Shared helpers make it easy to leak config-file instructions onto CLI flag errors or overwrite exact-match typo assertions. Keep retired rule IDs in one shared list (`src/migrate_config.rs`, search: `RETIRED_0_5_RULES`) verified disjoint from the built-in registry (`src/tests/config_and_selectors/config.rs`, search: `migrate_config_drops_retired_rules_and_empty_minimum_severity`), and test both config and CLI `rules --selector` paths (`tests/cli_regressions.rs`, search: `migrate_config_upgrades_legacy_05_config_and_unmigrated_shows_hint`).

## Footgun: Project-Root Ancestor Lookup Escapes Across .git Into Parent Ignores

**Status:** active | **Created:** 2026-11-25 | **Evidence:** ACTUAL_MEASURED
**Decision changed:** Keep `.git` as a hard ancestor boundary in project-root resolution using `symlink_metadata`, and verify corpus or nested-repo scans assert positive `score.evaluatedFiles` rather than exit status zero alone.
**Trigger phase:** ACT
**Caught at:** VERIFY

**Prevention:** Keep `ancestor.join(".git").symlink_metadata().is_ok()` beside `Cargo.toml` and `.gruff-rs.yaml` in `src/command_setup.rs` (search: `fn project_root_from_targets`). Never swap `symlink_metadata` for `exists`, because `exists` follows symlinks on untrusted source trees and fails open on dangling worktree or submodule `.git` links. Whenever scanning a repository rooted below another workspace, assert `score.evaluatedFiles > 0` instead of trusting exit code zero.

Polyglot and nested-Rust repositories (such as Tauri apps with `src-tauri/Cargo.toml` or monorepos with `v2/Cargo.toml`) have `.git` at the repo root and no top-level `Cargo.toml` or `.gruff-rs.yaml`. When `project_root_from_targets` checked only `Cargo.toml` and `.gruff-rs.yaml`, scanning `Handy` and `RuView` inside a gitignored parent folder walked past `.git` into `gruff-rs`, applied the parent `.gitignore`, and exited zero with zero evaluated files (`Composite: n/a`). Guarded by `src/tests/scenarios/stable_identity.rs` (search: `project_root_stops_at_git_boundary_for_nested_repos`) and `tests/cli_regressions.rs` (search: `nested_git_repo_under_ignored_parent_dir_scans_its_own_sources`).
