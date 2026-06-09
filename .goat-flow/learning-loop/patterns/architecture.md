---
category: architecture
last_reviewed: 2026-05-27
---

## Pattern: Per-Enum Display Helpers Live Next To The Enum, Not Per-Renderer

**Context:** Use this when adding a new output format (JSON / HTML / Markdown / text / SARIF / GitHub annotations) or a new variant to an existing `src/report.rs` enum (`Pillar`, `Severity`, `Confidence`, future enums). Any function that maps an enum variant to a display string is a candidate.

**Evidence:** Before 0.1.2, `pillar_label` existed as three byte-identical 14-line `match` definitions: private `fn pillar_label` in `src/summary.rs` and `src/render/markdown.rs`, plus `pub(crate) fn pillar_label` in `src/html_report/mod.rs`. PR #3 added the third copy as part of new format coverage; the duplication was invisible because each module compiled in isolation. Deduplicated in 0.1.2 by promoting to `pub(crate) fn pillar_label` in `src/report.rs` (search: `pub(crate) fn pillar_label`) next to the `Pillar` enum and re-exporting at crate root via `use report::{... pillar_label};` in `src/main.rs`. All three call sites now import `crate::pillar_label`. Test suite (132/132) still green; output unchanged.

**Approach:**

- Define the helper as `pub(crate) fn <name>(value: EnumType) -> &'static str` next to the enum in `src/report.rs`. Match-arm coverage of every variant lives there exactly once.
- Add the helper name to the `use report::{...}` block in `src/main.rs` so submodules access it as `crate::<name>`.
- Renderer modules import via `use crate::<name>` (alongside their other crate imports). No per-renderer redefinition.
- When reviewing a new renderer or rule module, grep `fn .*<Enum>.*-> &.*str` shapes — they signal duplication.

The pattern composes with adding new enum variants: adding `Pillar::NewVariant` requires updating exactly one `match` arm. Without the pattern, a missed renderer either silently produces a confusing default-arm string or — if the match was exhaustive — fails to compile in only the place that was remembered.

When NOT to apply: helpers that need per-format escaping (e.g. HTML-escaped variant of an already-canonical string) belong in the renderer module. The canonical helper in `report.rs` returns the unescaped form; the renderer composes with its own escape function (e.g. `html_escape(pillar_label(p))`).

Related: ../footguns/report.md "Per-Format Renderer Helpers Tend To Duplicate" for the failure mode this pattern prevents.

## Pattern: Default Config Constants Are Defined Once, Imported From init.rs

**Context:** Use this when adding a new default-list config field whose value must match between `Config::default()` (the compiled-in runtime default) and the YAML emitted by `gruff-rs init`. Examples: accepted abbreviations, secret prefixes, default allowlists.

**Evidence:** Before 0.1.2, `DEFAULT_ABBREVIATIONS` was a private const in `src/init.rs` and a separately-written inline array literal inside `Config::default()` in `src/config.rs` — byte-identical 16-entry lists that hadn't yet drifted because the same PR happened to update both. Deduplicated in 0.1.2 by promoting to `pub(crate) const DEFAULT_ABBREVIATIONS` in `src/config.rs` (search: `pub(crate) const DEFAULT_ABBREVIATIONS`); `src/init.rs` imports via `use crate::config::DEFAULT_ABBREVIATIONS` and the literal in `Config::default()` collapses to `DEFAULT_ABBREVIATIONS.iter().map(|value| (*value).to_string()).collect()`.

**Approach:**

- The const lives in `src/config.rs` next to `Config::default()`, with a one-line comment naming its semantic role.
- `init.rs` imports the const via `use crate::config::<NAME>`.
- Direction matters: `init.rs` depends on `config.rs`, never the reverse. `config.rs` is foundational and should not pull from CLI-subcommand modules.

When NOT to apply: defaults that *intentionally* differ between runtime and on-disk shapes — `DEFAULT_IGNORE_PATTERNS` is empty `Vec` at runtime via `Config::default()` but populated as YAML on disk by `init.rs` (search: `DEFAULT_IGNORE_PATTERNS`). That asymmetry is a deliberate design choice; see ../footguns/config.md "Stripping `paths.ignore` Defaults" for why. Do not collapse the two.

Related: ../footguns/config.md "Default-Allowlist Constants Duplicate Between config.rs And init.rs" for the failure mode this pattern prevents.

## Pattern: Pre-Load Config At The CLI Edge, Thread It Through

**Context:** Use this when a CLI command's behaviour (exit code, output shape, default values) needs to consult the project's `.gruff-rs.yaml` BEFORE the analysis runs. Today the only consumer is `--fail-on` resolution (M08a / ADR-013), but the same pattern applies if a future command needs config-derived selectors, output-format defaults, or per-project gating logic.

**Evidence:** Before 0.1.2, `src/analysis.rs` `run_analysis_in_project` (search: `pub(crate) fn run_analysis_in_project`) called `load_config(project_root, options)` internally. The CLI command functions (`run_analyse_command`, `run_report`, `run_summary`, `dashboard`) just built `AnalysisOptions` from clap args and called `run_analysis`. That hid the config load deep in the analysis pipeline. ADR-013 needs the CLI edge to know the resolved `fail_on` (from CLI flag > config key > binary default) BEFORE `AnalysisOptions::fail_on` is finalised, so the load has to move up. M08a moved it: `run_analysis_in_project` now takes `&Config` as a parameter; the wrapper `run_analysis` (which only resolved project_root) was removed. Callers in `main.rs` and `src/dashboard.rs` load the config via `command_setup::resolve_project_root_and_config` (search: `pub(crate) fn resolve_project_root_and_config`) and pass it in. `src/tests/mod.rs` `analyse_project_paths` (search: `fn analyse_project_paths`) does the same for test fixtures.

**Approach:**

- The shared edge helper lives in `src/command_setup.rs` (search: `pub(crate) fn resolve_project_root_and_config`). It returns `(PathBuf, Config)` so the caller never has to thread project_root and load_config separately.
- Per-command composites in the same module wrap the edge helper plus per-command resolution: `resolve_command_setup` (search: `pub(crate) fn resolve_command_setup`) takes a base `AnalysisOptions`, the CLI value, the command name, and the binary default; returns `(PathBuf, AnalysisOptions, Config)` with `fail_on` already resolved.
- Each consumer (`run_analyse_command`, `run_report`, `run_summary`, `dashboard::dashboard_response`) calls the helper once and threads the loaded Config into `run_analysis_in_project(&project_root, &options, &config)`.
- Hardcoded `FailThreshold::None` stays at consumer sites that do not gate (`run_summary`, `run_list_rules`, `dashboard_scan_options`). The validator in `apply_minimum_severity_section` (search: `const GATING_COMMANDS`) rejects `summary`/`dashboard`/`list-rules` as `minimumSeverity:` keys so the runtime hardcode and the config surface stay consistent.

When NOT to apply: pure analysis modules that have no CLI-edge concerns (e.g. `src/scoring.rs`, `src/render/*`). Keep config-loading at the edge; pass the loaded values down. Analysis modules consume `&Config` from `run_analysis_in_project`'s parameter; they should not re-load it.

The pattern composes with adding new CLI commands: a new gating command (a) adds itself to the `GATING_COMMANDS` accept-list in `src/config_loader/mod.rs`, (b) consumes the edge helper in `main.rs`, and (c) calls `resolve_fail_on` with its own command name + binary default.

Related: `.goat-flow/decisions/ADR-013-per-command-minimum-severity.md` is the decision record for the M08a/M08b split that introduced this pattern.

## Pattern: Inline Submodule To Keep `architecture.large-module` Off Cohesive Helper Groups

**Context:** Use this when adding a small cluster of cohesive helpers to an existing module that is already near the `architecture.large-module` threshold (default 25 indexed items per `(file_path, module_path)`). The new helpers belong semantically with the host file, but a flat addition would push the parent over the threshold and either (a) trigger a real findings regression that gates the dogfood scan or (b) force a premature file split that obscures the cohesion.

**Evidence:** Before M04b shipped, `src/summary.rs` was already at 23 indexed items. M04b's per-rule delta rendering adds three logical pieces (the entry point, a per-block ranking helper, and a shared cap constant). Flat addition would push `summary` to 26 items and fire `architecture.large-module` on a clean dogfood scan. Solved by wrapping the helpers in `mod rule_delta_blocks { use super::{RuleDelta, RULE_DELTA_BLOCK_LIMIT}; ... }` inline in `src/summary.rs` (search: `mod rule_delta_blocks {`). Items inside that inline submodule get `module_path = "summary::rule_delta_blocks"` from `src/project/items.rs` `collect_project_module` (search: `pub(crate) fn collect_project_module`), so `analyse_large_modules` groups them under a separate `(file_path, module_path)` bucket and they do not count toward `summary`. Dogfood scan stayed at 100.0 (A) / 0 findings; the helpers stay in their natural host file; the call-site becomes `rule_delta_blocks::render_text(...)` which is a readable signpost rather than a buried free function.

**Approach:**

- Wrap the cohesive helper group in an inline `mod <descriptive_name> { use super::*; ... }` at the bottom of the host file. Name the submodule for the *feature* (e.g. `rule_delta_blocks`), not for the file type (e.g. `helpers`).
- Use `pub(super)` (not `pub(crate)`) on the entry-point function so the parent module is the only caller. This keeps the submodule's surface minimal and signals "internal cohesive cluster" to readers.
- Re-import only the specific symbols the submodule needs (`use super::{RuleDelta, RULE_DELTA_BLOCK_LIMIT};`), not `use super::*;`, so the cluster's dependencies are visible at a glance.
- Call from the parent as `<modname>::entry_point(...)`. That namespacing is the readability payoff — readers see `rule_delta_blocks::render_text` and know exactly where to find the related helpers without grep.
- Counterindication: if the cluster grows past ~4 items or starts being referenced from outside the host file, promote it to its own file (`src/<host>/<modname>.rs` or `src/<modname>/mod.rs`). The inline submodule is a way to keep a small cluster together, not a substitute for file decomposition.

When NOT to apply: when the host module is already well below the threshold and adding helpers is fine flat. The inline submodule is not free — it adds a layer of indirection that costs readability if the cluster is too small (1-2 items) or too sprawling (>5 items). Reach for it when both "items belong together semantically" and "the parent is bumping up against the threshold" hold at once.

The same trick neutralises `architecture.module-fan-out` if a `mod.rs` declaration list is approaching its threshold: wrap a small group of cohesive child modules in `mod <group> { pub(super) mod a; pub(super) mod b; }` so they count as one child of the parent and N children of the new group. Use sparingly — file structure is the better long-term lever.

Related: `src/analyse_project/architecture.rs` `analyse_large_modules` (search: `pub(crate) fn analyse_large_modules`) is the rule that consults `(file_path, module_path)` groupings; `src/project/items.rs` `collect_project_module` (search: `pub(crate) fn collect_project_module`) is where the submodule's `module_path` is forked from its parent's path.
