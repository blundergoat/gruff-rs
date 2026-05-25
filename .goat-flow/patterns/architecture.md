---
category: architecture
last_reviewed: 2026-05-25
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

Related: footguns/report.md "Per-Format Renderer Helpers Tend To Duplicate" for the failure mode this pattern prevents.

## Pattern: Default Config Constants Are Defined Once, Imported From init.rs

**Context:** Use this when adding a new default-list config field whose value must match between `Config::default()` (the compiled-in runtime default) and the YAML emitted by `gruff-rs init`. Examples: accepted abbreviations, secret prefixes, default allowlists.

**Evidence:** Before 0.1.2, `DEFAULT_ABBREVIATIONS` was a private const in `src/init.rs` and a separately-written inline array literal inside `Config::default()` in `src/config.rs` — byte-identical 16-entry lists that hadn't yet drifted because the same PR happened to update both. Deduplicated in 0.1.2 by promoting to `pub(crate) const DEFAULT_ABBREVIATIONS` in `src/config.rs` (search: `pub(crate) const DEFAULT_ABBREVIATIONS`); `src/init.rs` imports via `use crate::config::DEFAULT_ABBREVIATIONS` and the literal in `Config::default()` collapses to `DEFAULT_ABBREVIATIONS.iter().map(|value| (*value).to_string()).collect()`.

**Approach:**

- The const lives in `src/config.rs` next to `Config::default()`, with a one-line comment naming its semantic role.
- `init.rs` imports the const via `use crate::config::<NAME>`.
- Direction matters: `init.rs` depends on `config.rs`, never the reverse. `config.rs` is foundational and should not pull from CLI-subcommand modules.

When NOT to apply: defaults that *intentionally* differ between runtime and on-disk shapes — `DEFAULT_IGNORE_PATTERNS` is empty `Vec` at runtime via `Config::default()` but populated as YAML on disk by `init.rs` (search: `DEFAULT_IGNORE_PATTERNS`). That asymmetry is a deliberate design choice; see footguns/config.md "Stripping `paths.ignore` Defaults" for why. Do not collapse the two.

Related: footguns/config.md "Default-Allowlist Constants Duplicate Between config.rs And init.rs" for the failure mode this pattern prevents.
