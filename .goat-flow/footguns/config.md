---
category: config
last_reviewed: 2026-05-24
---

## Footgun: Stripping `paths.ignore` Defaults From `.gruff-rs.yaml`

**Status:** active | **Created:** 2026-05-24 | **Evidence:** OBSERVED

`.gruff-rs.yaml` (search: `paths:`) ships with discovery-time ignores for agent, CI, fixture, and vendor directories. Commit `2a5cc31` (search commit message: `update gruff-rs configuration and rules to enhance maintainability checks`) collapsed that list to just `target/**`, `node_modules/**`, and four lockfiles. The trimmed config silently pulled `.claude/**`, `.codex/**`, `.github/**`, `.goat-flow/**`, `.agents/**`, `.antigravitycli/**`, `fixtures/**`, and `tests/fixtures/**` back into the scan surface.

The non-obvious failure mode is that the dogfood scan (`scripts/preflight-checks.sh` search: `dogfood_source_scan`) only scans `src/`, so the regression is invisible there. But any later command that scans the repo root, plus dashboard / `gruff-rs analyse .` invocations, will start descending into agent-skill markdown, CI YAML, calibration fixture configs, and analyzer fixture sources - producing dozens of advisory and error findings that are pure noise.

Two-part fix, both must stay in sync:
1. `.gruff-rs.yaml` `paths.ignore` must contain the agent/CI/fixture set this repo cares about (`.agents/**`, `.antigravitycli/**`, `.claude/**`, `.codex/**`, `.github/**`, `.goat-flow/**`, `fixtures/**`, `tests/fixtures/**`) on top of `target/**`, `node_modules/**`, and the lockfile globs.
2. `src/init.rs` (search: `DEFAULT_IGNORE_PATTERNS`) is the generator that `gruff-rs init` emits into new repos. The five universally-applicable agent/CI dirs (`.agents/**`, `.claude/**`, `.codex/**`, `.github/**`, `.goat-flow/**`) belong in that constant so freshly-initialised projects do not inherit the same trap.

When modifying `paths.ignore` in `.gruff-rs.yaml` or `DEFAULT_IGNORE_PATTERNS` in `src/init.rs`, do not remove the agent / CI / fixture entries. Always diff against the committed version and treat removal as a destructive change that needs explicit user approval. Add new ignores; do not silently prune.

Regression coverage:
- `src/tests/config_and_selectors/init_command.rs` (search: `default_config_round_trips_through_load_config`) now asserts the five agent/CI ignore prefixes (`.agents/`, `.claude/`, `.codex/`, `.github/`, `.goat-flow/`) appear in the rendered default.
- `src/tests/config_and_selectors/init_command.rs` (search: `init_preserves_existing_ignore_entries_on_regenerate`) writes a fake existing config with a custom `paths.ignore` entry and asserts the regenerated body retains it (and deduplicates entries that overlap with defaults).
- `src/tests/config_and_selectors/init_command.rs` (search: `read_existing_ignore_patterns_returns_empty_for_missing_or_malformed`) pins the graceful-degrade behaviour so `--force` can still repair a broken file.

The runtime defense lives in `src/init.rs` (search: `fn read_existing_ignore_patterns`). On every `gruff-rs init` invocation, the renderer reads the existing file's `paths.ignore` and unions it with `DEFAULT_IGNORE_PATTERNS` before writing - `--force` no longer wipes user customizations of the ignore list. Missing / malformed YAML / missing `paths.ignore` all degrade silently to an empty list with a stderr warning, so the regenerate path still works against a corrupted config.

**Scope caveat:** preservation today is `paths.ignore` only. Custom `rules:` thresholds, `allowlists:` extensions, `custom_rules:`, and the `exclude:` block are still regenerated from defaults on `--force`. Extending preservation further is intentional follow-up: do not silently broaden the scope without an explicit ask.
