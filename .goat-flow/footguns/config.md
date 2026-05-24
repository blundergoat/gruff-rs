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

Regression coverage: `src/tests/config_and_selectors/init_command.rs` (search: `default_config_round_trips_through_load_config`) asserts `ignored_paths` is non-empty but does not pin specific patterns - so a stripping regression would still pass tests. If this footgun recurs, tighten that test to assert the agent/CI prefixes are present.
