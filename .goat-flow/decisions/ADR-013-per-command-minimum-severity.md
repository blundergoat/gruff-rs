# ADR-013: Per-command minimumSeverity config block and config schemaVersion

**Status:** Accepted
**Date:** 2026-05-26
**Author(s):** Matthew Hansen (with Claude Code)
**Ticket/Context:** 0.1.2 M07-M10 cross-port alignment with gruff-go 0.1.2's minimumSeverity dimension; introduces gruff-rs's first config schemaVersion (`gruff-rs.config.v1`).

## Context

Before this ADR, gruff-rs's exit-code gating had a single configurability axis: the `--fail-on` CLI flag on `analyse` and `report` (`src/cli/args.rs:21`, `src/cli/args.rs:59`). To make a project's CI gate on, say, `warning` for `analyse`, every CI invocation had to pass `--fail-on warning`. There was no per-project "the default fail threshold for analyse on this codebase is X" surface.

Sibling port gruff-go 0.1.2 introduced a `minimumSeverity:` block in its config schema with per-subcommand keys, so callers can set defaults once in the project config and omit the flag at the invocation site. The cross-port-alignment effort applies the same pattern to gruff-rs.

Three secondary problems sat alongside the primary ask:

1. The `--fail-on` CLI default for `analyse` was `error`. Cross-port philosophy is "show everything, gate on anything" — i.e. the default should surface advisory findings as failures, leaving stronger thresholds as opt-in. Lowering the default to `advisory` is part of this work.
2. gruff-rs has never had a config schema version. Adding one defensively (`gruff-rs.config.v1`) lets future migrations be detected at load time rather than via silent shape drift.
3. The off-switch value spelling differs across ports. gruff-go uses `never`; gruff-rs already uses `none` (`src/cli/mod.rs:230-235` `FailThreshold::None`). Renaming to `never` would be cross-port symmetry, but it would also silently invalidate every existing CLI invocation, baseline regen script, and CI alias in any consumer using `--fail-on=none`.

## Decision

Introduce two new top-level keys in `.gruff-rs.yaml`:

- `schemaVersion: gruff-rs.config.v1` — required for every config file. Empty or version-less configs are rejected at load time with a useful error pointing at `gruff-rs init --force`. There is no shim accepting unversioned configs; per the `no-bc-ceremony` memory, gruff-rs has no external users to migrate.
- `minimumSeverity:` — optional. Accepts a mapping of subcommand name to threshold value. Accept-list: `{analyse, report}`. Threshold values: `none | advisory | warning | error`, parsed via `FailThreshold::FromStr` (M07).

Resolution precedence is **CLI flag > config key > binary default**, evaluated by a new `resolve_fail_on` helper in `src/main.rs`. The helper is called from `run_analyse_command` and `run_report` after loading the project Config; the resolved value populates `AnalysisOptions::fail_on`.

The clap `default_value` attributes on `AnalyseArgs::fail_on` and `ReportArgs::fail_on` are dropped; the args are `Option<FailThreshold>`. The binary defaults move into the resolution helper. **M08a preserves today's binary defaults** (`Error` for analyse, `None` for report); the default flip to `Advisory` is M08b's job.

The off-switch value remains `none` (not `never`). gruff-rs's port deviation from gruff-go is recorded here and surfaced in the CHANGELOG cross-port-status note. See the `feedback-minimum-severity-off-switch-none` auto-memory entry.

The fail_on-resolution architecture is **Option A** from the M08 fork-set: `run_analysis_in_project`'s signature is changed to accept a pre-loaded `&Config` parameter; `main.rs` (and the dashboard / test helpers) load the Config once and thread it through. Rejected alternatives:

- **Option B** (move `RunOutcome::classify` into `run_analysis`): mixes exit-code policy with pure analysis; harder to test independently.
- **Option C** (two-phase load: cheap pre-load in main.rs, full load inside run_analysis): two parse paths for the same file invite divergence under future parser changes.

## Failure Mode Comparison

| Option | What fails | Why rejected or accepted |
| --- | --- | --- |
| Keep CLI-only `--fail-on` | Every CI script duplicates the flag; per-project policy lives in shell aliases, not in the repo. | Rejected — cross-port alignment closes this gap deliberately. |
| Config-only `minimumSeverity:` (no CLI flag override) | One-off invocations (e.g. tighter gating for a release branch) require editing the yaml. | Rejected — CLI flag must remain the highest-precedence override. |
| Single `defaults.failOn:` scalar (no per-command) | Cannot differentiate `analyse` (gates) from `report` (today defaults to off). Future commands that gate would force a redesign. | Rejected — sibling-port `minimumSeverity:` mapping is forward-compatible. |
| Accept `summary`/`dashboard`/`list-rules` keys in `minimumSeverity:` | Those commands do not gate exit code; setting a threshold on them is a CI footgun (silent no-op). | Rejected — validator rejects unknown keys with an error naming the valid ones. |
| Rename `none` → `never` for cross-port symmetry | Silently breaks every existing `--fail-on=none` invocation in this project and any consumer's CI. | Rejected — conscious port deviation; documented in CHANGELOG cross-port-status note. |
| Skip `schemaVersion:`; rely on shape detection | Future config-format migrations have no fail-fast signal; consumers see cryptic key-unknown errors instead of a versioned migration prompt. | Rejected — `schemaVersion` is cheap insurance and required going forward. |
| Add a backwards-compat shim for unversioned configs | Per `no-bc-ceremony` memory, gruff-rs has no external users; a shim is debt with no constituency. | Rejected — break loudly, fix forward. |
| Option B fail_on resolution (move classify into run_analysis) | Mixes policy with analysis; tests for analysis must now stub policy. | Rejected for testability. |
| Option C fail_on resolution (two-phase config load) | Two parse paths invite divergence under future parser changes. | Rejected for correctness. |
| **Option A fail_on resolution (pre-load Config, change signature)** | Three internal callers update mechanically; tests update; one Config load per CLI invocation. | **Accepted** — single source of truth at the edge. |

## Consequences

- Every `.gruff-rs.yaml` MUST begin with `schemaVersion: gruff-rs.config.v1`. Loading an unversioned config errors with a fix-it suggestion (`gruff-rs init --force`).
- `AnalysisOptions::fail_on: FailThreshold` continues to be a concrete (non-Option) value at the consumer boundary. Resolution happens earlier, at the CLI edge, before the options struct is built.
- `run_analysis_in_project` and `run_analysis` now take a `&Config` parameter. Three call sites in `main.rs` (`run_analyse_command`, `run_report`, `run_summary`), the dashboard scan endpoint, and two test helpers update.
- The default flip from `error` to `advisory` for `analyse --fail-on` is **deferred to M08b** so the foundation milestone (M08a) ships invisible at runtime: no exit-code drift, no surprise CI breakage. M08b lands the visible change in a separate commit with its own CHANGELOG entry.
- The accept-list `{analyse, report}` is authoritative. If a future PR adds `--fail-on` to `summary`, `dashboard`, or `list-rules`, that PR extends the validator's accept-list. The dashboard explicitly does not gate today (`src/dashboard.rs:173` hardcodes `FailThreshold::None`); its absence from the accept-list is deliberate.
- `gruff-rs init` (M08b) emits the new template with `schemaVersion:` first and a commented `minimumSeverity:` block to surface the surface without forcing a pin.
- The project's own `.gruff-rs.yaml` gains an explicit `minimumSeverity.analyse: advisory` in M08b — matching the new binary default but freezing the project's CI behaviour against any future default flip.

## Reversibility

Two-way door for both the config key and the schemaVersion field. Removing `minimumSeverity:` from a yaml file restores binary-default behaviour. Removing `schemaVersion:` from a yaml file produces a load error today; reverting to "schemaVersion optional" is a one-line validator change, but the asymmetry (consumers omitted the field, builds broke, they ran `gruff-rs init --force`) means the "remove" direction is costly post-rollout.

The `none` vs `never` deviation is also two-way: aliasing `never` → `none` is a small validator change if cross-port symmetry becomes more important than the existing-invocation stability argument. The decision today is to keep `none`; revisit only if a real cross-port workflow surfaces friction.

Revisit triggers:
- A downstream consumer or sibling port adopts an incompatible spelling for the off-switch; weigh the breakage cost against the symmetry gain.
- The accept-list `{analyse, report}` grows because `summary` or `dashboard` gains gating semantics; that PR owns the validator update and any CHANGELOG note.
- A second schema-version bump (`gruff-rs.config.v2`) becomes necessary; this ADR's "required, no shim" decision is the baseline for the migration-strategy ADR.

## References

- M07 task file: `.goat-flow/tasks/0.1.2/M07-failthreshold-parser-hardening.md` (the `FromStr` + `Deserialize` impls this ADR relies on).
- M08a task file: `.goat-flow/tasks/0.1.2/M08a-config-schema-foundation.md` (foundation milestone).
- M08b task file: `.goat-flow/tasks/0.1.2/M08b-cli-default-flip-and-init-template.md` (default flip milestone).
- gruff-go 0.1.2 M02 task file: `gruff-go/.goat-flow/tasks/0.1.2/M02-config-schema-bump-and-cli-wire-through.md` (sibling-port reference design).
- Auto-memory entries: `feedback-minimum-severity-gating-philosophy`, `feedback-minimum-severity-off-switch-none`, `feedback-no-bc-ceremony`.
