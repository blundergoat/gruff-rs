# Architecture

## System Overview

`gruff-rs` is a Rust binary implemented through `src/main.rs` plus focused modules such as `src/rules.rs`. The binary has four user-facing modes: `analyse` walks source trees and emits findings, `report` renders analysis output to a file or stdout, `list-rules` prints registry metadata, and `dashboard` starts a small local HTTP server for browser-driven scans.

The crate keeps CLI orchestration, rendering, baseline, and dashboard code in `src/main.rs` for now. Rule metadata and the built-in rule registry live in `src/rules.rs`; built-in rule dispatch is behind a module boundary. Supporting shell entrypoints live in `scripts/check.sh` and `scripts/start-dev.sh`; intentionally noisy analyzer inputs live in `fixtures/` and `tests/fixtures/`.

## Request Flow

For CLI analysis, `main` parses Clap commands, `run_analysis` loads config, `discover_sources` walks input paths, reads each file into a parsed source record, builds an internal `ProjectContext`, dispatches project rules, then dispatches text, Rust, and config-defined regex custom rules through `analyse_source`. Exact baselines apply before report-level exclusions, and optional patch-input diff filtering runs last, so accepted historical findings stay suppressed before audited exclusions and changed-line narrowing. `render_report_with_scope` selects text, JSON, SARIF, HTML, Markdown, GitHub annotation, or hotspot output, threading a renderer-only `RequestedScope` (requested paths plus diff label) into HTML rendering without serialising it onto `AnalysisReport`. `list-rules` loads the same config surface, renders sorted built-in registry definitions followed by sorted `custom.<slug>` rules as text or JSON, and `list-rules --selector` previews the deterministic rule-id set matched by an exact id, dotted prefix, or public pillar selector.

The HTML inspection report lives in `src/html_report.rs`. It builds a renderer-internal `ReportView` view-model that derives pillar grade letters, per-pillar severity counts, top-offender grade pills, and a bucketed cyclomatic-complexity distribution from finding metadata. Visual identity (italic-serif `gruff.rs` wordmark, L-bracket "paper" container, rotated grade stamp, pillar grid, complexity histogram, severity-tagged finding rows, forge-orange accent) is shared by `analyse --format html` and the dashboard iframe body.

For dashboard scans, `run_dashboard` binds the requested host and port, `handle_dashboard_request` handles `/`, `/health`, and `/scan`, then `/scan` builds an `AnalysisOptions` value and renders the same report HTML through `dashboard_shell`. Dashboard scans call the analysis pipeline with an explicit project root instead of changing the process working directory.

## Auth / Trust Boundaries

There is no authentication layer. The dashboard defaults to loopback through `scripts/start-dev.sh`, so exposing it on a non-loopback host should be treated as a trust-boundary change.

The analyzer reads user-selected files and does not execute analyzed source. Patch-input diff mode reads unified diff text as data and does not run Git or external diff drivers, following `.goat-flow/decisions/ADR-009-suppression-baseline-and-diff-layering.md`. The older Git-backed `--diff` path is gated behind `--diff-git-unsafe` and emits a run diagnostic when used. Fixture files deliberately contain command execution, secret-looking strings, parser edge cases, and noisy rule examples so the scanner can prove those rules fire; those fixture strings are test inputs, not runtime credentials.

## Data Flow

Input paths are discovered with Git-ignore-aware traversal that reads ignore
files as data, includes non-ignored dot-directories, and layers `.gruff-rs.yaml`
`paths.ignore` on top of repository ignore policy. Explicit file paths are still
accepted as focused scan targets, and `--include-ignored` opts into local ignored
paths for deliberate inspection while VCS internals stay traversal-blocked.
Discovered inputs become `SourceFile` records,
then owned parsed-source records containing raw text, parser diagnostics, and an
optional `syn` Rust AST. `ProjectContext` is built from those parsed sources plus
read-only `Cargo.toml` and `Cargo.lock` summaries, Rust source summaries, module
summaries, item summaries, and call-name summaries. Module and item summaries
carry conservative cfg/test context so project rules can avoid overclaiming
type-aware certainty. The project context is internal analysis state and is not
serialized into `gruff.analysis.v1`.

Project rules run against `ProjectContext`. Text rules run for every supported file. Rust AST rules run only when parsing succeeds; parse failures emit a `parse-error` diagnostic while still allowing text-only checks such as sensitive-data detection. Rust function-scope rules include complexity, naming, test-quality, error-handling, async/concurrency, loop-scoped performance, and deterministic token metrics. Regex custom rules are loaded from top-level `custom_rules`, compile during config loading, and run after built-ins with explicit `text`, `rust-code`, or `comments` scopes plus optional include/exclude path filters. Findings are sorted and deduplicated by fingerprint before rendering. Baseline generation and history recording write JSON side files whose names are ignored by `.gitignore`; absence of those files in a clean checkout is normal. Report-level `exclude` entries are post-analysis suppressions with required reasons and counts; they filter rendered findings without changing discovery, rule ids, fingerprints, or exact baseline matching. `--diff-patch` filtering is report post-processing after exclusions: it preserves analysed file counts and finding identity, recomputes report summary/score after filtering, and records an informational `patch-filter` diagnostic with kept and suppressed counts.

SARIF output is a dedicated renderer over `AnalysisReport` and `RuleRegistry`, not
a native schema variant. It emits SARIF 2.1.0 with sorted driver rules, URI-safe
artifact paths, result-level `partialFingerprints.gruffFingerprint`, rule
metadata from the registry, and run diagnostics as invocation notifications.
Fatal diagnostics set SARIF `executionSuccessful` to `false`; informational
diagnostics such as `patch-filter` stay visible without failing the invocation.
Report-level exclusions appear as SARIF result suppressions with
`kind = "inSource"` and the configured reason as justification.
SARIF rendering must not change `gruff.analysis.v1`, rule ids, fingerprints,
baseline matching, scoring, or fail-on behavior.

Rule tuning is loaded by `load_config` from an explicit YAML config path or the default `.gruff-rs.yaml`. Config validation is strict: unknown root keys, rule ids, selectors, option names, exclusion fields, custom-rule fields, and unsupported value shapes return command errors. Rule selection follows `.goat-flow/decisions/ADR-005-rule-selection-profiles-and-selector-precedence.md`: `rules.select` is an optional allow-list over exact rule ids, dotted prefixes, and public pillars; `rules.ignore` subtracts matches and wins on overlap; exact per-rule blocks remain keyed by canonical rule id for `enabled` settings and, for thresholded rules, one `threshold` plus one fixed `severity`. Custom rules follow `.goat-flow/decisions/ADR-010-custom-rules-start-regex-only.md`: built-ins may not use the reserved `custom.` namespace, custom regexes must compile at config-load time, and the v1 surface deliberately excludes AST/Semgrep/XPath/script/plugin runtimes. Top-level `exclude` entries reuse selector parsing for their `rule` field and can narrow by gitignore-style paths plus message substring, including `custom.<slug>` ids. The committed `.gruff-rs.yaml` explicitly enumerates every built-in rule so the local rubric surface is visible while preserving the curated threshold overrides. Scoring includes all built-in static pillars even when a pillar has zero findings, so clean or narrow scans still communicate coverage.

## Deployment / Operations

CI lives in `.github/workflows/ci.yml` and runs the same local preflight command as developers: `bash scripts/check.sh`. That script runs formatting, Clippy, unit tests, rule-listing smoke, JSON and SARIF fixture scans, a patch-input diff smoke, an exclusion smoke, a custom-rule smoke, and self-scan diagnostics smoke. The expanded rubric still keeps this as a single default gate; a May 2026 measured run completed in about six and a half seconds after dependencies were built. `cargo build` remains the build smoke test, and `bash scripts/start-dev.sh` starts the dashboard using environment-overridable host, port, and project root values.

## Non-Obvious Constraints

- `src/main.rs` contains public report schema strings such as `gruff.analysis.v1`; changing them is a compatibility decision.
- Rule IDs and fingerprints are output contracts because baselines use fingerprints and consumers may key on rule IDs.
- Rust parsing uses `syn` with span locations; parser changes must preserve fixture line, symbol, and fingerprint contracts unless an explicit compatibility decision says otherwise.
- Cargo metadata readers parse `Cargo.toml` and `Cargo.lock` as data only. They must not run Cargo, build scripts, proc macros, package hooks, or network requests.
- Project-aware dead-code and architecture rules are candidate/structural checks. They must not claim type-aware certainty, module-cycle certainty, or cfg-matrix certainty without a new analysis model.
- Advanced metric rules use deterministic token counts and calibrated single thresholds for advisory findings. They complement, but do not replace, the existing `score` object in `gruff.analysis.v1`.
- `fixtures/` and `tests/fixtures/` intentionally contain noisy or invalid inputs and should not be cleaned up without replacing the analyzer coverage they provide.
- `.gruff-rs.yaml` is the default project config contract. Other gruff config names and non-YAML config files are intentionally unsupported before public release.
