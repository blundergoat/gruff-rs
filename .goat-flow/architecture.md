# Architecture

## System Overview

`gruff-rs` is a Rust binary implemented through `src/main.rs` plus focused modules such as `src/rules.rs`. The binary has four user-facing modes: `analyse` walks source trees and emits findings, `report` renders analysis output to a file or stdout, `list-rules` prints registry metadata, and `dashboard` starts a small local HTTP server for browser-driven scans.

The crate keeps CLI orchestration, rendering, baseline, and dashboard code in `src/main.rs` for now. Rule metadata and the built-in rule registry live in `src/rules.rs`; built-in rule dispatch is behind a module boundary. Supporting shell entrypoints live in `scripts/check.sh` and `scripts/start-dev.sh`; intentionally noisy analyzer inputs live in `fixtures/` and `tests/fixtures/`.

## Request Flow

For CLI analysis, `main` parses Clap commands, `run_analysis` loads config, `discover_sources` walks input paths, reads each file into a parsed source record, builds an internal `ProjectContext`, dispatches project rules, then dispatches text and Rust rules through `analyse_source`. `render_report` selects text, JSON, HTML, Markdown, GitHub annotation, or hotspot output. `list-rules` renders sorted built-in registry definitions as text or JSON.

For dashboard scans, `run_dashboard` binds the requested host and port, `handle_dashboard_request` handles `/`, `/health`, and `/scan`, then `/scan` builds an `AnalysisOptions` value and renders the same report HTML through `dashboard_shell`. Dashboard scans call the analysis pipeline with an explicit project root instead of changing the process working directory.

## Auth / Trust Boundaries

There is no authentication layer. The dashboard defaults to loopback through `scripts/start-dev.sh`, so exposing it on a non-loopback host should be treated as a trust-boundary change.

The analyzer reads user-selected files and does not execute analyzed source. Fixture files deliberately contain command execution, secret-looking strings, parser edge cases, and noisy rule examples so the scanner can prove those rules fire; those fixture strings are test inputs, not runtime credentials.

## Data Flow

Input paths become `SourceFile` records, then owned parsed-source records containing raw text, parser diagnostics, and an optional `syn` Rust AST. `ProjectContext` is built from those parsed sources plus read-only `Cargo.toml` and `Cargo.lock` summaries, Rust source summaries, module summaries, item summaries, and call-name summaries. Module and item summaries carry conservative cfg/test context so project rules can avoid overclaiming type-aware certainty. The project context is internal analysis state and is not serialized into `gruff.analysis.v1`.

Project rules run against `ProjectContext`. Text rules run for every supported file. Rust AST rules run only when parsing succeeds; parse failures emit a `parse-error` diagnostic while still allowing text-only checks such as sensitive-data detection. Rust function-scope rules include complexity, naming, test-quality, error-handling, async/concurrency, loop-scoped performance, and deterministic token metrics. Findings are sorted and deduplicated by fingerprint before rendering. Baseline generation and history recording write JSON side files whose names are ignored by `.gitignore`; absence of those files in a clean checkout is normal.

Rule tuning is loaded by `load_config` from an explicit config path or the first default project config found in this order: `.gruff.yaml`, `.gruff.yml`, `.gruff.json`. Config validation is strict: unknown root keys, rule ids, threshold names, option names, and unsupported value shapes return command errors. The committed `.gruff.yaml` mirrors the main tunable defaults without becoming a generated dump of every built-in rule. Scoring includes all built-in static pillars even when a pillar has zero findings, so clean or narrow scans still communicate coverage.

## Deployment / Operations

CI lives in `.github/workflows/ci.yml` and runs the same local preflight command as developers: `bash scripts/check.sh`. That script runs formatting, Clippy, unit tests, rule-listing smoke, fixture scan, and self-scan diagnostics smoke. The expanded rubric still keeps this as a single default gate; a May 2026 measured run completed in about six and a half seconds after dependencies were built. `cargo build` remains the build smoke test, and `bash scripts/start-dev.sh` starts the dashboard using environment-overridable host, port, and project root values.

## Non-Obvious Constraints

- `src/main.rs` contains public report schema strings such as `gruff.analysis.v1`; changing them is a compatibility decision.
- Rule IDs and fingerprints are output contracts because baselines use fingerprints and consumers may key on rule IDs.
- Rust parsing uses `syn` with span locations; parser changes must preserve fixture line, symbol, and fingerprint contracts unless an explicit compatibility decision says otherwise.
- Cargo metadata readers parse `Cargo.toml` and `Cargo.lock` as data only. They must not run Cargo, build scripts, proc macros, package hooks, or network requests.
- Project-aware dead-code and architecture rules are candidate/structural checks. They must not claim type-aware certainty, module-cycle certainty, or cfg-matrix certainty without a new analysis model.
- Advanced metric rules use deterministic token counts and calibrated thresholds for advisory findings. They complement, but do not replace, the existing `score` object in `gruff.analysis.v1`.
- `fixtures/` and `tests/fixtures/` intentionally contain noisy or invalid inputs and should not be cleaned up without replacing the analyzer coverage they provide.
- `.gruff.yaml` is the default project config contract. Keep `.gruff.yml` and explicit `.gruff.json` compatibility unless a config compatibility decision replaces them.
