# Architecture

## System Overview

`gruff-rs` is a Rust binary implemented through `src/main.rs` plus focused modules such as `src/rules.rs`. The binary has four user-facing modes: `analyse` walks source trees and emits findings, `report` renders analysis output to a file or stdout, `list-rules` prints registry metadata, and `dashboard` starts a small local HTTP server for browser-driven scans.

The crate keeps CLI orchestration, rendering, baseline, and dashboard code in `src/main.rs` for now. Rule metadata and the built-in rule registry live in `src/rules.rs`; built-in rule dispatch is behind a module boundary. Supporting shell entrypoints live in `scripts/check.sh` and `scripts/start-dev.sh`; intentionally noisy analyzer input lives in `fixtures/sample.rs`.

## Request Flow

For CLI analysis, `main` parses Clap commands, `run_analysis` loads config, `discover_sources` walks input paths, builds a `SourceUnit` for each readable file, `analyse_source` dispatches text and Rust rules, then `render_report` selects text, JSON, HTML, Markdown, GitHub annotation, or hotspot output. `list-rules` renders sorted built-in registry definitions as text or JSON.

For dashboard scans, `run_dashboard` binds the requested host and port, `handle_dashboard_request` handles `/`, `/health`, and `/scan`, then `/scan` builds an `AnalysisOptions` value and renders the same report HTML through `dashboard_shell`. Dashboard scans call the analysis pipeline with an explicit project root instead of changing the process working directory.

## Auth / Trust Boundaries

There is no authentication layer. The dashboard defaults to loopback through `scripts/start-dev.sh`, so exposing it on a non-loopback host should be treated as a trust-boundary change.

The analyzer reads user-selected files and does not execute analyzed source. `fixtures/sample.rs` deliberately contains command execution and secret-looking strings so the scanner can prove those rules fire; those fixture strings are test inputs, not runtime credentials.

## Data Flow

Input paths become `SourceFile` records, then `SourceUnit` records containing raw text, parser diagnostics, and an optional `syn` Rust AST. Text rules run for every supported file. Rust AST rules run only when parsing succeeds; parse failures emit a `parse-error` diagnostic while still allowing text-only checks such as sensitive-data detection. Findings are sorted and deduplicated by fingerprint before rendering. Baseline generation and history recording write JSON side files whose names are ignored by `.gitignore`; absence of those files in a clean checkout is normal.

Rule tuning is loaded by `load_config` from an explicit config path or the first default project config found in this order: `.gruff.yaml`, `.gruff.yml`, `.gruff.json`. Config validation is strict: unknown root keys, rule ids, threshold names, option names, and unsupported value shapes return command errors. The committed `.gruff.yaml` mirrors current defaults and documents the Rust-native config shape. Scoring includes all built-in static pillars even when a pillar has zero findings, so clean or narrow scans still communicate coverage.

## Deployment / Operations

CI lives in `.github/workflows/ci.yml` and runs the same local preflight command as developers: `bash scripts/check.sh`. That script runs formatting, Clippy, unit tests, rule-listing smoke, fixture scan, and self-scan diagnostics smoke. `cargo build` remains the build smoke test, and `bash scripts/start-dev.sh` starts the dashboard using environment-overridable host, port, and project root values.

## Non-Obvious Constraints

- `src/main.rs` contains public report schema strings such as `gruff.analysis.v1`; changing them is a compatibility decision.
- Rule IDs and fingerprints are output contracts because baselines use fingerprints and consumers may key on rule IDs.
- Rust parsing uses `syn` with span locations; parser changes must preserve fixture line, symbol, and fingerprint contracts unless an explicit compatibility decision says otherwise.
- `fixtures/sample.rs` is intentionally bad code and should not be cleaned up without replacing the analyzer coverage it provides.
- `.gruff.yaml` is the default project config contract. Keep `.gruff.yml` and explicit `.gruff.json` compatibility unless a config compatibility decision replaces them.
