# Architecture

## System Overview

`gruff-rs` is a single Rust binary implemented in `src/main.rs`. The binary has three user-facing modes: `analyse` walks source trees and emits findings, `report` renders analysis output to a file or stdout, and `dashboard` starts a small local HTTP server for browser-driven scans.

The crate keeps all analysis, rendering, baseline, and dashboard code in `src/main.rs` for now. Supporting shell entrypoints live in `scripts/check.sh` and `scripts/start-dev.sh`; intentionally noisy analyzer input lives in `fixtures/sample.rs`.

## Request Flow

For CLI analysis, `main` parses Clap commands, `run_analysis` loads config, `discover_sources` walks input paths, `analyse_source` dispatches text and Rust rules, then `render_report` selects text, JSON, HTML, Markdown, GitHub annotation, or hotspot output.

For dashboard scans, `run_dashboard` binds the requested host and port, `handle_dashboard_request` handles `/`, `/health`, and `/scan`, then `/scan` builds an `AnalysisOptions` value and renders the same report HTML through `dashboard_shell`.

## Auth / Trust Boundaries

There is no authentication layer. The dashboard defaults to loopback through `scripts/start-dev.sh`, so exposing it on a non-loopback host should be treated as a trust-boundary change.

The analyzer reads user-selected files and does not execute analyzed source. `fixtures/sample.rs` deliberately contains command execution and secret-looking strings so the scanner can prove those rules fire; those fixture strings are test inputs, not runtime credentials.

## Data Flow

Input paths become `SourceFile` records, then diagnostics and findings. Findings are sorted and deduplicated by fingerprint before rendering. Baseline generation and history recording write JSON side files whose names are ignored by `.gitignore`; absence of those files in a clean checkout is normal.

Rule tuning is loaded by `load_config` from an explicit config path or an optional default JSON config when present. Current checkout state has no project config file, so defaults in `Config::default` are the source of truth.

## Deployment / Operations

This repo has no CI or deployment assets. Local verification is `bash scripts/check.sh`, which runs formatting, Clippy, and unit tests. `cargo build` is the build smoke test, and `bash scripts/start-dev.sh` starts the dashboard using environment-overridable host, port, and project root values.

## Non-Obvious Constraints

- `src/main.rs` contains public report schema strings such as `gruff.analysis.v1`; changing them is a compatibility decision.
- Rule IDs and fingerprints are output contracts because baselines use fingerprints and consumers may key on rule IDs.
- `handle_dashboard_request` temporarily changes process cwd for scans; keep that side effect in mind before adding concurrency.
- `fixtures/sample.rs` is intentionally bad code and should not be cleaned up without replacing the analyzer coverage it provides.
