# Code Map

## Repository Root

`Cargo.toml` = Rust package metadata and dependencies for the `gruff-rs` binary, including the `ignore` crate used for Git-ignore-aware source discovery.
`Cargo.lock` = Locked dependency graph; update through Cargo, not by hand.
`README.md` = Project overview, CLI examples, and config shape.
`AGENTS.md` = Codex/goat-flow operating instructions.
`.gitignore` = Ignores Cargo output plus analyzer baseline/history side files.
`.gruff-rs.yaml` = Project-level analyzer config; default config file discovered by `gruff-rs`.

## Source

`src/` = Rust source directory.
`src/main.rs` = Entry point and command dispatch: `main`, `run_summary`, `run_report`, `options_from_analyse`/`options_from_report`, the `analyse_source` rule-dispatch shim, scan-timing instrumentation (`Instant::now()` around `run_analysis`), and a few orchestration helpers (`changed_files`, etc.). Most subsystem responsibilities live in dedicated modules below.
`src/cli/` = Clap argument structs (`AnalyseArgs`, `ReportArgs`, `SummaryArgs`, `DashboardArgs`, `ListRulesArgs`, `CompletionArgs`) in `args.rs`; CLI enum, `GlobalOptions`, `OutputWriter`, and `RunOutcome::classify` in `mod.rs`. Owns the `--help` template and the `paths` positional whose default is the current directory.
`src/analysis.rs` = `run_analysis` entry point: builds `AnalysisOptions`, drives discovery + per-source analysis + project-wide analysis, assembles the final `AnalysisReport` (schema `gruff.analysis.v1`).
`src/discovery.rs` = Git-ignore-aware source discovery; `resolve_input_paths` defaults empty paths to `["."]` and routes through the `ignore` crate's `WalkBuilder`.
`src/source.rs` = `SourceFile` and `SourceUnit` types plus parser invocation.
`src/parser.rs` = Rust file parsing via `syn`; emits `parse-error` diagnostics on failure while preserving text-only rule coverage.
`src/project/` = Project-wide aggregation (`mod.rs` builds `ProjectContext` and the identifier-count index used by cross-file dead-code analysis via `count_rust_identifiers`; `items.rs` collects project-wide item definitions; `manifest.rs`/`lockfile.rs` parse `Cargo.toml`/`Cargo.lock`).
`src/analyse_project/` = Project-wide rule pillars: `mod.rs` orchestrator, `architecture.rs`, `dead_code.rs`, `dependencies.rs`.
`src/built_in_rules/` = Per-source built-in rules organised by concern: `behavior_rules`, `naming_rules`, `secret_rules`, `text_rules`, `waste_rules`, `concurrency_rules`, `perf_rules`, `test_rules`, plus shared `helpers`, `predicates`, `function_block_metrics`, etc. `mod.rs` exposes the `analyse` entry point.
`src/custom_rules.rs` = Regex-based custom rule evaluator (config-loaded; `custom.<slug>` namespace).
`src/config.rs` = `Config`, `AnalysisOptions`, `RequestedScope` (the empty-paths→`["."]` default also lives here for renderer view-models), `FailThreshold`, `DiffSelection`.
`src/config_loader/` = YAML config loading (`mod.rs`) plus split modules for `custom_rules`, `exclusions`, `rule_settings`, and `selectors` (selector DSL).
`src/diff.rs` = Patch-input diff filtering for `--diff-patch`/`--diff` modes (post-analysis filter, preserves finding identity).
`src/baseline.rs` = `gruff-baseline.json` read/write and finding match logic.
`src/report.rs` = Public report types: `AnalysisReport`, `Finding`, `Summary`, `PathSummary`, `RunInfo`, `ToolInfo`, `ScoreReport`, `RunDiagnostic`, `BaselineReport`, and finding fingerprinting.
`src/scoring.rs` = Composite scoring, per-pillar scoring, grade-letter mapping, and top-offenders selection.
`src/summary.rs` = `gruff-rs summary` digest renderer: text scan card + per-pillar / top-rules / top-files digest, and `gruff.summary.v2` JSON.
`src/render/` = Output formatters: `text.rs` (scan-card header + findings + diagnostics + suppressions), `markdown.rs`, `github.rs` (Actions annotations), `hotspot.rs` (top-offenders JSON), `sarif.rs` (SARIF v2.1.0 emitter and helpers). `mod.rs` dispatches by `OutputFormat` and threads `Option<u128>` scan duration into text only.
`src/html_report/` = HTML inspection report renderer module (`mod.rs` orchestrator, `sections.rs` view-model, `styles.rs` CSS); builds the renderer-only view-model (pillar grade letters, per-pillar severity counts, cyclomatic distribution buckets), drives `analyse --format html` and the dashboard iframe body.
`src/dashboard.rs` = Dashboard HTTP server: TcpListener loop, request parsing, `/`, `/scan`, `/health`, `/favicon.ico` routes, and the form/iframe shell.
`src/rules/` = Rule metadata contracts and the sorted built-in rule registry (split by concern across `structure_docs_reliability_definitions.rs`, `idiom_security_size_test_definitions.rs`, and `waste_definitions.rs`, re-exported from `mod.rs`) used by config validation and `list-rules`; reserves the `custom.` namespace for config-defined regex rules.
`src/tests/` = Unit and integration tests grouped by concern (`scenarios/`, `rule_behaviours/`, `project_tests/`, `config_and_selectors/`, `renderers/`, `calibration/`).

## Fixtures

`fixtures/` = Sample input files for analyzer smoke tests and manual scans.
`fixtures/README.md` = Notes that analyzer fixtures are intentionally noisy inputs.
`fixtures/sample.rs` = Intentionally noisy Rust sample containing secret-like strings, command execution, long parameters, and a weak test.
`fixtures/rubric.rs` = Expanded rubric smoke fixture for complexity, naming, size, documentation, design, and metric findings.
`tests/` = Rust test support files and parser fixtures used by unit tests.
`tests/fixtures/README.md` = Fixture grouping notes for parser, rule, and temp-project scanner tests.
`tests/fixtures/parser/` = Parser-focused Rust inputs covering raw strings, macros/impl methods, test attributes, and invalid Rust.
`tests/fixtures/rules/` = Focused positive/negative rule fixtures for selected v0.1 rubric checks.

## Scripts

`scripts/` = Project shell entrypoints.
`scripts/preflight-checks.sh` = Shell syntax/lint, formatting, Clippy, unit-test, rule-listing, JSON/SARIF fixture-scan, patch-input diff, selector, exclusion/custom-rule smokes, and a whole-project dogfood scan gated by `minimumSeverity.analyse` in `.gruff-rs.yaml`.
`scripts/start-dev.sh` = Starts the local dashboard with `GRUFF_HOST`, `GRUFF_PORT`, and `GRUFF_PROJECT_ROOT` overrides.
`scripts/test-performance.sh` = End-to-end performance harness; runs N+1 iterations across 9-10 scenarios, writes `target/perf/last-run.json`, supports `--update-baseline` and `--check` with configurable time/RSS budgets.

## Documentation And Harness

`docs/` = Project documentation added outside the hot-path instruction file.
`docs/rust-rubric.md` = Standalone v0.1 Rust rule matrix and deferred-rule notes.
`docs/coding-standards/` = Local engineering policy docs.
`docs/coding-standards/git-commit.md` = Commit-message guidance used by goat-flow harness checks.
`.goat-flow/` = Goat-flow setup, project memory, and local continuity structure.
`.goat-flow/architecture.md` = Current system architecture and trust boundaries.
`.goat-flow/code-map.md` = This repository map.
`.goat-flow/glossary.md` = Project-specific terms.
`.goat-flow/footguns/` = Durable codebase traps with evidence.
`.goat-flow/lessons/` = Durable agent-behavior lessons.
`.goat-flow/patterns/` = Reusable successful approaches.
`.goat-flow/decisions/` = Architecture decision records.
`.goat-flow/skill-reference/` = Shared goat-flow skill conventions.
`.goat-flow/skill-playbooks/` = Tool availability and usage playbooks.
`.goat-flow/tasks/` = Local milestone/task tracking path; contents are mostly local state.
`.goat-flow/logs/` = Local session, quality, critique, and security log paths.

## Codex Harness

`.agents/skills/` = Installed goat-flow skills shared by Codex/Gemini style agents.
`.codex/config.toml` = Codex feature and filesystem permission template for this project.
`.codex/hooks.json` = Codex hook registration for command safety.
`.codex/hooks/` = Installed deny hook and self-test script.

## Generated Or Local-Only

`target/` = Cargo build output; never edit or commit.
`.idea/` = IDE project metadata from this checkout.
`.git/` = Git repository metadata; never edit directly.
