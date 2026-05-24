# Glossary - gruff-rs

Last reviewed 2026-05-24.

This glossary defines terms used by `gruff-rs`, its public reports, and local project memory. Keep shared gruff-family terms aligned with the sibling implementations; keep Rust-specific differences explicit rather than making them look identical.

## Scope

`gruff-rs` is the Rust implementation of the gruff quality-scanner family. The crate and CLI binary are both `gruff-rs`; Cargo package metadata lives in `Cargo.toml`; product code lives under `src/`.

## Shared Gruff Terms

### Analysis Report

The complete result of one scan: schema version, tool metadata, run metadata, paths, summary counts, score data, diagnostics, findings, suppressions, baseline state, and optional diff/history state. Native JSON uses `gruff.analysis.v1`.

### Baseline

A reviewed-finding suppression file. `gruff-rs` writes and reads `gruff.baseline.v1`; entries match findings by fingerprint, rule ID, and file path.

### Changed-Code Scan

A scan filtered to changed lines or files. `--diff-patch <path>` treats a unified diff as data; older Git-backed `--diff <mode>` is available only with `--diff-git-unsafe`.

### Confidence

The certainty tier attached to a finding: `low`, `medium`, or `high`. It helps scoring and reviewers distinguish high-signal findings from heuristic prompts.

### Dashboard

The local browser UI served by `gruff-rs dashboard`. It binds to `127.0.0.1:8766` by default and has no authentication; use `--port` when another gruff dashboard is already using the port.

### Diagnostic

A run-level problem such as a missing path, read error, parse error, config error, baseline error, diff error, or history write failure. Fatal diagnostics force exit code `2`.

### Display Filter

A report-only filter or suppression layer that changes rendered output after analysis. In Rust, top-level `exclude` entries are audited report-level suppressions with reasons.

### Exit Codes

`0` means the run completed and no finding met the failure threshold. `1` means at least one finding met the threshold. `2` means a fatal diagnostic or invalid input stopped the requested scan from being fully trustworthy.

### Finding

One rule-produced result with rule ID, message, severity, confidence, pillar, location, remediation, metadata, and fingerprint.

### Fingerprint

A stable 16-character hash derived from finding identity fields. Baselines and downstream tooling key on it together with rule ID and file path.

### Gruff Config

Project configuration that tunes discovery, allowlists, rule selection, per-rule thresholds/severity, report suppressions, and custom rules. Shared keys include `paths.ignore`, `allowlists.acceptedAbbreviations`, `allowlists.secretPreviews`, and per-rule configuration.

### Hotspot Output

A compact JSON view of the worst file offenders for dashboards or trend tooling. `gruff-rs` emits it as `gruff.hotspot.v1`.

### Output Format

A renderer over the same analysis report. `analyse` supports `text`, `json`, `sarif`, `html`, `markdown`, `github`, and `hotspot`; `report` supports `html` and `json`.

### Pillar

The quality dimension a finding belongs to, such as `complexity`, `security`, `sensitive-data`, or `test-quality`. Pillars feed per-pillar scoring and display filters.

### Rule Catalogue

The set of built-in and configured custom rules plus their public metadata. `list-rules --format json` is the source of truth for rule IDs, pillars, severity, confidence, thresholds, options, and default enablement.

### Rule ID

Stable public identifier for one rule, using dotted gruff-family names such as `size.function-length`, `docs.todo-density`, and `sensitive-data.high-entropy-string`. Rust-specific namespaces such as `architecture.*`, `metrics.*`, `dependency.*`, `concurrency.*`, and `error-handling.*` may emit shared public pillars.

### SARIF

Static Analysis Results Interchange Format. `gruff-rs` emits SARIF 2.1.0 from the same report data used by the other renderers.

### Score And Grade

The numeric and letter quality summary derived from findings after baseline and suppression layers have been applied according to the current command.

### Secret Preview

A redacted representation of sensitive-data matches. Raw secret values must not appear in terminal, JSON, SARIF, GitHub, Markdown, hotspot, or HTML output.

### Severity And Failure Threshold

`gruff-rs` uses `advisory`, `warning`, and `error`. `--fail-on` controls exit code `1`; `none` reports findings without failing for severity.

### Source Discovery

The process that turns input paths into classifiable Rust or text/config files. By default it honours Git ignores, default ignored directories, and configured `paths.ignore`; `--include-ignored` includes those paths for deliberate inspection while VCS internals stay blocked.

### Trust Boundary

Default scans are source-only and local-only. `gruff-rs` does not execute target code, run Cargo build scripts, call Git unless unsafe Git diff is explicitly requested, query registries, or read vulnerability feeds.

## Implementation-Specific Terms

### Selector

A rule-selection expression used by `rules.select`, `rules.ignore`, and `list-rules --selector`. It accepts exact rule IDs, dotted prefixes, and public pillar names; negative selectors win on overlap.

### Patch Diff Filtering

The preferred changed-code workflow. `--diff-patch <path>` reads unified diff content as data, applies normal analysis, then filters findings to new-side hunk ranges.

### Unsafe Git Diff

The explicit `--diff-git-unsafe` opt-in that allows the older Git-backed diff path. It is named to make the trust boundary visible.

### Report-Level Exclusion

A top-level `exclude` config entry with a required reason. It hides reviewed findings after analysis and baseline application; it does not prevent files from being read or rules from running.

### Custom Rule

A config-defined regex rule under `custom_rules` with an ID in the reserved `custom.<slug>` namespace. Custom rules are regex-only in the current contract.

### Cargo Dependency Check

A local-only check that reads `Cargo.toml` and `Cargo.lock` as data. It does not run Cargo, query registries, or consume vulnerability feeds.

### Fixture

Intentionally noisy analyzer input under `fixtures/` or `tests/fixtures/`. Fixture findings are calibration data, not product debt.

## Agent Workflow Terms

### GOAT Flow

Local agent workflow framework installed from `@blundergoat/goat-flow`. It provides skills, audit commands, safety references, and `.goat-flow/` project-memory directories.

### Agent-Owned Surface

Files one agent setup owns without widening scope. Claude owns `CLAUDE.md` and `.claude/**`; Codex owns `AGENTS.md` and `.codex/**`; shared agent skills live under `.agents/skills/**`.

### Learning Loop

Durable shared project-memory directories under `.goat-flow/footguns/`, `.goat-flow/lessons/`, `.goat-flow/patterns/`, and `.goat-flow/decisions/`.
