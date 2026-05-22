# Glossary

Last reviewed 2026-05-23.

## Analyzer Terms

Finding = One reported issue with a rule ID, severity, pillar, confidence, location, and fingerprint. Findings are produced by `analyse_source` in `src/main.rs`, which dispatches into `src/built_in_rules/` and `src/custom_rules.rs`.

Pillar = Quality category used for scoring, such as security, size, naming, sensitive data, or test quality. Pillar scores are assembled by `score_report` in `src/scoring.rs`.

Rule ID = Stable public rule identifier using the gruff-family `<namespace>.<rule-slug>` convention, for example `size.file-length`, `docs.todo-density`, and `sensitive-data.high-entropy-string`. Rust-specific namespaces such as `architecture.*`, `metrics.*`, `dependency.*`, `concurrency.*`, and `error-handling.*` are documented rule families; the emitted pillar may still be `design`, `complexity`, `security`, or `waste`.

Baseline = A JSON suppression file for accepted findings. Baseline entries match findings by fingerprint, rule ID, and file path.

Fingerprint = Stable-ish 16-character hash derived from rule ID, file path, line, and symbol. Fingerprints are output contracts because baseline suppression depends on them.

Diagnostic = A run-level issue such as a missing input path, read error, parse error, or history write failure. Diagnostics make the process exit with code 2.

Selector = A rule-selection expression used by `rules.select` / `rules.ignore` in config and by `list-rules --selector`. Accepts exact rule ids, dotted prefixes, and public pillar names. Negative wins on overlap per ADR-005.

Scan card = The two-line header printed by `analyse --format text` and `summary` showing tool/version, project root (`$HOME`-shortened to `~`), files scanned, scan duration, score/grade, and severity counts. Built in `src/render/text.rs::render_text_header` and `src/summary.rs::render_scan_card`.

## CLI And Output Terms

Analyse command = CLI mode that scans paths and prints a report in the requested format. Empty `paths` defaults to the current directory.

Report command = CLI mode that scans paths and writes HTML or JSON output to a file or stdout. Empty `paths` defaults to the current directory.

Summary command = CLI mode that prints a compact digest: scan card + per-pillar finding counts + top rules + top file offenders. Text or `gruff.summary.v1` JSON. Empty `paths` defaults to the current directory.

Dashboard command = Local HTTP server that renders an HTML form and runs the same analyzer through `/scan`. Implemented in `src/dashboard.rs`.

Completion command = Emits a shell completion script (bash, zsh, fish, powershell, elvish) for the `gruff-rs` CLI via `clap_complete`.

Hotspot output = Compact `gruff.hotspot.v1` JSON view containing the overall score and top offending files.

GitHub output = Annotation format built from findings so CI logs can expose notices, warnings, and errors.

SARIF output = SARIF 2.1.0 JSON document covering tool metadata, rule metadata, results with partial fingerprints, run diagnostics as invocation notifications, and in-source suppressions for report-level exclusions. Implemented in `src/render/sarif.rs`.

## Project Artifacts

Fixture = Intentionally flawed sample input under `fixtures/` used to exercise analyzer rules.

History file = Optional JSON side file updated by `record_history` to capture score/finding counts over time.

Config = Optional YAML settings input parsed by `load_config` from `.gruff-rs.yaml` or an explicit `--config` path. Shared keys are `paths.ignore`, `allowlists.acceptedAbbreviations`, `allowlists.secretPreviews`, `rules.select`/`rules.ignore` (selector DSL), `rules.<id>` (per-rule enable/threshold/severity), `exclude` (report-level suppressions with reasons), and `custom_rules` (regex custom rules in the `custom.<slug>` namespace).

Custom rule = Config-defined regex rule under `custom_rules` in `.gruff-rs.yaml`. Reserved id namespace `custom.<slug>`. Loaded and compiled at config-load time by `src/config_loader/custom_rules.rs`; evaluated by `src/custom_rules.rs`. ADR-010 deliberately limits v1 to regex (no AST/Semgrep/XPath/script/plugin runtimes).
