# Glossary

Last reviewed 2026-05-18.

## Analyzer Terms

Finding = One reported issue with a rule ID, severity, pillar, confidence, location, and fingerprint. Findings are produced by `analyse_source` in `src/main.rs`.

Pillar = Quality category used for scoring, such as security, size, naming, sensitive data, or test quality. Pillar scores are assembled by `score_report` in `src/main.rs`.

Rule ID = Stable public rule identifier using the gruff-family `<namespace>.<rule-slug>` convention, for example `size.file-length`, `docs.todo-density`, and `sensitive-data.high-entropy-string`. Rust-specific namespaces such as `architecture.*`, `metrics.*`, `dependency.*`, `concurrency.*`, and `error-handling.*` are documented rule families; the emitted pillar may still be `design`, `complexity`, `security`, or `waste`.

Baseline = A JSON suppression file for accepted findings. Baseline entries match findings by fingerprint, rule ID, and file path.

Fingerprint = Stable-ish 16-character hash derived from rule ID, file path, line, and symbol. Fingerprints are output contracts because baseline suppression depends on them.

Diagnostic = A run-level issue such as a missing input path, read error, parse error, or history write failure. Diagnostics make the process exit with code 2.

## CLI And Output Terms

Analyse command = CLI mode that scans paths and prints a report in the requested format.

Report command = CLI mode that scans paths and writes HTML or JSON output to a file or stdout.

Dashboard command = Local HTTP server that renders an HTML form and runs the same analyzer through `/scan`.

Hotspot output = Compact JSON view containing the overall score and top offending files.

GitHub output = Annotation format built from findings so CI logs can expose notices, warnings, and errors.

## Project Artifacts

Fixture = Intentionally flawed sample input under `fixtures/` used to exercise analyzer rules.

History file = Optional JSON side file updated by `record_history` to capture score/finding counts over time.

Config = Optional YAML settings input parsed by `load_config` from `.gruff-rs.yaml` or an explicit `--config` path. Shared keys are `paths.ignore`, `allowlists.acceptedAbbreviations`, `allowlists.secretPreviews`, and `rules`; Rust currently does not implement `selection`.
