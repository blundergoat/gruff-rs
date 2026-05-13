# Glossary

## Analyzer Terms

Finding = One reported issue with a rule ID, severity, pillar, confidence, location, and fingerprint. Findings are produced by `analyse_source` in `src/main.rs`.

Pillar = Quality category used for scoring, such as security, size, naming, sensitive data, or test quality. Pillar scores are assembled by `score_report` in `src/main.rs`.

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

Config = Optional JSON settings input parsed by `load_config` to ignore paths, allow abbreviations or secret previews, and tune rule thresholds.
