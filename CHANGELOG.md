# Changelog

## 0.1.0 - 2026-05-23

First public release. Deterministic, schema-versioned quality analyzer for
Rust projects; single-binary CLI you can drop into CI.

- Commands: `analyse`, `report`, `summary`, `list-rules`, `dashboard`, `completion`.
- Outputs: text, JSON (`gruff.analysis.v1`), SARIF 2.1.0, HTML, Markdown,
  GitHub annotations, hotspot.
- Default-on rules cover the shared pillars: complexity, dead-code, design,
  documentation, maintainability, modernisation, naming, security,
  sensitive-data, size, test-quality.
- `.gruff-rs.yaml` config with selectors, thresholds, allowlists, custom
  regex rules, and report-level exclusions.
- Baselines and patch-diff filtering for incremental adoption.
