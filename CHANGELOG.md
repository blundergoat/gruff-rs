# Changelog

## 0.1.2 - 2026-05-25

### Added

- `gruff-rs summary --format json` pillars[] entries expose nine fields:
  `pillar`, `grade`, `score`, `applicable`, `findings`, `advisory`,
  `warning`, `error`, `penalty`.
- `pillars[]` lists every score pillar (not only pillars with findings)
  and is sorted deterministically by `findings DESC, then pillar ASC`.
  `applicable` records whether the pillar contributes to the composite
  score.
- `penalty` exposes the raw, unclamped score subtraction so saturated
  pillars (score 0) still surface the underlying penalty for
  worst-pillar ranking that survives the `max(0.0, 100.0 - penalty)`
  clamp.
- Markdown report gains a `## Pillars` section: a seven-column table
  (`Pillar | Grade | Score | Findings | Advisory | Warning | Error`)
  inserted between the score header and the bulleted findings list.
  Same sort as the JSON.
- Default `accepted_abbreviations` grows from six entries
  (`id`, `db`, `io`, `ui`, `tx`, `rx`) to sixteen, adding `age`, `app`,
  `fs`, `key`, `log`, `max`, `min`, `now`, `raw`, `url`. Naming rules
  accept these out of the box; project-specific vocabulary still goes in
  user config.

### Changed

- Summary JSON `schemaVersion` moves from `gruff.summary.v1` to
  `gruff.summary.v2`.
- Analysis JSON (`gruff.analysis.v1`) `score.pillars[]` entries gain a
  `penalty: f64` field alongside the existing `pillar`, `score`,
  `findings`.
- HTML inspection report replaces the pillar card grid with a
  seven-column table (`<table class="pillar-list">`) matching the JSON
  and Markdown column set and sort. Grade renders inside a
  `<span class="grade-pill {letter}">` pill. Per-severity count cells
  get a tier CSS class (`.note`, `.warn`, `.fail`) only when non-zero;
  zero counts stay neutral. The "pillar grades" heading shortens to
  "pillars".
- HTML verdict stat labels singularised: "errors" → "error", "warnings"
  → "warning", "advisories" → "advisory".
- HTML pillar section no longer renders the mutation placeholder card.
- `gruff-rs summary` text output prefixes each pillar line with its
  grade letter and two-decimal score and aligns columns by max name /
  digit width. Severity labels widen from `err` / `warn` / `adv` to
  `error` / `warning` / `advisory`, and ordering follows
  `findings DESC, then pillar ASC`.
- Version bumped to `0.1.2`.

### Internal

- `PillarScore` (`src/report.rs`) gains `penalty: f64`, populated by
  `pillar_scores` in `src/scoring.rs`.
- `summary::pillar_digests` becomes `pub(crate)` and is the single
  source of truth for pillar grade, score, severity counts, and sort
  order across the JSON, HTML, Markdown, and text views.
  `src/html_report/mod.rs` and `src/render/markdown.rs` consume it
  directly, replacing `html_report::build_pillar_rows`' duplicate
  per-pillar tabulation.
- `ReportView` drops the `pillar_for_mutation_missing` field that gated
  the removed mutation placeholder.
- Cross-port: the v2 JSON pillar shape and the seven-column HTML /
  Markdown table match the corresponding `gruff-go`, `gruff-ts`,
  `gruff-py`, and `gruff-php` ports.
- New regression tests in `src/tests/renderers/output.rs` lock the
  canonical JSON / HTML / Markdown pillar contracts (column set, sort,
  severity tier classes, score precision).
- Documentation references to `gruff.summary.v1` updated to
  `gruff.summary.v2` in `.goat-flow/architecture.md`,
  `.goat-flow/code-map.md`, and the `summary_json_smoke` check in
  `scripts/preflight-checks.sh`.

## 0.1.1 - 2026-05-24

### Added

- 10 new default-on rubrics across four pillars (catalogue: 67 → 77 rules):
  - `modernisation.manual-is-empty` — flag `len() == 0` / `len() != 0` checks that
    should use `is_empty()`.
  - `modernisation.manual-contains` — flag `iter().any(|x| *x == y)` or
    `iter().any(|x| x == &y)` shapes that should use `contains(&y)`.
  - `modernisation.manual-strip-prefix` — flag
    `if s.starts_with(p) { &s[p.len()..] }` shapes that should use
    `strip_prefix`.
  - `modernisation.manual-unwrap-or-default` — flag
    `match opt { Some(v) => v, None => Default::default() }` shapes that should
    use `unwrap_or_default()`.
  - `docs.missing-panics-section` — public functions containing
    `panic!`/`unwrap`/`expect` without a `# Panics` rustdoc section.
  - `docs.missing-safety-section` — public `unsafe fn` items lacking a
    `# Safety` rustdoc section.
  - `docs.missing-param-doc` — public functions whose rustdoc does not mention
    each parameter by identifier.
  - `docs.missing-return-doc` — public non-`Result` functions returning a value
    whose rustdoc does not describe the return.
  - `security.path-traversal-candidate` — filesystem path construction from
    non-literal identifiers (Tauri/JS-bridge params, env vars, user-controlled
    request paths).
  - `test-quality.should-panic-without-expected` — `#[should_panic]` attributes
    without an `expected = "..."` clause.
- `gruff-rs init` command to generate a default `.gruff-rs.yaml` from the
  built-in rule registry; preserves user-customized `paths.ignore` entries on
  regeneration.
- CLI options for explicit baseline path and additional discovery-time ignored
  paths.
- `scripts/dependency-install.sh` and `scripts/dependency-update.sh` with
  auto-install for `cargo-audit` used by the dependency-audit preflight check.
- Documentation pages for CI integration, configuration, the dashboard, output
  formats, and the release process.

### Changed

- `security.path-traversal-candidate` ships with six layered precision guards
  (added after deep-testing against an external Tauri codebase): expanded
  safe-arg list (`safe`, `sanitized`, `normalized`, `validated`, `file_name`,
  `filename`, `display_path`, plus base-path conventions); skip when the
  argument is typed `&Path` / `&PathBuf` / `impl AsRef<Path>` in a nearby fn
  signature; skip when the same function performs `.canonicalize()` followed by
  `.starts_with(` within 25 lines after the join (validate-then-trust); skip
  when a `validate_*` / `verify_*` / `sanitize_*` / `check_*` call took the
  argument in the preceding 30 lines or an inline `if arg.contains(..)` taint
  check appears; skip loop variables bound to literal arrays
  (`for ARG in [...]` or `for ARG in &ITER`); skip `let`-bindings to string
  literals (raw or quoted, including multi-line `let` shapes).
- `modernisation.manual-contains` tightened to require either deref
  (`|x| *x == y`) or RHS-ref (`|x| x == &y`) shape — bare `|x| x == y` is
  intentionally NOT matched because the closure typically compiles only through
  `PartialEq` cross-type impls where `.contains()` would not.
- `docs.missing-param-doc` and `docs.missing-return-doc` skip functions
  carrying a frontend-bridge attribute (`#[tauri::command]`, `#[command]`,
  `#[wasm_bindgen]`, `#[pyfunction]`, `#[pyo3::pyfunction]`) — those macros
  follow user-facing-summary rustdoc convention rather than the Rust API
  contract style.
- `.gruff-rs.yaml` rule handling: rule entries regenerated deterministically
  from the built-in registry; per-rule overrides preserved; user-customized
  `paths.ignore` entries kept on regeneration.
- Default `paths.ignore` patterns expanded to suppress scan noise from
  agent/CLI directories (`.agents/`, `.antigravitycli/`, `.claude/`, `.codex/`,
  `.goat-flow/`) and dependency lockfiles (`Cargo.lock`, `package-lock.json`,
  `yarn.lock`, `pnpm-lock.yaml`).
- Version bumped to `0.1.1`.

### Internal

- New built-in-rule files split out for size + module-item-count compliance:
  `src/built_in_rules/path_traversal_rules.rs` (extracted from
  `behavior_rules.rs`), `src/built_in_rules/docs_rules.rs` and
  `src/built_in_rules/rustdoc_parsing.rs` (extracted from
  `function_block_rules.rs`), `src/built_in_rules/modernisation_rules.rs`
  (new). `analyse_should_panic_without_expected` moved to
  `src/built_in_rules/test_rules.rs` (its natural pillar home).
- Reduced Halstead/maintainability pressure in path-traversal, modernisation,
  and docs analyzers via helper extraction (`PathTraversalScan` struct,
  `ModernisationCheck` struct, per-rule `*_finding` helpers,
  `is_documentable_block` predicate).
- Renamed boolean helpers to predicate-shaped names
  (`mentions_identifier` → `has_identifier_mention`,
  `mentions_returns` → `has_returns_section`,
  `window_validates_path_after` → `window_has_validation_after`,
  `line_declares_path_typed_param` → `line_has_path_typed_param`).
- Calibration matrix extended to 77/77 rules (new file
  `src/tests/calibration/cases_pillar_expansion.rs` for the 10 new rules);
  every rule has positive + negative cases that the matrix harness verifies on
  every test run.
- Self-scan (dogfood) score: 100/A with 0 findings; `scripts/preflight-checks.sh`
  passes all 17/17 checks.
- New learning-loop entries:
  `.goat-flow/footguns/analyzer.md` (bare-bare equality FP class;
  candidate-rule defence-pattern recognition);
  `.goat-flow/patterns/rule-precision.md` (local-defence suppression pattern
  for candidate rules; safe-arg name semantics);
  `.goat-flow/lessons/naming.md` (alphabet-sequel file-name lesson);
  `.goat-flow/lessons/verification.md` (deep-scan-on-external-repo lesson;
  zero-finding ambiguity lesson).

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
