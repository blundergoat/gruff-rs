# Changelog

## 0.2.0 - 2026-05-27

This version collects the cross-port ergonomics work originally planned as
`0.1.2`, plus the schema and CLI-default changes the README's stability
contract reserved for `0.2.0`: the `analyse --fail-on` binary default flips
from `error` to `advisory`, `.gruff-rs.yaml` now requires a
`schemaVersion: gruff-rs.config.v1` field, the analysis JSON schema bumps from
`gruff.analysis.v1` to `gruff.analysis.v2`, and the summary JSON schema bumps
from `gruff.summary.v1` to `gruff.summary.v2`.

### Schema versions

- Analysis JSON: `gruff.analysis.v1` → `gruff.analysis.v2`. The v2 shape adds
  `score.pillars[].penalty: f64`, `findings[].stableIdentity: string`, and an
  optional `perRuleDeltas[]` array populated when a baseline or diff context
  is active. All other fields keep their v1 names, types, and meaning.
  Consumers that validated `schemaVersion == "gruff.analysis.v1"` must
  update to accept `gruff.analysis.v2`.
- Summary JSON: `gruff.summary.v1` → `gruff.summary.v2`. The v2 shape exposes
  nine pillar fields (`pillar`, `grade`, `score`, `applicable`, `findings`,
  `advisory`, `warning`, `error`, `penalty`) and enriches `topRules[]` with
  `severity`, `confidence`, and `description`.
- Baseline JSON (`gruff.baseline.v1`), hotspot JSON (`gruff.hotspot.v1`), and
  SARIF (2.1.0) surfaces are unchanged.

### Breaking

- `analyse --fail-on` binary default lowered from `error` to `advisory`.
  Pipelines that relied on the prior default to ignore advisory and warning
  findings now fail. Restore the prior behaviour with `--fail-on error` on
  the CLI, or `minimumSeverity.analyse: error` in `.gruff-rs.yaml`.
- `.gruff-rs.yaml` now requires `schemaVersion: gruff-rs.config.v1`. Configs
  without the field are rejected at load time. Run `gruff-rs init --force` to
  regenerate; `paths.ignore`, per-rule overrides, and `minimumSeverity:` are
  preserved.
- See `UPGRADING.md` for the full 0.1.x → 0.2.0 migration workflow.

### Added

- `rules.<id>.excludeFromScore: bool` per-rule config field (ADR-014).
  When `true`, the rule continues to run and its findings appear in every
  reporter; only the composite-score penalty bucket skips them. Distinct
  axis from `enabled` (which hides findings entirely) and from `severity`
  (a per-finding property). Default is `false`. Non-boolean values
  produce a config-load error naming the rule id.
- Non-fatal `excluded-security-rule-from-score` diagnostic when an
  `excludeFromScore: true` rule belongs to the Security or
  SensitiveData pillar. The diagnostic names the rule + pillar so the
  choice is user-visible without blocking the run. Strict-mode
  escalation to error is deferred until a `--strict` flag exists.
- `perRuleDeltas[]` additive field on `AnalysisReport` populated when a
  baseline or diff comparison context is active (ADR-014 second half).
  Each entry carries `ruleId`, `introduced`, `removed`, `net`.
  `introduced` is current findings not matched by the baseline (or, in
  diff-patch mode, findings inside the patched ranges); `removed` is
  baseline entries no current finding reproduces (or findings outside
  the patched ranges). Field is omitted entirely on full-tree scans via
  `skip_serializing_if = Option::is_none`, so existing JSON consumers
  stay byte-identical.
- Text and Markdown reporters render `Top 5 improved: ...` and
  `Top 5 regressed: ...` ranked blocks before the composite-score line
  when `perRuleDeltas` is present. Blocks cap at five entries each,
  omit zero-net rules, sort by absolute net DESC then `rule_id` ASC
  for deterministic output, and stay suppressed when no comparison
  context is in scope.
- `gruff-rs summary` surfaces the same per-rule delta data: the text
  view inserts a "Top 5 improved / regressed" block between the scan
  card and pillars block, and the JSON view emits an additive
  `perRuleDeltas[]` array. Same omission contract on full-tree runs.
- Eleven built-in rules' `remediation` text now follows the two-sentence
  "fix sentence + escape-hatch sentence" pattern: the second sentence
  names the relevant `.gruff-rs.yaml` key (typically `paths.ignore`,
  occasionally `allowlists.acceptedAbbreviations`) so consumers see the
  config knob without grepping the source. Affected:
  `naming.placeholder-identifier` (variable and function variants),
  `naming.short-variable`, `security.insecure-rng-for-secrets`,
  `security.sql-dynamic-query`, `security.weak-crypto`,
  `security.process-command`, `security.hardcoded-bind-all-interfaces`,
  `security.path-traversal-candidate`, `dead-code.unused-private-function`,
  and `concurrency.unbounded-channel`. Detection logic, severity, and
  confidence unchanged.
- `list-rules <rule_id>` now renders a detail card for a single rule:
  description, default severity / confidence / enabled-by-default, options
  with their descriptions, escape-hatch config paths (`rules.<id>.options.*`,
  `rules.<id>.enabled`, `paths.ignore`), documented false-positive shapes
  with mitigations, and related rules. `--format=json` exposes the same
  data structured as `escapeHatches`, `falsePositiveShapes`, and
  `relatedRules` arrays. Unknown rule ids exit 2 with up to three
  Levenshtein-distance suggestions.
- `RuleDefinition` (`src/rules/mod.rs`) gains optional
  `false_positive_shapes: &'static [FalsePositiveShape]` and
  `related_rules: &'static [&'static str]` fields, defaulted to empty
  slices via the `rule_definition!` macro. Twelve built-in rules ship
  with curated metadata in 0.1.2 (naming family, size family,
  `security.process-command`, `modernisation.public-field`,
  `test-quality.no-assertions`, `waste.unwrap-expect`,
  `complexity.cognitive`, `dead-code.unused-private-item-candidate`).
- `summary` `topRules[]` entries enriched with `severity`, `confidence`,
  and a one-sentence `description` sourced from the rule registry. JSON
  output gains the three fields; text output renders them as columns
  (`count`, `rule_id`, `severity`, `confidence`, `description`). Custom
  rules with no registry entry omit the new fields rather than emit
  blanks. Existing `topRules[]` keys (`ruleId`, `count`) are unchanged
  and the `gruff.summary.v2` schema version stays.
- `analyse --format text` appends a one-paragraph output-volume hint
  when finding count reaches 50, pointing at `gruff-rs summary --top 20`
  as the triage path. Text-only by construction - JSON, SARIF, Markdown,
  GitHub, and hotspot outputs are byte-identical.
- `stableIdentity` field on every `Finding` in JSON output. 16-character
  SHA-256 prefix of `rule_id`, `file_path`, and either `symbol` (when set)
  or `message`. Line-insensitive by design - external diff tooling can
  match "same finding" across unrelated edits without disturbing
  baseline behaviour. `fingerprint` stays line-sensitive so
  `src/baseline.rs` keeps its existing contract; SARIF output is
  byte-identical (the new field is JSON-only).
- `minimumSeverity:` block in `.gruff-rs.yaml` sets per-subcommand
  `--fail-on` defaults. Accepts `analyse` and `report` keys; values are
  `none | advisory | warning | error`. Precedence is CLI flag > config
  key > binary default. Unknown command keys (e.g. `summary`,
  `dashboard`) are rejected with a useful error. See ADR-013.
- Required `schemaVersion: gruff-rs.config.v1` field on `.gruff-rs.yaml`,
  introduced for the first time. Run `gruff-rs init --force` to
  regenerate any existing config. Configs without it are rejected at
  load time.
- `gruff-rs init --force` preserves hand-edited `minimumSeverity:`
  entries the same way it already preserves `paths.ignore`.
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

### Fixed

- `excluded-security-rule-from-score` diagnostics now emit in
  deterministic order. The previous loop iterated `config.rule_settings`
  (a `HashMap`) directly, so multiple excluded Security/SensitiveData
  rules could produce different orderings across runs — breaking the
  deterministic-report contract for JSON/HTML consumers. Matched rule
  ids are sorted before construction.
- `summary` `topRules[].severity` now reflects the configured per-rule
  severity (e.g. `rules.size.function-length: { threshold: 10, severity:
  advisory }`) instead of the registry default. Previously the digest
  pulled from `RuleDefinition.default_severity`, so the entry could
  report `warning` while the same rule's findings carried `advisory` —
  topRules and the findings array disagreed on the same rule's effective
  severity. Source is now the first matching finding's severity, which
  is set once at rule-emission time via `config.severity(rule_id,
  default)`.
- Baseline `perRuleDeltas.introduced` no longer over-counts duplicate
  raw findings. `run_analysis_in_project` now runs
  `sort_and_dedupe_findings` BEFORE `resolve_baseline`, so the
  introduced count matches the per-rule finding count in the final
  report. The previous order counted duplicates as separate introduced
  findings even though they collapsed to one entry in the report.
- Six relative cross-references inside `.goat-flow/` (between
  `footguns/`, `lessons/`, and `patterns/`) corrected from
  `<dir>/<file>.md` to `../<dir>/<file>.md` so they resolve from the
  containing directory.
- `dashboard_scan_rejects_absolute_or_escaping_paths` now builds its
  out-of-root and absolute-path inputs from canonicalized tempdirs
  instead of hardcoded `/` and `/etc` literals, so the security-boundary
  test exercises the same intent on any platform where
  `Path::is_absolute()` classifies paths differently.
- `list-rules <rule_id>` now resolves configured `custom.<slug>` ids in
  addition to built-in rules. Previously the M05 detail view only
  consulted the built-in registry, so the catalogue mode listed a custom
  rule while `list-rules custom.<slug>` returned `Unknown rule`. Custom
  rules render a kind-`custom` detail card (pillar, severity, confidence,
  scope, pattern, message, optional remediation, escape hatches) in both
  text and JSON; the unknown-rule suggestion pool now spans built-in and
  custom ids together.

### Changed

- `analyse --fail-on` default lowered from `error` to `advisory` to match
  the cross-port "show everything, gate on anything" philosophy. Existing
  CI scripts that depend on the prior default should set
  `minimumSeverity.analyse: error` in `.gruff-rs.yaml` or pass
  `--fail-on error` explicitly.
- `scripts/preflight-checks.sh` dogfood step now scans the whole project
  (`bin/gruff-rs analyse .`) instead of only `src/`, and the script no
  longer accepts `--fail-on` or `GRUFF_RS_FAIL_ON`. The gate is now
  driven entirely by `minimumSeverity.analyse` in `.gruff-rs.yaml`, so
  threshold drift between local dev and CI is impossible. The
  `dogfood_failure_pattern`, `validate_fail_on`, and "dogfood fail
  threshold" header line are removed as dead code.
- `size.file-length` now exempts `*.sh` files alongside the existing
  `*.md` / `*.markdown` exemption. Shell scripts and Markdown both have
  different size norms from Rust modules, and the 600-line threshold
  was calibrated for the latter. Lockfiles and agent-hook directories
  (`.codex/hooks/`, `.claude/hooks/`) remain exempt. Other text formats
  (`.py`, `.yaml`, `.toml`, `.txt`, …) are still scanned.
- `docs.missing-*` rule messages (`docs.missing-public-doc`,
  `docs.missing-errors-section`, `docs.missing-panics-section`,
  `docs.missing-safety-section`, `docs.missing-param-doc`,
  `docs.missing-return-doc`) reworded from absence reports
  ("`x` is missing a Rust doc comment") to intent guidance ("`x` needs a
  brief intent description … one plain-English line, not a restatement
  of the type"). Remediations spell out the no-boilerplate framing so
  agents reading the finding cannot mistake the rule for a request to
  add stub comments that restate code. Detection logic, severity,
  confidence, and pillar all unchanged.
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
- `Config` (`src/config.rs`) gains required `schema_version: String` and
  `minimum_severity: BTreeMap<String, FailThreshold>` fields. New
  `apply_schema_version_section` / `apply_minimum_severity_section`
  handlers in `src/config_loader/mod.rs`; new `command_setup` module
  hosts `resolve_fail_on`, `resolve_project_root_and_config`,
  `resolve_command_setup`, and `emit_report_output`.
- `run_analysis_in_project` signature now takes a pre-loaded `&Config`;
  the `run_analysis` wrapper that resolved project_root and loaded
  config internally was removed. `main.rs` loads Config once at the CLI
  edge before resolving `fail_on`.
- `AnalyseArgs::fail_on` and `ReportArgs::fail_on` become
  `Option<FailThreshold>`; clap defaults move to runtime resolution.
- `FailThreshold` gains a hand-written `FromStr` and `serde::Deserialize`
  impl (M07) plus `PartialEq` / `Eq` derives. Off-switch value remains
  `none` (gruff-rs convention); `never` rejects with the four-value
  list verbatim.
- Cross-port: aligns with gruff-go 0.1.2's `minimumSeverity:` dimension;
  gruff-rs uses `none` as the off-switch value where gruff-go uses
  `never`, per port convention. Sibling ports (`gruff-ts`, `gruff-py`,
  `gruff-php`) may track this work independently.

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
