# Rust Rubric

`gruff-rs` v0.1 focuses on deterministic, explainable static checks that work from source text plus a shared `syn` AST for Rust files. Findings are calibrated as advisory, warning, or error: likely secrets are errors, and higher-risk complexity, security, waste, size, and test-quality findings are warnings.

## Pillars

| Pillar | Current scope |
| --- | --- |
| Size | File length, function length, and parameter-count thresholds. |
| Complexity | Cyclomatic complexity, cognitive complexity, nesting depth, conservative NPath approximation, Halstead-style token volume, and maintainability pressure. |
| Dead code | Private functions with no same-file call sites, plus project-level private item candidates whose names are not referenced elsewhere in discovered Rust sources. |
| Waste | Unwrap/expect, clone candidates, unreachable statements, production panic/placeholder hazards, public API unwraps, narrow async/concurrency hazards, and loop-scoped allocation hot spots. |
| Naming | Generic function names, short variables, bool predicate prefixes, and placeholder identifiers. |
| Documentation | Public Rust API documentation, TODO/FIXME density, root README presence, and package metadata presence. |
| Modernisation | Public struct fields that expose representation. |
| Security | Process command construction, unsafe blocks without a nearby `SAFETY:` rationale, and local-only dependency posture checks for git/path sources, wildcard requirements, and duplicate lockfile versions. |
| Sensitive data | Common API keys, AWS keys, JWT-looking tokens, database URLs with passwords, private-key markers, environment-style secret assignments, and high-entropy string literals. |
| Test quality | Missing assertions, sleeps, loops, conditionals, unwrap/expect, ignored tests without reasons, long tests, and trivial assertions. |
| Design | God-function composite when size and complexity overlap on the same function, plus project-level module fan-out, large-module, and public API surface checks. |

## Rule Selection

The v0.1 expansion chooses rule additions that can be backed by clear fixture coverage. Focused positive and negative fixtures cover selected rule families, while the normal fixture scan preserves representative findings across the expanded rubric. Syntax-sensitive rules use the Rust AST model; text rules are reserved for source/config scans such as secrets. Project rules use a read-only project context built from discovered sources, `Cargo.toml`, and `Cargo.lock`. Rules that mainly need type resolution, live registry data, whole-project call graphs, framework knowledge, or high-noise semantic inference are deferred.

The scanner intentionally complements `cargo clippy` instead of restating every lint. For example, unsafe-block findings enforce a reportable `SAFETY:` explanation for scoring, while complexity metrics produce deterministic report data for project trends.

Project-level architecture rules report structural facts from the read-only project model. They do not require type resolution, build-script execution, or Cargo metadata execution. Project-level dead-code findings use candidate wording: they skip public items, test contexts, cfg-gated items, and private items whose names appear elsewhere in discovered Rust source, including macro registrations or comments.

Error-handling and concurrency rules are deliberately syntactic. Production panic and placeholder findings skip test functions and helpers inside `tests` modules; public API unwrap findings add API-context signal on top of the broader unwrap/expect rule. Async/concurrency findings use medium confidence unless the scanner has only a narrow source pattern such as an async function calling `std::thread::sleep`, a lock binding that appears to cross `.await`, or an unbounded channel constructor. These checks complement Clippy by making the patterns visible in Gruff reports and scoring; they do not claim runtime deadlock certainty or type-aware error taxonomy.

Performance rules are narrow source-pattern checks for `Regex::new`, `format!`, and `clone()` inside loop bodies. They are reported as waste because the current report schema does not define a separate performance pillar.

Advanced metric rules use deterministic tokenization after Rust string literals are masked. Tokens are identifiers, numeric literals, multi-character operators, and punctuation. `metrics.halstead-volume` reports `total_tokens * log2(unique_tokens)` above the default `volume` threshold of `900`. `metrics.maintainability-pressure` reports when `100 - min(100, total_tokens * 0.08 + cyclomatic * 2.0 + halstead_volume / 60.0)` falls below the default `minimum` threshold of `45`. Config may use the `threshold` shorthand for these single-threshold rules; the canonical threshold names are `volume` and `minimum`. These metric findings complement the existing score report and do not change `gruff.analysis.v1`.

## Deferred

- Type-aware unused symbol and call-graph dead-code certainty. Peer unlocks:
  rust-analyzer HIR/Semantics APIs and Clippy late-pass boundaries, but ADR-008
  requires no-execute default analysis.
- Module cycle, coupling, and crate-graph rules that need a reliable import
  graph. Peer unlocks: rust-analyzer crate graphs and semantic databases;
  default gruff scans still avoid Cargo/build-script execution.
- Vulnerability advisory, package freshness, and license policy checks that need live external data or organization-specific policy.
- Framework-specific test rules for mocking, fixtures, async runtimes, and data
  providers. Peer unlocks: rust-analyzer path/type resolution can identify
  framework APIs, but framework policy remains external.
- Broad error swallowing, excessive task spawning, runtime deadlock detection,
  and type-aware error taxonomy. Peer unlocks: rust-analyzer type/method
  resolution and Clippy late lint passes; runtime certainty remains out of
  static-scan scope.
- Type-aware allocation analysis, needless collection-before-iteration claims,
  large-literal allocation claims, benchmarks, and runtime profiling ingestion.
  Peer unlocks: rust-analyzer type inference and Clippy performance lint
  structure; profiling remains external data.
- Automatic fixes. Peer unlocks: Ruff, Biome, Clippy, rust-analyzer, and
  RuboCop all separate fix safety from severity; ADR-007 requires explicit
  safe/unsafe metadata before any gruff fix mode.
- Additional dedicated CI renderers such as Checkstyle XML and Code Climate
  JSON. Peer unlocks: Detekt, PMD, Semgrep, and golangci-lint; ADR-006 keeps
  these as renderers over `gruff.analysis.v1`. SARIF is the first implemented
  CI renderer.
- User-defined rules. Peer unlocks: SwiftLint regex rules, Semgrep pattern
  rules, and PMD XPath rules; ADR-010 limits the first gruff custom-rule surface
  to config-only regex rules with reserved `custom.*` ids.
- Diff/new-code-only reporting. Peer unlocks: Semgrep baseline-by-ref and
  golangci-lint line-level new-code filters; ADR-009 requires patch-input
  filtering before direct Git/ref modes.
- Count baselines, report-level exclusions, and source suppressions. Peer
  unlocks: SwiftLint count-like baselines, Detekt source suppressions, RuboCop
  TODO config, and golangci-lint exclusions; ADR-009 keeps exact baselines first
  and discovery ignores separate from report suppressions.
