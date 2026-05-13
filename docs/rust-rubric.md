# Rust Rubric

`gruff-rs` v0.1 focuses on deterministic, explainable static checks that work from source text plus a shared `syn` AST for Rust files. Rules are advisory by default unless they report likely secrets or higher-risk complexity.

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

The v0.1 expansion chooses rules that can be proven with clear positive and negative fixtures. Syntax-sensitive rules use the Rust AST model; text rules are reserved for source/config scans such as secrets. Project rules use a read-only project context built from discovered sources, `Cargo.toml`, and `Cargo.lock`. Rules that mainly need type resolution, live registry data, whole-project call graphs, framework knowledge, or high-noise semantic inference are deferred.

The scanner intentionally complements `cargo clippy` instead of restating every lint. For example, unsafe-block findings enforce a reportable `SAFETY:` explanation for scoring, while complexity metrics produce deterministic report data for project trends.

Project-level architecture rules report structural facts from the read-only project model. They do not require type resolution, build-script execution, or Cargo metadata execution. Project-level dead-code findings use candidate wording: they skip public items, test contexts, cfg-gated items, and private items whose names appear elsewhere in discovered Rust source, including macro registrations or comments.

Error-handling and concurrency rules are deliberately syntactic. Production panic and placeholder findings skip test functions and helpers inside `tests` modules; public API unwrap findings add API-context signal on top of the broader unwrap/expect rule. Async/concurrency findings use medium confidence unless the scanner has only a narrow source pattern such as an async function calling `std::thread::sleep`, a lock binding that appears to cross `.await`, or an unbounded channel constructor. These checks complement Clippy by making the patterns visible in Gruff reports and scoring; they do not claim runtime deadlock certainty or type-aware error taxonomy.

Performance rules are narrow source-pattern checks for `Regex::new`, `format!`, and `clone()` inside loop bodies. They are reported as waste because the current report schema does not define a separate performance pillar.

Advanced metric rules use deterministic tokenization after Rust string literals are masked. Tokens are identifiers, numeric literals, multi-character operators, and punctuation. `metrics.halstead-volume` reports `total_tokens * log2(unique_tokens)` above the default `volume` threshold of `900`. `metrics.maintainability-pressure` reports when `100 - min(100, total_tokens * 0.08 + cyclomatic * 2.0 + halstead_volume / 60.0)` falls below the default `minimum` threshold of `45`. These metric findings complement the existing score report and do not change `gruff.analysis.v1`.

## Deferred

- Type-aware unused symbol and call-graph dead-code certainty.
- Module cycle, coupling, and crate-graph rules that need a reliable import graph.
- Vulnerability advisory, package freshness, and license policy checks that need live external data or organization-specific policy.
- Framework-specific test rules for mocking, fixtures, async runtimes, and data providers.
- Broad error swallowing, excessive task spawning, runtime deadlock detection, and type-aware error taxonomy.
- Type-aware allocation analysis, needless collection-before-iteration claims, large-literal allocation claims, benchmarks, and runtime profiling ingestion.
- Automatic fixes.
