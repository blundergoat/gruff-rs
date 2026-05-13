# Rust Rubric

`gruff-rs` v0.1 focuses on deterministic, explainable static checks that work from source text plus a shared `syn` AST for Rust files. Rules are advisory by default unless they report likely secrets or higher-risk complexity.

## Pillars

| Pillar | Current scope |
| --- | --- |
| Size | File length, function length, and parameter-count thresholds. |
| Complexity | Cyclomatic complexity, cognitive complexity, nesting depth, and conservative NPath approximation. |
| Dead code | Private functions with no same-file call sites. |
| Waste | Unwrap/expect, clone candidates, and unreachable statements. |
| Naming | Generic function names, short variables, bool predicate prefixes, and placeholder identifiers. |
| Documentation | Public Rust API documentation, TODO/FIXME density, and root README presence. |
| Modernisation | Public struct fields that expose representation. |
| Security | Process command construction and unsafe blocks without a nearby `SAFETY:` rationale. |
| Sensitive data | Common API keys, AWS keys, JWT-looking tokens, database URLs with passwords, private-key markers, environment-style secret assignments, and high-entropy string literals. |
| Test quality | Missing assertions, sleeps, loops, conditionals, unwrap/expect, ignored tests without reasons, long tests, and trivial assertions. |
| Design | God-function composite when size and complexity overlap on the same function. |

## Rule Selection

The v0.1 expansion chooses rules that can be proven with clear positive and negative fixtures. Syntax-sensitive rules use the Rust AST model; text rules are reserved for source/config scans such as secrets. Rules that mainly need type resolution, whole-project graphs, framework knowledge, or high-noise semantic inference are deferred.

The scanner intentionally complements `cargo clippy` instead of restating every lint. For example, unsafe-block findings enforce a reportable `SAFETY:` explanation for scoring, while complexity metrics produce deterministic report data for project trends.

## Deferred

- Type-aware unused symbol and call-graph dead-code analysis.
- Architecture, coupling, and crate-graph rules.
- Framework-specific test rules for mocking, fixtures, async runtimes, and data providers.
- Maintainability-index and Halstead-style metrics until the token model and scoring calibration are stable.
- Automatic fixes.
