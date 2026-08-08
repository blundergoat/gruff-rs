# Rules

`gruff-rs` focuses on deterministic, explainable static checks that work from source text plus a shared `syn` AST for Rust files. Findings are calibrated as advisory, warning, or error: likely secrets are errors, and higher-risk complexity, security, maintainability, size, and test-quality findings are warnings. Advisory means enforceable low-severity signal, not optional advice; default-on advisory rules must still be precise enough for 100% compliance projects. Thresholded rubrics use one numeric threshold paired with one severity; non-threshold rules may also accept a fixed severity override. Rules do not escalate through warning/error ranges.

## Pillars

| Pillar | Current scope |
| --- | --- |
| Size | File length, function length, and parameter-count thresholds. Function length counts the declaration through the closing brace, excluding attached rustdoc and attributes. File-length stays default-on for Rust source over 1000 substantive lines, while dependency lockfiles, Markdown docs, Codex/Claude hook scripts, declarative rule-definition tables, and calibration case tables are skipped because those surfaces are governed by different review contracts. |
| Complexity | Cyclomatic complexity, cognitive complexity, and nesting depth. |
| Dead code | Private functions with no same-file call sites, unreachable statements, plus project-level private function, type, trait, const, static, struct, enum, and type-alias candidates whose names are not referenced elsewhere in discovered Rust sources when the run covers every discoverable Rust source under the selected project root. Partial-context path or diff runs suppress the project-level candidate rule and emit a diagnostic. |
| Maintainability | Unwrap/expect, opt-in clone candidates, production panic/placeholder hazards, public API unwraps, narrow async/concurrency hazards, and loop-scoped allocation hot spots. |
| Naming | Generic function names, cryptic two-character variables (including fn parameters, closure parameters, and destructured bindings), bool predicate prefixes, placeholder identifiers, and `let X = X(...)` shadows of same-file free functions. Single-letter bindings are allowed because they are common in small closures and parser/math code. Common AWS/cloud abbreviations are accepted in AWS-context files where the abbreviation is part of the domain model. The boolean-prefix, placeholder-identifier, and generic-function rules accept user-supplied allowlists via the `predicatePrefixes`, `extraPlaceholders`, and `extraGenericNames` string-array options. |
| Documentation | Public Rust API documentation, root README presence, package metadata presence, stale TODO markers without an owner/issue/reason, comments whose payload looks like disabled Rust code, weak `SAFETY:` rationales near unsafe blocks, externally public `Result`-returning functions missing an error contract, public panic-capable functions missing a panic contract, public `unsafe fn` items missing a `# Safety` section, and public functions whose rustdoc fails to describe parameters or return values. Function checks accept attached outer `///` and `/** */` rustdoc; inner or ordinary comments do not count. `# Errors`, `# Panics`, and `# Returns` headings are accepted, but concise contract prose is enough when it conveys the same behaviour. |
| Modernisation | Four `manual-*` idiom rules covering `len() == 0` (use `is_empty`), `iter().any(|x| x == y)` (use `contains`), `if s.starts_with(p) { &s[p.len()..] }` (use `strip_prefix`), and `match opt { Some(v) => v, None => Default::default() }` (use `unwrap_or_default`); and `question-mark-candidate` covering manual `match`/`if let Err` Result-propagation shapes that should use `?`. |
| Security | Process command uses with concrete risk signals, dynamic SQL query arguments, explicit TLS verification bypasses, weak cryptographic primitive review signals, non-cryptographic RNG use inside secret-like generation functions, unsafe blocks without a nearby `SAFETY:` rationale, filesystem path construction from non-literal input (candidate), SSRF/template/deserialization/XXE candidates, hardcoded `0.0.0.0`/`[::]` listener binds in executable Rust including tests, local-only dependency posture checks for git/path sources, unpinned git revisions, wildcard requirements, and duplicate lockfile versions, plus GitHub Actions workflow and explicit composite-action metadata checks described below. |
| Sensitive data | Common API keys, AWS keys, JWT-looking tokens, database URLs with passwords, HTTP(S) URLs with embedded credentials, private-key blocks, GCP service-account keys, PHI-like identifiers, environment-style secret assignments, and high-entropy string literals. The high-entropy rule skips package integrity prefixes, base64 alphabet tables, separator-bearing word slugs, and model/provider identifiers, but still reports zero-separator mixed-case identifiers and unknown digest/signature fields unless an existing reviewed `allowlists.secretPreviews` entry matches its exact legacy suppression alias. The common API-key pattern includes provider-prefixed tokens such as GitHub, GitLab, npm, Slack, Stripe, SendGrid, Hugging Face, Linear, Discord webhooks, Google, Anthropic-style, and common cloud connection strings. A separate `pii-test-fixture` rule flags realistic emails, SSN-shaped strings, and US phone numbers in committed fixture or sample files (skips obvious placeholders such as `@example.com`, 555-prefix phones, 000-prefix SSNs). |
| Test quality | Sleeps, loops, conditionals, unwrap/expect that hides setup or fixture failures, ignored tests without reasons, long post-assertion test bodies, trivial assertions, and `#[should_panic]` attributes without an `expected = "..."` clause. |
| Design | Project-level module fan-out, large-module, and public API surface checks. |

## Rule Selection

The v0.1 expansion chooses rule additions that can be backed by clear fixture coverage. Focused positive and negative fixtures cover selected rule families, while the normal fixture scan preserves representative findings across the expanded rubric. Syntax-sensitive rules use the Rust AST model; text rules are reserved for source/config scans such as secrets. Project rules use a read-only project context built from discovered sources, `Cargo.toml`, and `Cargo.lock`. Rules that mainly need type resolution, live registry data, whole-project call graphs, framework knowledge, or high-noise semantic inference are deferred.

The scanner intentionally complements `cargo clippy` instead of restating every lint. For example, unsafe-block findings enforce a reportable `SAFETY:` explanation for scoring, while complexity metrics produce deterministic report data for project trends.

Project-level architecture rules report structural facts from the read-only project model. They do not require type resolution, build-script execution, or Cargo metadata execution. Project-level dead-code findings use candidate wording: they skip public items, test contexts, cfg-gated items, FFI/plugin attribute exports, explicit `allow(dead_code)` contexts, and private items whose names appear elsewhere in discovered Rust source. Comments and ordinary strings do not keep items alive; structured references such as `serde(default = "helper")` and macro registrations still count as source evidence. When a path or diff run analyses only part of the discoverable Rust source universe, the project-level dead-code candidate rule is suppressed and the report includes a `partial-context-rule-suppressed` diagnostic pointing to a full `gruff-rs analyse .` scan from the selected project root.

Error-handling and concurrency rules are deliberately syntactic. Production panic and placeholder findings skip test functions and helpers inside `tests` modules; public API unwrap findings add API-context signal on top of the broader unwrap/expect rule. Async/concurrency findings use medium confidence unless the scanner has only a narrow source pattern such as an async function calling `std::thread::sleep`, a lock binding that appears to cross `.await`, or an unbounded channel constructor. The lock-across-await rule requires a bound, zero-argument acquisition: `.lock()` remains an explicit lock-named heuristic, while ambiguous `.read()` and `.write()` calls require the same function to tie that receiver to a `Mutex` or `RwLock` type or constructor. Guard-preserving `.await`, `.unwrap()`, `.expect(...)`, and `?` suffixes remain covered; calls with arguments, immediate value extraction, explicit drops, and guards scoped out before the later await stay silent. These checks complement Clippy by making the patterns visible in Gruff reports and scoring; they do not resolve type aliases or struct fields and do not claim runtime deadlock certainty or type-aware error taxonomy.

Security rules are deliberately narrow static signals. `security.process-command` only reports command construction/execution when the local source shows a concrete risk shape such as shell execution, a dynamic executable or argument, custom environment values, or a custom working directory. `security.sql-dynamic-query` reports direct and one-hop `format!` values passed to `query`, `execute`, or `prepare` only when their literal fragments form an anchored supported SQL statement or clause-pair shape after SQL comments and whitespace are normalized. Plain prose and non-SQL DSL text with isolated SQL words stay quiet. Fixed `?` placeholder arity construction also stays quiet when values are later bound with parameter APIs such as `params_from_iter`, while unbounded table/schema/prefix interpolation remains visible because SQL identifiers cannot be bind parameters. `security.tls-verification-disabled` also follows local `true` bindings into TLS bypass setters. `security.weak-crypto` reports explicit weak primitive imports or constructors for review and does not claim every checksum use is exploitable. `security.insecure-rng-for-secrets` requires both a secret-like production function name and an explicit `rand::thread_rng()` or `rand::random()` call. The path-traversal candidate rule requires filesystem evidence for `.join(...)` receivers and skips locally visible segment sanitizers that remove traversal plus both path separators, while keeping generic names reportable unless the defense is explicit. SSRF, unsafe-deserialization, template/XSS, and path-traversal candidate rules use bounded same-function source evidence only; they do not perform type resolution or whole-program taint analysis.

GitHub Actions text rules classify root `.github/workflows/*.yml`/`*.yaml`
paths as workflows. A file named exactly `action.yml` or `action.yaml` is
composite-action metadata only when supplied explicitly; directory discovery
does not recursively enable action rules. Event interpolation, remote shell
installers, and unpinned third-party `uses:` dependencies apply to both kinds.
Broad permissions, `pull_request_target`, and pull-request secret exposure
remain workflow-only because composite actions have no workflow `on:` or
permission contract. The permissions rule reports workflow-level scoped writes
and `permissions: write-all` at any level; a bounded job-scoped mapping such as
release-only `contents: write` stays silent.

Sensitive-data rules report likely secret material directly from text. Identity-independent findings serialize only zero-payload detector markers such as `[redacted]`, `[redacted:private-key]`, or `[redacted:connection-string:https]`; source characters and the historic partial aliases are not report metadata. Existing `allowlists.secretPreviews` entries retain their exact suppression behavior through an internal legacy alias, but that key does not authorize a preview to be revealed. `sensitive-data.database-url-password` is scoped to database and message-bus URL schemes, while `sensitive-data.url-embedded-credentials` covers generic HTTP(S) `user:password@host` URLs and skips reserved documentation hosts and obvious placeholder credentials. `sensitive-data.high-entropy-string` keeps real base64/base64url/JWT/PAT-like secret shapes reportable while skipping known non-secret structures: package integrity literals including `sha1-`, exact standard and URL-safe base64 alphabets, separator-bearing word slugs, and provider/model identifiers such as `provider/Family/Model-Size-Variant`. It deliberately does not infer that arbitrary checksum or signature fields are safe from value shape alone. Provider-prefixed token coverage stays under `sensitive-data.api-key-pattern` unless a separate rule ID adds distinct user-facing value; GCP service-account key material and PHI-style identifiers have dedicated IDs because their remediation and triage differ from generic tokens.

For 0.5.0, `sensitive-data.pii-test-fixture` deliberately retains its historic partially redacted message because that message is part of the line-scoped `stableIdentity`. Fully masking those fixture-PII messages would change hook new-only matching across the analyzer family, so the message and identity migration are deferred to the coordinated family JSON break rather than being presented as a display-only fix.

Performance rules are narrow source-pattern checks for `Regex::new`, `format!`, and `clone()` inside real loop bodies. They ignore loop words in comments/strings, bounded static inventory loops, and user-facing output assembly where the allocation is not meaningful performance debt. They are reported under maintainability because the shared cross-language contract does not define a separate performance pillar.

`test-quality.unwrap-in-test` allows a direct call result unwrapped inside an assertion expression when that call is the subject under test. It still reports setup/local unwraps that feed assertions because those can hide fixture failures behind a panic.

`test-quality.long-test` counts the test body from the first assertion onward, so fixture setup before the first assertion does not trigger the rule. `waste.unnecessary-clone-candidate` is opt-in because ownership-preserving clones can be the more readable and verifiable choice.

## Threshold Calibration

Threshold defaults are anchored to documented peer analyzers where one exists, and called out as gruff-specific where no peer ships a comparable numeric default.

| Rule | Default | Peer anchor | Note |
| --- | --- | --- | --- |
| `complexity.cognitive` | 15 | Detekt CognitiveComplexMethod 15, PMD CognitiveComplexity 15 | Matches the Detekt/PMD consensus. |
| `complexity.cyclomatic` | 10 | PMD CyclomaticComplexity 10 | Between Detekt (14) and RuboCop (7). |
| `complexity.nesting-depth` | 4 | RuboCop Metrics/BlockNesting 3 | One step looser than RuboCop's Ruby default. |
| `architecture.large-module` | 25 items | Detekt LargeClass 600 lines (different unit) | Gruff measures public-or-visible item count per module, not raw lines; not directly comparable. |
| `architecture.module-fan-out` | 8 | none | Gruff-specific; PMD CouplingBetweenObjects exists but its threshold is not documented in the neighbor studies. |
| `architecture.public-api-surface` | 12 items | none | Gruff-specific external-public count; PMD TooManyMethods is the nearest peer concept. |
| `dependency.duplicate-locked-version` | 1 | none | Cargo-specific; no peer analyzer ships this check. |
| `docs.stale-todo` | unthresholded | none (peers use binary presence) | Gruff flags each TODO/FIXME/HACK/XXX comment that lacks an owner, issue reference, or reason. |
| `size.file-length` | 1000 (substantive) | family ratification 2026-08-05 | Counts non-blank, non-comment lines at error severity, unified across the gruff family; Detekt LargeClass is 600 raw, PMD 1500 NCSS, RuboCop 250. |
| `size.function-length` | 50 | Detekt LongMethod 60, PMD NcssCount 60 | Counts declaration/body lines without attached rustdoc or attributes; slightly stricter than Detekt/PMD and far looser than RuboCop's 10-line Ruby default. |
| `size.parameter-count` | 7 | Clippy `too_many_arguments` 7 | Aligned to Clippy, the default Rust devs calibrate to; idiomatic Rust tolerates 6-7 params (builders, context structs). |
| `test-quality.long-test` | 120 | RuboCop RSpec/ExampleLength 25 (unit only) | Gruff-specific; counts lines after the first assertion so setup-heavy integration tests are not penalised for fixture construction. |

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
  these as renderers over `gruff.analysis.v2`. SARIF is the first implemented
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
