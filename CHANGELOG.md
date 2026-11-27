# Changelog

## v0.6.0 - 2026-11-27

0.6.0 is a coordinated family release aligning machine JSON (`gruff.analysis.v3`, `gruff.summary.v3`), baselines (`gruff.baseline.v3`), coding-agent hooks (`gruff.hook.v2`), normalized scoring, fallback discovery, config keys, and precision-calibrated rules across all five ports (rule catalogue `85 -> 71`: 15 rules removed, 1 added; 61 default-on, 10 opt-in). Upgrading from 0.5.x: this release changes every machine-readable contract at once; `UPGRADING.md` lists every migration command and the retreat path (pin the 0.5 line and keep the pre-upgrade config and baseline files, which 0.5 still reads).

### Breaking Changes

- **BREAKING: Machine JSON moves to `gruff.analysis.v3` and `gruff.summary.v3`.** `analyse` and `report` emit `gruff.analysis.v3`, and `summary --format json` emits the exact `gruff.summary.v3` projection (same envelope omitting only `findings`, replacing its independent digest); text `summary` ends with the shared `Suppressed findings: N via ...` line. `findings[].filePath`, `score.topOffenders[].filePath`, and top-level `suppressedCount` are removed; ignored paths live under `paths.details`, paths are project-relative slash paths, absent optional locations and symbols are omitted, scanner-pinpointed columns carry `metadata.locationPrecision`, and Rust-only finding scope and per-rule deltas live under `extensions.rs`. `findings[].fingerprint` and `stableIdentity` remain non-null on every finding.
- **BREAKING: Agent-hook contract moves from `gruff.hook.v1` to `gruff.hook.v2`.** `contractVersion` bumps and the envelope adds required `run` (mode, scope, operands, `analysedFiles`, applied baseline) and `suppressions` (configured sensitive exclusions) keys (`gruff-spec/contracts/core/hook.v2.json`, ratified 2026-09-06). Exit codes are `0` (below gate), `1` (reached `--fail-on`, `--fail-on-new`, or `--fail-on-diagnostics`), and `2` (run could not happen); update consumers that validate the exact key set.
- **BREAKING: `list-rules --format json` returns `{"rules": [...]}` with named `thresholds` maps.** The top-level array moves under `rules`, and scalar `threshold` moves to `thresholds` (such as `{"maxLines": 1000}` or `{"threshold": 25}`, printed as integers when whole and omitted for threshold-free rules). `list-rules --selector`, `list-rules <id> --format json`, SARIF properties, and `.gruff-rs.yaml` keys are unchanged.
- **BREAKING: Baselines move to `gruff.baseline.v3` with line-free durable identities, and sensitive-data findings can no longer be baselined.**
  - Each row stores a 16-lowercase-hex SHA-256 identity (uppercase or mixed-case rows fail with `identity must be 16 lowercase hex characters`) over tool language, rule ID, project-relative path, and subject (symbol plus enclosing-function ordinal across all same-named functions in the file, or digit-normalised message when symbol-less) plus an occurrence count, so edits above a finding keep reviews intact and extra occurrences report as new.
  - `gruff.baseline.v1` files fail closed and name `gruff-rs analyse --migrate-baseline <old> --generate-baseline <new>`. Regenerate any earlier 0.6.0 prerelease baseline with `analyse --generate-baseline` if function ordinals changed.
  - Sensitive-data findings are counted only under `sensitive.counts` (never stored as rows or hidden by hand-written rows), staying visible and blocking until fixed or excluded under `sensitiveExclusions`; a 0.5 baseline that suppressed fixture PII no longer suppresses it.
- **BREAKING: SARIF `partialFingerprints.gruffFingerprint` uses the durable baseline identity, and secrets carry none.** Existing code-scanning alerts close and reopen once (same-named declarations in one file split into separate alerts) and then survive ordinary edits. Sensitive findings omit `partialFingerprints` so alerts remain ungrouped.
- **BREAKING: Normalized scoring formula, nullable scores, and full pillar coverage.**
  - Every pillar uses `floor + (100 - floor) / (1 + density / densityScale)` (size-independent: duplicating a project preserves its grade), with error weight rising `8 -> 12`, advisory weight falling `1.5 -> 1`, and grade boundaries unchanged (`A>=90`, `B>=80`, `C>=70`, `D>=60`). `score.topOffenders[]` follows the same curve and adds raw `penalty`.
  - `score.composite.{score,grade}` and pillar/file grades are `null` when nothing was evaluated (rendering `Composite: n/a (nothing evaluated)` in human views instead of `100` / `A`).
  - `score.pillars[]` lists every rule-backed pillar with `applicable` and per-pillar `grade`.
- **BREAKING: Exit gate moves from `minimumSeverity:` to `failOn:`; `minimumSeverity:` becomes a scalar display floor.** Legacy per-command `minimumSeverity:` maps fail at load time with exit `2` naming `failOn` (`analyse` and `report` only). Scalar `minimumSeverity:` (`advisory`, `warning`, or `error`) hides lower-severity findings without changing counts, score, or exit code; migrate with `gruff-rs migrate-config --config <old> --output <new>`.
- **BREAKING: Default scans use the family fallback ignore policy.** Non-VCS fallbacks defer to governing `.gitignore` files and match at any depth, committed control metadata stays scannable, and explicit supported file arguments bypass Git and fallback exclusions; Rust retains `target` and VCS internals remain blocked even with `--include-ignored`.
- **BREAKING: Fifteen 0.5 rules are removed (ADR-024).** Remove them from `.gruff-rs.yaml` and CI flags or run `gruff-rs migrate-config --config <old> --output <new>`; config entries, `--include-rule`, and `--exclude-rule` exit `2` on retired IDs while existing baseline rows load and report as resolved.
  - Ten rules retired below the precision deletion floor: `concurrency.unbounded-channel`, `docs.stale-todo`, `modernisation.manual-is-empty`, `naming.boolean-prefix`, `naming.generic-function`, `performance.clone-in-loop`, `performance.format-in-loop`, `test-quality.conditional-logic`, `test-quality.sleep-in-test`, `waste.unreachable-code`.
  - Five rules removed below 50% precision: `dependency.path-source` (0/13 actionable; all 13 true but not worth acting on), `error-handling.public-unwrap` (14/44), `security.path-traversal-candidate` (1/20), `sensitive-data.database-url-password` (0/25), `sensitive-data.hardcoded-env-value` (0/25).
- **BREAKING: Eight rules are off by default.** Enable any of them with `rules.<id>.enabled: true` or `--include-rule <id>` (which also narrows the run); a `severity:` override alone keeps them off, while an earlier `init` config listing `enabled: true` keeps them on.
  - `complexity.cyclomatic` (23/45 actionable at >=1.5x limit, below the 0.60 floor; `complexity.cognitive` stays on).
  - `security.process-command` and `security.unsafe-deserialization` (precision sampling left input provenance unresolved).
  - `security.github-actions-broad-permissions` and `security.hardcoded-bind-all-interfaces` (1 and 9 blind findings with 7/7 audit agreement, populations too small to establish the floor).
  - `ci.github-event-shell-interpolation`, `security.sql-dynamic-query`, and `security.ssrf-candidate` (0/4 judged findings each; ADR-024).
- **BREAKING: All nine `sensitive-data.*` rules default to `warning`.** Moves `api-key-pattern`, `aws-access-key`, `gcp-service-account-key`, `high-entropy-string`, `jwt-token`, `phi-pattern`, `pii-test-fixture`, `private-key`, and `url-embedded-credentials` from `error` to `warning` (detectors emit catalogue severity instead of hard-coded `error`, shifting score weights). `--fail-on error` no longer fails on secret findings unless you set `rules.<id>.severity: error`; `--fail-on warning` and `advisory` still fail.
- **BREAKING: Rule confidence follows measured precision and catalogue confidence applies to every built-in finding.** Ten rules change confidence (high >= 0.85 error-adjusted precision, medium >= 0.70, low < 0.70), changing score weights; unmeasured rules keep their confidence under `Confidence evidence` in `docs/rules.md`.
  - Down from high: `complexity.cognitive` (to low), `error-handling.production-panic`, `security.unsafe-block`, `sensitive-data.private-key`, and `waste.unwrap-expect` (to medium; 2 rules dropping from high add reviewed false-positive guidance).
  - Up to high: `dead-code.unused-private-function` (from low), `docs.missing-public-doc`, `docs.weak-safety-rationale`, `naming.short-variable`, and `security.github-actions-unpinned-action` (from medium).
  - Detectors no longer override catalogue confidence, moving default `modernisation.manual-contains` findings from high to medium and medium `docs.missing-public-doc` and `security.github-actions-remote-shell` findings to high.
- **BREAKING: `everyCallable` widens three documentation rules on by default.** `docs.missing-public-doc`, `docs.missing-param-doc`, and `docs.missing-return-doc` now also check private and crate-visible functions, bridge-macro functions, and `const`/`static` closures, require describing a `Result`'s success value, and require exact parameter names rather than contract words such as `"path"`. `init` seeds `everyCallable: true` (omitted configs use the same default); set `rules.<id>.options.everyCallable: false` to restrict a rule to public functions.

### Added

- **`gruff-rs migrate-config --config <old> --output <new>`.** Rewrites 0.5 configs into a separate file (preserving comments when the line rewrite matches the YAML mapping), renaming `minimumSeverity:` gate maps to `failOn:`, removing `allowlists.secretPreviews`, empty `minimumSeverity:` (`null`) placeholders, and all 15 retired 0.5 rule IDs across `rules:`, `rules.select`, `rules.ignore`, `exclude`, and `sensitiveExclusions` (refusing if stripping `rules.select` would empty a non-empty selection). Legacy config load errors suggest this command, while `rules --selector` and non-retired typos keep their existing errors.
- **Non-destructive baseline migration and safety guards.** `analyse --migrate-baseline <old> --generate-baseline <new>` re-identifies 0.5 reviews into a separate v3 file without modifying the original (refusing same-path, symlink, or hardlink targets and multi-container 0.5 files). Generating at `gruff-baseline.json` refuses to overwrite a non-v3 baseline without `--force`; collisions stay visible with a non-fatal `baseline-collision` diagnostic; the `baseline` envelope section publishes all nine cross-port fields (`applied`, `entries`, `generated`, `newFindings`, `resolvedFindings`, `source`, `suppressedFindings`, `unchangedFindings`, `path`) with zeroed movement counts on generate or migrate; `analyse` text appends `Baseline: default gruff-baseline.json; suppressed N findings` (or `explicit`) (ADR-006).
- **`sensitiveExclusions` config section and end-to-end suppression auditing.** Suppress reviewed sensitive-data findings by exact `sensitive-data.*` rule ID, project-relative path, optional `symbol`, and required `reason` (authored by hand; forbids `message_contains`, `value`, `preview`, wildcards, globs, unknown or non-sensitive rules, absolute/`..` paths, empty reasons, or duplicate scopes with exit `2`; unmatched entries report `suppressed: 0`). Configured `exclude` and `sensitiveExclusions` run before baseline matching and generation (preserving `exclude` counts so reviewed baseline rows are not marked resolved) and publish audit rows in JSON `suppressions[]` (omitting absent `symbol`), text `Suppressed findings: N via ...` (labelled `sensitiveExclusions[<index>]`), HTML, and Markdown reports.
- **Counted inline lint and zizmor suppressions (`FAMILY-CONTRACT.md` section 13c).** Rust `allow`/`expect` attributes for `clippy::too_many_lines`, `clippy::too_many_arguments`, `clippy::cognitive_complexity`, `dead_code`, `unused`, and `clippy::disallowed_names` (on the item, enclosing impl/trait/inline module, or file) and workflow `zizmor: ignore[unpinned-uses]` / `ignore[dangerous-triggers]` comments suppress matching findings and publish `inline` rows in `suppressions`, text output, and SARIF `inSource`; `#[allow(dead_code)]` is now audited rather than silently skipped.
- **`test-quality.duplicate-test-body` enabled by default.** Reports one finding for three or more tests in one module (at least four statements, matching attributes and signature) whose bodies match after eligible literal normalization, listing every member and suggesting a table-driven loop; text containing ASCII whitespace, index/slice/key literals, inner non-constant items, attribute arguments, and names/calls/assertions/operators/delimiters stay exact (comments and formatting ignored; no options; never reports pairs).
- **Configurable `deepScanBudget` and `--deep-scan-budget LINES:BYTES|off`.** Rust sources over 20,000 lines or 2,000,000 bytes skip AST and block analysis while keeping size and sensitive-data checks, publishing a non-fatal `bounded-deep-scan` diagnostic with counts, limits, and override provenance across all output formats.
- **Configurable `sensitive-data.high-entropy-string` thresholds.** `rules.sensitive-data.high-entropy-string.thresholds.minLength` (1..=65535, default 32) and `thresholds.entropy` (zero or more, default 4.2) are configurable in `.gruff-rs.yaml`, seeded by `init`, and published by `list-rules` (a lowered `minLength` reaches shorter literals; other rules still reject `thresholds:`).
- **Scoring transparency, catalogue guidance, and HTML cognitive fallback.** Envelopes publish `score.evaluatedFiles` (parsed Rust files without read or parse failure, distinct from raw-text totals) and `score.scoredPillars`; flat `list-rules` JSON and detail cards publish reviewed false-positive shapes and mitigations for every medium- and low-confidence built-in rule; HTML complexity charts fall back to `complexity.cognitive` when `complexity.cyclomatic` is off.

### Changed

- **Building from source requires Rust 1.90.** `rust-version` now names the oldest toolchain that compiles the crate (Rust 1.89 and earlier reject its `const` rule tables); prebuilt binaries need no Rust toolchain.
- **Security and sensitive-data rules skip test, fixture, and example files with audited rows.** Every security rule (including security-pillar `dependency.*` and `ci.*`, with the five network-security descriptions updated) and every sensitive-data rule except `sensitive-data.pii-test-fixture` skips directories named `test`, `tests`, `__tests__`, `spec`, `testdata`, `fixtures`, or `examples` (any case) and test filenames (`*_test.go`, `test_*.py`, `*_test.py`, `*Test.php`, `*.test.*`, `*.spec.*`). **The trade-off is deliberate: a real vulnerability or credential committed under one of those paths is no longer reported.** Each skip publishes a counted `source: "built-in"` audit row (`FAMILY-CONTRACT.md` section 13a; sensitive-data rows follow lockfile rows).
- **Vendored, built, and minified files skipped by default (`FAMILY-CONTRACT.md` section 7).** `vendor`, `vendors`, `third_party`, `third-party`, `bower_components`, `dist` (any depth or case), and `*.min.*` files are skipped even under `.gitignore` and listed in `paths.details` as `dependency`, `build-output`, or `generated`; pass `--include-ignored` or name the file explicitly to scan it.
- **`sensitive-data.high-entropy-string` lockfile skips, character-class floor, and public-format exemptions.**
  - Skips nine ratified lockfiles (`package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock`, `pnpm-lock.yaml`, `composer.lock`, `Cargo.lock`, `go.sum`, `uv.lock`, `poetry.lock`) at any depth with counted `source: "built-in"` audit rows while every other sensitive-data rule still scans them; `init` stops seeding lockfile globs into `paths.ignore`.
  - Requires at least one letter and one digit rather than upper, lower, and digit together (`FAMILY-CONTRACT.md` section 12; +5 corpus findings in one `sqlx` example test), and skips public PEM blocks (certificates, public keys, CSRs, PKCS7, CRLs) when the closing marker is next and inner lines are base64, PGP checksums, or armour headers (private keys and secrets between marker constants still report).
  - Keeps whole-value public formats quiet while reporting opaque tails or property-name-only values: relative dot-prefixed paths (`./.hidden/...`, `../.hidden/...`, `../../.hidden/...`), stored help-article links (including short words `a`, `to`, `in`), bounded help-category routes, EC2 import paths (up to two parent prefixes), complete GitHub commit references, nine Symfony signature service IDs, and exact lowercase-letter-then-digit, uppercase/lowercase/digit, Hashids, Base64-with-`=`, and UUID alphabets.
- **Vendor sample values and AWS session/placeholder keys.** Twenty vendor-documented sample values (AWS example keys, jwt.io sample token, Google reCAPTCHA v2 test site key, and 14 test card numbers stored as SHA-256 digests; AWS, jwt.io, and reCAPTCHA affect `gruff-rs`) stop reporting when matched whole. `sensitive-data.aws-access-key` reports temporary `ASIA` session tokens alongside `AKIA` while ignoring all-`X` 16-character placeholder bodies under both prefixes (`FAMILY-CONTRACT.md` section 5).
- **Code-line counting, inline test-module split, and two-band size/complexity reporting.**
  - `size.function-length`, `test-quality.long-test` (from the first assertion, or full test if none), and `size.file-length` (Rust files only, even over `deepScanBudget`) count code lines only, excluding blank lines, comments, doc comments, and `#[...]`/`#![...]` attributes (thresholds 50, 120, and 1000 unchanged).
  - `size.file-length` excludes inline `#[cfg(test)]` modules from the file total, records `metadata.testModuleLines`, and emits a separate `mod`-line advisory (``Inline test module `NAME` has N substantive lines, above the threshold of T.``) carrying `testModule` instead of a band.
  - `size.*` and `complexity.*` findings below 1.5x their limit emit advisory `limitBand: "lower"` notices; findings at 1.5x or above keep their severity and split/simplify advice with `limitBand: "upper"`.
- **AST-based complexity and guard/match-arm scoring.** Complexity counts on the syntax tree (`match` counts once regardless of arms, `?` adds 0, closure bars and struct-literal braces ignored; default trait methods and `const` closures are measured by function-length, parameter-count, and complexity). `complexity.cognitive` charges no nesting penalty for early-exit guards (`if` without `else` containing one `return`, `break`, `continue`, or `panic!`) and keeps match-arm bodies at the match's level (`complexity.nesting-depth` unchanged).
- **Function finding anchors and rule-specific remediations.** Function findings anchor on the `fn` signature line rather than the first doc-comment or attribute line (baselines unchanged; line-sensitive `fingerprint` moves with the anchor). Modernisation, unsafe, clone, unwrap, remote-shell, and XML findings provide rule-specific fixes; eight remediations (including `security.process-command` and `dead-code.unused-private-function`) drop `paths.ignore` hints (kept in catalogue mitigations), and `complexity.cognitive` suggests a flat tuple `match`.
- **Documentation-rule messages and accepted Rust summaries.** `docs.missing-param-doc` lists every undocumented parameter in one message, `docs.missing-public-doc` adds `"Also say ..."` for parameters, return values, and errors present in the signature, and `docs.missing-return-doc` skips `-> ()` and `-> !` and accepts getter (`Direction of the search` on `direction(&self)`) and conversion (`Converts an i128 to a Number` for `Number`/`Option<Number>`) summaries.
- **Rust and workflow rule precision.**
  - `dead-code.unused-private-item-candidate` recognises inline `{ident}` and `{ident:...}` captures (including dynamic width and precision) in `format!`, `println!`, `eprintln!`, `print!`, `eprint!`, `write!`, `writeln!`, `panic!`, and `format_args!` while excluding ordinary strings, comments, and `{{escaped}}` braces.
  - `naming.short-variable` accepts `at`, `by`, `on`, `to`, and `up` without changing `allowlists.acceptedAbbreviations`.
  - `waste.unwrap-expect` skips Cargo-set build variables in `build.rs` (such as `env::var("OUT_DIR").unwrap()`), single-literal `CString::new`, `Regex::new`, `Url::parse`, or address `from_str`, and external `tests.rs` modules declared via parent `#[cfg(test)]`/`#[cfg(all(test, ...))]` `mod tests;` in full scans.
  - `security.unsafe-block` reads the entire contiguous comment block above `unsafe` for `SAFETY` (removing the 16-line limit; blank lines and completed statements still end the block).
  - `security.process-command` accepts in-scope immutable string-literal arrays in `.args(name)` and bare program names setting only working directory (`./configure`, caller/rebound/extra args, env changes, and dynamic programs still report).
  - `security.github-actions-broad-permissions` skips single concrete non-matrix job scopes (multiple jobs, reusable workflows, unknown structure, and `write-all` still warn); `security.hardcoded-bind-all-interfaces` skips CIDR comparisons, string-prefix checks, and proven client-only address bindings; `security.template-injection-xss` skips direct Axum handlers formatting only a same-file payload-free `#[derive(Debug)]` enum.
  - `security.github-actions-unpinned-action` exempts first-party `actions/*` and `github/*` (474 -> 271 on the corpus); `security.github-actions-secrets-in-pr` reports only `pull_request_target`, skips `secrets.GITHUB_TOKEN`, skips jobs or steps with unreachable event guards, and (with `security.github-actions-pull-request-target`) recognises block-list triggers with trailing comments such as `- pull_request_target  # label bot` (7 -> 0 on the corpus).

### Fixed

- **Launch-directory path resolution and redacted errors.** Relative `--config`, `--baseline`, and `--generate-baseline` paths resolve from the launch directory rather than project root (discovered `.gruff-rs.yaml` still reads at project root), config and baseline errors name files as typed or discovered instead of host paths, and `analyse ../proj --format json` with a broken `--config` exits `2` with a `config-error` JSON envelope (omitting the out-of-root target) instead of panicking with exit `101`.
- **Project-root discovery stops at `.git` boundaries.** Scanning a nested Git repository (`.git` directory or worktree/submodule `.git` file) whose `Cargo.toml` lives in a subdirectory no longer escapes into an ancestor repository's config or `.gitignore`.
- **Unreadable scopes and empty `--changed-ranges` fail closed cleanly.** Both `analyse` and `hook` exit `2` with one `changed-region` diagnostic and no findings alongside it (run-invalidating diagnostics no longer publish unscoped findings).
- **`#` symbols and raw identifiers no longer abort baselines.** Raw identifiers normalize to their plain name (`r#match` -> `match`, `Parser::r#type` -> `Parser::type`) in baseline identities and SARIF fingerprints (regenerate once if affected), and other `#`-bearing symbols (such as `Cargo.toml` dependency `"bad#dep"`) drop only that finding's identity instead of failing the run (0 -> 4 baseline rows written on that case).
- **Seven Rust rule false-positive fixes (11-repo Rust corpus 31,710 -> 29,338 findings).** `error-handling.unimplemented-placeholder` skips test-infrastructure paths (`tests/support/`), ignores comments and `quote!` streams, and lists only called macros in `metadata.macros`; `docs.missing-return-doc` accepts `-> Self` constructors, `Return`/`Get`/`Create` openings, and `&self` getters naming the final word; `test-quality.should-panic-without-expected` accepts `#[should_panic = "msg"]` and non-test `cfg` skips; `security.unsafe-block` accepts lead-in, first-inside, and bare `SAFETY`/`# Safety` rationales while `docs.weak-safety-rationale` flags `todo`/`fixme`/`xxx`/`hack` openers; `docs.commented-out-code` requires parseable Rust outside fenced examples and clippy UI tests with a 16 KiB/depth guard; `dead-code.unused-private-function` and `dead-code.unused-private-item-candidate` mark `test`/`bench`/`_test`/`_bench` attributes, serde's `default`, `deserialize_with`, `serialize_with`, `with`, and `skip_serializing_if` (including `cfg_attr`), and empty-body `where` assertions as reached.
- **Private-key headers and CLI selector handling.** `sensitive-data.private-key` retains bare headers and truncated or escaped key material (enabled service-account warnings still replace generic duplicates); CLI `--include-rule`/`--include-pillar` override config `rules.ignore`, and `--show-*`/`--hide-*` display selectors reject unknown rules and pillars with exit `2` and match pillars case-insensitively.

### Known Limitations & Notes

- **`security.process-command` import resolution lacks a family regression suite.** Distinguishing `clap::Command` from `std::process::Command` (measured 2026-08-12: 1,265 -> 6 findings on `clap`) ships without a cross-port suite, which is deferred past 0.6.0.
- **Self-scan gate scope.** `gruff-rs` finding nothing in its own repository is a release invariant, not evidence about false-positive rates (which negative fixtures measure).

## v0.5.0 - 2026-08-16

0.5.0 retunes rule families against real Rust idiom and measured corpus noise, replaces secret and PHI previews with markers, moves the action to `argv` with a pinned verified install, and upgrades the agent harness to goat-flow 1.15.1.

- **`security.process-command` requires std provenance.** Third-party `Command` types and comment examples stay quiet; clap drops 1,265 findings to 4.
- **GitHub `uses:` findings follow step structure.** Unpinned-action checks read `jobs.<job>.steps`, `runs.steps`, and a job's own reusable-workflow `uses:`, not a nested `with` value.
- **Pull-request gating reads the top-level `on` mapping.** A `with:` input or matrix key named `pull_request` no longer fakes a trigger on a push-only workflow.
- **Quoted `"on":` keys and quoted event names count as triggers.** YAML 1.1 reads bare `on` as a boolean, so linters quote it and those workflows were invisible.
- **Remote-shell findings require the payload to reach the shell.** A pipe still reports; `;` and `||` report only when the interpreter reads a path the downloader wrote.
- **A `permissions:` key inside a step is an action input, not a grant.** `with: permissions: write-all` stays silent while a workflow-level grant and a job's `write-all` still report.
- **Quoted step keys are read like plain ones.** `- "uses":` and `- "run":` reach the pinning, remote-shell, and event-interpolation checks.
- **Block headers carrying an indentation indicator open a run block.** `run: |2` and `>2-` keep their shell lines in scope instead of skipping the whole step.
- **Container images must name a digest.** `docker://alpine:latest` reports as unpinned; a `docker://image@sha256:...` reference stays exempt.
- **Secret expressions match without interior whitespace.** `${{secrets.TOKEN}}` gates pull-request secret exposure like `${{ secrets.TOKEN }}`.
- **Lock guards taken from struct fields report.** `self.state.write().await` held across an await reports; I/O and domain `read`/`write` receivers stay silent.
- **Root-qualified process constructors report.** `::std::process::Command::new` names the standard-library type, while `vendor::std::process::Command` still does not.
- **Release setup rejects unpublished identities.** The action takes only core `X.Y.Z` versions and stops when actionlint's SHA-256 check fails.
- **`test-quality.unwrap-in-test` is off by default.** Still Advisory when enabled; baselines lose its findings, 622 in clap and 773 in tokio.
- **`naming.short-variable` skips narrow Rust idioms.** Loop and closure bindings and `cx: *Context` parameters stay quiet; tokio drops 1,584 to 881.
- **Agent harness upgraded to goat-flow 1.15.1.** Agent surfaces, skill docs, and managed hooks move to its templates, retiring three local hotfixes.
- **`goat-flow-allow-secret` survives the upgrade.** Both scan paths honour it again, after CR stripping so a Windows-edited marker still counts.
- **The allow marker exempts secrets only.** No other form counts, not `gitleaks:allow`, and a conflict marker carrying it still blocks the turn.
- **Unreadable changed files block the turn instead of passing as clean.** The scan reports `scan incomplete`; oversized and binary paths block too.
- **Preflight names skipped checks in its success line.** The line quoted as gate evidence carries the skip count, so green cannot mean full coverage.
- **Permission rules and hook repairs are gated.** Preflight fails on a lost `Read`/`Edit` deny pair, an inert rule form, or one of six hook repairs.
- **Managed skill-doc repairs are gated too.** Preflight asserts the analyzer playbook's `bin/<target>` probe and its `analyse --help` guidance.
- **`.goat-flow/security-policy.md` states this repository's boundaries.** Each entry names the architecture section, ADR, or footgun that decides it.
- **Codex denies every non-sample env-file variant.** The workspace profile denies `**/.env*` for direct file tools and reopens only `.env.example`.
- **Claude denies every non-sample env-file variant too.** Paired `Read(**/.env*)` and `Edit(**/.env*)` denies refuse `.env.qa` and `.env.bak`.
- **Claude permission wording matches current tool semantics.** An `Edit` deny covers every file-writing tool, so `Read` and `Edit` pairs suffice.
- **Native Windows action paths.** `working-directory` and `output-file` accept a drive root or UNC share; a drive-relative `C:crate` is rejected.
- **`security.sql-dynamic-query` reads SQL shape, not words.** An all-interpolated `SELECT` with no `FROM` reports; prose and non-SQL DSL stay quiet.
- **Unused private functions report even when generic.** `fn helper<T>(..)` and `fn helper<F: Fn()>(..)` counted as their own reference; rust-clippy rises from 3,293 to 3,630.
- **API-key detection skips hyphenated prose.** The `sk-` arm had no left boundary, so `risk-of-script-injections` matched; real keys still report.
- **Annotated deserialization sinks report.** `security.unsafe-deserialization` matches `serde_yaml::from_str::<Config>(..)` in all four families.
- **Split download-to-shell pipelines report.** A `curl` and its `bash` on separate block-scalar lines are joined; a trailing `||` ends the join.
- **Stop-hook scan bypass closed on both dispatch paths.** An added line whose own text starts with `++` is no longer skipped as a file header.
- **Release reruns fail closed on an existing draft.** The workflow contract rejects `--clobber`, release deletion, and existence-probe gating.
- **file-length: 1000 substantive lines at error (family ratification).** Blank and comment-only lines are free, replacing the 600-line warning.
- **Zero-payload sensitive metadata markers.** JSON, SARIF, and hook findings serialize detector-owned markers instead of secret or PHI previews.
- **Narrower lock-across-await signal.** I/O and domain `.read()`/`.write()` no longer read as guards; zero-arg calls need local lock evidence.
- **Wrapper normalisation skips unknown options.** `watch` and `parallel` now match `xargs`, so no destructive payload hides from the deny hook.
- **Action metadata keys are not executable steps.** `run:` is read structurally like `uses:`, so a top-level `run` input is not scanned as shell.
- **Risk-based network-security test scans.** Executable Rust tests keep bind-all and SSRF findings; scoped mitigations replace blanket suppression.
- **Block rustdoc and function-length precision.** Doc rules accept outer `/** */` comments; `size.function-length` excludes rustdoc and attributes.
- **Structured composite-action arguments.** The action accepts newline-delimited `argv`, rejects legacy `args`, and contains paths in the workspace.
- **Explicit composite-action security coverage.** Supplied `action.yml` files now get event-interpolation, remote-shell, and full-SHA checks.
- **Inert Markdown finding fields.** Rule IDs and paths use safe code spans and messages escape as text, so untrusted values cannot inject markup.
- **SAFETY rationales follow Rust conventions.** `security.unsafe-block` matches `SAFETY:`, `Safety:`, and `safety:`; tokio drops 704 to 493.
- **Exact, verified composite-action install.** The action pins an exact binary version, verifies the SHA-256 sidecar and archive members.
- **Verified five-platform release candidates.** A non-publishing workflow binds commit and package to Linux, macOS, and Windows archives.
- **Pinned, least-privilege release execution.** Workflows pin full SHAs and exact tool versions, and grant write only for final publication.
- **Accurate secret-preview suppression guidance.** Mitigations name the accepted `allowlists.secretPreviews` key; `secret_previews` stays rejected.
- **Visible accepted-abbreviation contract.** `gruff-rs init` explains that `allowlists.acceptedAbbreviations` replaces the built-in list.
- **Validated rule relationships.** Registries reject related-rule links that do not resolve, and `security.process-command` links to a shipped rule.
- **Exact documentation drift checks.** Preflight derives rule and pillar counts plus release examples from the catalogue and Cargo metadata.

## v0.4.0 - 2026-06-14

0.4.0 is a precision, correctness, and runtime-efficiency release for hook-facing scans. It keeps the report schema stable, makes partial-context analysis safer, tightens high-noise rules found by external scans, and retires two default rubrics that could not be made precise enough for agent hooks.

- **Partial-context dead-code safety.** Project-level dead-code findings are held back when a scan doesn't cover the whole Rust tree; a diagnostic points to a full scan.
- **Sharper security and secret rules.** Dynamic SQL findings now require a real SQL keyword; high-entropy checks skip inert text (integrity hashes, base64 alphabets, slugs, model IDs) but still flag real secrets.
- **Hook and Rust-pipeline efficiency.** Hook diff analysis avoids duplicate work, batched Git export cuts overhead, and rule dispatch skips disabled families sooner.
- **Non-UTF-8 text robustness.** Broad scans skip invalid (non-UTF-8) text with a diagnostic instead of failing; named and security-relevant files stay visible.
- **External-scan false-positive fixes.** Dead-code skips exported/plugin/allowed items; path-traversal needs filesystem-join evidence and honors sanitizers; lock-across-await ignores immediate extraction.
- **Removed two noisy default rules:** `modernisation.public-field` and `test-quality.no-assertions`. Public contract fields and harness-style tests need design intent the analyzer can't reliably guess.
- **Kept `security.path-traversal-candidate` on by default.** A review found no reason to weaken it; wording or metadata may still change without cutting coverage.
- **Rule catalogue 87 → 85.** The two retired IDs are gone from `list-rules`, config, docs, and output; schema versions and finding identities are unchanged.

## v0.3.0 - 2026-06-09

0.3.0 makes gruff easier to adopt and sharpens its rules: a new `hook` command that speaks the cross-analyzer `gruff.hook.v1` contract, tri-state baselines, count-based gates, a "fail-on-new" mode, eleven new security/secret rules, and four low-value rubrics dropped. JSON stays additive; new gates are opt-in.

- **New `hook` command.** `gruff-rs hook --format json` emits the cross-analyzer `gruff.hook.v1` contract — render-ready findings (`file`, `scope`, `stableIdentity`, non-null `remediation`, `metadata`) plus `suppressed.count`, `ignored.paths`, and `config`; `--capabilities` advertises support.
- **Changed-region hook fairness.** `line`/`symbol` findings stay scoped to changed ranges; `file`/`project` findings are dropped and counted in `suppressed.count` instead of leaking via synthetic anchors.
- **Native new-only hook.** `hook --baseline`/`--diff <ref>` surface only findings new vs. the base, with count-based suppression so a newly added duplicate still shows. `--diff` runs Git, so it needs the hidden `--diff-git-unsafe` opt-in (per ADR-019).
- **Additive finding enrichment.** Findings gain `scope`; threshold rules emit `metadata.measured`/`threshold`/`unit`/`direction`. File/project stable identities are value-independent; fingerprints and baselines unchanged.
- **Changed-region scoping for `analyse`.** Limit findings to changed lines via `--diff-patch`/`--changed-ranges` (no Git) or `--since`/`--diff` (Git, needs `--diff-git-unsafe`).
- **`paths.ignore` applies everywhere** — the walk, explicit file args, and diff modes — so a hook can't flag a deliberately-ignored file.
- **New `check-ignore` command.** Reports whether gruff would ignore a path and why, matching `git check-ignore` exit codes.
- **Tri-state baselines.** Findings are labelled `new`/`unchanged`/`resolved`; the default list is unchanged.
- **Count-based gates + `--fail-on-new`.** A `gate:` block caps findings by count (e.g. "10 warnings, no errors"); `--fail-on-new` gates only on findings new since the baseline.
- **Nine new security rules** — five GitHub Actions checks plus SSRF, unsafe-deserialization, XXE, and template/XSS; `severity:` overrides now apply to security/dependency rules.
- **Two new secret checks** — `phi-pattern` (health IDs) and `gcp-service-account-key`, with wider token coverage. Output stays redacted.
- **Removed four low-value rubrics:** `complexity.npath`, `metrics.halstead-volume`, `metrics.maintainability-pressure`, and `design.god-function`.
- **Sharper, quieter rules** — dead-code now flags unused private `const`s/`static`s/type aliases (skipping cfg/test/trait-impl); complexity ignores comments and `?`; `parameter-count` 5 → 7.
- **Rule catalogue 80 → 87** (four removed, eleven added); `waste.unnecessary-clone-candidate` ships disabled. Schemas, rule IDs, and fingerprints unchanged.
- **JSON `file` alias.** `analyse --format json` emits canonical `findings[].file` (and `score.topOffenders[].file`) alongside the deprecated `filePath`.

## v0.2.0 - 2026-05-28

The first `0.2.x` release: cross-port ergonomics plus schema and CLI-default changes held for a major bump. See `UPGRADING.md` to migrate from 0.1.x.

- **Breaking: `analyse --fail-on` now defaults to `advisory`** (was `error`) - restore with `--fail-on error` or `minimumSeverity.analyse: error`.
- **Breaking: `.gruff-rs.yaml` requires `schemaVersion: gruff-rs.config.v1`** - configs without it are rejected; `init --force` adds it.
- **Breaking: JSON schemas bumped to v2** (`gruff.analysis.v2`, `gruff.summary.v2`) with additive fields; v1 carries forward, baseline and SARIF unchanged.
- **Per-rule scoring opt-out** - `excludeFromScore: true` keeps a rule's findings visible but drops its score penalty.
- **Per-rule deltas in baseline/diff scans** - reports show top improved/regressed rules; JSON adds `perRuleDeltas[]`.
- **`list-rules <rule_id>` detail card** - defaults, options, escape hatches, false-positive shapes, and related rules.
- **`stableIdentity` on every finding** - a line-insensitive hash so external diff tools match findings across edits; `fingerprint` stays line-sensitive.
- **Per-subcommand `--fail-on` defaults** via a `minimumSeverity:` block for `analyse` and `report`.
- **Richer summary JSON** - `pillars[]` carries nine fields for every pillar; `topRules[]` gains severity, confidence, and a description.
- **Markdown and HTML reports gain a pillars table** - seven columns; HTML drops its card grid for it.
- **Triage hint** - text scans past 50 findings point at `summary --top 20`.
- **Escape-hatch hints in eleven remediations** - each names the relevant `.gruff-rs.yaml` knob.
- **`docs.missing-*` reworded for agents** - ask for a brief intent line, not a stub doc comment.
- **Default `accepted_abbreviations` grows 6 → 16.** Upgrade note: the loader replaces (not merges) the list, so run `init --force` to pick up the new ones.
- **Twelve rules ship false-positive metadata** (`false_positive_shapes`, `related_rules`).
- **Determinism and correctness fixes** - stable diagnostic ordering, finding-sourced summary severity, and de-duplicated baseline deltas.
- **Internal refactors** - shared single sources for pillar labels/digests; v2 shape aligns with the `gruff-go`/`-ts`/`-py`/`-php` ports.

## v0.1.1 - 2026-05-24

Ten new default-on rules, the `gruff-rs init` scaffold, broader `paths.ignore` defaults, and split-out docs.

- **Ten new default-on rules** (67 → 77) - four `modernisation.*` lints, four `docs.missing-*` rules, `security.path-traversal-candidate`, and `test-quality.should-panic-without-expected`.
- **`gruff-rs init` scaffold** - writes a default `.gruff-rs.yaml`, preserving custom `paths.ignore`.
- **`security.path-traversal-candidate` precision guards** - six guards (typed-path args, validate-then-trust, sanitizer calls, …) cut false positives.
- **`modernisation.manual-contains` tightened** - matches only deref/RHS-ref shapes; bare `|x| x == y` is skipped.
- **`docs.missing-param-doc`/`-return-doc` skip bridge functions** - `#[tauri::command]`, `#[wasm_bindgen]`, `#[pyfunction]`, etc.
- **Broader `paths.ignore` defaults** - skips agent/CLI dirs (`.claude/`, `.codex/`, `.goat-flow/`, …) and lockfiles.
- **CLI and dependency tooling** - a `--baseline` path option and `dependency-{install,update}.sh` that auto-install `cargo-audit`.
- **Documentation pages** - separate guides for CI, config, the dashboard, output formats, and releases.
- **Calibration matrix 77/77 and internal refactors** - every rule has positive/negative cases (dogfood 100/A); rule files split for size, helpers renamed to predicate form.

## v0.1.0 - 2026-05-23

First public release. Deterministic, schema-versioned quality analyzer for Rust projects; single-binary CLI you can drop into CI.

- **Commands** - `analyse`, `report`, `summary`, `list-rules`, `dashboard`, `completion`.
- **Output formats** - text, JSON (`gruff.analysis.v1`), SARIF 2.1.0, HTML, Markdown, GitHub annotations, hotspot.
- **Default-on rules across eleven pillars** - complexity, dead-code, design, documentation, maintainability, modernisation, naming, security, sensitive-data, size, test-quality.
- **`.gruff-rs.yaml` config** - selectors, thresholds, allowlists, custom regex rules, and report-level exclusions.
- **Baselines and patch-diff filtering** - for incremental adoption against an existing codebase.
