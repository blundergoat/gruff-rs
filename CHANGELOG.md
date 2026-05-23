# Changelog

All notable changes to this project are documented here.

## 0.1.0 - 2026-05-23

### Added

- Initial public release of the `analyse`, `list-rules`/`rules`, `report`,
  `summary`, `completion`, and loopback dashboard entry points.
- Added deterministic native JSON output with `schemaVersion:
  "gruff.analysis.v1"`, plus text, SARIF, HTML, Markdown, GitHub annotation,
  hotspot, and compact report outputs.
- Added strict `.gruff-rs.yaml` config loading for path ignores, rule
  selectors, threshold/severity overrides, allowlists, custom regex rules, and
  report-level exclusions.
- Added exact finding baselines and patch-input diff filtering that layer after
  analysis without changing fingerprints or schema output.
- Added default-on security rules for explicit TLS verification bypasses,
  direct dynamic SQL query arguments, weak cryptographic primitive review
  signals, non-cryptographic RNG use in secret-like generation functions, and
  GitHub event interpolation into workflow shell steps.
- Added default-on dependency posture detection for git dependencies that omit
  a fixed `rev`.
- Added `config.security-blind-ignore` to report `.gruff-rs.yaml`
  `paths.ignore` entries that hide security-relevant surfaces from scanning.
- Added `sensitive-data.url-embedded-credentials` for HTTP(S) URLs containing
  embedded username/password credentials.
- Expanded `sensitive-data.api-key-pattern` to include Stripe restricted keys
  with `rk_live_` and `rk_test_` prefixes.

### Changed

- Tightened noisy rubrics so default-on findings remain suitable for
  enforceable/100%-compliance projects: env-style secret detection now skips
  placeholders, GitHub secret references, dependency names, runtime variable
  handling, and detector tables while preserving structured config coverage.
- `security.process-command` now requires a concrete risk signal such as shell
  execution, a dynamic executable or argument, custom environment values, or a
  custom working directory. Fixed command builders and cleanup commands stay
  silent.
- `sensitive-data.private-key` now requires a private-key block instead of a
  standalone marker string.
- `modernisation.public-field` now skips serde transport/config structs where
  public fields are the serialization contract.
- `dead-code.unused-private-function` now recognises bare function references
  such as function pointers, macro registrations, and serde default strings,
  and skips trait-implementation methods.
- `concurrency.lock-across-await` now respects lexical block scopes before
  reporting a lock guard across `.await`.
- Loop-scoped performance rules now use source-scoped loop context and skip
  prose/comment matches, bounded static inventory loops, and user-facing output
  assembly that is not meaningful performance debt.
- `test-quality.unwrap-in-test` now allows a direct call result unwrapped inside
  an assertion expression when that call is the subject under test, while still
  reporting setup/local unwraps that hide fixture failures.
- `size.file-length` now skips dependency lockfiles such as `Cargo.lock` and
  `package-lock.json`, Markdown docs, and Codex/Claude hook scripts.
- `naming.short-variable` now skips single-letter bindings and accepts common
  AWS/cloud abbreviations in AWS-context files so idiomatic closure/error names
  and cloud DTO fields are not treated as enforceable findings.
- Narrowed `sensitive-data.database-url-password` to database and message-bus
  style URL schemes so generic HTTP(S) credentials are reported by
  `sensitive-data.url-embedded-credentials` without double-counting.
- Updated security and sensitive-data calibration coverage so every built-in
  rule has positive and negative fixture cases.

### Notes

- The new security rules remain deterministic, source-only checks. They do not
  change `gruff.analysis.v1`, finding fingerprints, baseline matching, or
  renderer contracts.
- `license = "proprietary"` remains in `Cargo.toml`; choose an explicit public
  license before publishing this crate to a public registry.
