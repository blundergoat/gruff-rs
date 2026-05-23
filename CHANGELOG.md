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
- Added default-on rubrics calibrated for enforceable/100%-compliance projects:
  env-style secret detection skips placeholders, GitHub secret references,
  dependency names, runtime variable handling, and detector tables while
  preserving structured config coverage.
- Added risk-signal filtering for `security.process-command`: shell execution,
  dynamic executables or arguments, custom environment values, and custom
  working directories are reported while fixed command builders and cleanup
  commands stay silent.
- Added private-key block detection that ignores standalone detector marker
  strings.
- Added serde transport/config struct handling for `modernisation.public-field`
  so public fields used as serialization contracts stay silent.
- Added dead-code handling for bare function references such as function
  pointers, macro registrations, serde default strings, and trait-implementation
  methods.
- Added lexical-scope handling for `concurrency.lock-across-await` before
  reporting a lock guard across `.await`.
- Added source-scoped loop context for loop performance rules, with guards for
  prose/comment matches, bounded static inventory loops, and user-facing output
  assembly that is not meaningful performance debt.
- Added assertion-subject handling for `test-quality.unwrap-in-test`: direct
  call results unwrapped inside assertion expressions stay silent while
  setup/local unwraps that hide fixture failures are reported.
- Added file-length ignores for dependency lockfiles such as `Cargo.lock` and
  `package-lock.json`, Markdown docs, and Codex/Claude hook scripts.
- Added `naming.short-variable` allowances for single-letter bindings and common
  AWS/cloud abbreviations in AWS-context files.
- Added default-on dependency posture detection for git dependencies that omit
  a fixed `rev`.
- Added `config.security-blind-ignore` to report `.gruff-rs.yaml`
  `paths.ignore` entries that hide security-relevant surfaces from scanning.
- Added `sensitive-data.url-embedded-credentials` for HTTP(S) URLs containing
  embedded username/password credentials.
- Added Stripe restricted-key prefixes (`rk_live_`, `rk_test_`) to
  `sensitive-data.api-key-pattern`.
- Added database/message-bus scheme scoping for
  `sensitive-data.database-url-password` so generic HTTP(S) credentials are
  reported by `sensitive-data.url-embedded-credentials` without double-counting.
- Added security and sensitive-data calibration coverage so every built-in rule
  has positive and negative fixture cases.

### Notes

- Security rules are deterministic, source-only checks and preserve
  `gruff.analysis.v1`, finding fingerprints, baseline matching, and renderer
  contracts.
- `license = "proprietary"` remains in `Cargo.toml`; choose an explicit public
  license before publishing this crate to a public registry.
