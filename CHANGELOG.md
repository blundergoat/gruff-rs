# Changelog

All notable changes to this project are documented here.

## Unreleased

### Added

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
- `sensitive-data.private-key` now requires a private-key block instead of a
  standalone marker string.
- `modernisation.public-field` now skips serde transport/config structs where
  public fields are the serialization contract.
- `dead-code.unused-private-function` now recognises bare function references
  such as function pointers, macro registrations, and serde default strings,
  and skips trait-implementation methods.
- `concurrency.lock-across-await` now respects lexical block scopes before
  reporting a lock guard across `.await`.
- `size.file-length` now skips dependency lockfiles such as `Cargo.lock` and
  `package-lock.json`.
- `naming.short-variable` now skips single-letter bindings so idiomatic
  closure/error names are not treated as enforceable findings.
- Narrowed `sensitive-data.database-url-password` to database and message-bus
  style URL schemes so generic HTTP(S) credentials are reported by
  `sensitive-data.url-embedded-credentials` without double-counting.
- Updated security and sensitive-data calibration coverage so every built-in
  rule has positive and negative fixture cases.

### Notes

- The new security rules remain deterministic, source-only checks. They do not
  change `gruff.analysis.v1`, finding fingerprints, baseline matching, or
  renderer contracts.
