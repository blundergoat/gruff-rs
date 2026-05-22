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

- Narrowed `sensitive-data.database-url-password` to database and message-bus
  style URL schemes so generic HTTP(S) credentials are reported by
  `sensitive-data.url-embedded-credentials` without double-counting.
- Updated security and sensitive-data calibration coverage so every built-in
  rule has positive and negative fixture cases.

### Notes

- The new security rules remain deterministic, source-only checks. They do not
  change `gruff.analysis.v1`, finding fingerprints, baseline matching, or
  renderer contracts.
