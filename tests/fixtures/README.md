# Test Fixtures

Fixture directories are grouped by scanner surface:

- `parser/` contains Rust syntax edge cases and invalid Rust parser fixtures.
- `rules/` contains focused positive and negative fixtures for rule-family assertions.

Project-level scanner behavior such as baselines, source discovery, reports, and dashboard scans is built in temporary directories inside unit tests so each test owns its files and paths.
