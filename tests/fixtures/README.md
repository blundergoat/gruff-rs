# Test Fixtures

Fixture directories are grouped by scanner surface:

- `parser/` contains Rust syntax edge cases and invalid Rust parser fixtures.
- `rules/` contains focused positive and negative fixtures for rule-family assertions.

Project-level scanner behavior such as baselines, source discovery, reports, and dashboard scans is built in temporary directories inside unit tests so each test owns its files and paths.

The `rules/` fixtures are public calibration inputs, not examples of recommended
code. Each new default-on rubric should have a positive and a negative fixture
before it becomes enforceable at warning or error severity. False-positive
guards that depend on path shape, generated config, or multi-file project state
belong in temporary test projects instead of this static fixture tree.
