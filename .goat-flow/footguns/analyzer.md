---
category: analyzer
last_reviewed: 2026-05-13
---

## Footgun: Fixture Findings Are Intentional

**Status:** active | **Created:** 2026-05-13 | **Evidence:** ACTUAL_MEASURED

`fixtures/sample.rs` (search: `AKIA1111111111111111`) intentionally includes secret-looking strings, command execution, a long parameter list, and a weak test. Do not "fix" this file as ordinary bad code unless the replacement still proves the analyzer reports those rule families.

The non-obvious failure mode is losing analyzer coverage while making the repository appear cleaner. The smoke command `cargo run -- analyse fixtures --format json --fail-on none` currently reports findings from this fixture.

## Footgun: Dashboard Scans Change Process Cwd

**Status:** active | **Created:** 2026-05-13 | **Evidence:** ACTUAL_MEASURED

`src/main.rs` (search: `std::env::set_current_dir(&root)`) handles dashboard `/scan` by changing the process working directory before calling `run_analysis`, then restoring the previous directory afterward.

This is easy to miss because the server loop is currently synchronous. Adding concurrency, background scans, or long-lived shared state around `handle_dashboard_request` can make cwd a cross-request race.

## Footgun: Rust Parsing Is Regex And Brace Counting

**Status:** active | **Created:** 2026-05-13 | **Evidence:** ACTUAL_MEASURED

`src/main.rs` (search: `fn rust_function_blocks`) extracts functions with a regex and brace-depth scan, and `parse_diagnostics` only checks delimiter balance.

The analyzer does not use `syn` or rustc parsing. Rule changes that assume full Rust AST semantics can silently misclassify macros, strings, comments, attributes, or unusual signatures.

## Resolved Entries
