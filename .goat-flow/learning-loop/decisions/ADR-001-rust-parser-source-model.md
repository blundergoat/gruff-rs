# ADR-001: Rust Parser Source Model

**Status:** Implemented
**Date:** 2026-05-13

## Decision

`gruff-rs` parses Rust files with `syn::parse_file` using span locations and builds a shared `SourceUnit` containing raw source, parser diagnostics, and an optional Rust AST. Text rules run for every supported source/config file. Rust AST rules run only when parsing succeeds. Parse failures emit one `parse-error` diagnostic for the file and do not fabricate findings.

## Context

The earlier regex-and-delimiter approach reported parse diagnostics against valid Rust because it counted braces inside strings and generated text. The current parser fixtures cover raw strings, macros, impl methods, test attributes, and invalid Rust. The self-scan command `cargo run -- analyse src --format json --fail-on none` exits 0 with zero diagnostics.

## Failure Mode Comparison

| Option | What fails | Why rejected or accepted |
| --- | --- | --- |
| Regex and delimiter counting | Valid Rust with strings/macros can look malformed | Rejected after self-scan produced false parse diagnostics. |
| `syn` shared AST per file | Some type-aware rules remain out of scope | Accepted because it is deterministic, local, and sufficient for v0.1 syntax rules. |
| Rust compiler or language-server integration | Higher setup cost and more moving parts | Deferred until rules need semantic type information. |

## Reversibility

This is reversible if `syn` span fidelity blocks required rules. Any replacement must preserve parser fixtures, fixture finding identity, and diagnostic behavior before changing the parser contract.
