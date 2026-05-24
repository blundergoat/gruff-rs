---
category: rule-precision
last_reviewed: 2026-05-24
---

## Pattern: Suppress Candidate Findings With Local Defence Evidence

**Context:** Use this when a `-candidate` security/correctness rule has high recall but low precision because the codebase commonly *defends* the flagged pattern in nearby lines (validate-then-trust, type-narrowing, allowlist intersection). The goal is to keep recall on un-defended uses while dropping noise on idiomatic defended uses.

**Evidence:** On 2026-05-24, `security.path-traversal-candidate` self-scan reported 10 findings on `gruff-rs/src/` and 30 on a Tauri app (`/home/devgoat/projects/devgoat`). Manual classification showed ~70% FP in the smaller repo (path-typed utility helpers, hardcoded loop iterators, internal path-string normalisers) and ~30% FP in the Tauri app (validated env vars, sanitised filenames). After applying three local-evidence guards (`fn path_traversal_finding_is_suppressed` in `src/built_in_rules/behavior_rules.rs`), gruff-rs dropped to 0 findings and the Tauri app dropped from 30 to 24 (the remainder are real Tauri command params from the JS frontend). The rule's positive calibration case (untyped `&str` parameter, no validation) still fires.

**Approach:** Build the rule as a two-stage check. The first stage produces the candidate finding from a pattern match (here, `Path::new(arg)` / `PathBuf::from(arg)` / `.join(arg)` where `arg` is a bare identifier). The second stage runs a small suite of suppression checks before emitting:

1. **Name-based exemptions**: maintain an explicit list of identifiers whose name carries safety semantics (`safe`, `sanitized`, `normalized`, `validated`, `file_name`, plus base-path conventions like `root`, `cwd`, `tmp`). Names like `name` or `path` are too generic to add — they should be renamed at the call site instead.
2. **Type-context lookback**: scan a small window of lines before the finding for a fn signature that declares `arg` with a type that already narrows the value (`&Path`, `&PathBuf`, `impl AsRef<Path>`). A path-typed parameter cannot carry an unconstrained string segment; any external input was widened upstream.
3. **Defence-pattern lookahead**: scan a small window of lines after the finding for the idiomatic validation pair that makes this codebase trust the result (`.canonicalize()` AND `.starts_with(`). Detect both tokens, not just one — `canonicalize` alone resolves symlinks without checking the result is inside a trusted root.

Each guard runs in `O(window_size)` and uses simple string contains/regex on the already-stripped source. Order them cheapest-first so the common case (no match) terminates early. Keep the safe-arg list short and prefer renaming at the call site over expanding the list with generic names.

The pattern composes with calibration: the positive case must avoid all three suppression shapes, the negative case can use any of them. Workshop 2026-05-24: positive `pub fn open(input: &str) { let _ = std::path::Path::new(input); }` (untyped `&str` parameter, no validation, no safe-args name), negative `pub fn open() { let _ = std::path::Path::new("/etc/static-fixture"); }` (literal, fails the bare-identifier match). When the rule's logic changes, re-run `cargo test rule_calibration_matrix_covers_every_rule -- --nocapture` to confirm the matrix stays green.

When NOT to apply: rules whose pattern itself is the violation (e.g. `security.unsafe-block` — the unsafe block is the finding, not a candidate to be defended elsewhere). This pattern only fits `-candidate` rules where the surface-level shape is ambiguous and local context decides safety.

## Pattern: Safe-Arg Lists Should Carry Semantic Weight, Not Catch-All Names

**Context:** Use this when extending the exemption list for a rule that fires on bare identifiers (path-traversal candidates, dynamic SQL candidates, command-injection candidates).

**Evidence:** During the 2026-05-24 path-traversal calibration, candidate additions to the safe-arg list fell into two clear buckets. Adding `safe`, `sanitized`, `validated`, `normalized`, `file_name` cleared real false positives without losing any true positives across two repos (~140 findings inspected). Considering and rejecting `name`, `path`, `key`, `value` would have masked legitimate attack surfaces — those names appear on both safe-by-validation and externally-controlled values across the same codebases.

**Approach:** When extending the safe-arg list for a rule, apply this filter:

- **Keep**: identifiers whose name *describes a validation outcome* (`safe`, `sanitized`, `validated`, `normalized`, `canonicalized`, `escaped`) or *describes a constrained sub-component* (`file_name`, `filename`, `extension`, `prefix`). These names communicate "this value has been narrowed."
- **Reject**: identifiers whose name *describes the slot* without saying anything about provenance (`name`, `path`, `key`, `value`, `input`, `arg`). These appear on both validated and unvalidated values with equal frequency — exempting them lets real attacks slip past.
- **Reject**: base-path conventions that are already exempt for unrelated reasons (`self`, `root`, `cwd`, `tmp`) — these are already in the list and don't need expansion.

When the call site uses a generic name (`name`, `path`, `key`) and the value really is validated, prefer renaming at the call site (`let file_name = ...; project_root.join(file_name)`) over adding the generic name to the global safe list. The rename is local, reviewable, and self-documenting. Adding the generic name silently exempts every other use of that identifier across the codebase.

Concrete instance: `src/config_loader/mod.rs` (search: `default_config_path`) was rewritten from `.map(|name| project_root.join(name))` to `.map(|file_name| project_root.join(file_name))` after the safe-arg expansion. The rename made the closure parameter self-documenting and silenced the rule without growing the global exemption list.
