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

## Pattern: PII Placeholder Exemptions Should Be Grounded In Standards, Not Guesses

**Context:** Use this when shipping a rule that detects realistic-looking personal data (emails, phone numbers, SSNs, payment card numbers, IP addresses for end users). Any such rule must ship with a placeholder exemption list, because committed sample data uses placeholder values intentionally — flagging those creates pure noise.

**Evidence:** On 2026-05-24, `sensitive-data.pii-test-fixture` first version exempted `@example.com`, `@example.org`, `@example.net`, `@test.com`, `@test.org`, `@foo.*`, `@bar.*`, `@baz.*`. Dogfood scan flagged `fixtures/sample.rs:17`: `mysql://demo:password123@example.test/app`. The `.test` TLD is reserved by RFC 6761 for testing — explicitly intended as a documentation placeholder — but the rule's exemption list was guessing at common conventions and missed the standard. The fix added `.test` and `.example` (also RFC 6761) to the exemption list as suffix matches. After the fix: dogfood clean, calibration positive case (`alice.smith@gmail.com`) still fires.

**Approach:** Ground each PII placeholder exemption in a published standard or universal convention. Resist ad-hoc additions ("I saw this domain once in a test file"). The standards are stable, externally referenceable, and exist *precisely* to give engineers placeholder values that won't accidentally hit real services.

Reference list for the common PII shapes:

- **Email / hostname / URL** — RFC 6761 reserved domains: `.test`, `.example`, `.invalid`, `.localhost`, and the second-level domains `example.com` / `example.org` / `example.net`. Also IANA AS112 examples and `arpa` reserved.
- **Phone numbers (US/NANP)** — Numbers with exchange `555` (i.e. `NXX-555-XXXX` and any `555-01XX` end-of-line). NANPA explicitly reserves these for fictitious use.
- **SSN (US)** — Numbers starting `000`, `666`, or `9XX`. The Social Security Administration documents these as never-assigned.
- **Credit card numbers** — The Luhn-valid test cards published by each card network (e.g. Visa `4111111111111111`, MasterCard `5555555555554444`, Amex `378282246310005`). Skip if the value matches a known test card.
- **IPv4 documentation** — RFC 5737: `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`. RFC 3849 for IPv6: `2001:DB8::/32`.

**How to apply:**

- For each new "realistic-looking PII" rule, the first PR-review checklist item is: "Does the exemption list cite the standard(s) that reserve placeholder values for this PII type?"
- When the dogfood scan flags a sample file, the first question is: "Is this hit on a value the relevant standard reserves for documentation?" If yes, extend the exemption list (and link the RFC in code comments). If no, the sample file genuinely has bad data — replace it with a standards-reserved value.
- Calibration positive cases must use *non-reserved* PII (e.g. a `@gmail.com` address with a fictitious local part), so the rule actually fires. Negative cases must use *reserved* values, so the exemption is exercised on every test run.

**Concrete instance (this repo, 2026-05-24):** `src/built_in_rules/secret_rules.rs` (search: `email_is_obvious_placeholder`) and the SSN/phone filters in `push_pii_ssn_findings` / `push_pii_phone_findings`. The exemption list grew during a single dogfood iteration from "guesses based on memory" to "RFC 6761 + NANP 555-prefix + SSA reserved SSN prefixes" — that change is the durable form. Pairs with [[analyzer]] footgun about text-pattern rules self-firing on their own sentinel values.
