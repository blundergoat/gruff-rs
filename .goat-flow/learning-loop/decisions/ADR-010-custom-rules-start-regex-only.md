# ADR-010: Custom Rules Start Regex Only

**Status:** Accepted
**Date:** 2026-05-16

## Decision

If gruff adds user-defined rules, the first supported custom-rule surface should
be config-only regex rules. Custom rule ids must use a reserved `custom.<slug>`
namespace, must not collide with built-in rule ids, and must participate in the
existing fingerprint input through their full custom rule id.

The minimum custom-rule contract should require stable metadata: id, pillar,
severity, confidence or default confidence, message, and one matcher. Regex
rules need include/exclude path scopes and an explicit match scope such as
`text`, `rust-code`, or `comments` so users can avoid obvious string/comment
false positives when needed.

Semgrep-style pattern composition, metavariables, ellipsis matching, PMD-style
XPath/AST custom rules, embedded scripts, external rule runtimes, and custom
Rust plugins are deferred. AST custom rules require a separate ADR because they
would expose gruff's AST/source model as a public contract.

## Context

The M24 matrix records convergent custom-rule evidence from SwiftLint, Semgrep,
and PMD:

- `.goat-flow/scratchpad/related-projects/swiftlint/STUDY.md`
- `.goat-flow/scratchpad/related-projects/semgrep/STUDY.md`
- `.goat-flow/scratchpad/related-projects/pmd/STUDY.md`

SwiftLint shows that regex custom rules are portable and useful. Semgrep shows
that full semantic pattern matching is powerful but represents a much larger
matcher architecture. PMD shows that declarative AST rules can work when the AST
contract is mature and public.

ADR-002 requires stable rule ids and deterministic fingerprints. ADR-003
requires strict config validation. Custom rules touch both contracts, so their
first implementation must be deliberately narrow.

## Failure Mode Comparison

| Option | What fails | Why rejected or accepted |
| --- | --- | --- |
| Allow arbitrary custom rule ids | Built-in ids and baseline identity can collide | Rejected; reserve `custom.*`. |
| Start with full Semgrep-compatible patterns | Parser and matcher scope exceeds gruff's current architecture | Rejected for the first custom-rule milestone. |
| Start with AST/XPath rules | Exposes a public AST contract before gruff has designed one | Rejected until a separate AST custom-rule ADR exists. |
| Start with config-only regex rules and explicit scopes | Regex rules are less precise than AST rules | Accepted; useful, portable, and testable. |

## Reversibility

The exact config shape is reversible before custom rules ship. After users can
write `custom.*` rules, id validation, fingerprint behavior, and match-scope
semantics become compatibility contracts and need migration tests for any
change.
