# ADR-015: Mission — Govern Agent-Generated Code for Reviewer Verifiability

**Status:** Accepted
**Date:** 2026-05-30
**Author(s):** Claude, from the mission stated by the user
**Ticket/Context:** The mission drove the rule set but was never written down; the user directed it into the project docs.

## Decision

gruff-rs exists to **govern code written by coding agents so a human who did not write it can read, review, and trust it.** Run as a coding-agent hook, gruff guides — or forces — the agent toward code a person can sign off on along three axes:

1. **Verifiable** — legible enough to review by reading. Complexity and size rubrics keep functions holdable-in-head; they are not a pursuit of abstract "code health".
2. **Secure** — hardened where human review is weakest.
3. **Genuinely tested** — real tests that exercise the contract, not low-signal bloat or ceremony. Test rubrics measure signal, not volume.

Two binding principles follow and constrain all future rule work:

- **Doc comments are a verification anchor and are required even on private one-liners.** Forcing the agent to state intent, usage, contract, and failure behaviour in prose gives the reviewer something to check the implementation against; a doc-comment/code mismatch is the signal that a change needs a deeper look.
- **A finding is a command, not advice.** Because gruff runs as a hook, the agent acts on findings. A false positive therefore orders the agent to change code it may have gotten right. **Finding correctness is weighted above breadth of coverage**, and every rule, threshold, and report is judged against verifiability + security + test-signal first.

## Context

The mission was the implicit driver of the rule set but had never been recorded: `CLAUDE.md`, `AGENTS.md`, `README.md`, the architecture doc, and the glossary described determinism, schema-versioning, and untrusted-source-tree safety, but not *why the project exists*. Absent a stated mission, rule and threshold decisions were argued from generic linter convention rather than the project's actual goal, and future agents could "correct" deliberately strict rubrics toward industry defaults that do not serve reviewer verifiability.

Concrete evidence that the mission must drive tuning (gathered 2026-05-30): `complexity.npath` fired on `validate_script_path` in an external Rust project — a three-guard, zero-loop, fully documented validation function — because the complexity scanners read comment-unmasked source (`src/built_in_rules/blocks.rs`, search: `strip_rust_string_literals(&block.body)`) and counted the word "for" inside the function's mandated comments as `for` loops. NPath exponentiates branch counts, so the miscount crossed threshold where `complexity.cyclomatic` (which only sums) did not. As a hook, that finding would command the agent to rewrite correct, legible, secure code — and to do it by removing or contorting the very doc/comment prose this mission requires. That failure mode is only legible once "a false positive is a command" is explicit.

## Failure Mode Comparison

| Option | What fails | Why rejected or accepted |
| --- | --- | --- |
| Frame gruff as a generic code-quality linter | Rules drift to industry-default "code health" numbers; deliberately strict rubrics get "fixed" toward looseness; the agent-hook cost of false positives stays invisible | Rejected; discards the project's reason to exist and invites regressions. |
| Optimise the test pillar for coverage / test count | An agent optimises whatever is measured and emits low-signal test bloat to satisfy the metric | Rejected; contradicts the "genuinely tested" axis. |
| Maximise the number of findings ("catch everything") | False positives become commands that degrade correct code; reviewer trust erodes | Rejected; finding correctness is weighted above coverage. |
| Govern agent code for verifiability + security + test-signal, findings-as-commands, correctness-first | Some genuinely complex code may occasionally slip a quiet rule | Accepted; this is the project's purpose and the documented basis for every rubric trade-off. |

## Consequences

- The mission is documented as `## Mission` in `CLAUDE.md`, `AGENTS.md`, `README.md`, `.goat-flow/architecture.md`, and as a user-facing `docs/mission.md`.
- Complexity strictness (`complexity.cyclomatic` 10, `complexity.cognitive` 15, `complexity.nesting-depth` 4) is justified by verifiability, not convention, and must not be relaxed toward generic defaults without re-deciding against this ADR.
- Rule and threshold reviews weigh false-positive rate above coverage. New default-on rules must be classified TP/FP against at least one repository outside this tree (`.goat-flow/lessons/verification.md`).
- Known divergences to reconcile against this mission (open as of 2026-05-30):
  - the complexity scanners count control-flow keywords inside comments (`src/built_in_rules/blocks.rs`), inflating `npath` / `cyclomatic` / `cognitive` / `nesting-depth` — and they do so via the doc comments the mission mandates;
  - `complexity.npath`'s only independent signal is flat sequential branching, which is the *easiest* code to verify, making it anti-aligned with the mission and a demote-to-opt-in candidate;
  - the `docs.*` rules fire on `pub` items only (`src/built_in_rules/docs_rules.rs`, search: `is_externally_public`), but the mission requires doc comments even on private one-liners.

## Reversibility

The specific rubric tunings this mission implies are two-way doors, revisited per-rule against the three axes. The mission itself is a foundational charter: reversing it would make gruff a different product. Revisit triggers: gruff stops being used as a coding-agent hook, or evidence shows reviewer verifiability is better served by a different optimisation target.
