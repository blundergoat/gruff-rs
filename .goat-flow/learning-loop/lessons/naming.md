---
category: naming
last_reviewed: 2026-11-25
---

## Lesson: Never Name Files or Folders After Milestones (M33, M35, etc.)

**Created:** 2026-05-21 | **Incident count:** 2 | **Latest occurrence:** 2026-11-25
**Decision changed:** Before creating any new file, directory, module, or test function, name it for the domain behaviour it owns — never after a milestone, PR number, release version, review finding ID, or implementation wave.
**Trigger phase:** SCOPE | **Caught at:** VERIFY

**Prevention:**
- Before naming a new file, directory, module, or test function, reject any proposed name containing a temporal or process token: milestones (`M<digits>`), PR numbers (`pr<digits>`, `pr_<digits>`), release versions (`v060_*`, `v0_6_*`), review finding/lead/wave IDs (`r002_*`, `lead1`, `wave2_*`), ticket/sprint IDs (`T<digits>`, `sprint_*`), or dates (`march_refactor`).
- Check existing domain suites first (such as `tests/cli_regressions.rs` or `src/tests/rule_behaviours/false_positive_guards.rs`) and add new regressions there; only create a new file when the target suite would cross its dogfood size limit or represents a distinct domain (such as `tests/analyzer_regressions.rs`).
- Name every test function after the invariant it proves (for example `exclusions_precede_baseline_generation_and_application`), not the review ticket that uncovered the bug.

Do not encode milestone identifiers (`M01`, `M33`, `M37`, etc.) — or any task/ticket/PR/version/review-finding identifier — into source file names, directory names, module names, or test function names. The same prohibition applies to test files, helper files, ADR-referenced code paths, and config keys that touch persistent storage.

**Why:**
- Milestones, PR numbers, release tags, and review finding IDs are temporal. `M33` or `pr7_v060` names a moment in time or a review thread rather than what the code checks. Once the work lands, the identifier is dead context that future readers cannot navigate without searching git history.
- Temporal names don't compose. A file named `m33_regressions.rs` or `pr7_v060_regressions.rs` is the wrong home for the next regression on the same subsystem, forcing future work to either pollute a misleadingly named file or spawn another disposable file for the same concern.
- Renaming later loses git blame continuity for the same reason avoiding `*_new`, `*_v2`, `*_backup` suffixes does (see `CLAUDE.md` Hard Rules). Get the name right when you create the file.

**Concrete example (this repo, 2026-05-21):** During the M41 test split, the regression tests added during M33, M35, M37, and M38 were grouped into milestone-named files. The user flagged this immediately and required a rename. The semantic home is now `src/tests/rule_behaviours/false_positive_guards.rs` and `src/tests/rule_behaviours/idiomatic_handling.rs` — grouped by what the tests *guard against*, not by which milestone introduced them.

**Recurrence 2026-11-25:** After fixing findings from the `v0.6.0` PR #7 review, the agent created a new integration test file named `tests/pr7_v060_regressions.rs` and prefixed its tests and doc comments with ephemeral review IDs (`r002_`, `r006_`, `lead1`, `wave2_`). The user caught the bad filename immediately. The file was deleted and its cases were moved with behaviour-based names into `tests/cli_regressions.rs` (search: `exclusions_precede_baseline_generation_and_application`) and `tests/analyzer_regressions.rs` (search: `deep_assignment_and_let_comments_do_not_overflow_parser`).

**How to apply:**
- Before naming a new file/folder/module, ask: "What does this file contain?" — not "When was it added?" or "Which PR/ticket motivated it?"
- Acceptable names describe the domain: `cli_regressions.rs`, `analyzer_regressions.rs`, `false_positive_guards.rs`, `dead_code_recovery.rs`, `selector_parsing.rs`.
- Unacceptable names encode time/process: `m33_*.rs`, `pr7_v060_regressions.rs`, `pr_142_fixes.rs`, `sprint_3_cleanup.rs`, `march_refactor.rs`, `r002_*`, `wave2_*`.
- The same rule applies inside files: don't put `// M33 added this` or `/// R-006:` markers in code where a `// SAFETY:` or `// Why:` comment explaining the invariant is what the reader actually needs. Git blame already records when something was added.
- Milestone, PR, and review-finding IDs belong in plans, PR descriptions, and review logs — not in the permanent codebase.

## Lesson: Don't Extend Alphabet-Sequel File Series (cases_d.rs, helpers_b.rs)

**Created:** 2026-05-24

When adding a new file to an existing series whose members use opaque sequel suffixes (`cases_a.rs`, `cases_b.rs`, `helpers_b.rs`, etc.), do NOT simply continue the alphabet (`cases_d.rs`). The next file is your chance to name by content; the existing weak names do not justify a new weak name. Continuing the sequel pattern doubles the dead context and signals that you copied the shape without thinking about what the new file actually owns.

**Why:**
- Alphabet sequels are the file-naming equivalent of milestone IDs (see lesson above): they encode arrival order, not domain. A reader who opens `cases_d.rs` has to read the file to learn what it tests.
- Weak sequel names are legacy debt; treating them as a *naming convention* propagates the mistake into every subsequent file. A descriptive new name is a small step toward eventually splitting any legacy files by concept too.
- When a future maintainer adds an 11th rule, they have to pick between `cases_e.rs` (continuing the pattern) and `cases_pillar_expansion.rs` (the new pattern). Establishing the descriptive precedent now ends the ambiguity.

**Concrete example (this repo, 2026-05-24):** While adding calibration cases for 10 new default-on rules (modernisation idioms, rustdoc contracts, security candidate, test-attribute precision), the file was first created as `cases_d.rs` by continuing the existing `cases_a/b/c.rs` alphabet sequence. The user immediately flagged it. Renamed to `cases_pillar_expansion.rs` — describes the *intent* of the file (calibration for the second-wave rules added to fill thin pillars) rather than its position in an arrival queue.

**Update (this repo, 2026-05-31):** The legacy calibration shards were later renamed to `structural_project_cases.rs`, `documentation_error_idiom_cases.rs`, and `security_size_test_waste_cases.rs`; the rule-definition shards were renamed to `structure_docs_reliability_definitions.rs`, `idiom_security_size_test_definitions.rs`, and `waste_definitions.rs`. Keep this lesson active because the failure mode still applies to any future `cases_d.rs`, `definitions_d.rs`, `helpers_b.rs`, or similar next-letter temptation.

**How to apply:**
- Before adding a file to an existing series, ask: "If the existing file names disappeared, would my new file's name still tell a future reader what it contains?" If the answer is no — because the name only makes sense as the next letter in a sequence — pick a descriptive name instead.
- Acceptable names describe the domain the file owns: `cases_pillar_expansion.rs`, `cases_dependency_resolution.rs`, `cases_calibration_baselines.rs`.
- Unacceptable names continue an opaque sequence: `cases_d.rs`, `cases_e.rs`, `helpers_b.rs`, `module_v3.rs`, `utils_extra.rs`.
- The same rule applies inside `src/built_in_rules/` — a new file should match the existing `<concept>_rules.rs` pattern (e.g. `modernisation_rules.rs`) AND should not mix unrelated pillars (e.g. don't park a security rule inside `modernisation_rules.rs` even if it was implemented in the same batch).
- If an existing weak-named series bothers you, the right fix is a dedicated semantic rename — not perpetuating the weak names in new ones.

**Why:** Alphabet sequels propagate dead context into every subsequent file in a series. Each new file is a chance to break the chain; passing on that chance commits the next maintainer to either continuing the weak pattern or having a mixed naming policy.

**How to apply:** Reject any new file name whose only meaning is "the next one in the series" (`*_d.rs`, `*_b.rs`, `*_v2.rs`, `*_extra.rs`). The new file's name should describe what it contains so a fresh reader can navigate without opening it.
