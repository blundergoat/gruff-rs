---
category: naming
last_reviewed: 2026-05-21
---

## Lesson: Never Name Files or Folders After Milestones (M33, M35, etc.)

**Created:** 2026-05-21

Do not encode milestone identifiers (`M01`, `M33`, `M37`, etc.) — or any task/ticket/PR/sprint identifier — into source file names, directory names, or module names. The same prohibition applies to test files, helper files, ADR-referenced code paths, and config keys that touch persistent storage.

**Why:**
- Milestones are temporal. `M33` means "the thirty-third milestone in version 0.1's plan" — a moment in time. Once the work lands, the milestone identifier is dead context: future readers must look up what `M33` was before they understand the file's purpose.
- Milestones don't compose. A file named `m33_regressions.rs` is the wrong home for the next M40 regression on the same false-positive class. You then either pollute the file (the M33 prefix lies) or create `m40_regressions.rs` (now you have two files for the same concern).
- Renaming later loses git blame continuity for the same reason avoiding `*_new`, `*_v2`, `*_backup` suffixes does (see `CLAUDE.md` Hard Rules). Get the name right when you create the file.

**Concrete example (this repo, 2026-05-21):** During the M41 test split, the regression tests added during M33, M35, M37, and M38 were grouped into `src/tests/m33_regressions.rs` and `src/tests/m35_m37_m38_regressions.rs`. The user flagged this immediately and required a rename. The semantic rename was `src/tests/{false_positive_guards,idiom_and_option_regressions}.rs` — grouped by what the tests *guard against*, not by which milestone introduced them.

**How to apply:**
- Before naming a new file/folder/module, ask: "What does this file contain?" — not "When was it added?" or "Which ticket motivated it?"
- Acceptable names describe the domain: `false_positive_guards.rs`, `dead_code_recovery.rs`, `selector_parsing.rs`.
- Unacceptable names encode time/process: `m33_*.rs`, `pr_142_fixes.rs`, `sprint_3_cleanup.rs`, `march_refactor.rs`.
- The same rule applies inside files: don't put `// M33 added this` markers in code where a `// SAFETY:` or `// Why:` comment is what the reader actually needs. Git blame already records when something was added.
- Milestone IDs belong in the milestone file (`.goat-flow/tasks/<version>/M33-*.md`) and in PR descriptions — not in the codebase itself.
- Test *function* names can keep a `m33_` prefix when they prove a specific regression scenario tied to a documented incident (and the regression scenario itself is what matters, not the milestone). The file containing them should still be named for the *class of behavior under test*.

**Why:** Encoding sequence identifiers in code paths creates dead context that future readers must decode before they can act, and traps new work into either misnamed homes or fragmented files.

**How to apply:** Reject any proposed file/folder/module name that contains a task-ID-shaped token (`M<digits>`, `T<digits>`, `PR<digits>`, `sprint_*`, `<month>_refactor`, `phase_<n>`, etc.). Ask what behavior or concept the file owns and use that.
