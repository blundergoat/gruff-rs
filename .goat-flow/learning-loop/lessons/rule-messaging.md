---
category: rule-messaging
last_reviewed: 2026-05-26
---

## Lesson: Rule Messages Must Communicate Intent, Not Just Absence

**Created:** 2026-05-26

**What happened:** Before 0.1.2 M06, `docs.missing-*` rule messages described absence ("Public function `x` is missing a Rust doc comment"). When agents — trained on "no boilerplate" / "don't add comments that restate the type" policies — read those findings, they interpreted them as a request to add boilerplate comments, not as a request to add intent descriptions. Two failure modes followed: the agent either skipped the finding ("the project doesn't want comments, this rule is wrong"), or it added a one-line stub that restated the type signature, which is the comment-as-noise pattern the project's own policy was trying to avoid.

The fix is text-only. The rule's detection logic is correct; the rule's *message* is what miscommunicated. After 0.1.2 M06, messages name the *content* the rule wants ("needs a brief intent description above its signature - one plain-English line, not a restatement of the type") and remediations spell out the no-boilerplate framing explicitly ("This rule wants content, not boilerplate - if your project policy is 'no comments', that policy is about avoiding comments that restate code, not about removing documentation").

**Why:** Rule consumers — both humans and agents — read messages as guidance on what success looks like, not just as alarms. An absence-shaped message ("X is missing") tells you that the gate is unhappy but does not tell you what the gate would accept. A guidance-shaped message ("X needs a brief intent description") tells you what to write. Agents in particular are trained on shorthand cultural conventions ("no comments", "don't restate the type", "minimal diff"); message text that does not preempt those conventions gets misread.

**How to apply:**
- When writing or reviewing a rule message, ask: "Does this tell the reader what to write, not just what's wrong?" If the reader has to infer the success criterion from the rule name alone, the message is too thin.
- When a rule's detection target is "missing content X", the message should name what X looks like at the minimum (one-line description, name mention, error condition, panic trigger, etc.).
- Remediations on noisy or culture-conflicting rules should spell out the framing explicitly ("the rule wants content, not boilerplate"). Trust no inference about "what the rule really means."
- One sentence per message; remediation can be one paragraph. Longer drifts into prose nobody reads.
- Reword as text-only. Do not change detection logic, severity, confidence, or pillar to "fix" a noisy rule - those carry independent semantic weight.

**Concrete example (this repo, 2026-05-26):**
- Before: `Public function \`process\` is missing a Rust doc comment.` + remediation: `Add a /// doc comment explaining the public API contract.`
- After: `Public function \`process\` needs a brief intent description above its signature (one plain-English line, not a restatement of the type signature).` + remediation that names the no-boilerplate framing and what the description should answer.

**Where the pattern lives in code:**
- `src/built_in_rules/docs_rules.rs` (search: `fn analyse_public_function_doc`, `fn analyse_missing_errors_section`, `fn missing_panics_section_finding`, `fn analyse_missing_safety_section`, `fn missing_param_doc_finding`, `fn missing_return_doc_finding`)
- `src/built_in_rules/comment_item_and_blocks.rs` (search: `fn push_missing_public_item_doc`)

Each shares the structure: message names the *content shape* the rule wants; remediation names the *anti-pattern* (boilerplate, stub-comments) the rule does NOT want.

**Where tests assert this pattern:** No tests pin the message text directly. M06's kill criterion was "tests that pin specific text use substring matching" - any test added later should follow that pattern. Greppable contract: `rg -n 'is missing|lacks a' src/built_in_rules/` should find zero hits for absence-shaped rule messages in any future audit (the pattern is the absence of those phrases).
