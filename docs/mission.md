# Mission

gruff governs AI-generated code so a human who didn't write it can read, review, and trust it.

Coding agents routinely produce code that superficially works while misunderstanding the requirement. gruff exists to make that gap visible to a reviewer. Run as a coding-agent hook, it guides — or forces — the agent to produce code a person can actually sign off on.

## What "sign-off-able" means

gruff optimises for three things, each in tension with raw output volume:

- **Verifiable** — legible enough that a reviewer can confirm the code does what was asked. The complexity and size rubrics exist to keep functions holdable-in-head, not to chase abstract "code health".
- **Secure** — hardened where human review is weakest; the security pillar favours the findings a tired reviewer would miss by eye.
- **Genuinely tested** — real tests that exercise the contract, not low-signal bloat or ceremony. The test rubrics measure signal, never volume: rewarding raw test count or coverage only trains an agent to pad.

## Intent (as surfaced to the agent)

> You are a coding agent, and a human who didn't write this code has to read, review, and trust it. This playbook optimises for that — governing AI-generated code so a reviewer can verify it does what was asked.

## Why doc comments are mandatory — even on a private one-liner

> Coding agents routinely produce code that superficially works while misunderstanding the requirement. Forcing the agent to state intent, usage, contract, and failure behaviour in prose gives a reviewer something to check the implementation against — a mismatch between the doc comment and the code is a signal the change needs a deeper look.

The doc comment is not decoration; it is the artefact the reviewer diffs against the implementation. Prose that disagrees with the code is the cheapest available signal that the agent misunderstood the task.

## How this shapes the rules

Because gruff runs as a hook, a finding is not advice a human weighs — it is a **command** the agent acts on. A false positive therefore costs more here than in a human-facing linter: it orders the agent to change code it may have gotten right, often degrading legibility or security in the process. Two consequences follow:

- **Finding correctness outranks breadth of coverage.** A rule that fires on clean code is worse than a rule that occasionally stays quiet.
- **Every rule, threshold, and report is judged against verifiability + security + test-signal** — not generic notions of "good code".

See [`ADR-015`](../.goat-flow/decisions/ADR-015-mission-agent-code-governance.md) for the binding decision and [`.goat-flow/architecture.md`](../.goat-flow/architecture.md) for how the analysis pipeline serves it.
