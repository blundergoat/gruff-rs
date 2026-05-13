# gruff-rs - goat-flow 1.6.4

Rust CLI quality analyzer for Rust and text projects. Primary invariant: reports must stay deterministic, schema-versioned, and safe to run against untrusted source trees in this target repository.

## Truth Order

1. User's explicit instruction for the current session.
2. This `CLAUDE.md` file.
3. `.goat-flow/architecture.md`, `.goat-flow/code-map.md`, and `.goat-flow/glossary.md`.
4. Loaded goat-flow skills and local project files.

## Workspace Boundary

Treat this repository root as the selected target workspace. Parent workspaces, npm package internals, and other agent surfaces (`AGENTS.md`, `.agents/`, `.codex/`) are context only unless the user explicitly widens scope.

## Autonomy Tiers

**Always:** Read relevant files before edits, keep changes scoped, use `Edit`/`Write` for in-place file changes, run the smallest real verification command that covers the change, and update `.goat-flow/` memory when verification changes the approach.

**Ask First:** Before changing report schemas, rule IDs, fingerprints, baseline/history behavior, dashboard cwd handling, `fixtures/`, `.codex/`, `.agents/skills/`, `.goat-flow/config.yaml`, hooks, `AGENTS.md`, or 3+ docs/scripts, state the boundary, files read, matching footgun/lesson checked, local instruction checked, and rollback command.

**Never:** Do not edit secrets, push, commit, run destructive git commands, overwrite existing instruction content, delete fixtures as "bad code", or modify peer agent files (`AGENTS.md`, `.codex/`, `.agents/`) without explicit user direction.

## Hard Rules

- If a file exists, modify it in place; no `_new`, `_modified`, `_backup`, or `_v2` variants.
- Severity order: SECURITY > CORRECTNESS > INTEGRATION > PERFORMANCE > STYLE.
- Keep cross-file concepts consistent across `src/main.rs`, fixtures, docs, and CLI output examples.
- Preserve evidence with semantic anchors, not brittle line numbers.
- Do not add features, abstractions, or error handling beyond the request.
- Sub-agents get one objective, a structured return, and a 5-call budget.
- Ambiguous requirements: present interpretations before writing.

## Key Resources

- Learning loop: grep `.goat-flow/footguns/`, `.goat-flow/lessons/`, `.goat-flow/patterns/`, and `.goat-flow/decisions/` before changes.
- Tool playbooks: read `.goat-flow/skill-playbooks/browser-use.md`, `.goat-flow/skill-playbooks/page-capture.md`, or `.goat-flow/skill-playbooks/skill-quality-testing.md` before declaring those tools unavailable.
- Skill reference (meta): `.goat-flow/skill-reference/skill-preamble.md` and `.goat-flow/skill-reference/skill-conventions.md`.
- Orientation: use `.goat-flow/code-map.md` and `.goat-flow/glossary.md` before broad repo edits.

## Essential Commands

```bash
bash scripts/check.sh
cargo build
cargo run -- analyse fixtures --format json --fail-on none
shellcheck scripts/check.sh scripts/start-dev.sh .claude/hooks/deny-dangerous.sh .claude/hooks/deny-dangerous.self-test.sh
```

Use `bash scripts/start-dev.sh` only when the dashboard needs manual browser testing.

## Execution Loop: READ -> SCOPE -> ACT -> VERIFY

When a goat-* skill is active, the skill's Step 0 replaces READ and selects the skill's mode/depth. SCOPE still applies before writes: a skill may write when its selected mode permits writes or the user explicitly approves them. `/goat-plan` File-Write may create gitignored milestone files without a separate approval gate; `/goat-debug` D3 still requires approval before fixes. Resume at ACT after Step 0 output or when a blocking gate releases.

### READ

MUST read relevant files before changes. Never fabricate codebase facts. Check browser evidence first for URL, local HTML, localhost, screenshot, rendered UI, or browser-visible behaviour. Use grep-first retrieval across learning-loop dirs; include decisions for architecture, policy, or setup work. Before declaring any tool or capability unavailable, read the matching playbook in `.goat-flow/skill-playbooks/` (e.g. `browser-use.md`, `page-capture.md`) and run that doc's "Availability Check" section verbatim - project-local CLI tools at `~/.local/bin/` are valid; do not conflate "no harness/MCP tool" with "no tool".

### SCOPE

Declare intent, complexity tier, mode, files allowed to change, non-goals, and blast radius. Expanding beyond scope means stop and re-scope.

### ACT

Declare `State: [MODE] | Goal: [one line] | Exit: [condition]`. Mode must be Plan, Implement, Explain, Debug, or Review.

### VERIFY

Run required checks for changed files. Check cross-references after renames. Tick milestone checkboxes immediately. Do not claim checks passed without the literal pass/fail line from this session. Stop the line when tests break, builds fail, or behaviour regresses. If VERIFY caught a failure or corrected course, update the learning loop before DoD.

## Definition of Done

Confirm all gates: relevant checks pass, no broken cross-references, no unapproved boundary changes, learning-loop notes updated if tripped, working notes current when useful, and old paths/patterns grepped after renames.

## Artifact Routing

Route "add a footgun" to `.goat-flow/footguns/`, "add a lesson" to `.goat-flow/lessons/`, "add a decision" to `.goat-flow/decisions/`, and "add a pattern" to `.goat-flow/patterns/`. Read the target directory's `README.md` before editing.

## Router Table

| Resource | Path |
| --- | --- |
| Instruction file | `CLAUDE.md` |
| Source | `src/` |
| Fixtures | `fixtures/` |
| Scripts | `scripts/` |
| Rust manifest | `Cargo.toml`, `Cargo.lock` |
| Tool playbooks (CLI/MCP availability checks: browser-use, page-capture, skill-quality-testing) | `.goat-flow/skill-playbooks/` - read BEFORE declaring a tool unavailable |
| Skill reference (meta) | `.goat-flow/skill-reference/` |
| Learning loop | `.goat-flow/footguns/`, `.goat-flow/lessons/`, `.goat-flow/patterns/`, `.goat-flow/decisions/` |
| Orientation | `.goat-flow/code-map.md`, `.goat-flow/glossary.md` |
| Architecture | `.goat-flow/architecture.md` |
| Claude skills/config | `.claude/skills/`, `.claude/settings.json`, `.claude/hooks/` |
| Peer instruction files | `AGENTS.md` (Codex) |
| Commit guidance | `docs/coding-standards/git-commit.md` |
| Workspace notes | `.goat-flow/tasks/`, `.goat-flow/logs/sessions/` |
