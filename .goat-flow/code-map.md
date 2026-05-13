# Code Map

## Repository Root

`Cargo.toml` = Rust package metadata and dependencies for the `gruff-rs` binary.
`Cargo.lock` = Locked dependency graph; update through Cargo, not by hand.
`README.md` = Minimal project title.
`AGENTS.md` = Codex/goat-flow operating instructions.
`.gitignore` = Ignores Cargo output plus analyzer baseline/history side files.

## Source

`src/` = Rust source directory.
`src/main.rs` = Entire CLI, analyzer pipeline, renderers, dashboard server, path helpers, and unit tests.

## Fixtures

`fixtures/` = Sample input files for analyzer smoke tests and manual scans.
`fixtures/sample.rs` = Intentionally noisy Rust sample containing secret-like strings, command execution, long parameters, and a weak test.

## Scripts

`scripts/` = Project shell entrypoints.
`scripts/check.sh` = Formatting, Clippy, and unit-test gate.
`scripts/start-dev.sh` = Starts the local dashboard with `GRUFF_HOST`, `GRUFF_PORT`, and `GRUFF_PROJECT_ROOT` overrides.

## Documentation And Harness

`docs/` = Project documentation added outside the hot-path instruction file.
`docs/coding-standards/` = Local engineering policy docs.
`docs/coding-standards/git-commit.md` = Commit-message guidance used by goat-flow harness checks.
`.goat-flow/` = Goat-flow setup, project memory, and local continuity structure.
`.goat-flow/architecture.md` = Current system architecture and trust boundaries.
`.goat-flow/code-map.md` = This repository map.
`.goat-flow/glossary.md` = Project-specific terms.
`.goat-flow/footguns/` = Durable codebase traps with evidence.
`.goat-flow/lessons/` = Durable agent-behavior lessons.
`.goat-flow/patterns/` = Reusable successful approaches.
`.goat-flow/decisions/` = Architecture decision records.
`.goat-flow/skill-reference/` = Shared goat-flow skill conventions.
`.goat-flow/skill-playbooks/` = Tool availability and usage playbooks.
`.goat-flow/tasks/` = Local milestone/task tracking path; contents are mostly local state.
`.goat-flow/logs/` = Local session, quality, critique, and security log paths.

## Codex Harness

`.agents/skills/` = Installed goat-flow skills shared by Codex/Gemini style agents.
`.codex/config.toml` = Codex feature and filesystem permission template for this project.
`.codex/hooks.json` = Codex hook registration for command safety.
`.codex/hooks/` = Installed deny hook and self-test script.

## Generated Or Local-Only

`target/` = Cargo build output; never edit or commit.
`.idea/` = IDE project metadata from this checkout.
`.git/` = Git repository metadata; never edit directly.
