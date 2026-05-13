# Code Map

## Repository Root

`Cargo.toml` = Rust package metadata and dependencies for the `gruff-rs` binary.
`Cargo.lock` = Locked dependency graph; update through Cargo, not by hand.
`README.md` = Project overview, CLI examples, and config shape.
`AGENTS.md` = Codex/goat-flow operating instructions.
`.gitignore` = Ignores Cargo output plus analyzer baseline/history side files.
`.gruff.yaml` = Project-level analyzer config; default config file discovered by `gruff-rs`.

## Source

`src/` = Rust source directory.
`src/main.rs` = CLI orchestration, analyzer pipeline, config loading, renderers, dashboard server, path helpers, built-in rule dispatch module, and unit tests.
`src/rules.rs` = Rule metadata contracts and the sorted built-in rule registry used by config validation and `list-rules`.

## Fixtures

`fixtures/` = Sample input files for analyzer smoke tests and manual scans.
`fixtures/README.md` = Notes that analyzer fixtures are intentionally noisy inputs.
`fixtures/sample.rs` = Intentionally noisy Rust sample containing secret-like strings, command execution, long parameters, and a weak test.
`fixtures/rubric.rs` = Expanded rubric smoke fixture for complexity, naming, size, documentation, and design findings.
`tests/` = Rust test support files and parser fixtures used by unit tests.
`tests/fixtures/README.md` = Fixture grouping notes for parser, rule, and temp-project scanner tests.
`tests/fixtures/parser/` = Parser-focused Rust inputs covering raw strings, macros/impl methods, test attributes, and invalid Rust.
`tests/fixtures/rules/` = Focused positive/negative rule fixtures for selected v0.1 rubric checks.

## Scripts

`scripts/` = Project shell entrypoints.
`scripts/check.sh` = Formatting, Clippy, and unit-test gate.
`scripts/start-dev.sh` = Starts the local dashboard with `GRUFF_HOST`, `GRUFF_PORT`, and `GRUFF_PROJECT_ROOT` overrides.

## Documentation And Harness

`docs/` = Project documentation added outside the hot-path instruction file.
`docs/rust-rubric.md` = Standalone v0.1 Rust rule matrix and deferred-rule notes.
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
