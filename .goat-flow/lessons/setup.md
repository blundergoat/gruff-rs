---
category: setup
last_reviewed: 2026-06-06
---

## Lesson: Verify Goat-Flow Setup Output Before Assuming Apply Finished

**Created:** 2026-05-13

During initial goat-flow installation, `goat-flow setup . --agent codex --apply` reran deterministic file installation but did not create project-specific docs or `AGENTS.md`. The correct recovery was to inspect `goat-flow setup . --agent codex --format markdown`, read the referenced setup workflow, then create the missing project-specific artifacts.

Future setup work should treat command output as evidence, not intent. If audit still reports missing architecture, code map, glossary, or instruction files, follow the generated setup prompt instead of rerunning the same apply command.

## Lesson: Multi-Agent Repos Need `install` Per Agent; `drift` Is Repo-Wide

**Created:** 2026-06-06

Upgrading goat-flow 1.7.0 to 1.9.1 with `install . --agent claude` refreshed only the Claude surface (`.claude/skills/`, `.claude/hooks/`, `.claude/settings.json`). This repo also carries a Codex surface (`AGENTS.md`, `.codex/`, `.agents/skills/`), and the audit `drift` check is repo-wide: it compares every installed agent copy against the goat-flow skill templates bundled in the installer. So both `audit . --agent claude` and the `--harness` variant kept failing on `drift` (19 stale `.agents/skills/` files plus `.codex/hooks/deny-dangerous.sh`) even though the Claude surface was already clean. The fix was a second pass, `install . --agent codex`, which refreshed `.agents/skills/` and `.codex/hooks/` and migrated `.codex/config.toml` to the expanded secret-path deny table. Installer passes leave the instruction file (`CLAUDE.md` / `AGENTS.md`) untouched, so version headers are bumped by hand.

**How to apply:** In a multi-agent repo, run `install` once per configured agent before expecting `drift` to clear; one `--agent` pass is not enough. Confirm which surfaces exist before declaring an upgrade done, and treat any change under `.agents/`, `.codex/`, or `AGENTS.md` as a peer-agent boundary that needs explicit user direction first.

## Lesson: `config.yaml` Hook Toggles Are Declarative, Not Runtime Switches

**Created:** 2026-06-06

The 1.9.x installer adds a `hooks:` block to `.goat-flow/config.yaml` (for example `gruff-code-quality` set to `enabled: false`). That toggle is NOT read by the hook scripts at runtime: `.claude/hooks/gruff-code-quality.sh` runs because it is wired in `.claude/settings.json` PostToolUse and gates on file extension plus a matching `.gruff-rs.yaml` and a gruff binary, never on the config toggle (a grep across `.claude/hooks/` and `.goat-flow/hook-lib/` for the toggle keys returns nothing). The installer defaults `gruff-code-quality` to disabled even when the hook is live-wired. Set it to `enabled: true` so the declarative state matches reality and a future `install` cannot use the toggle to un-wire the hook. Do not read `enabled: false` as proof the hook is off; check the `settings.json` wiring.
