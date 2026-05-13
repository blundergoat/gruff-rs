---
category: setup
last_reviewed: 2026-05-13
---

## Lesson: Verify Goat-Flow Setup Output Before Assuming Apply Finished

**Created:** 2026-05-13

During initial goat-flow installation, `goat-flow setup . --agent codex --apply` reran deterministic file installation but did not create project-specific docs or `AGENTS.md`. The correct recovery was to inspect `goat-flow setup . --agent codex --format markdown`, read the referenced setup workflow, then create the missing project-specific artifacts.

Future setup work should treat command output as evidence, not intent. If audit still reports missing architecture, code map, glossary, or instruction files, follow the generated setup prompt instead of rerunning the same apply command.
