# gruff-rs docs

Use these docs with the top-level README for the stable user-facing surface.

## Core Docs

- [Mission](mission.md) - what gruff governs and why: agent-code governance for reviewer verifiability, security, and genuine tests.
- [Configuration](configuration.md) - config discovery, selectors, exclusions, and custom rules.
- [Rules](rules.md) - rule IDs, severities, thresholds, and remediation guidance.
- [Output Formats](output-formats.md) - text, JSON, HTML, Markdown, GitHub annotations, hotspot, and SARIF.
- [CI Integration](ci-integration.md) - GitHub Actions, SARIF upload, baselines, and patch diff scans.
- [Dashboard](dashboard.md) - local dashboard flags and safety model.

## Extra Docs

- [Git Commit Standard](https://github.com/blundergoat/gruff-rs/blob/main/docs/coding-standards/git-commit-message.md) - maintainer-only: local coding standard. `Cargo.toml` excludes `docs/coding-standards/` from the published crate, so this one is linked absolutely.

## Shared Contract

Cross-language naming and CLI expectations live in the workspace-level
`FAMILY-CONTRACT.md` (at the gruff workspace root, sibling to this crate). That file is workspace-internal and ships in no published crate; the behaviour it governs is documented here and in the top-level README. Rust keeps
documented extensions for patch-based diffing, explicit unsafe Git diff opt-in,
and `init --stdout`.
