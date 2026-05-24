# gruff-rs docs

Use these docs with the top-level README for the stable user-facing surface.

## Core Docs

- [Configuration](configuration.md) - config discovery, selectors, exclusions, and custom rules.
- [Rules](rules.md) - rule IDs, severities, thresholds, and remediation guidance.
- [Output Formats](output-formats.md) - text, JSON, HTML, Markdown, GitHub annotations, hotspot, and SARIF.
- [CI Integration](ci-integration.md) - GitHub Actions, SARIF upload, baselines, and patch diff scans.
- [Dashboard](dashboard.md) - local dashboard flags and safety model.
- [Releasing](releasing.md) - release checks and packaging notes.

## Extra Docs

- [Git Commit Standard](coding-standards/git-commit.md) - local coding standard.

## Shared Contract

Cross-language naming and CLI expectations live in the workspace-level
`CONTRACT.md` (at the gruff workspace root, sibling to this crate). Rust keeps
documented extensions for patch-based diffing, explicit unsafe Git diff opt-in,
and `init --stdout`.
