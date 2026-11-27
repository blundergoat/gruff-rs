# Output Formats

`gruff-rs analyse --format <format>` renders the same analysis data for
different consumers.

## Text

Use `text` for local terminal scans:

```sh
./.cargo-tools/bin/gruff-rs analyse src --format text --fail-on warning
```

## JSON

Use `json` for automation. Analysis reports use `gruff.analysis.v3`.

```sh
./.cargo-tools/bin/gruff-rs analyse src --format json --fail-on none > gruff-rs.json
```

The v3 envelope emits project-relative slash paths and one canonical `file` key.
Optional `column`, `endLine`, and `symbol` keys are omitted when absent. A
scanner-pinpointed column is paired with
`metadata.locationPrecision: "scanner-pinpointed"`; line-only findings declare
`"line-only"` and omit `column`. Rust-only finding scope lives at
`extensions.rs.finding.scope`.

When a baseline or diff context supplies per-rule comparison data, the report
publishes `extensions.rs.topLevel.perRuleDeltas` entries shaped as
`{ruleId, introduced, removed, net}`. Full-tree scans omit that extension.

### Migrating v2 JSON consumers

Version 3 is a hard break with no v2 writer or compatibility flag:

- Accept `gruff.analysis.v3` and `gruff.summary.v3`; `run.generatedAt` is removed
  so repeated equivalent reports remain deterministic.
- Read `findings[].file` and `score.topOffenders[].file`; the deprecated
  `filePath` aliases are removed.
- Read ignore evidence from `paths.details` beside `paths.ignoredPaths`; the
  former `paths.ignoredPathDetails` name is removed.
- Read changed-region suppression counts from `summary.suppressedFindings`; the
  top-level `suppressedCount` alias is removed.
- Read Rust comparison data from `extensions.rs.topLevel.perRuleDeltas`; the
  former top-level extension is removed.
- Treat absent optional locations and symbols as omitted keys, not `null`.
- Read the composite as `score.composite.{score,grade}` and offender rows from
  `score.topOffenders`; the v2 flat composite and independent summary `pillars`,
  `topRules`, and `topFiles` shapes are retired.

## HTML

Use `html` for archived human review or dashboard scan output.

## Markdown

Use `markdown` for pull request comments and release notes.

Finding rule IDs and file paths use delimiter-safe code spans. Finding messages
escape Markdown and HTML structure, with carriage returns and newlines shown as
literal `\r` and `\n` text so source-controlled values cannot add report blocks.
This encoding is Markdown-specific; `github` remains a separate workflow-command
protocol.

## GitHub

Use `github` inside GitHub Actions to emit workflow annotations.

## Hotspot

Use `hotspot` for compact score and offender analysis.

## SARIF

Use `sarif` for GitHub code scanning or other SARIF consumers:

```sh
./.cargo-tools/bin/gruff-rs analyse src --format sarif --fail-on none > gruff-rs.sarif
```

## Summary

`summary` text remains the compact human view. `summary --format json` emits the
exact findings-free projection of analysis JSON for the same inputs: it changes
`schemaVersion` to `gruff.summary.v3` and removes only the top-level `findings`
array. Because JSON projection is fixed, `--top` affects text output only.

```sh
./.cargo-tools/bin/gruff-rs summary src --format json --top 5
```

## Exit Codes

`analyse` exits `1` when at least one finding meets `--fail-on`. Use
`--fail-on none` for report-only jobs.
