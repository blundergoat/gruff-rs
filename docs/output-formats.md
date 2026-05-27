# Output Formats

`gruff-rs analyse --format <format>` renders the same analysis data for
different consumers.

## Text

Use `text` for local terminal scans:

```sh
cargo run -- analyse src --format text --fail-on warning
```

## JSON

Use `json` for automation. JSON reports use `gruff.analysis.v1`.

```sh
cargo run -- analyse src --format json --fail-on none > gruff-rs.json
```

When a baseline or diff-patch context is in scope, the report gains an additive `perRuleDeltas[]` array (`{ruleId, introduced, removed, net}`). Full-tree scans omit the key entirely so existing consumers stay byte-identical.

## HTML

Use `html` for archived human review or dashboard scan output.

## Markdown

Use `markdown` for pull request comments and release notes.

## GitHub

Use `github` inside GitHub Actions to emit workflow annotations.

## Hotspot

Use `hotspot` for compact score and offender analysis.

## SARIF

Use `sarif` for GitHub code scanning or other SARIF consumers:

```sh
cargo run -- analyse src --format sarif --fail-on none > gruff-rs.sarif
```

## Summary

`summary` has its own compact text/JSON contract:

```sh
cargo run -- summary src --format json --top 5
```

## Exit Codes

`analyse` exits `1` when at least one finding meets `--fail-on`. Use
`--fail-on none` for report-only jobs.
