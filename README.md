# gruff-rs

Rust project quality analyzer with deterministic, schema-versioned reports.

## Commands

```bash
cargo run -- analyse fixtures --format json --fail-on none
cargo run -- analyse src --format text --fail-on none
cargo run -- list-rules --format text
cargo run -- list-rules --format json
cargo run -- report src --format html --output gruff-report.html
```

Report formats for `analyse` are `text`, `json`, `html`, `markdown`, `github`, and
`hotspot`. The `report` command supports static `html` and `json` output.

## Config

`gruff-rs` reads `.gruff.yaml` by default. It also recognizes `.gruff.yml` and `.gruff.json`, and an explicit path passed with `--config`.
Unknown keys and unknown rule ids are rejected.

```yaml
paths:
  ignore:
    - target/**
allowlists:
  acceptedAbbreviations:
    - id
    - db
  secretPreviews: []
rules:
  size.parameter-count:
    enabled: true
    threshold: 5
  complexity.cyclomatic:
    thresholds:
      warn: 10
      error: 20
```

Use `--no-config` to ignore project config.

## Baselines

Generate a baseline from the current findings:

```bash
cargo run -- analyse src --format json --fail-on none --generate-baseline
```

Apply the default `gruff-baseline.json` when present:

```bash
cargo run -- analyse src --format json --fail-on none --baseline
```

Baseline suppression is exact on fingerprint, rule id, and file path. Message text,
end line, and column are not baseline identity fields in `v0.1`.

## Local Checks

```bash
bash scripts/check.sh
cargo run -- analyse fixtures --format json --fail-on none
cargo run -- analyse src --format json --fail-on none
cargo run -- list-rules --format json
```

`scripts/check.sh` runs formatting, Clippy, unit tests, rule listing, fixture scan,
and self-scan diagnostics smoke checks.

## Fixtures

`fixtures/` and `tests/fixtures/` intentionally contain code and config snippets that
look noisy. They prove analyzer behavior and should not be cleaned up unless the
replacement preserves the rule coverage.

## Troubleshooting

- Parse diagnostics: run `cargo run -- analyse <path> --format json --fail-on none` and inspect `diagnostics`; Rust AST rules are skipped for parse-failed files while text rules still run.
- Config errors: check unknown root keys, unknown rule ids, unsupported threshold names, and invalid value shapes in `.gruff.yaml`.
- Baselines: regenerate only after confirming the current findings are intentionally accepted.
- Intentional fixture findings: use `fixtures/README.md` and `tests/fixtures/README.md` to confirm whether a noisy file is a test input.
