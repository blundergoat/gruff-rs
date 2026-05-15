# gruff-rs

Rust project quality analyzer with deterministic, schema-versioned reports.

## Commands

```bash
./bin/gruff-rs analyse fixtures --format json --fail-on none
./bin/gruff-rs analyse src --format text --fail-on none
./bin/gruff-rs list-rules --format text
./bin/gruff-rs list-rules --format json
./bin/gruff-rs report src --format html --output gruff-report.html
bash scripts/start-dev.sh
```

From a source checkout, `bin/gruff-rs` resolves this repository's Cargo manifest
and forwards arguments to the Rust CLI.

Report formats for `analyse` are `text`, `json`, `html`, `markdown`, `github`, and
`hotspot`. The `report` command supports static `html` and `json` output.

`scripts/start-dev.sh` starts the dashboard on `127.0.0.1:8766` by default. The
dashboard has no authentication; bind it to a non-loopback host only for a trusted
local network or another explicitly controlled environment. Override dashboard
settings with `GRUFF_HOST`, `GRUFF_PORT`, and `GRUFF_PROJECT_ROOT`.

## More Docs

- [Rust rubric](docs/rust-rubric.md) describes the v0.1 rule families, limits,
  and deferred checks.
- [Architecture](.goat-flow/architecture.md) describes analysis flow, trust
  boundaries, report contracts, and non-obvious constraints.
- [Code map](.goat-flow/code-map.md) maps source, fixtures, scripts, and local
  goat-flow memory.

## Config

`gruff-rs` reads `.gruff.yaml` by default. It also recognizes `.gruff.yml` and `.gruff.json`, and an explicit path passed with `--config`.
Unknown keys and unknown rule ids are rejected.

```yaml
paths:
  ignore:
    - target/**
    - fixtures/**
    - tests/fixtures/**
allowlists:
  acceptedAbbreviations:
    - id
    - db
    - io
    - ui
    - tx
    - rx
  secretPreviews: []
rules:
  architecture.large-module:
    threshold: 25
  architecture.module-fan-out:
    threshold: 8
  architecture.public-api-surface:
    threshold: 12
  complexity.cognitive:
    threshold: 15
  complexity.cyclomatic:
    thresholds:
      warn: 10
      error: 20
  complexity.nesting-depth:
    thresholds:
      warn: 4
      error: 6
  complexity.npath:
    thresholds:
      warn: 32
      error: 128
  docs.todo-density:
    threshold: 4
  dependency.duplicate-locked-version:
    threshold: 2
  metrics.halstead-volume:
    threshold: 900
  metrics.maintainability-pressure:
    threshold: 45
  size.file-length:
    thresholds:
      warn: 400
      error: 800
  size.function-length:
    thresholds:
      warn: 30
      error: 60
  size.parameter-count:
    threshold: 5
  test-quality.long-test:
    threshold: 30
```

Use `--no-config` to ignore project config.

Cargo dependency checks are local-only. They read `Cargo.toml` and `Cargo.lock`
as data and do not query registries, run Cargo, or consume vulnerability feeds.
Project architecture and dead-code candidate checks are also local-only. They use
the discovered Rust sources and phrase cross-file unused private items as
candidates because the scanner does not run rustc type resolution.
Performance and metric checks use syntactic source patterns and deterministic
token counts, not benchmarks or runtime profiling.

## Interpreting Findings And Exits

Findings have a severity (`advisory`, `warning`, or `error`) and confidence
(`low`, `medium`, or `high`). Candidate wording means the scanner found a
conservative static signal, not type-aware certainty.

`--fail-on none` reports findings without failing for their severity. Diagnostics
always fail analysis with exit code 2 because they mean the analyzer could not
complete part of the requested scan. `--fail-on advisory` fails on any finding,
`--fail-on warning` fails on warnings and errors, and `--fail-on error` fails on
errors only.

The security and sensitive-data rules are local static checks. They do not replace
`cargo audit`, vulnerability feeds, license policy, code review, or runtime tests.
See the [Rust rubric](docs/rust-rubric.md) for deferred type-aware, registry-backed,
framework-specific, and runtime checks.

## Baselines

Generate a baseline from the current findings:

```bash
./bin/gruff-rs analyse src --format json --fail-on none --generate-baseline
```

Apply the default `gruff-baseline.json` when present:

```bash
./bin/gruff-rs analyse src --format json --fail-on none --baseline
```

Baseline suppression is exact on fingerprint, rule id, and file path. Message text,
end line, and column are not baseline identity fields in `v0.1`.

## Report Contract

JSON analysis output uses `schemaVersion: "gruff.analysis.v1"`. The top-level
contract includes `schemaVersion`, `tool`, `run`, `paths`, `summary`, `score`,
`findings`, `diagnostics`, and `baseline`. Finding objects include stable
integration fields such as `ruleId`, `severity`, `confidence`, `pillar`,
`filePath`, `line`, `column`, `endLine`, `symbol`, `message`, `remediation`,
`fingerprint`, `tier`, `secondaryPillars`, and `metadata`.

Rule ids and fingerprints are compatibility-sensitive because baselines and
downstream consumers may key on them. Changing a rule id, fingerprint inputs, or
`schemaVersion` is a compatibility decision.

## Local Checks

```bash
bash scripts/check.sh
./bin/gruff-rs analyse fixtures --format json --fail-on none
./bin/gruff-rs analyse src --format json --fail-on none
./bin/gruff-rs list-rules --format json
```

`scripts/check.sh` runs formatting, Clippy, unit tests, rule listing, fixture scan,
and self-scan diagnostics smoke checks. Self-scan findings are visible under
`--fail-on none`; diagnostics are treated as gate failures.

## Fixtures

`fixtures/` and `tests/fixtures/` intentionally contain code and config snippets that
look noisy. They prove analyzer behavior and should not be cleaned up unless the
replacement preserves the rule coverage.

## Troubleshooting

- Parse diagnostics: run `./bin/gruff-rs analyse <path> --format json --fail-on none` and inspect `diagnostics`; Rust AST rules are skipped for parse-failed files while text rules still run.
- Config errors: check unknown root keys, unknown rule ids, unsupported threshold names, and invalid value shapes in `.gruff.yaml`.
- Baselines: regenerate only after confirming the current findings are intentionally accepted.
- Intentional fixture findings: use `fixtures/README.md` and `tests/fixtures/README.md` to confirm whether a noisy file is a test input.
