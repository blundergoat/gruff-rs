# gruff-rs

[![Crates.io](https://img.shields.io/crates/v/gruff-rs.svg)](https://crates.io/crates/gruff-rs)
[![Docs.rs](https://img.shields.io/docsrs/gruff-rs)](https://docs.rs/gruff-rs)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

`gruff-rs` is an opinionated quality analyzer for Rust projects. It scans Rust source, Cargo metadata, and common project files, then emits deterministic reports for terminals, CI annotations, SARIF consumers, static HTML, and a local dashboard. It is heuristic static analysis; run it beside Clippy, `cargo audit`, rustfmt, tests, and code review, not instead of them.

## Status At A Glance

| Field | Value |
| --- | --- |
| Release line | Published `0.1.0` package line |
| Runtime | Prebuilt binary, or Rust `1.82+` when building from source |
| Package | `gruff-rs` on crates.io |
| Binary | `gruff-rs` |
| Rule catalogue | 69 rules across 11 pillars |
| Primary config | `.gruff-rs.yaml` |
| Analysis schema | `gruff.analysis.v1` |
| Baseline schema | `gruff.baseline.v1` |
| Severity gate | `--fail-on` with `none`, `advisory`, `warning`, `error` |
| Dashboard | `127.0.0.1:8766` by default |

Rule IDs, fingerprints, baseline identity, JSON schema version, and SARIF behavior are compatibility-sensitive inside the `0.1.x` line.

## Requirements

- No Rust toolchain is needed when using a prebuilt binary through `cargo-binstall`.
- Rust `1.82+` is required when building from source with Cargo.
- Git is not used by default; Git-backed diff mode requires explicit `--diff-git-unsafe`.

## Install

Install into a repository-local tool directory:

```bash
cargo install gruff-rs --locked --version 0.1.0 --root ./.cargo-tools
./.cargo-tools/bin/gruff-rs init
./.cargo-tools/bin/gruff-rs summary .
```

Prebuilt binary, also into a repository-local tool directory:

```bash
cargo binstall gruff-rs --root ./.cargo-tools
./.cargo-tools/bin/gruff-rs init
./.cargo-tools/bin/gruff-rs summary .
```

From a source checkout:

```bash
cargo install --path . --locked --root ./.cargo-tools
./.cargo-tools/bin/gruff-rs --help
```

## Quick Start

```bash
# Create a starter config.
./.cargo-tools/bin/gruff-rs init

# Review the current finding mix.
./.cargo-tools/bin/gruff-rs summary .

# Explore without failing because of findings.
./.cargo-tools/bin/gruff-rs analyse . --fail-on none

# Gate on warning and error findings.
./.cargo-tools/bin/gruff-rs analyse . --fail-on warning

# Emit SARIF for code scanning.
./.cargo-tools/bin/gruff-rs analyse . --format sarif --fail-on none > gruff-rs.sarif

# Generate a fresh-start baseline.
./.cargo-tools/bin/gruff-rs analyse . --generate-baseline --fail-on none
```

## Commands

| Command | Purpose |
| --- | --- |
| `analyse [paths...]` | Run the analyzer and print findings. |
| `summary [paths...]` | Print compact score, pillar, rule, and file summaries. |
| `report [paths...]` | Render an HTML or JSON report to stdout or `--output`. |
| `init` | Generate a starter `.gruff-rs.yaml`. |
| `list-rules` | Print rule metadata as text or JSON, optionally filtered by selector. |
| `dashboard` | Serve the local browser dashboard. |
| `completion [shell]` | Print a shell completion script. |

## Output Formats

`analyse --format <fmt>` accepts:

| Format | Use it for |
| --- | --- |
| `text` | Human terminal output. |
| `json` | Full `gruff.analysis.v1` report. |
| `sarif` | SARIF 2.1.0 for code scanning. |
| `html` | Self-contained inspection report. |
| `markdown` | Pull-request or issue comment summary. |
| `github` | GitHub Actions workflow annotations. |
| `hotspot` | `gruff.hotspot.v1` file-offender JSON. |

`report --format <fmt>` accepts `html` and `json`.

## Exit Codes

| Code | Meaning |
| --- | --- |
| `0` | Run completed and no finding met `--fail-on`. |
| `1` | At least one finding met `--fail-on`. |
| `2` | Fatal diagnostic such as config failure, missing path, parse error, baseline error, diff failure, or invalid input. |

`analyse` defaults to `--fail-on error`.

## CI Usage

Generic CI command:

```bash
./.cargo-tools/bin/gruff-rs analyse . --format github --fail-on warning --no-baseline
```

The repo ships a composite GitHub Action:

```yaml
jobs:
  gruff:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: blundergoat/gruff-rs@v0.1.0
        with:
          args: analyse . --format sarif --fail-on warning --no-baseline
```

The action installs the matching binary via `cargo-binstall` and runs `gruff-rs` with the supplied args. Pin to a tag for reproducibility. See [`action.yml`](action.yml) for inputs.

## Configuration

`gruff-rs` reads `.gruff-rs.yaml` by default. Use `--config <path>` to pass another YAML file, or `--no-config` to ignore project config. Unknown keys, unknown rule IDs, unknown selectors, and invalid threshold shapes fail closed.

```yaml
paths:
  ignore:
    - target/**
    - fixtures/**

allowlists:
  acceptedAbbreviations: [id, db, io, ui]
  secretPreviews: []

rules:
  select: []
  ignore: []
  complexity.cognitive:
    threshold: 15
    severity: warning
  security.process-command:
    severity: error

exclude:
  - rule: security.process-command
    paths: ["tests/**"]
    message_contains: "Command::new"
    reason: "test-only synthetic command"
```

Selectors can target exact rule IDs, dotted prefixes such as `security.*`, or public pillars such as `Security`.

## Rules And Pillars

The v0.1 catalogue contains 69 rules:

| Pillar | Rules |
| --- | ---: |
| `complexity` | 6 |
| `dead-code` | 2 |
| `design` | 4 |
| `documentation` | 7 |
| `modernisation` | 1 |
| `naming` | 5 |
| `security` | 13 |
| `sensitive-data` | 8 |
| `size` | 3 |
| `test-quality` | 8 |
| `waste` | 12 |

Use `./.cargo-tools/bin/gruff-rs list-rules --format json` for the exact rule metadata. See [Rules](docs/rules.md) for rule families, limits, and deferred checks.

## Custom Rules

Top-level `custom_rules` entries register config-only regex rules under the reserved `custom.<slug>` namespace. They can be selected with exact IDs, `custom.*`, or their public pillar, and they use the normal fingerprint formula.

```yaml
custom_rules:
  - id: custom.no-hack-comment
    pillar: Documentation
    severity: warning
    message: HACK comment marker
    scope: comments
    pattern: '(?m)^[ \t]*//[ \t]*HACK\b'
```

Custom rules are intentionally regex-only in `0.1.x`; AST patterns, plugins, scripts, external runtimes, and Semgrep-style metavariables are out of scope.

## Baselines And Changed-Code Scans

Baselines suppress reviewed findings by exact fingerprint, rule ID, and file path:

```bash
./.cargo-tools/bin/gruff-rs analyse src --generate-baseline --fail-on none
./.cargo-tools/bin/gruff-rs analyse src --baseline --fail-on warning
./.cargo-tools/bin/gruff-rs analyse src --no-baseline --fail-on none
```

Patch diff filtering treats a unified diff as data and does not execute Git:

```bash
git diff --no-ext-diff > /tmp/gruff.patch
./.cargo-tools/bin/gruff-rs analyse . --diff-patch /tmp/gruff.patch --format json --fail-on none
```

Pass `--diff-patch -` to read a patch from stdin. The older Git-backed `--diff <mode>` path is available only with `--diff-git-unsafe`.

## Dashboard

```bash
./.cargo-tools/bin/gruff-rs dashboard --host 127.0.0.1 --port 8766 --project-root .
```

The dashboard renders HTML reports on demand. It has no authentication and must not be exposed to untrusted networks; keep the default loopback bind unless the environment is trusted.

In polyglot repositories, `gruff-rs` defaults to port `8766` while `gruff-go`, `gruff-php`, and `gruff-py` default to `8765`; use `--port` when running multiple dashboards at the same time.

## Trust Boundary

Default scans are source-only and local-only. `gruff-rs` does not execute target code, run Cargo build scripts, call Git unless an unsafe Git diff mode is explicitly requested, query registries, read vulnerability feeds, or run benchmarks. Dependency checks read `Cargo.toml` and `Cargo.lock` as data. Candidate wording means the analyzer found a deterministic static signal, not type-aware or runtime certainty.

## Stability Contract

`0.1.x` is the "mostly stable, with caveats" line. Rule IDs, finding fingerprints, baseline identity, JSON schema version `gruff.analysis.v1`, SARIF rendering, and CLI exit semantics are compatibility-sensitive. Breaking changes to those surfaces ship as `0.2.0`, not inside `0.1.x`. See [UPGRADING.md](UPGRADING.md) for the full contract.

## How It Compares

| Tool | Relationship |
| --- | --- |
| Clippy | Canonical Rust lint pass. `gruff-rs` adds deterministic reports, baselines, scoring, project-level rules, and SARIF. Run both. |
| `cargo audit` / `cargo deny` | Vulnerability and dependency policy tools. `gruff-rs` does not query advisory feeds. |
| rustfmt | Formatting only. `gruff-rs` does not format code. |
| rust-analyzer | IDE language server. `gruff-rs` is a CI/CLI gate with stable fingerprints and reports. |
| Tests and review | Still required; gruff findings are static review prompts, not runtime proof. |

## Development

```bash
bash scripts/preflight-checks.sh
cargo test
cargo clippy --all-targets -- -D warnings
cargo run -- analyse src --format json --fail-on warning --no-baseline
```

`scripts/preflight-checks.sh` runs formatting, Clippy, unit tests, rule listing, JSON and SARIF fixture scans, patch-input diff smoke tests, selector/exclusion/custom-rule smokes, and a dogfood scan of `src/`.

## Documentation

- [Changelog](CHANGELOG.md)
- [Upgrading](UPGRADING.md)
- [Rules](docs/rules.md)
- [Action metadata](action.yml)
- [Fixture notes](fixtures/README.md)
- [Test fixture notes](tests/fixtures/README.md)

## Author

Built by [Matthew Hansen](https://www.blundergoat.com/about).

## License

Licensed under either of:

- [MIT](LICENSE-MIT)
- [Apache-2.0](LICENSE-APACHE)
