# gruff-rs

[![Crates.io](https://img.shields.io/crates/v/gruff-rs.svg)](https://crates.io/crates/gruff-rs)
[![Docs.rs](https://img.shields.io/docsrs/gruff-rs)](https://docs.rs/gruff-rs)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

`gruff-rs` is an opinionated quality analyzer for Rust projects. It scans Rust source, Cargo metadata, and common project files, then emits deterministic reports for terminals, CI annotations, SARIF consumers, static HTML, and a local dashboard. It is heuristic static analysis; run it beside Clippy, `cargo audit`, rustfmt, tests, and code review, not instead of them.

## Mission

gruff governs AI-generated code so a human who didn't write it can read, review, and trust it. Coding agents routinely produce code that superficially works while misunderstanding the requirement, and gruff exists to make that gap visible to a reviewer. Run as a coding-agent hook, it guides — or forces — the agent toward code a person can actually sign off on:

- **Verifiable** — legible enough that a reviewer can confirm it does what was asked.
- **Secure** — hardened where human review is weakest.
- **Genuinely tested** — tests that exercise the contract, not low-signal bloat or ceremony.

Doc comments are mandatory even on a private one-liner: forcing the agent to state intent, usage, contract, and failure behaviour in prose gives the reviewer something to check the implementation against. A mismatch between the doc comment and the code is the signal that a change needs a deeper look.

## Status At A Glance

| Field | Value |
| --- | --- |
| Release line | Published `1.0.0` package line |
| Runtime | Prebuilt binary, or Rust `1.82+` when building from source |
| Package | `gruff-rs` on crates.io |
| Binary | `gruff-rs` |
| Rule catalogue | 80 rules across 11 pillars |
| Primary config | `.gruff-rs.yaml` (requires `schemaVersion: gruff-rs.config.v1`) |
| Analysis schema | `gruff.analysis.v2` |
| Baseline schema | `gruff.baseline.v1` |
| Severity gate | `--fail-on` with `none`, `advisory`, `warning`, `error`; per-subcommand defaults via `minimumSeverity:` in `.gruff-rs.yaml` |
| Dashboard | `127.0.0.1:8766` by default |

Rule IDs, fingerprints, baseline identity, JSON schema version, and SARIF behavior are compatibility-sensitive inside the `1.0.x` line.

## Requirements

- No Rust toolchain is needed when using a prebuilt binary through `cargo-binstall`.
- Rust `1.82+` is required when building from source with Cargo.
- Git is not used by default; Git-backed changed-region modes run only when `--diff`/`--since` is explicitly passed.

## Install

Install into a repository-local tool directory:

```bash
cargo install gruff-rs --locked --version 1.0.0 --root ./.cargo-tools
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
| `json` | Full `gruff.analysis.v2` report. |
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

`analyse` defaults to `--fail-on advisory`; `report` defaults to `--fail-on none`. Set per-project defaults with the `minimumSeverity:` block in `.gruff-rs.yaml`; the CLI flag always overrides the config value (see ADR-013).

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
      - uses: blundergoat/gruff-rs@v1.0.0
        with:
          args: analyse . --format sarif --fail-on warning --no-baseline
```

The action installs the matching binary via `cargo-binstall` and runs `gruff-rs` with the supplied args. Pin to a tag for reproducibility. See [`action.yml`](action.yml) for inputs.

## Configuration

`gruff-rs` reads `.gruff-rs.yaml` by default. Use `--config <path>` to pass another YAML file, or `--no-config` to ignore project config. Unknown keys, unknown rule IDs, unknown selectors, and invalid threshold shapes fail closed.

Every config must declare `schemaVersion: gruff-rs.config.v1` as the first key. Configs without it are rejected at load time; run `gruff-rs init --force` to regenerate.

The optional `minimumSeverity:` block sets per-subcommand defaults for `--fail-on` so CI invocations can omit the flag. Accepted keys are `analyse` and `report` (the two commands that gate exit code); values are `none`, `advisory`, `warning`, or `error`. The CLI `--fail-on` flag always wins; if both the CLI flag and the config key are absent, the binary default (`advisory` for `analyse`, `none` for `report`) applies. See ADR-013 for the rationale and the gating-only accept-list rule.

```yaml
schemaVersion: gruff-rs.config.v1

minimumSeverity:
  analyse: advisory  # CI gates on advisory+; CLI --fail-on always wins
  # report: none

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

Unknown `minimumSeverity:` keys are rejected with a useful error: setting `minimumSeverity.summary: advisory` errors with `unknown command "summary" in minimumSeverity: gruff-rs's summary does not gate exit code. Valid keys: analyse, report.` The off-switch value is `none` (gruff-rs convention; sibling ports may use `never`).

## Rules And Pillars

The v1.0 catalogue contains 76 rules:

| Pillar | Rules |
| --- | ---: |
| `complexity` | 3 |
| `dead-code` | 3 |
| `design` | 3 |
| `documentation` | 11 |
| `maintainability` | 11 |
| `modernisation` | 6 |
| `naming` | 5 |
| `security` | 14 |
| `sensitive-data` | 9 |
| `size` | 3 |
| `test-quality` | 8 |

Use `./.cargo-tools/bin/gruff-rs list-rules --format json` for the exact rule metadata. See [Rules](docs/rules.md) for rule families, limits, and deferred checks.

Generated default config keeps `size.file-length` enabled for Rust source over 600 lines and marks `waste.unnecessary-clone-candidate` as opt-in, because a clone can be the clearer ownership boundary. `test-quality.long-test` counts from the first assertion onward so fixture setup does not dilute the test-signal check.

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

Custom rules are intentionally regex-only in `1.0.x`; AST patterns, plugins, scripts, external runtimes, and Semgrep-style metavariables are out of scope.

## Baselines And Changed-Code Scans

Baselines suppress reviewed findings by exact fingerprint, rule ID, and file path:

```bash
./.cargo-tools/bin/gruff-rs analyse src --generate-baseline --fail-on none
./.cargo-tools/bin/gruff-rs analyse src --baseline --fail-on warning
./.cargo-tools/bin/gruff-rs analyse src --no-baseline --fail-on none
```

Changed-code scans keep findings whose location or enclosing declaration
overlaps the changed hunk. JSON output includes `suppressedCount` for findings
excluded as out of scope.

```bash
./.cargo-tools/bin/gruff-rs analyse --format json --changed-ranges "3-3,8-10" src/foo.rs
./.cargo-tools/bin/gruff-rs analyse --format json --since HEAD src/foo.rs
git diff | ./.cargo-tools/bin/gruff-rs analyse --format json --diff - src/foo.rs
```

Use `--changed-scope=hunk` for line/hunk-only filtering; the default is
`--changed-scope=symbol`.

When a baseline or diff comparison context is active, `analyse` and `summary` surface per-rule deltas before the composite-score line:

```text
Top 5 improved: -12 docs.missing-public-doc, -7 size.method-length, ...
Top 5 regressed: +4 modernisation.semver-pin, +2 naming.identifier-quality, ...
```

The JSON output exposes the same data as a `perRuleDeltas[]` array (`{ruleId, introduced, removed, net}`). Both surfaces stay omitted on full-tree scans so the schema remains byte-identical for non-comparison runs.

**Coding-agent hook.** Coding agents can run gruff-rs after each edit so they only see findings on the code they just changed, not unrelated debt in the same file. The goat-flow project ships a PostToolUse hook (`gruff-code-quality.sh`) that runs `gruff-rs analyse <file> --format json --fail-on none` on the edited file and filters the JSON to the changed line ranges (from the agent's tool payload or `git diff --unified=0`), reporting a suppressed count for pre-existing same-file findings; see its `gruff-code-quality.md` playbook for setup and triage. gruff-rs's side of the contract is the stable per-file JSON (`filePath`, `line`, `severity`, `ruleId`) under `gruff.analysis.v2`; the `--diff-patch` / `--diff <mode>` flags above are the in-binary change-scoping equivalent for CI or single-binary use.

Config `paths.ignore` is authoritative in every invocation mode (walk, explicit file args, and all diff modes), so a hook can pass an ignored file and gruff-rs emits no findings for it — `--include-ignored` opts into git/default ignores only and never overrides `paths.ignore`. Ignored paths are reported under `paths.ignoredPathDetails` with their `source` and `pattern`. The `check-ignore` command lets a hook query the same decision per path without analysing (`gruff-rs check-ignore --format json <path>...` → `[{path, ignored, source, pattern}]`, `git check-ignore` exit codes). See [CI Integration](docs/ci-integration.md) and ADR-018.

## Dashboard

```bash
./.cargo-tools/bin/gruff-rs dashboard --host 127.0.0.1 --port 8766 --project-root .
```

The dashboard renders HTML reports on demand. It has no authentication and must not be exposed to untrusted networks; keep the default loopback bind unless the environment is trusted.

In polyglot repositories, `gruff-rs` defaults to port `8766` while `gruff-go`, `gruff-php`, and `gruff-py` default to `8765`; use `--port` when running multiple dashboards at the same time.

## Trust Boundary

Default scans are source-only and local-only. `gruff-rs` does not execute target code, run Cargo build scripts, call Git unless a Git-backed changed-region mode is explicitly requested, query registries, read vulnerability feeds, or run benchmarks. Dependency checks read `Cargo.toml` and `Cargo.lock` as data. Candidate wording means the analyzer found a deterministic static signal, not type-aware or runtime certainty.

## Stability Contract

`1.0.x` is the first stable line. Rule IDs, finding fingerprints, baseline identity, JSON schema version `gruff.analysis.v2`, SARIF rendering, and CLI exit semantics are compatibility-sensitive. Breaking changes to those surfaces ship as `2.0.0`, not inside `1.0.x`. See [UPGRADING.md](UPGRADING.md) for the full contract.

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
bin/gruff-rs analyse . --format json --no-baseline
```

`scripts/preflight-checks.sh` runs formatting, Clippy, unit tests, rule listing, JSON and SARIF fixture scans, patch-input diff smoke tests, selector/exclusion/custom-rule smokes, and a dogfood scan of the whole project gated by `minimumSeverity.analyse` in `.gruff-rs.yaml`.

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
