# Releasing

This page captures the gruff-rs release checks that protect the user-facing CLI
and report contracts.

## Preflight

Run the local check suite before tagging:

```sh
scripts/preflight-checks.sh
cargo run -- --help
cargo run -- list-rules --format json
```

## CLI Contract

Verify the common command surface:

```sh
cargo run -- --help
cargo run -- analyse --help
cargo run -- summary --help
cargo run -- dashboard --help
```

Rust-specific flags such as `--diff-patch`, `--diff-git-unsafe`,
`init --stdout`, and `init --output` should remain documented when they are kept.

## Docs

Update docs when command output or schemas change:

- `docs/configuration.md`
- `docs/output-formats.md`
- `docs/ci-integration.md`
- `docs/dashboard.md`
- `docs/rules.md`

If the rule registry changes, verify `docs/rules.md` against
`cargo run -- list-rules --format json`.

## Changelog

Record compatibility-sensitive changes in `CHANGELOG.md`, especially:

- schema strings
- severity names
- default exit thresholds
- baseline behaviour
- dashboard defaults
- output format additions or removals

See [`../UPGRADING.md`](../UPGRADING.md) for the compatibility policy.
