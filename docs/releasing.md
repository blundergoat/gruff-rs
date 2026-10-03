# Releasing

This is the maintainer's path from a verified commit to a published gruff-rs release. Publication is always a
human step: nothing here tags, pushes, or uploads on its own.

## Bump The Version

```bash
bash scripts/bump-version.sh --version X.Y.Z
```

The script sets the crate version in `Cargo.toml`, the source of truth, and refreshes `Cargo.lock`. It never runs
git. Then, by hand:

- Rename the `## Unreleased` heading in `CHANGELOG.md` to `## vX.Y.Z - Unreleased`, and date it when you tag.
- Move the README's machine-checked release blocks to the new version: the published package line, the
  `cargo install --version` example, the action pin comment and `version:` input, and the active release line.
  The preflight's documentation drift guard names every stale value in one run.

## Required Release Gates

```bash
bash scripts/preflight-checks.sh
bash scripts/preflight-checks.sh --release-check
```

The first run is the full project gate CI runs. `--release-check` also requires the crate version to be newer than
the latest local `vX.Y.Z` tag and present in `CHANGELOG.md`.

## Package Review

```bash
cargo package --locked --list
bash scripts/publish-crates.sh
```

`publish-crates.sh` verifies the crate package and runs `cargo publish --dry-run --locked`. It uploads only with
`--publish`, after a confirmation.

## Publish And Verify

1. Dispatch the `Release` workflow on the release commit before tagging. It proves the source, the Cargo package and
   all five platform archives at that one commit, using the rows `scripts/release-targets.sh` prints, and stops
   there.
2. Push the exact `vX.Y.Z` tag. The same workflow then publishes the verified crate. It creates an unpublished
   GitHub draft, uploads the verified archives, checks with `scripts/release-contract.sh verify-draft` that the
   draft holds exactly the verified asset set, and only then publishes it.
3. Confirm the published version with `cargo install gruff-rs --locked --version X.Y.Z` in a clean directory.
