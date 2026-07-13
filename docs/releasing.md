# Releasing

This page explains how maintainers prove a gruff-rs release before users can
download it. The candidate and tag paths share one source, Cargo package, and
five-platform asset contract. Candidate runs cannot publish; tag runs publish
only after the same evidence passes again at the tagged commit.

## Preflight

Run the local check suite before tagging:

```sh
scripts/preflight-checks.sh
cargo run -- --help
cargo run -- list-rules --format json
```

The release-specific local harness exercises source, package, archive,
checksum, manifest, and workflow-graph failures without contacting GitHub or
crates.io:

```sh
bash scripts/test-release-workflow.sh
```

## Pinned Release Supply Chain

CI and release jobs use full 40-character commit SHAs for every third-party
GitHub Action. The adjacent version comment is the maintainer-readable release
identity; a moving tag such as `@v4`, a branch such as `@stable`, or a short SHA
fails the checked-in release-security contract. Workflow permissions default to
`contents: read`; only the final GitHub-release job receives `contents: write`,
and the crates.io credential exists only on the crate-publish step.

Rust is pinned to `1.97.0`. The release build pins `cross` to `0.2.5`, and local
setup pins `cargo-audit` to `0.22.2` plus `action-validator` to `0.9.0`, using
`cargo install --version ... --locked`. `actionlint` is the Go release
`1.7.12`; its four supported platform archives are downloaded from that exact
release and checked against repository-owned SHA-256 values before execution.

These controls provide bounded reproducibility: source, actions, Rust, Cargo
tools, targets, archives, and checksums are fixed. GitHub-hosted runner labels
can still change their underlying images, so this is not a claim that separate
hosted runs produce bit-identical binaries.

To update a pin:

1. Review the upstream release notes and retain the existing major unless the
   major upgrade is intentionally in scope.
2. Resolve the release tag to its commit, for example
   `gh api repos/actions/checkout/commits/v4.3.1 --jq .sha`. For the toolchain
   action, resolve the reviewed snapshot with
   `gh api repos/dtolnay/rust-toolchain/commits/stable --jq .sha` while keeping
   the separate Rust version exact.
3. Update the workflow SHA and its version comment together. Update exact tool
   constants in `scripts/dependency-install.sh` and
   `scripts/preflight-checks.sh` together.
4. For actionlint, download
   `actionlint_<version>_checksums.txt` from the matching upstream release and
   replace all four Linux/macOS checksums together. Never copy a digest from
   the archive download response itself.
5. Update the expected identities in `tests/release_security_contract.rs`, then
   run:

   ```sh
   bash scripts/dependency-install.sh --force
   cargo test --test release_security_contract -- --nocapture
   action-validator action.yml
   actionlint
   bash scripts/preflight-checks.sh
   ```

The focused test deliberately mutates checkout back to `@v4` in memory and
must still prove that the moving ref is rejected. A changed pin that passes only
after weakening that negative case is not an acceptable update.

Repository release immutability is a separate GitHub setting, not a substitute
for these pins. Read its live value before release and obtain explicit operator
authority before enabling or disabling it. The draft-first publication order
below is designed so immutability locks only a complete, verified release.

## Pre-Tag Candidate

The release workflow must already exist on the default branch before GitHub
allows a maintainer to dispatch it at another ref. Preparing or pushing that
candidate ref and dispatching the hosted workflow are separate external
changes: obtain explicit operator authority before either action.

After approval:

1. Push the prospective release commit to a dedicated candidate ref without
   creating a version tag.
2. Dispatch `release.yml` at that exact ref in GitHub Actions. With the GitHub
   CLI, the equivalent command is
   `gh workflow run release.yml --ref <candidate-ref>`.
3. Record the run URL, run ID, and `github.sha`. Confirm that `source_verify`,
   all five `build` jobs, and `asset_verify` succeed at that same SHA.
4. Confirm both publication jobs are skipped. Candidate jobs have read-only
   repository access and receive no crates.io or GitHub publication secret.

A successful candidate produces Linux x86_64/ARM64, macOS x86_64/ARM64, and
Windows x86_64 archives. The verified evidence contains ten downloadable files
(five archives and five checksum sidecars) plus
`release-assets-manifest.txt`. Build identities and source evidence bind those
files to the Cargo version, commit, Rust toolchain, previous release tag,
package digest/file list, and checked-in target matrix.

Do not substitute locally fabricated or current-host-only archives for this
hosted five-runner proof. Do not create the release tag until the candidate run
is recorded and the remaining release milestones, including immutable-release
configuration, are complete.

## Tag Publication

An exact `vX.Y.Z` tag push re-runs the candidate gates at the tagged SHA. The
source job rejects a tag that differs from Cargo metadata, a checkout that
differs from the trigger SHA, or a commit that does not descend from the newest
lower SemVer release tag.

Publication is deliberately serialized:

1. Recreate the locked Cargo package and compare its filename, byte size,
   SHA-256, and normalized file list with the tag run's source evidence.
2. Publish that verified crate to crates.io.
3. Create an unpublished GitHub draft with `--verify-tag`, upload exactly the
   ten archives/sidecars and their release manifest, and compare GitHub's remote
   asset names and sizes with the local verified set.
4. Make the GitHub release visible only after the complete draft passes.

If crates.io already contains the version, a rerun stops rather than treating
the existing crate as verified. Checksum-based reconciliation is intentionally
deferred; investigate the partial publication before taking another external
action.

## Release Gate Failures

- A source failure means the event, Cargo version, tag, SHA, previous release,
  or ancestry does not describe one unambiguous release commit.
- A package failure means Cargo could not create the locked package or the
  recreated archive/file list differs from verified source evidence.
- A build upload failure means one expected target did not produce its archive,
  checksum sidecar, and build identity.
- An asset failure means a target/file is missing or extra, a checksum differs,
  an archive has unexpected members or link types, or build identity drifted.
- A draft failure means GitHub does not expose exactly the eleven verified
  files with their expected sizes. The release remains unpublished.

Fix the cause at source and run a new candidate. Never weaken the exact-file
checks, change `if-no-files-found: error`, or manually attach replacement files
to make a partial run appear complete.

## Benchmarking

Do not benchmark a previously-built `target/release/gruff-rs` unless you just ran
`cargo build --release`. That path is a local Cargo artifact and can silently lag
behind HEAD. Prefer `scripts/test-performance.sh` for performance checks because
it rebuilds the release binary before timing it; `bin/gruff-rs` is also fresh by
construction because it delegates to `cargo run`.

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

Record user-visible changes in `CHANGELOG.md`, especially:

- schema strings
- severity names
- default exit thresholds
- baseline behaviour
- dashboard defaults
- output format additions or removals

See [`../UPGRADING.md`](../UPGRADING.md) for version-specific change notes.
