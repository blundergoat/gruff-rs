#!/usr/bin/env bash
# Adversarial local harness for candidate and tag release verification.
# Maintainers run it without publishing to exercise the production source,
# package, archive, manifest, and draft checks plus the parsed workflow graph.
# Temporary Git history and platform assets keep every result repeatable offline.

set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd -- "$SCRIPT_DIR/.." && pwd)
RELEASE_CONTRACT=$SCRIPT_DIR/release-contract.sh
TARGET_CONTRACT=$SCRIPT_DIR/release-targets.sh
WORK_DIR=""
CANDIDATE_COMMIT=""
PREVIOUS_COMMIT=""
SOURCE_DIRECTORY=""
BUILD_DIRECTORY=""
VERIFIED_DIRECTORY=""

# Stop the harness with one actionable contract-test failure.
fail_release_test() {
  printf 'release workflow test: %s\n' "$*" >&2
  exit 1
}

# Remove only the private candidate simulation created by this test process.
cleanup_release_test() {
  # An empty path means setup stopped before temporary release state existed.
  if [[ -z $WORK_DIR || ! -d $WORK_DIR ]]; then
    return
  fi
  find "$WORK_DIR" -depth -delete
}

# Read one named GitHub-style output produced by source resolution.
workflow_output_value() {
  local output_file=$1
  local output_name=$2
  local output_line
  local output_line_count

  output_line_count=$(grep -c "^${output_name}=" "$output_file" || true)
  [[ $output_line_count -eq 1 ]] \
    || fail_release_test "source output must contain one $output_name value"
  output_line=$(grep "^${output_name}=" "$output_file")
  printf '%s\n' "${output_line#*=}"
}

# Require a production command to fail with the stage-specific message users need.
expect_release_failure() {
  local scenario_name=$1
  local expected_message=$2
  shift 2
  local scenario_output=$WORK_DIR/$scenario_name.output
  local scenario_error=$WORK_DIR/$scenario_name.error
  local scenario_status

  set +e
  "$@" >"$scenario_output" 2>"$scenario_error"
  scenario_status=$?
  set -e
  # A zero status would let the unsafe release state advance to a later job.
  [[ $scenario_status -ne 0 ]] || fail_release_test "$scenario_name unexpectedly succeeded"
  grep -q "$expected_message" "$scenario_error" \
    || fail_release_test "$scenario_name did not report <$expected_message>"
}

# Rewrite one fixture manifest field to model identity drift from a hosted build.
rewrite_fixture_manifest_value() {
  local manifest_file=$1
  local manifest_key=$2
  local replacement_value=$3
  local rewritten_manifest=$manifest_file.rewritten
  local manifest_line
  local replacement_count=0

  : >"$rewritten_manifest"
  # Each row is copied until the selected build identity field is replaced.
  while IFS= read -r manifest_line || [[ -n $manifest_line ]]; do
    # A matching field models one user-visible build property changing after source proof.
    if [[ $manifest_line == "$manifest_key="* ]]; then
      printf '%s=%s\n' "$manifest_key" "$replacement_value" >>"$rewritten_manifest"
      replacement_count=$((replacement_count + 1))
    else
      printf '%s\n' "$manifest_line" >>"$rewritten_manifest"
    fi
  done <"$manifest_file"
  [[ $replacement_count -eq 1 ]] \
    || fail_release_test "fixture manifest must contain one $manifest_key field"
  mv -- "$rewritten_manifest" "$manifest_file"
}

# Create two commits and a prior release tag for candidate/tag source checks.
create_release_history_fixture() {
  local fixture_repository=$WORK_DIR/repository

  mkdir -p -- "$fixture_repository"
  git -C "$fixture_repository" init -q -b main
  git -C "$fixture_repository" config user.name "Release Contract Test"
  git -C "$fixture_repository" config user.email "release-contract@example.invalid"
  printf '[package]\nname = "gruff-rs"\nversion = "0.4.0"\n' \
    >"$fixture_repository/Cargo.toml"
  git -C "$fixture_repository" add Cargo.toml
  GIT_AUTHOR_DATE='2026-01-01T00:00:00Z' GIT_COMMITTER_DATE='2026-01-01T00:00:00Z' \
    git -C "$fixture_repository" commit -q -m "release 0.4.0"
  git -C "$fixture_repository" tag v0.4.0
  PREVIOUS_COMMIT=$(git -C "$fixture_repository" rev-parse HEAD)

  printf '[package]\nname = "gruff-rs"\nversion = "0.5.0"\n' \
    >"$fixture_repository/Cargo.toml"
  git -C "$fixture_repository" add Cargo.toml
  GIT_AUTHOR_DATE='2026-01-02T00:00:00Z' GIT_COMMITTER_DATE='2026-01-02T00:00:00Z' \
    git -C "$fixture_repository" commit -q -m "candidate 0.5.0"
  CANDIDATE_COMMIT=$(git -C "$fixture_repository" rev-parse HEAD)
}

# Prove candidate and tag events share one commit while malformed events fail closed.
assert_source_event_contract() {
  local fixture_repository=$WORK_DIR/repository
  local candidate_outputs=$WORK_DIR/candidate-outputs
  local tag_outputs=$WORK_DIR/tag-outputs

  "$RELEASE_CONTRACT" resolve-source "$fixture_repository" workflow_dispatch \
    candidate-ref "$CANDIDATE_COMMIT" stable "$candidate_outputs" >/dev/null
  [[ $(workflow_output_value "$candidate_outputs" version) == 0.5.0 ]] \
    || fail_release_test "candidate did not derive Cargo version 0.5.0"
  [[ $(workflow_output_value "$candidate_outputs" commit) == "$CANDIDATE_COMMIT" ]] \
    || fail_release_test "candidate did not bind its immutable commit"
  [[ $(workflow_output_value "$candidate_outputs" previous_tag) == v0.4.0 ]] \
    || fail_release_test "candidate did not identify v0.4.0 as predecessor"

  expect_release_failure wrong-tag-version "does not match Cargo version" \
    "$RELEASE_CONTRACT" resolve-source "$fixture_repository" push v0.6.0 \
    "$CANDIDATE_COMMIT" stable "$WORK_DIR/wrong-tag-outputs"
  expect_release_failure wrong-checkout-commit "checked-out commit does not match" \
    "$RELEASE_CONTRACT" resolve-source "$fixture_repository" workflow_dispatch \
    candidate-ref "$PREVIOUS_COMMIT" stable "$WORK_DIR/wrong-commit-outputs"

  git -C "$fixture_repository" tag v0.5.0
  "$RELEASE_CONTRACT" resolve-source "$fixture_repository" push v0.5.0 \
    "$CANDIDATE_COMMIT" stable "$tag_outputs" >/dev/null
  [[ $(workflow_output_value "$tag_outputs" commit) == "$CANDIDATE_COMMIT" ]] \
    || fail_release_test "tag mode did not reuse the candidate commit"

  git -C "$fixture_repository" tag v0.6.0
  expect_release_failure stale-release-tag "is not the newest release tag" \
    "$RELEASE_CONTRACT" resolve-source "$fixture_repository" push v0.5.0 \
    "$CANDIDATE_COMMIT" stable "$WORK_DIR/stale-tag-outputs"
}

# Write deterministic fake Cargo evidence for manifest and publication comparisons.
create_source_package_fixture() {
  local package_file=$WORK_DIR/gruff-rs-0.5.0.crate
  local package_file_list=$WORK_DIR/package-files.input

  printf 'deterministic crate fixture\n' >"$package_file"
  printf '%s\n' Cargo.toml Cargo.lock src/main.rs >"$package_file_list"
  SOURCE_DIRECTORY=$WORK_DIR/source-verification
  mkdir -p -- "$SOURCE_DIRECTORY"
  "$RELEASE_CONTRACT" write-source-manifest \
    "$SOURCE_DIRECTORY" \
    workflow_dispatch \
    0.5.0 \
    "$CANDIDATE_COMMIT" \
    stable \
    v0.4.0 \
    "$PREVIOUS_COMMIT" \
    "$package_file" \
    "$package_file_list" >/dev/null
}

# Stage all five production-shaped archives and merge their uploaded files.
create_build_artifact_fixture() {
  local target
  local _runner_label
  local _archive_kind
  local _build_mode
  local _runner_os
  local _runner_arch
  local binary_name
  local target_output
  local compiled_binary

  BUILD_DIRECTORY=$WORK_DIR/build-artifacts
  mkdir -p -- "$BUILD_DIRECTORY"
  # Each target uses the production archive stage with a harmless local binary.
  while IFS='|' read -r target _runner_label _archive_kind _build_mode _runner_os _runner_arch binary_name; do
    target_output=$WORK_DIR/build-$target
    compiled_binary=$WORK_DIR/compiled-$target/$binary_name
    mkdir -p -- "$target_output" "${compiled_binary%/*}"
    cp /bin/true "$compiled_binary"
    "$RELEASE_CONTRACT" stage-archive \
      "$REPO_ROOT" \
      0.5.0 \
      "$CANDIDATE_COMMIT" \
      stable \
      "$target" \
      "$compiled_binary" \
      "$target_output" >/dev/null
    cp -- "$target_output"/* "$BUILD_DIRECTORY/"
  done < <("$TARGET_CONTRACT" table)
}

# Prove a complete set passes and every partial/corrupt identity variant stops.
assert_asset_manifest_contract() {
  local missing_builds=$WORK_DIR/missing-builds
  local extra_builds=$WORK_DIR/extra-builds
  local bad_checksum_builds=$WORK_DIR/bad-checksum-builds
  local wrong_commit_builds=$WORK_DIR/wrong-commit-builds
  local first_archive=gruff-rs-0.5.0-x86_64-unknown-linux-gnu.tar.gz
  local first_identity=build-identity-x86_64-unknown-linux-gnu.txt

  VERIFIED_DIRECTORY=$WORK_DIR/verified-release
  mkdir -p -- "$VERIFIED_DIRECTORY"
  "$RELEASE_CONTRACT" verify-assets \
    "$BUILD_DIRECTORY" \
    "$SOURCE_DIRECTORY" \
    "$VERIFIED_DIRECTORY" \
    workflow_dispatch \
    0.5.0 \
    "$CANDIDATE_COMMIT" \
    stable >/dev/null
  [[ $("$RELEASE_CONTRACT" publish-files "$VERIFIED_DIRECTORY" | wc -l) -eq 11 ]] \
    || fail_release_test "verified set did not expose ten assets plus one manifest"

  cp -a -- "$BUILD_DIRECTORY" "$missing_builds"
  mv -- "$missing_builds/$first_archive" "$WORK_DIR/held-missing-archive"
  expect_release_failure missing-target "missing, extra, or duplicate files" \
    "$RELEASE_CONTRACT" verify-assets "$missing_builds" "$SOURCE_DIRECTORY" \
    "$WORK_DIR/missing-output" workflow_dispatch 0.5.0 "$CANDIDATE_COMMIT" stable

  cp -a -- "$BUILD_DIRECTORY" "$extra_builds"
  printf 'unexpected\n' >"$extra_builds/extra-release-file"
  expect_release_failure extra-file "missing, extra, or duplicate files" \
    "$RELEASE_CONTRACT" verify-assets "$extra_builds" "$SOURCE_DIRECTORY" \
    "$WORK_DIR/extra-output" workflow_dispatch 0.5.0 "$CANDIDATE_COMMIT" stable

  cp -a -- "$BUILD_DIRECTORY" "$bad_checksum_builds"
  printf '%064d  %s\n' 0 "$first_archive" \
    >"$bad_checksum_builds/$first_archive.sha256"
  expect_release_failure bad-checksum "checksum does not match" \
    "$RELEASE_CONTRACT" verify-assets "$bad_checksum_builds" "$SOURCE_DIRECTORY" \
    "$WORK_DIR/bad-checksum-output" workflow_dispatch 0.5.0 "$CANDIDATE_COMMIT" stable

  cp -a -- "$BUILD_DIRECTORY" "$wrong_commit_builds"
  rewrite_fixture_manifest_value "$wrong_commit_builds/$first_identity" commit \
    0000000000000000000000000000000000000000
  expect_release_failure wrong-commit-identity "build identity commit does not match" \
    "$RELEASE_CONTRACT" verify-assets "$wrong_commit_builds" "$SOURCE_DIRECTORY" \
    "$WORK_DIR/wrong-commit-output" workflow_dispatch 0.5.0 "$CANDIDATE_COMMIT" stable
}

# Prove package recreation and final manifest rows remain exact before publication.
assert_package_and_publish_manifest_contract() {
  local recreated_package_directory=$WORK_DIR/recreated-package
  local recreated_package=$recreated_package_directory/gruff-rs-0.5.0.crate
  local recreated_package_list=$WORK_DIR/recreated-package-files
  local duplicate_manifest_directory=$WORK_DIR/duplicate-manifest
  local duplicate_asset_row

  mkdir -p -- "$recreated_package_directory"
  cp -- "$SOURCE_DIRECTORY/gruff-rs-0.5.0.crate" "$recreated_package"
  cp -- "$SOURCE_DIRECTORY/package-files.txt" "$recreated_package_list"
  "$RELEASE_CONTRACT" verify-package \
    "$SOURCE_DIRECTORY" "$recreated_package" "$recreated_package_list" >/dev/null
  printf 'changed package\n' >>"$recreated_package"
  expect_release_failure changed-package "digest does not match" \
    "$RELEASE_CONTRACT" verify-package \
    "$SOURCE_DIRECTORY" "$recreated_package" "$recreated_package_list"

  cp -a -- "$VERIFIED_DIRECTORY" "$duplicate_manifest_directory"
  duplicate_asset_row=$(grep -m1 '^asset=' \
    "$duplicate_manifest_directory/release-assets-manifest.txt")
  printf '%s\n' "$duplicate_asset_row" \
    >>"$duplicate_manifest_directory/release-assets-manifest.txt"
  expect_release_failure duplicate-asset-row "missing, extra, or duplicate assets" \
    "$RELEASE_CONTRACT" publish-files "$duplicate_manifest_directory"
}

# Model GitHub's draft JSON and prove remote missing/extra assets cannot publish.
assert_remote_draft_contract() {
  local draft_asset_rows=$WORK_DIR/draft-assets.tsv
  local draft_json=$WORK_DIR/draft.json
  local extra_draft_json=$WORK_DIR/extra-draft.json
  local publishable_file

  # Every local publishable file becomes the name/size pair returned by GitHub.
  while IFS= read -r publishable_file; do
    printf '%s\t%s\n' "${publishable_file##*/}" "$(wc -c <"$publishable_file")" \
      >>"$draft_asset_rows"
  done < <("$RELEASE_CONTRACT" publish-files "$VERIFIED_DIRECTORY")
  jq -Rn \
    --arg tag v0.5.0 \
    '[inputs | split("\t") | {name: .[0], size: (.[1] | tonumber)}]
     | {isDraft: true, tagName: $tag, assets: .}' \
    <"$draft_asset_rows" >"$draft_json"
  "$RELEASE_CONTRACT" verify-draft "$VERIFIED_DIRECTORY" "$draft_json" 0.5.0 >/dev/null

  jq '.assets += [{"name":"unexpected","size":1}]' "$draft_json" >"$extra_draft_json"
  expect_release_failure extra-draft-asset "missing, extra, or wrong-size assets" \
    "$RELEASE_CONTRACT" verify-draft "$VERIFIED_DIRECTORY" "$extra_draft_json" 0.5.0
}

# Run parsed graph tests and every production manifest/archive negative scenario.
run_release_workflow_suite() {
  [[ -x $RELEASE_CONTRACT && -x $TARGET_CONTRACT ]] \
    || fail_release_test "release contract scripts are not executable"
  # A developer without TMPDIR still gets an isolated local candidate simulation.
  WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/gruff-rs-release-workflow.XXXXXX")
  trap cleanup_release_test EXIT
  create_release_history_fixture
  assert_source_event_contract
  create_source_package_fixture
  create_build_artifact_fixture
  assert_asset_manifest_contract
  assert_package_and_publish_manifest_contract
  assert_remote_draft_contract
  cargo test --quiet --test release_workflow -- --nocapture
  printf 'PASS: candidate and tag release paths enforce source, package, asset, and draft contracts\n'
}

run_release_workflow_suite "$@"
