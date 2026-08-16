#!/usr/bin/env bash
# Release verifier shared by candidate and tag-triggered GitHub workflows.
# Maintainers use it to bind Cargo source/package identity to five platform
# archives, reject partial or extra artifact sets, and prepare the exact files
# that may be attached to a draft release after every verification gate passes.

set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
TARGET_CONTRACT=$SCRIPT_DIR/release-targets.sh
PRIVATE_WORK_DIR=""

# Stop one release stage with a concise maintainer-facing explanation.
fail_release_contract() {
  printf 'release contract: %s\n' "$*" >&2
  exit 2
}

# Remove private manifest/archive inspection files after the stage finishes.
cleanup_release_contract() {
  # No private directory means the command failed before staging user artifacts.
  if [[ -z $PRIVATE_WORK_DIR || ! -d $PRIVATE_WORK_DIR ]]; then
    return
  fi
  find "$PRIVATE_WORK_DIR" -depth -delete
}

# Create private temporary storage beneath the runner's normal temp directory.
create_private_work_dir() {
  # A runner without an explicit temp path falls back to its normal local temp area.
  local runner_temp=${RUNNER_TEMP:-${TMPDIR:-/tmp}}

  # A nested verifier reuses the current private directory and its exit trap.
  if [[ -n $PRIVATE_WORK_DIR && -d $PRIVATE_WORK_DIR ]]; then
    return
  fi
  # An empty temp root gives the verifier nowhere private to inspect artifacts.
  [[ -n $runner_temp ]] || fail_release_contract "RUNNER_TEMP is empty"
  [[ -d $runner_temp ]] || fail_release_contract "RUNNER_TEMP is not an existing directory"
  umask 077
  PRIVATE_WORK_DIR=$(mktemp -d "$runner_temp/gruff-rs-release-contract.XXXXXX") \
    || fail_release_contract "could not create private verification storage"
  trap cleanup_release_contract EXIT
}

# Fail early when a release runner lacks a command needed by the current stage.
require_release_command() {
  command -v "$1" >/dev/null 2>&1 \
    || fail_release_contract "required command is unavailable: $1"
}

# Detect line breaks that could split one manifest or workflow-command record.
contains_line_break() {
  [[ $1 == *$'\n'* || $1 == *$'\r'* ]]
}

# Report whether a release directory already contains visible or hidden entries.
directory_has_entries() {
  local directory_path=$1
  local possible_entry

  # Portable Bash globs cover normal files and both forms of hidden filename.
  for possible_entry in "$directory_path"/* "$directory_path"/.[!.]* "$directory_path"/..?*; do
    # A real file or link means this release stage could mix separate attempts.
    if [[ -e $possible_entry || -L $possible_entry ]]; then
      return 0
    fi
  done
  return 1
}

# Write portable sorted basenames for one exact release artifact directory.
write_directory_entry_names() {
  local directory_path=$1
  local output_file=$2
  local possible_entry
  local entry_name

  : >"$output_file"
  # Each portable glob exposes one visible or hidden artifact for exact comparison.
  for possible_entry in "$directory_path"/* "$directory_path"/.[!.]* "$directory_path"/..?*; do
    # An unmatched glob is not a user artifact and must not become a literal row.
    if [[ ! -e $possible_entry && ! -L $possible_entry ]]; then
      continue
    fi
    entry_name=${possible_entry##*/}
    contains_line_break "$entry_name" \
      && fail_release_contract "release artifact filename contains a line break"
    printf '%s\n' "$entry_name" >>"$output_file"
  done
  LC_ALL=C sort -o "$output_file" "$output_file"
}

# Accept the core Cargo versions used by release tags and artifact names.
release_version_is_valid() {
  [[ $1 =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]
}

# Require one exact Cargo release version before using it in a public filename.
require_release_version() {
  release_version_is_valid "$1" \
    || fail_release_contract "version must be an exact X.Y.Z release"
}

# Require the immutable commit form recorded in candidate and release evidence.
require_release_commit() {
  [[ $1 =~ ^[0-9a-f]{40}$ ]] \
    || fail_release_contract "commit must be a full lowercase 40-hex SHA"
}

# Compare two core semantic versions without relying on platform sort behavior.
version_is_greater_than() {
  local candidate_version=$1
  local prior_version=$2
  local candidate_major
  local candidate_minor
  local candidate_patch
  local prior_major
  local prior_minor
  local prior_patch

  IFS=. read -r candidate_major candidate_minor candidate_patch <<<"$candidate_version"
  IFS=. read -r prior_major prior_minor prior_patch <<<"$prior_version"
  ((candidate_major > prior_major)) && return 0
  ((candidate_major < prior_major)) && return 1
  ((candidate_minor > prior_minor)) && return 0
  ((candidate_minor < prior_minor)) && return 1
  ((candidate_patch > prior_patch))
}

# Calculate one lowercase SHA-256 with the utility available on the runner OS.
sha256_file() {
  local file_path=$1
  local checksum_output

  # Linux and Windows expose sha256sum, while macOS normally exposes shasum.
  if command -v sha256sum >/dev/null 2>&1; then
    checksum_output=$(sha256sum "$file_path") \
      || fail_release_contract "could not hash ${file_path##*/}"
  # A macOS runner normally offers shasum instead of the Linux command above.
  elif command -v shasum >/dev/null 2>&1; then
    checksum_output=$(shasum -a 256 "$file_path") \
      || fail_release_contract "could not hash ${file_path##*/}"
  else
    fail_release_contract "sha256sum or shasum is required"
  fi
  printf '%s\n' "${checksum_output%% *}"
}

# Report the exact byte size GitHub later exposes for a draft release asset.
file_size_bytes() {
  local file_path=$1
  local byte_count

  byte_count=$(wc -c <"$file_path") \
    || fail_release_contract "could not measure ${file_path##*/}"
  printf '%s\n' "${byte_count//[[:space:]]/}"
}

# Read the package version Cargo presents to release users.
read_cargo_package_version() {
  local repository_root=$1

  awk '
    /^\[package\]/ { in_package = 1; next }
    /^\[/ { in_package = 0 }
    in_package && /^version[[:space:]]*=/ {
      sub(/^version[[:space:]]*=[[:space:]]*"/, "")
      sub(/".*$/, "")
      print
      exit
    }
  ' "$repository_root/Cargo.toml"
}

# Find the highest core SemVer tag currently visible in fetched repository history.
latest_release_tag() {
  local repository_root=$1
  local release_tag
  local tag_version

  # Each sorted tag is checked until a published core version is found.
  while IFS= read -r release_tag; do
    tag_version=${release_tag#v}
    # A core version tag is the previous public release users can install.
    if release_version_is_valid "$tag_version"; then
      printf '%s\n' "$release_tag"
      return 0
    fi
  done < <(git -C "$repository_root" tag --list 'v*' --sort=-v:refname)
  return 1
}

# Find the newest published core tag strictly older than the candidate version.
previous_release_tag() {
  local repository_root=$1
  local candidate_version=$2
  local release_tag
  local tag_version

  # Each sorted tag is checked until the candidate has one older release parent.
  while IFS= read -r release_tag; do
    tag_version=${release_tag#v}
    # Non-core tags such as a prerelease do not define this release-lineage gate.
    if ! release_version_is_valid "$tag_version"; then
      continue
    fi
    # The first lower version is the exact predecessor the candidate must descend from.
    if version_is_greater_than "$candidate_version" "$tag_version"; then
      printf '%s\n' "$release_tag"
      return 0
    fi
  done < <(git -C "$repository_root" tag --list 'v*' --sort=-v:refname)
  return 1
}

# Append one safe single-line output for later jobs in the workflow graph.
append_workflow_output() {
  local output_file=$1
  local output_name=$2
  local output_value=$3

  # A blank output path means GitHub cannot transport verified source identity.
  [[ -n $output_file ]] || fail_release_contract "workflow output file is empty"
  contains_line_break "$output_name$output_value" \
    && fail_release_contract "workflow output contains a line break"
  printf '%s=%s\n' "$output_name" "$output_value" >>"$output_file" \
    || fail_release_contract "could not write workflow output $output_name"
}

# Prove the trigger, Cargo version, commit, and predecessor before any build runs.
resolve_source_context() {
  local repository_root=$1
  local event_name=$2
  local ref_name=$3
  local trigger_sha=$4
  local rust_toolchain=$5
  local workflow_output_file=$6
  local cargo_version
  local trigger_commit
  local checkout_commit
  local newest_tag
  local newest_version
  local predecessor_tag
  local predecessor_commit
  local target_contract_sha256
  local build_matrix

  [[ -d $repository_root/.git ]] \
    || fail_release_contract "source verification requires a Git worktree"
  cargo_version=$(read_cargo_package_version "$repository_root")
  # An empty Cargo value means the release cannot name a package or archive.
  [[ -n $cargo_version ]] || fail_release_contract "Cargo.toml package version is empty"
  require_release_version "$cargo_version"
  # An empty toolchain would let source and platform builds choose independently.
  [[ -n $rust_toolchain ]] || fail_release_contract "Rust toolchain selector is empty"
  contains_line_break "$event_name$ref_name$trigger_sha$rust_toolchain" \
    && fail_release_contract "source context contains a line break"

  trigger_commit=$(git -C "$repository_root" rev-parse "$trigger_sha^{commit}" 2>/dev/null) \
    || fail_release_contract "trigger SHA does not resolve to a commit"
  checkout_commit=$(git -C "$repository_root" rev-parse HEAD) \
    || fail_release_contract "could not resolve checked-out commit"
  require_release_commit "$trigger_commit"
  [[ $checkout_commit == "$trigger_commit" ]] \
    || fail_release_contract "checked-out commit does not match the workflow trigger"

  case $event_name in
    push)
      [[ $ref_name == "v$cargo_version" ]] \
        || fail_release_contract "tag $ref_name does not match Cargo version $cargo_version"
      [[ $(git -C "$repository_root" rev-list -n 1 "refs/tags/$ref_name" 2>/dev/null) == "$trigger_commit" ]] \
        || fail_release_contract "release tag does not resolve to the triggering commit"
      newest_tag=$(latest_release_tag "$repository_root") \
        || fail_release_contract "tag publication requires a previous release history"
      # A tag behind a newer release would publish users onto a stale release line.
      [[ $newest_tag == "$ref_name" ]] \
        || fail_release_contract "tag $ref_name is not the newest release tag ($newest_tag)"
      ;;
    workflow_dispatch)
      newest_tag=$(latest_release_tag "$repository_root") \
        || fail_release_contract "candidate verification requires a previous release tag"
      newest_version=${newest_tag#v}
      version_is_greater_than "$cargo_version" "$newest_version" \
        || fail_release_contract "candidate version $cargo_version must be newer than $newest_tag"
      ;;
    *) fail_release_contract "event must be a tag push or workflow_dispatch candidate" ;;
  esac

  predecessor_tag=$(previous_release_tag "$repository_root" "$cargo_version") \
    || fail_release_contract "could not identify the previous release tag"
  predecessor_commit=$(git -C "$repository_root" rev-list -n 1 "$predecessor_tag") \
    || fail_release_contract "could not resolve previous release commit"
  require_release_commit "$predecessor_commit"
  # A disconnected release would make upgrade history and generated notes misleading.
  if ! git -C "$repository_root" merge-base --is-ancestor "$predecessor_commit" "$trigger_commit"; then
    fail_release_contract "candidate $trigger_commit does not descend from $predecessor_tag ($predecessor_commit)"
  fi

  target_contract_sha256=$(sha256_file "$TARGET_CONTRACT")
  build_matrix=$(bash "$TARGET_CONTRACT" matrix-json) \
    || fail_release_contract "could not build the release target matrix"
  append_workflow_output "$workflow_output_file" version "$cargo_version"
  append_workflow_output "$workflow_output_file" commit "$trigger_commit"
  append_workflow_output "$workflow_output_file" previous_tag "$predecessor_tag"
  append_workflow_output "$workflow_output_file" previous_commit "$predecessor_commit"
  append_workflow_output "$workflow_output_file" rust_toolchain "$rust_toolchain"
  append_workflow_output "$workflow_output_file" target_contract_sha256 "$target_contract_sha256"
  append_workflow_output "$workflow_output_file" build_matrix "$build_matrix"
  printf 'release contract: source %s %s at %s descends from %s\n' \
    "$event_name" "$cargo_version" "$trigger_commit" "$predecessor_tag"
}

# Normalize Cargo's package file list and reject ambiguous or unsafe entries.
normalize_package_file_list() {
  local input_file=$1
  local output_file=$2
  local package_path
  local raw_count=0
  local duplicate_path

  : >"$output_file"
  # Each Cargo-selected path becomes one stable, relative package evidence row.
  while IFS= read -r package_path || [[ -n $package_path ]]; do
    # A blank package row would hide whether Cargo selected an unnamed file.
    [[ -n $package_path ]] || fail_release_contract "Cargo package list contains an empty path"
    contains_line_break "$package_path" \
      && fail_release_contract "Cargo package path contains a line break"
    [[ $package_path != /* && $package_path != .. && $package_path != ../* \
      && $package_path != */../* && $package_path != */.. ]] \
      || fail_release_contract "Cargo package list contains a path outside the crate"
    printf '%s\n' "$package_path" >>"$output_file"
    raw_count=$((raw_count + 1))
  done <"$input_file"
  # No files means the candidate did not produce a publishable Cargo package.
  [[ $raw_count -gt 0 ]] || fail_release_contract "Cargo package list is empty"
  LC_ALL=C sort -o "$output_file" "$output_file"
  duplicate_path=$(uniq -d "$output_file" | head -1 || true)
  # A duplicate path makes the package file-count and digest contract ambiguous.
  [[ -z $duplicate_path ]] || fail_release_contract "Cargo package list contains a duplicate path"
}

# Write the source/package manifest consumed by builds and both publish gates.
write_source_manifest() {
  local output_directory=$1
  local event_name=$2
  local release_version=$3
  local release_commit=$4
  local rust_toolchain=$5
  local predecessor_tag=$6
  local predecessor_commit=$7
  local package_file=$8
  local package_list_file=$9
  local package_basename=gruff-rs-$release_version.crate
  local normalized_package_list
  local build_matrix_file
  local source_manifest
  local package_sha256
  local package_size
  local package_files_sha256
  local package_file_count
  local target_contract_sha256
  local build_matrix_sha256

  require_release_version "$release_version"
  require_release_commit "$release_commit"
  require_release_commit "$predecessor_commit"
  # Empty event or toolchain fields would sever the package from its workflow context.
  [[ -n $event_name && -n $rust_toolchain && -n $predecessor_tag ]] \
    || fail_release_contract "source manifest context contains an empty field"
  [[ -f $package_file && ! -L $package_file ]] \
    || fail_release_contract "Cargo package file is not a regular non-link file"
  [[ ${package_file##*/} == "$package_basename" ]] \
    || fail_release_contract "Cargo package filename does not match release version"
  [[ -f $package_list_file && ! -L $package_list_file ]] \
    || fail_release_contract "Cargo package list is not a regular non-link file"

  # A linked output could redirect candidate evidence outside the runner workspace.
  [[ ! -L $output_directory ]] \
    || fail_release_contract "source manifest output directory must not be a link"
  mkdir -p -- "$output_directory" \
    || fail_release_contract "could not create source manifest output directory"
  # Existing output could mix evidence from two candidate attempts.
  if directory_has_entries "$output_directory"; then
    fail_release_contract "source manifest output directory is not empty"
  fi
  normalized_package_list=$output_directory/package-files.txt
  build_matrix_file=$output_directory/build-matrix.json
  source_manifest=$output_directory/source-manifest.txt
  normalize_package_file_list "$package_list_file" "$normalized_package_list"
  bash "$TARGET_CONTRACT" matrix-json >"$build_matrix_file" \
    || fail_release_contract "could not write build matrix evidence"
  cp -- "$package_file" "$output_directory/$package_basename"

  package_sha256=$(sha256_file "$output_directory/$package_basename")
  package_size=$(file_size_bytes "$output_directory/$package_basename")
  package_files_sha256=$(sha256_file "$normalized_package_list")
  package_file_count=$(wc -l <"$normalized_package_list")
  package_file_count=${package_file_count//[[:space:]]/}
  target_contract_sha256=$(sha256_file "$TARGET_CONTRACT")
  build_matrix_sha256=$(sha256_file "$build_matrix_file")
  {
    printf 'format=gruff-rs-release-source-v1\n'
    printf 'event=%s\n' "$event_name"
    printf 'version=%s\n' "$release_version"
    printf 'commit=%s\n' "$release_commit"
    printf 'toolchain=%s\n' "$rust_toolchain"
    printf 'previous_tag=%s\n' "$predecessor_tag"
    printf 'previous_commit=%s\n' "$predecessor_commit"
    printf 'target_contract_sha256=%s\n' "$target_contract_sha256"
    printf 'build_matrix_sha256=%s\n' "$build_matrix_sha256"
    printf 'package_name=%s\n' "$package_basename"
    printf 'package_sha256=%s\n' "$package_sha256"
    printf 'package_size=%s\n' "$package_size"
    printf 'package_files_sha256=%s\n' "$package_files_sha256"
    printf 'package_file_count=%s\n' "$package_file_count"
  } >"$source_manifest"
  printf 'release contract: packaged %s with %s files\n' \
    "$package_basename" "$package_file_count"
}

# Read one required value from a strict key=value release manifest.
manifest_value() {
  local manifest_file=$1
  local requested_key=$2
  local matching_line_count
  local matching_line
  local manifest_value_text

  matching_line_count=$(grep -c "^${requested_key}=" "$manifest_file" || true)
  [[ $matching_line_count -eq 1 ]] \
    || fail_release_contract "${manifest_file##*/} must contain one $requested_key field"
  matching_line=$(grep "^${requested_key}=" "$manifest_file")
  manifest_value_text=${matching_line#*=}
  # An empty field gives later jobs no identity to compare.
  [[ -n $manifest_value_text ]] \
    || fail_release_contract "${manifest_file##*/} contains an empty $requested_key field"
  printf '%s\n' "$manifest_value_text"
}

# Require exactly the named one-per-line keys in a manifest with no duplicates.
require_exact_manifest_keys() {
  local manifest_file=$1
  shift
  local expected_keys_file=$PRIVATE_WORK_DIR/expected-keys
  local actual_keys_file=$PRIVATE_WORK_DIR/actual-keys
  local expected_key

  : >"$expected_keys_file"
  # Each caller-provided key defines one field a reviewer expects to see.
  for expected_key in "$@"; do
    printf '%s\n' "$expected_key" >>"$expected_keys_file"
  done
  cut -d= -f1 "$manifest_file" | LC_ALL=C sort >"$actual_keys_file"
  LC_ALL=C sort -o "$expected_keys_file" "$expected_keys_file"
  cmp -s "$expected_keys_file" "$actual_keys_file" \
    || fail_release_contract "${manifest_file##*/} contains missing, extra, or duplicate fields"
}

# Verify source evidence before a build, asset check, or crate publication uses it.
verify_source_manifest() {
  local source_directory=$1
  local expected_event=$2
  local expected_version=$3
  local expected_commit=$4
  local expected_toolchain=$5
  local source_manifest=$source_directory/source-manifest.txt
  local package_list=$source_directory/package-files.txt
  local build_matrix=$source_directory/build-matrix.json
  local package_name
  local package_file
  local actual_source_files=$PRIVATE_WORK_DIR/source-files
  local expected_source_files=$PRIVATE_WORK_DIR/expected-source-files
  local recorded_package_file_count
  local actual_package_file_count

  # A linked source directory could substitute evidence from outside this run.
  [[ -d $source_directory && ! -L $source_directory ]] \
    || fail_release_contract "source verification directory is missing or linked"
  [[ -f $source_manifest && ! -L $source_manifest ]] \
    || fail_release_contract "source-manifest.txt is missing or not a regular file"
  require_exact_manifest_keys "$source_manifest" \
    format event version commit toolchain previous_tag previous_commit \
    target_contract_sha256 build_matrix_sha256 package_name package_sha256 \
    package_size package_files_sha256 package_file_count
  [[ $(manifest_value "$source_manifest" format) == gruff-rs-release-source-v1 ]] \
    || fail_release_contract "source manifest format is unsupported"
  [[ $(manifest_value "$source_manifest" event) == "$expected_event" ]] \
    || fail_release_contract "source manifest event does not match this workflow"
  [[ $(manifest_value "$source_manifest" version) == "$expected_version" ]] \
    || fail_release_contract "source manifest version does not match this workflow"
  [[ $(manifest_value "$source_manifest" commit) == "$expected_commit" ]] \
    || fail_release_contract "source manifest commit does not match this workflow"
  [[ $(manifest_value "$source_manifest" toolchain) == "$expected_toolchain" ]] \
    || fail_release_contract "source manifest toolchain does not match this workflow"
  [[ $(manifest_value "$source_manifest" target_contract_sha256) == "$(sha256_file "$TARGET_CONTRACT")" ]] \
    || fail_release_contract "source manifest target contract does not match the checkout"
  [[ -f $package_list && ! -L $package_list && -f $build_matrix && ! -L $build_matrix ]] \
    || fail_release_contract "source package-list or matrix evidence is missing"
  [[ $(manifest_value "$source_manifest" package_files_sha256) == "$(sha256_file "$package_list")" ]] \
    || fail_release_contract "source package file-list digest does not match"
  [[ $(manifest_value "$source_manifest" build_matrix_sha256) == "$(sha256_file "$build_matrix")" ]] \
    || fail_release_contract "source build-matrix digest does not match"
  [[ $(sha256_file "$build_matrix") == "$(bash "$TARGET_CONTRACT" matrix-json | sha256_file /dev/stdin)" ]] \
    || fail_release_contract "source build matrix does not match the target contract"

  package_name=$(manifest_value "$source_manifest" package_name)
  package_file=$source_directory/$package_name
  [[ -f $package_file && ! -L $package_file ]] \
    || fail_release_contract "source package artifact is missing or not a regular file"
  [[ $(manifest_value "$source_manifest" package_sha256) == "$(sha256_file "$package_file")" ]] \
    || fail_release_contract "source package digest does not match"
  [[ $(manifest_value "$source_manifest" package_size) == "$(file_size_bytes "$package_file")" ]] \
    || fail_release_contract "source package size does not match"
  recorded_package_file_count=$(manifest_value "$source_manifest" package_file_count)
  # A non-number cannot describe how many files a user receives in the crate.
  [[ $recorded_package_file_count =~ ^[0-9]+$ ]] \
    || fail_release_contract "source package file count is not numeric"
  actual_package_file_count=$(wc -l <"$package_list")
  actual_package_file_count=${actual_package_file_count//[[:space:]]/}
  [[ $recorded_package_file_count == "$actual_package_file_count" ]] \
    || fail_release_contract "source package file count does not match"

  write_directory_entry_names "$source_directory" "$actual_source_files"
  printf '%s\n' build-matrix.json package-files.txt source-manifest.txt "$package_name" \
    | LC_ALL=C sort >"$expected_source_files"
  cmp -s "$expected_source_files" "$actual_source_files" \
    || fail_release_contract "source verification artifact contains missing or extra files"
}

# Resolve one target row into fields used by archive creation and verification.
resolve_release_target_fields() {
  local release_target=$1
  local target_record
  local unexpected_field

  target_record=$(bash "$TARGET_CONTRACT" resolve-target "$release_target") \
    || fail_release_contract "release target is not supported: $release_target"
  IFS='|' read -r TARGET RUNNER_LABEL ARCHIVE_KIND BUILD_MODE RUNNER_OS RUNNER_ARCH \
    BINARY_NAME unexpected_field <<<"$target_record"
  # Empty or extra fields indicate the checked-in target contract is malformed.
  [[ -n $TARGET && -n $RUNNER_LABEL && -n $ARCHIVE_KIND && -n $BUILD_MODE \
    && -n $RUNNER_OS && -n $RUNNER_ARCH && -n $BINARY_NAME \
    && -z $unexpected_field ]] \
    || fail_release_contract "release target contract returned an invalid record"
}

# Build one release-shaped archive and identity file from a compiled binary.
stage_release_archive() {
  local repository_root=$1
  local release_version=$2
  local release_commit=$3
  local rust_toolchain=$4
  local release_target=$5
  local compiled_binary=$6
  local output_directory=$7
  local archive_root
  local archive_basename
  local archive_file
  local checksum_file
  local identity_file
  local stage_directory
  local archive_sha256
  local archive_size
  local target_contract_sha256
  local release_document

  require_release_version "$release_version"
  require_release_commit "$release_commit"
  # An empty toolchain would make this archive impossible to compare with source evidence.
  [[ -n $rust_toolchain ]] || fail_release_contract "archive toolchain is empty"
  resolve_release_target_fields "$release_target"
  [[ -f $compiled_binary && ! -L $compiled_binary ]] \
    || fail_release_contract "compiled binary is missing or not a regular file"
  [[ ${compiled_binary##*/} == "$BINARY_NAME" ]] \
    || fail_release_contract "compiled binary name does not match target contract"
  # A linked output could redirect a platform archive outside the runner workspace.
  [[ ! -L $output_directory ]] \
    || fail_release_contract "archive output directory must not be a link"
  mkdir -p -- "$output_directory" \
    || fail_release_contract "could not create archive output directory"
  # Existing files could mix two targets or attempts in one uploaded artifact.
  if directory_has_entries "$output_directory"; then
    fail_release_contract "archive output directory is not empty"
  fi
  create_private_work_dir
  archive_root=gruff-rs-$release_version-$TARGET
  stage_directory=$PRIVATE_WORK_DIR/$archive_root
  mkdir -p -- "$stage_directory"
  cp -- "$compiled_binary" "$stage_directory/$BINARY_NAME"
  # Each public document must come from this checkout, not a linked external file.
  for release_document in README.md LICENSE-MIT LICENSE-APACHE CHANGELOG.md; do
    # A missing or linked document would make the user's archive unreviewable.
    [[ -f $repository_root/$release_document && ! -L $repository_root/$release_document ]] \
      || fail_release_contract "release document is missing or linked: $release_document"
  done
  cp -- "$repository_root/README.md" "$repository_root/LICENSE-MIT" \
    "$repository_root/LICENSE-APACHE" "$repository_root/CHANGELOG.md" "$stage_directory/"

  archive_basename=$archive_root.$ARCHIVE_KIND
  archive_file=$output_directory/$archive_basename
  case $ARCHIVE_KIND in
    tar.gz)
      require_release_command tar
      (cd -- "$PRIVATE_WORK_DIR" && tar -czf "$archive_file" "$archive_root") \
        || fail_release_contract "could not create $archive_basename"
      ;;
    zip)
      # Local verification commonly has zip; Windows hosted release jobs expose 7z.
      if command -v 7z >/dev/null 2>&1; then
        (cd -- "$PRIVATE_WORK_DIR" && 7z a "$archive_file" "$archive_root" >/dev/null) \
          || fail_release_contract "could not create $archive_basename"
      # Local maintainers can use zip when their machine does not provide 7z.
      elif command -v zip >/dev/null 2>&1; then
        (cd -- "$PRIVATE_WORK_DIR" && zip -qr "$archive_file" "$archive_root") \
          || fail_release_contract "could not create $archive_basename"
      else
        fail_release_contract "7z or zip is required to create the Windows archive"
      fi
      ;;
    *) fail_release_contract "unsupported archive kind: $ARCHIVE_KIND" ;;
  esac

  archive_sha256=$(sha256_file "$archive_file")
  archive_size=$(file_size_bytes "$archive_file")
  checksum_file=$archive_file.sha256
  printf '%s  %s\n' "$archive_sha256" "$archive_basename" >"$checksum_file"
  identity_file=$output_directory/build-identity-$TARGET.txt
  target_contract_sha256=$(sha256_file "$TARGET_CONTRACT")
  {
    printf 'format=gruff-rs-release-build-v1\n'
    printf 'version=%s\n' "$release_version"
    printf 'commit=%s\n' "$release_commit"
    printf 'toolchain=%s\n' "$rust_toolchain"
    printf 'target=%s\n' "$TARGET"
    printf 'archive=%s\n' "$archive_basename"
    printf 'archive_sha256=%s\n' "$archive_sha256"
    printf 'archive_size=%s\n' "$archive_size"
    printf 'target_contract_sha256=%s\n' "$target_contract_sha256"
  } >"$identity_file"
  printf 'release contract: staged %s\n' "$archive_basename"
}

# Require the publisher's checksum sidecar to name only its matching archive.
verify_checksum_sidecar() {
  local sidecar_file=$1
  local archive_file=$2
  local expected_basename=${archive_file##*/}
  local sidecar_line=""
  local current_line
  local sidecar_line_count=0
  local expected_sha256

  # Each sidecar row is counted so a second checksum cannot select another file.
  while IFS= read -r current_line || [[ -n $current_line ]]; do
    sidecar_line=$current_line
    sidecar_line_count=$((sidecar_line_count + 1))
  done <"$sidecar_file"
  [[ $sidecar_line_count -eq 1 ]] \
    || fail_release_contract "${sidecar_file##*/} must contain exactly one line"
  expected_sha256=${sidecar_line:0:64}
  [[ $expected_sha256 =~ ^[0-9a-f]{64}$ \
    && $sidecar_line == "$expected_sha256  $expected_basename" ]] \
    || fail_release_contract "${sidecar_file##*/} has an invalid checksum record"
  [[ $(sha256_file "$archive_file") == "$expected_sha256" ]] \
    || fail_release_contract "$expected_basename checksum does not match"
}

# Require one archive root, binary, README, licenses, and changelog by name.
validate_archive_member_names() {
  local member_listing_file=$1
  local archive_root=$2
  local binary_name=$3
  local archive_member
  local root_seen=0
  local binary_seen=0
  local readme_seen=0
  local mit_seen=0
  local apache_seen=0
  local changelog_seen=0

  # Every member must be one file a release user expects to download or inspect.
  while IFS= read -r archive_member || [[ -n $archive_member ]]; do
    archive_member=${archive_member//\\//}
    [[ $archive_member != "$archive_root" ]] || archive_member=$archive_member/
    case $archive_member in
      "$archive_root/") ((root_seen == 0)) || fail_release_contract "duplicate archive root"; root_seen=1 ;;
      "$archive_root/$binary_name") ((binary_seen == 0)) || fail_release_contract "duplicate archive binary"; binary_seen=1 ;;
      "$archive_root/README.md") ((readme_seen == 0)) || fail_release_contract "duplicate archive README"; readme_seen=1 ;;
      "$archive_root/LICENSE-MIT") ((mit_seen == 0)) || fail_release_contract "duplicate archive MIT license"; mit_seen=1 ;;
      "$archive_root/LICENSE-APACHE") ((apache_seen == 0)) || fail_release_contract "duplicate archive Apache license"; apache_seen=1 ;;
      "$archive_root/CHANGELOG.md") ((changelog_seen == 0)) || fail_release_contract "duplicate archive changelog"; changelog_seen=1 ;;
      *) fail_release_contract "archive contains an unexpected member" ;;
    esac
  done <"$member_listing_file"
  [[ $root_seen -eq 1 && $binary_seen -eq 1 && $readme_seen -eq 1 \
    && $mit_seen -eq 1 && $apache_seen -eq 1 && $changelog_seen -eq 1 ]] \
    || fail_release_contract "archive member set is incomplete"
}

# Inspect one tar archive without extracting any publisher-controlled path.
validate_tar_release_archive() {
  local archive_file=$1
  local archive_root=$2
  local binary_name=$3
  local member_listing_file=$PRIVATE_WORK_DIR/tar-members
  local member_types_file=$PRIVATE_WORK_DIR/tar-types
  local verbose_member_line
  local directory_count=0
  local file_count=0

  require_release_command tar
  tar -tzf "$archive_file" >"$member_listing_file" \
    || fail_release_contract "could not list ${archive_file##*/}"
  validate_archive_member_names "$member_listing_file" "$archive_root" "$binary_name"
  tar -tvzf "$archive_file" >"$member_types_file" \
    || fail_release_contract "could not inspect ${archive_file##*/} member types"
  # Each member type must be a regular file or the one expected directory.
  while IFS= read -r verbose_member_line || [[ -n $verbose_member_line ]]; do
    case ${verbose_member_line:0:1} in
      d) directory_count=$((directory_count + 1)) ;;
      -) file_count=$((file_count + 1)) ;;
      *) fail_release_contract "tar archive contains a link or special member" ;;
    esac
  done <"$member_types_file"
  [[ $directory_count -eq 1 && $file_count -eq 5 ]] \
    || fail_release_contract "tar archive member types do not match the release contract"
}

# Inspect one zip archive without extracting any publisher-controlled path.
validate_zip_release_archive() {
  local archive_file=$1
  local archive_root=$2
  local binary_name=$3
  local member_listing_file=$PRIVATE_WORK_DIR/zip-members
  local member_types_file=$PRIVATE_WORK_DIR/zip-types
  local verbose_member_line
  local directory_count=0
  local file_count=0

  require_release_command unzip
  require_release_command zipinfo
  unzip -Z1 "$archive_file" >"$member_listing_file" \
    || fail_release_contract "could not list ${archive_file##*/}"
  validate_archive_member_names "$member_listing_file" "$archive_root" "$binary_name"
  zipinfo -l "$archive_file" >"$member_types_file" \
    || fail_release_contract "could not inspect ${archive_file##*/} member types"
  # Only permission rows describe archive members; headers and totals are skipped.
  while IFS= read -r verbose_member_line || [[ -n $verbose_member_line ]]; do
    # A permission row exposes whether the stored member is a file, directory, or link.
    if [[ $verbose_member_line =~ ^[dl-][rwx-]{9}[[:space:]] ]]; then
      case ${verbose_member_line:0:1} in
        d) directory_count=$((directory_count + 1)) ;;
        -) file_count=$((file_count + 1)) ;;
        *) fail_release_contract "zip archive contains a link or special member" ;;
      esac
    fi
  done <"$member_types_file"
  [[ $directory_count -eq 1 && $file_count -eq 5 ]] \
    || fail_release_contract "zip archive member types do not match the release contract"
}

# Validate one platform archive against its canonical target/member contract.
validate_release_archive() {
  local archive_file=$1
  local release_version=$2
  local release_target=$3
  local archive_root=gruff-rs-$release_version-$release_target

  resolve_release_target_fields "$release_target"
  case $ARCHIVE_KIND in
    tar.gz) validate_tar_release_archive "$archive_file" "$archive_root" "$BINARY_NAME" ;;
    zip) validate_zip_release_archive "$archive_file" "$archive_root" "$BINARY_NAME" ;;
    *) fail_release_contract "unsupported archive kind: $ARCHIVE_KIND" ;;
  esac
}

# Verify one build identity binds its archive to source, target, and toolchain.
verify_build_identity() {
  local identity_file=$1
  local expected_version=$2
  local expected_commit=$3
  local expected_toolchain=$4
  local expected_target=$5
  local expected_archive=$6
  local archive_file=$7

  require_exact_manifest_keys "$identity_file" format version commit toolchain target \
    archive archive_sha256 archive_size target_contract_sha256
  [[ $(manifest_value "$identity_file" format) == gruff-rs-release-build-v1 ]] \
    || fail_release_contract "build identity format is unsupported"
  [[ $(manifest_value "$identity_file" version) == "$expected_version" ]] \
    || fail_release_contract "build identity version does not match"
  [[ $(manifest_value "$identity_file" commit) == "$expected_commit" ]] \
    || fail_release_contract "build identity commit does not match"
  [[ $(manifest_value "$identity_file" toolchain) == "$expected_toolchain" ]] \
    || fail_release_contract "build identity toolchain does not match"
  [[ $(manifest_value "$identity_file" target) == "$expected_target" ]] \
    || fail_release_contract "build identity target does not match"
  [[ $(manifest_value "$identity_file" archive) == "$expected_archive" ]] \
    || fail_release_contract "build identity archive name does not match"
  [[ $(manifest_value "$identity_file" archive_sha256) == "$(sha256_file "$archive_file")" ]] \
    || fail_release_contract "build identity archive digest does not match"
  [[ $(manifest_value "$identity_file" archive_size) == "$(file_size_bytes "$archive_file")" ]] \
    || fail_release_contract "build identity archive size does not match"
  [[ $(manifest_value "$identity_file" target_contract_sha256) == "$(sha256_file "$TARGET_CONTRACT")" ]] \
    || fail_release_contract "build identity target contract does not match"
}

# Build the exact filenames expected after GitHub merges all five build artifacts.
write_expected_build_file_list() {
  local release_version=$1
  local output_file=$2
  local target
  local archive_kind
  local _runner_label
  local _build_mode
  local _runner_os
  local _runner_arch
  local _binary_name
  local archive_basename

  : >"$output_file"
  # Every build contributes one archive, sidecar, and target identity file.
  while IFS='|' read -r target _runner_label archive_kind _build_mode _runner_os _runner_arch _binary_name; do
    archive_basename=gruff-rs-$release_version-$target.$archive_kind
    printf '%s\n%s.sha256\nbuild-identity-%s.txt\n' \
      "$archive_basename" "$archive_basename" "$target" >>"$output_file"
  done < <(bash "$TARGET_CONTRACT" table)
  LC_ALL=C sort -o "$output_file" "$output_file"
}

# Verify all build artifacts and create one candidate/release evidence directory.
verify_release_asset_set() {
  local build_directory=$1
  local source_directory=$2
  local output_directory=$3
  local expected_event=$4
  local release_version=$5
  local release_commit=$6
  local rust_toolchain=$7
  local expected_build_files
  local actual_build_files
  local release_manifest
  local source_manifest=$source_directory/source-manifest.txt
  local target
  local archive_kind
  local _runner_label
  local _build_mode
  local _runner_os
  local _runner_arch
  local _binary_name
  local archive_basename
  local archive_file
  local checksum_file
  local identity_file
  local asset_basename
  local asset_file

  create_private_work_dir
  expected_build_files=$PRIVATE_WORK_DIR/expected-build-files
  actual_build_files=$PRIVATE_WORK_DIR/actual-build-files
  verify_source_manifest "$source_directory" "$expected_event" "$release_version" \
    "$release_commit" "$rust_toolchain"
  # A linked build directory could replace one runner's uploaded evidence.
  [[ -d $build_directory && ! -L $build_directory ]] \
    || fail_release_contract "downloaded build directory is missing or linked"
  # A linked output could redirect verified user downloads outside the workspace.
  [[ ! -L $output_directory ]] \
    || fail_release_contract "verified release output directory must not be a link"
  mkdir -p -- "$output_directory" \
    || fail_release_contract "could not create verified release output directory"
  # Existing verified files could mix candidate evidence from separate commits.
  if directory_has_entries "$output_directory"; then
    fail_release_contract "verified release output directory is not empty"
  fi
  write_expected_build_file_list "$release_version" "$expected_build_files"
  write_directory_entry_names "$build_directory" "$actual_build_files"
  cmp -s "$expected_build_files" "$actual_build_files" \
    || fail_release_contract "downloaded build set contains missing, extra, or duplicate files"

  # Each target is checksum-checked, member-checked, identity-checked, then copied.
  while IFS='|' read -r target _runner_label archive_kind _build_mode _runner_os _runner_arch _binary_name; do
    archive_basename=gruff-rs-$release_version-$target.$archive_kind
    archive_file=$build_directory/$archive_basename
    checksum_file=$archive_file.sha256
    identity_file=$build_directory/build-identity-$target.txt
    [[ -f $archive_file && ! -L $archive_file && -f $checksum_file && ! -L $checksum_file \
      && -f $identity_file && ! -L $identity_file ]] \
      || fail_release_contract "target $target has a missing or non-regular build file"
    verify_checksum_sidecar "$checksum_file" "$archive_file"
    validate_release_archive "$archive_file" "$release_version" "$target"
    verify_build_identity "$identity_file" "$release_version" "$release_commit" \
      "$rust_toolchain" "$target" "$archive_basename" "$archive_file"
    cp -- "$archive_file" "$checksum_file" "$output_directory/"
  done < <(bash "$TARGET_CONTRACT" table)

  cp -- "$source_directory/source-manifest.txt" "$source_directory/package-files.txt" \
    "$source_directory/build-matrix.json" "$output_directory/"
  release_manifest=$output_directory/release-assets-manifest.txt
  {
    printf 'format=gruff-rs-release-assets-v1\n'
    printf 'event=%s\n' "$expected_event"
    printf 'version=%s\n' "$release_version"
    printf 'commit=%s\n' "$release_commit"
    printf 'toolchain=%s\n' "$rust_toolchain"
    printf 'previous_tag=%s\n' "$(manifest_value "$source_manifest" previous_tag)"
    printf 'previous_commit=%s\n' "$(manifest_value "$source_manifest" previous_commit)"
    printf 'target_contract_sha256=%s\n' "$(sha256_file "$TARGET_CONTRACT")"
    printf 'source_manifest_sha256=%s\n' "$(sha256_file "$source_manifest")"
    printf 'package_name=%s\n' "$(manifest_value "$source_manifest" package_name)"
    printf 'package_sha256=%s\n' "$(manifest_value "$source_manifest" package_sha256)"
    printf 'package_files_sha256=%s\n' "$(manifest_value "$source_manifest" package_files_sha256)"
    # Every published archive and sidecar is bound by name, digest, and size.
    while IFS= read -r asset_basename; do
      asset_file=$output_directory/$asset_basename
      printf 'asset=%s|%s|%s\n' "$asset_basename" \
        "$(sha256_file "$asset_file")" "$(file_size_bytes "$asset_file")"
    done < <(bash "$TARGET_CONTRACT" expected-assets "$release_version")
  } >"$release_manifest"
  printf 'release contract: verified five targets and ten release assets\n'
}

# Validate the final manifest and print only files allowed on the GitHub release.
print_publishable_release_files() {
  local verified_directory=$1
  local release_manifest=$verified_directory/release-assets-manifest.txt
  local release_version
  local expected_assets
  local manifest_assets
  local asset_record
  local asset_basename
  local asset_sha256
  local asset_size
  local asset_file

  create_private_work_dir
  expected_assets=$PRIVATE_WORK_DIR/expected-release-assets
  manifest_assets=$PRIVATE_WORK_DIR/manifest-release-assets
  # A linked directory could swap the files a maintainer is about to publish.
  [[ -d $verified_directory && ! -L $verified_directory ]] \
    || fail_release_contract "verified release directory is missing or linked"
  [[ -f $release_manifest && ! -L $release_manifest ]] \
    || fail_release_contract "release asset manifest is missing or not a regular file"
  release_version=$(manifest_value "$release_manifest" version)
  require_release_version "$release_version"
  bash "$TARGET_CONTRACT" expected-assets "$release_version" | LC_ALL=C sort \
    >"$expected_assets"
  grep '^asset=' "$release_manifest" | cut -d= -f2- | cut -d'|' -f1 | LC_ALL=C sort \
    >"$manifest_assets"
  cmp -s "$expected_assets" "$manifest_assets" \
    || fail_release_contract "release manifest contains missing, extra, or duplicate assets"

  # Each manifest row is rechecked against the exact file about to be uploaded.
  while IFS= read -r asset_record; do
    IFS='|' read -r asset_basename asset_sha256 asset_size <<<"${asset_record#asset=}"
    asset_file=$verified_directory/$asset_basename
    [[ $asset_basename != */* && -f $asset_file && ! -L $asset_file ]] \
      || fail_release_contract "publishable asset is missing or not a regular file"
    [[ $asset_sha256 == "$(sha256_file "$asset_file")" ]] \
      || fail_release_contract "publishable asset digest does not match: $asset_basename"
    [[ $asset_size == "$(file_size_bytes "$asset_file")" ]] \
      || fail_release_contract "publishable asset size does not match: $asset_basename"
    printf '%s\n' "$asset_file"
  done < <(grep '^asset=' "$release_manifest")
  printf '%s\n' "$release_manifest"
}

# Compare a freshly recreated Cargo package with source verification evidence.
verify_recreated_package() {
  local source_directory=$1
  local recreated_package=$2
  local recreated_package_list=$3
  local normalized_package_list
  local source_manifest=$source_directory/source-manifest.txt

  create_private_work_dir
  normalized_package_list=$PRIVATE_WORK_DIR/recreated-package-files
  # A linked source directory could compare the crate against unrelated evidence.
  [[ -d $source_directory && ! -L $source_directory ]] \
    || fail_release_contract "source verification directory is missing or linked"
  [[ -f $source_manifest ]] || fail_release_contract "source manifest is missing"
  [[ -f $recreated_package && ! -L $recreated_package ]] \
    || fail_release_contract "recreated Cargo package is missing or not a regular file"
  normalize_package_file_list "$recreated_package_list" "$normalized_package_list"
  [[ ${recreated_package##*/} == "$(manifest_value "$source_manifest" package_name)" ]] \
    || fail_release_contract "recreated Cargo package name does not match"
  [[ $(sha256_file "$recreated_package") == "$(manifest_value "$source_manifest" package_sha256)" ]] \
    || fail_release_contract "recreated Cargo package digest does not match source verification"
  [[ $(file_size_bytes "$recreated_package") == "$(manifest_value "$source_manifest" package_size)" ]] \
    || fail_release_contract "recreated Cargo package size does not match source verification"
  [[ $(sha256_file "$normalized_package_list") == "$(manifest_value "$source_manifest" package_files_sha256)" ]] \
    || fail_release_contract "recreated Cargo package file list does not match source verification"
  printf 'release contract: recreated Cargo package matches source verification\n'
}

# Require a draft release to contain exactly the local verified names and sizes.
verify_remote_draft_assets() {
  local verified_directory=$1
  local remote_release_json=$2
  local release_version=$3
  local expected_assets
  local actual_assets
  local publishable_file

  create_private_work_dir
  expected_assets=$PRIVATE_WORK_DIR/expected-draft-assets
  actual_assets=$PRIVATE_WORK_DIR/actual-draft-assets
  require_release_command jq
  require_release_version "$release_version"
  # A missing or linked JSON file cannot prove what users would see on GitHub.
  [[ -f $remote_release_json && ! -L $remote_release_json ]] \
    || fail_release_contract "remote release JSON is missing or linked"
  jq -e --arg tag "v$release_version" '.isDraft == true and .tagName == $tag' \
    "$remote_release_json" >/dev/null \
    || fail_release_contract "remote release is not the expected draft tag"
  : >"$expected_assets"
  # Each locally verified publishable file contributes its remote name and byte size.
  while IFS= read -r publishable_file; do
    printf '%s\t%s\n' "${publishable_file##*/}" "$(file_size_bytes "$publishable_file")" \
      >>"$expected_assets"
  done < <(print_publishable_release_files "$verified_directory")
  LC_ALL=C sort -o "$expected_assets" "$expected_assets"
  jq -r '.assets[] | [.name, .size] | @tsv' "$remote_release_json" \
    | LC_ALL=C sort >"$actual_assets"
  cmp -s "$expected_assets" "$actual_assets" \
    || fail_release_contract "draft release contains missing, extra, or wrong-size assets"
  printf 'release contract: draft contains the complete verified asset set\n'
}

# Route only the release stages invoked by the checked-in workflow and harness.
dispatch_release_contract_command() {
  # No command means the workflow did not select a release stage to verify.
  case ${1:-} in
    resolve-source)
      # Six fields bind the workflow trigger to its selected source checkout.
      [[ $# -eq 7 ]] || fail_release_contract "resolve-source requires repository, event, ref, SHA, toolchain, and output file"
      resolve_source_context "$2" "$3" "$4" "$5" "$6" "$7"
      ;;
    write-source-manifest)
      # Nine fields bind the Cargo package to source, lineage, and toolchain evidence.
      [[ $# -eq 10 ]] || fail_release_contract "write-source-manifest received the wrong field count"
      write_source_manifest "$2" "$3" "$4" "$5" "$6" "$7" "$8" "$9" "${10}"
      ;;
    stage-archive)
      # Seven fields bind one compiled binary to its public platform archive.
      [[ $# -eq 8 ]] || fail_release_contract "stage-archive received the wrong field count"
      stage_release_archive "$2" "$3" "$4" "$5" "$6" "$7" "$8"
      ;;
    verify-assets)
      # Seven fields join source evidence with all downloaded platform artifacts.
      [[ $# -eq 8 ]] || fail_release_contract "verify-assets received the wrong field count"
      verify_release_asset_set "$2" "$3" "$4" "$5" "$6" "$7" "$8"
      ;;
    publish-files)
      # One verified directory determines the exact files a release may expose.
      [[ $# -eq 2 ]] || fail_release_contract "publish-files requires one directory"
      print_publishable_release_files "$2"
      ;;
    verify-package)
      # Three files prove the package recreated immediately before publication.
      [[ $# -eq 4 ]] || fail_release_contract "verify-package requires source evidence, package, and file list"
      verify_recreated_package "$2" "$3" "$4"
      ;;
    verify-draft)
      # Three fields prove the remote draft holds only the complete local asset set.
      [[ $# -eq 4 ]] || fail_release_contract "verify-draft requires verified files, release JSON, and version"
      verify_remote_draft_assets "$2" "$3" "$4"
      ;;
    *) fail_release_contract "unknown release-contract stage" ;;
  esac
}

dispatch_release_contract_command "$@"
