#!/usr/bin/env bash
# Canonical platform contract for gruff-rs release artifacts.
# Release jobs use it to build the five supported archives, while the composite
# action uses the same rows to select the archive a workflow user can install.
# Keep target, runner, archive, and binary names together so they cannot drift.

set -euo pipefail

# Stop when a release command cannot produce one unambiguous target result.
fail_target_contract() {
  printf 'release target contract: %s\n' "$*" >&2
  exit 2
}

# Print the reviewed target rows consumed by release and action workflows.
print_release_targets() {
  cat <<'TARGETS'
x86_64-unknown-linux-gnu|ubuntu-24.04|tar.gz|native|Linux|X64|gruff-rs
aarch64-unknown-linux-gnu|ubuntu-24.04|tar.gz|cross|Linux|ARM64|gruff-rs
x86_64-apple-darwin|macos-15-intel|tar.gz|native|macOS|X64|gruff-rs
aarch64-apple-darwin|macos-15|tar.gz|native|macOS|ARM64|gruff-rs
x86_64-pc-windows-msvc|windows-2025|zip|native|Windows|X64|gruff-rs.exe
TARGETS
}

# Reject workflow fields that could split one target record across output lines.
contains_line_break() {
  [[ $1 == *$'\n'* || $1 == *$'\r'* ]]
}

# Accept the core Cargo release versions used for tags and archive names.
release_version_is_valid() {
  [[ $1 =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]
}

# Require one safe Cargo version before constructing user-downloadable filenames.
require_release_version() {
  local release_version=$1

  release_version_is_valid "$release_version" \
    || fail_target_contract "version must be an exact X.Y.Z release"
}

# Emit the matrix object GitHub uses to schedule every supported release runner.
print_build_matrix_json() {
  local target
  local runner_label
  local archive_kind
  local build_mode
  local runner_os
  local runner_arch
  local binary_name
  local separator=""

  printf '{"include":['
  # Each canonical row becomes one hosted build visible in the Actions graph.
  while IFS='|' read -r target runner_label archive_kind build_mode runner_os runner_arch binary_name; do
    printf '%s' "$separator"
    printf '{"target":"%s","os":"%s","archive":"%s","build":"%s","binary":"%s"}' \
      "$target" "$runner_label" "$archive_kind" "$build_mode" "$binary_name"
    separator=,
  done < <(print_release_targets)
  printf ']}\n'
}

# Resolve one action runner into the exact target, archive, and binary names.
resolve_action_runner() {
  local requested_runner_os=$1
  local requested_runner_arch=$2
  local target
  local runner_label
  local archive_kind
  local build_mode
  local runner_os
  local runner_arch
  local binary_name

  contains_line_break "$requested_runner_os$requested_runner_arch" \
    && fail_target_contract "runner metadata must not contain line breaks"
  # Each row is checked until the user's hosted runner has one exact match.
  while IFS='|' read -r target runner_label archive_kind build_mode runner_os runner_arch binary_name; do
    # A matching OS and architecture identify the user's downloadable asset.
    if [[ $requested_runner_os == "$runner_os" && $requested_runner_arch == "$runner_arch" ]]; then
      printf '%s|%s|%s\n' "$target" "$archive_kind" "$binary_name"
      return 0
    fi
  done < <(print_release_targets)
  fail_target_contract "unsupported action runner: $requested_runner_os/$requested_runner_arch"
}

# Resolve one release target into its complete reviewed build record.
resolve_release_target() {
  local requested_target=$1
  local target
  local runner_label
  local archive_kind
  local build_mode
  local runner_os
  local runner_arch
  local binary_name

  contains_line_break "$requested_target" \
    && fail_target_contract "target must not contain line breaks"
  # Each row is checked until the release job's target has one exact match.
  while IFS='|' read -r target runner_label archive_kind build_mode runner_os runner_arch binary_name; do
    # A matching target returns every field used to build and inspect its asset.
    if [[ $requested_target == "$target" ]]; then
      printf '%s|%s|%s|%s|%s|%s|%s\n' \
        "$target" "$runner_label" "$archive_kind" "$build_mode" \
        "$runner_os" "$runner_arch" "$binary_name"
      return 0
    fi
  done < <(print_release_targets)
  fail_target_contract "unsupported release target: $requested_target"
}

# List the ten archive and checksum filenames a complete release must contain.
print_expected_release_assets() {
  local release_version=$1
  local target
  local runner_label
  local archive_kind
  local build_mode
  local runner_os
  local runner_arch
  local binary_name
  local archive_basename

  require_release_version "$release_version"
  # Every target contributes exactly one archive and its matching checksum.
  while IFS='|' read -r target runner_label archive_kind build_mode runner_os runner_arch binary_name; do
    archive_basename=gruff-rs-$release_version-$target.$archive_kind
    printf '%s\n%s.sha256\n' "$archive_basename" "$archive_basename"
  done < <(print_release_targets)
}

# Route the small command surface used by workflows and contract tests.
dispatch_target_command() {
  # No command means the caller did not request a target view or lookup.
  case ${1:-} in
    table) print_release_targets ;;
    matrix-json) print_build_matrix_json ;;
    resolve-runner)
      # Missing runner fields mean the action cannot select a user download.
      [[ $# -eq 3 ]] || fail_target_contract "resolve-runner requires OS and architecture"
      resolve_action_runner "$2" "$3"
      ;;
    resolve-target)
      # A missing target means the release job cannot select a build contract.
      [[ $# -eq 2 ]] || fail_target_contract "resolve-target requires one target"
      resolve_release_target "$2"
      ;;
    expected-assets)
      # A missing version means release filenames cannot be constructed safely.
      [[ $# -eq 2 ]] || fail_target_contract "expected-assets requires one version"
      print_expected_release_assets "$2"
      ;;
    *) fail_target_contract "expected table, matrix-json, resolve-runner, resolve-target, or expected-assets" ;;
  esac
}

dispatch_target_command "$@"
