#!/usr/bin/env bash
# Install the exact developer tools used by local preflight and hosted CI.
# Run this when a check reports a missing or stale validator; successful output
# lists the installed versions. Project source, Cargo metadata, and Git state
# remain unchanged so developers can safely repeat setup.

set -u
set -o pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

FORCE=0
INSTALL_ROOT=""
CARGO_AUDIT_VERSION=0.22.2
ACTION_VALIDATOR_VERSION=0.9.0
ACTIONLINT_VERSION=1.7.12

# Interactive users get readable status colours; redirected CI logs stay plain.
if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
  BOLD=$'\033[1m'
  DIM=$'\033[2m'
  GREEN=$'\033[32m'
  RESET=$'\033[0m'
else
  BOLD=""
  DIM=""
  GREEN=""
  RESET=""
fi

# Show developers the supported setup options and the tools they install.
usage() {
  cat <<'USAGE'
Usage: scripts/dependency-install.sh [options]

Installs local tool dependencies used by preflight and CI checks.

Tools installed:
  cargo-audit  RustSec vulnerability audit for Cargo.lock (exact locked release).
  action-validator  GitHub Action metadata validator (exact locked Cargo release).
  actionlint  GitHub Actions workflow validator (checksum-verified Go release).

Options:
  --force      Reinstall tools even when Cargo thinks they are current.
  --root PATH  Install tools under PATH instead of Cargo's default install root.
  -h, --help   Show this help.

The script never edits project files.
USAGE
}

# Stop setup with one actionable error instead of leaving a partial success message.
fail_install() {
  printf 'dependency-install: %s\n' "$*" >&2
  exit 2
}

# Show the command or reuse decision currently visible to the developer.
show_install_detail() {
  printf '  %s%s%s\n' "$DIM" "$*" "$RESET"
}

# Confirm the exact tool version a developer can now use in preflight.
show_installed_tool() {
  printf '  %s%s%s\n' "$GREEN" "$*" "$RESET"
}

# Require a host command before setup starts the dependent install step.
require_install_command() {
  # A missing command means the developer must install that prerequisite first.
  command -v "$1" >/dev/null 2>&1 \
    || fail_install "$1 is not available on PATH"
}

# Resolve where installed binaries will be visible to the current developer or CI job.
resolved_install_root() {
  # An explicit --root keeps this setup isolated at the path the developer chose.
  if [[ -n "$INSTALL_ROOT" ]]; then
    printf '%s\n' "$INSTALL_ROOT"
  # CI may provide Cargo's dedicated install root without passing a script option.
  elif [[ -n "${CARGO_INSTALL_ROOT:-}" ]]; then
    printf '%s\n' "$CARGO_INSTALL_ROOT"
  # A custom Cargo home means its bin directory is the expected user-facing location.
  elif [[ -n "${CARGO_HOME:-}" ]]; then
    printf '%s\n' "$CARGO_HOME"
  else
    printf '%s/.cargo\n' "$HOME"
  fi
}

# Run a displayed install command from the repository root used by local checks.
run_from_workspace() {
  show_install_detail "$*"
  (cd "$REPO_ROOT" && "$@")
}

# Install one Cargo-based checker at its reviewed version with its lockfile enforced.
install_cargo_tool() {
  local crate_name=$1
  local requested_version=${2:-}
  local replace_existing_binary=${3:-0}
  local cargo_install_arguments=(install "$crate_name")

  # A non-empty version binds the developer and CI to the reviewed crate release.
  if [[ -n $requested_version ]]; then
    cargo_install_arguments+=(--version "$requested_version")
  fi
  cargo_install_arguments+=(--locked)

  # --force or an unmanaged binary lets Cargo replace an otherwise blocking file.
  if ((FORCE || replace_existing_binary)); then
    cargo_install_arguments+=(--force)
  fi
  # An explicit install root keeps the resulting binary where the developer requested.
  if [[ -n "$INSTALL_ROOT" ]]; then
    cargo_install_arguments+=(--root "$INSTALL_ROOT")
  fi

  run_from_workspace cargo "${cargo_install_arguments[@]}"
}

# Find the installed checker where this script placed it, then fall back to PATH.
installed_tool_path() {
  local binary_name=$1
  local candidate_install_root

  candidate_install_root=$(resolved_install_root)
  # A binary under the resolved install root is the one this setup owns for the user.
  if [[ -x "$candidate_install_root/bin/$binary_name" ]]; then
    printf '%s/bin/%s\n' "$candidate_install_root" "$binary_name"
    return 0
  fi

  command -v "$binary_name"
}

# Map the developer's machine to the exact actionlint release artifact it can run.
actionlint_release_platform() {
  local operating_system
  local machine_architecture

  operating_system=$(uname -s)
  machine_architecture=$(uname -m)
  case "$operating_system:$machine_architecture" in
    Linux:x86_64|Linux:amd64) printf 'linux_amd64\n' ;;
    Linux:aarch64|Linux:arm64) printf 'linux_arm64\n' ;;
    Darwin:x86_64|Darwin:amd64) printf 'darwin_amd64\n' ;;
    Darwin:arm64|Darwin:aarch64) printf 'darwin_arm64\n' ;;
    *) fail_install "unsupported validator platform: $operating_system/$machine_architecture" ;;
  esac
}

# Verify the downloaded validator before any developer or CI job executes it.
verify_download_checksum() {
  local expected_checksum=$1
  local downloaded_file=$2

  # Linux normally provides sha256sum for the visible integrity check.
  if command -v sha256sum >/dev/null 2>&1; then
    printf '%s  %s\n' "$expected_checksum" "$downloaded_file" | sha256sum -c -
  # macOS normally provides shasum, which gives the same SHA-256 assurance.
  elif command -v shasum >/dev/null 2>&1; then
    printf '%s  %s\n' "$expected_checksum" "$downloaded_file" | shasum -a 256 -c -
  else
    fail_install "sha256sum or shasum is required to verify validator downloads"
  fi
}

# Return the reviewed checksum for the developer's exact actionlint platform archive.
actionlint_release_checksum() {
  case $1 in
    linux_amd64) printf '8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8\n' ;;
    linux_arm64) printf '325e971b6ba9bfa504672e29be93c24981eeb1c07576d730e9f7c8805afff0c6\n' ;;
    darwin_amd64) printf '5b44c3bc2255115c9b69e30efc0fecdf498fdb63c5d58e17084fd5f16324c644\n' ;;
    darwin_arm64) printf 'aba9ced2dee8d27fecca3dc7feb1a7f9a52caefa1eb46f3271ea66b6e0e6953f\n' ;;
    *) fail_install "unsupported actionlint platform: $1" ;;
  esac
}

# Report whether the user already has the exact action metadata validator requested.
installed_action_validator_matches() {
  local validator_path=$1

  [[ -x $validator_path \
    && $("$validator_path" --version 2>/dev/null) == "action-validator $ACTION_VALIDATOR_VERSION" ]]
}

# Reuse or install the exact action metadata validator used by repository checks.
install_action_validator() {
  local action_validator_path
  local replace_existing_binary=0

  action_validator_path=$(resolved_install_root)/bin/action-validator
  # A matching checker lets the developer continue without an unnecessary download.
  if ((FORCE == 0)) && installed_action_validator_matches "$action_validator_path"; then
    show_install_detail "action-validator $ACTION_VALIDATOR_VERSION already installed"
    return 0
  fi
  # An unmanaged file must be explicitly replaced so Cargo can complete setup.
  if [[ -e $action_validator_path ]]; then
    replace_existing_binary=1
  fi
  install_cargo_tool \
    action-validator \
    "$ACTION_VALIDATOR_VERSION" \
    "$replace_existing_binary"
  # A mismatched result would make local and hosted action checks disagree.
  installed_action_validator_matches "$action_validator_path" \
    || fail_install "installed action-validator did not report version $ACTION_VALIDATOR_VERSION"
}

# Report whether an executable is the exact actionlint release expected by preflight.
installed_actionlint_matches() {
  local actionlint_path=$1
  local reported_version

  # A missing executable means setup still needs to install actionlint for the user.
  if [[ ! -x $actionlint_path ]]; then
    return 1
  fi
  reported_version=$("$actionlint_path" -version 2>/dev/null | head -1)
  [[ $reported_version == "$ACTIONLINT_VERSION" ]]
}

# Download, verify, and place actionlint where the current developer can invoke it.
install_actionlint() {
  local actionlint_path=$1
  local release_platform=$2
  local temporary_directory=$3
  local expected_checksum
  local downloaded_archive=$temporary_directory/actionlint.tar.gz
  local extracted_binary=$temporary_directory/actionlint

  # A matching checker lets the developer continue without an unnecessary download.
  if ((FORCE == 0)) && installed_actionlint_matches "$actionlint_path"; then
    show_install_detail "actionlint $ACTIONLINT_VERSION already installed"
    return 0
  fi
  expected_checksum=$(actionlint_release_checksum "$release_platform")
  curl -fsSL --proto '=https' --tlsv1.2 \
    -o "$downloaded_archive" \
    "https://github.com/rhysd/actionlint/releases/download/v$ACTIONLINT_VERSION/actionlint_${ACTIONLINT_VERSION}_${release_platform}.tar.gz"
  verify_download_checksum "$expected_checksum" "$downloaded_archive" \
    || fail_install "downloaded actionlint archive failed SHA-256 verification"
  tar -xzf "$downloaded_archive" -C "$temporary_directory" actionlint
  install -m 0755 "$extracted_binary" "$actionlint_path"
  # A mismatched result would make local and hosted workflow checks disagree.
  installed_actionlint_matches "$actionlint_path" \
    || fail_install "installed actionlint did not report version $ACTIONLINT_VERSION"
}

# Prepare the platform-specific actionlint install and remove its temporary files.
install_actionlint_release() {
  local actionlint_install_root
  local actionlint_bin_directory
  local release_platform
  local temporary_directory

  require_install_command curl
  require_install_command install
  require_install_command tar
  actionlint_install_root=$(resolved_install_root)
  actionlint_bin_directory=$actionlint_install_root/bin
  release_platform=$(actionlint_release_platform)
  temporary_directory=$(mktemp -d "${TMPDIR:-/tmp}/gruff-rs-validator-install.XXXXXX")
  mkdir -p "$actionlint_bin_directory"
  install_actionlint \
    "$actionlint_bin_directory/actionlint" \
    "$release_platform" \
    "$temporary_directory"
  rm -rf "$temporary_directory"
}

# Parse setup options, install every checker, and show users the resulting versions.
install_dependency_tools() {
  # Each user option adjusts setup before any download or Cargo install begins.
  while (($#)); do
    case "$1" in
      --force)
        FORCE=1
        shift
        ;;
      --root)
        # A missing path cannot tell setup where the user wants tools installed.
        if (($# < 2)); then
          fail_install "--root requires a path"
        fi
        INSTALL_ROOT=$2
        shift 2
        ;;
      -h|--help)
        usage
        return 0
        ;;
      *)
        fail_install "unknown argument: $1 (try --help)"
        ;;
    esac
  done

  require_install_command cargo

  printf '\n  %sDependency Tool Install%s\n' "$BOLD" "$RESET"
  # Failure here means the developer cannot run the RustSec gate yet.
  install_cargo_tool cargo-audit "$CARGO_AUDIT_VERSION" \
    || fail_install "failed to install cargo-audit"
  # Failure here means action metadata cannot be validated before CI use.
  install_action_validator \
    || fail_install "failed to install action-validator"
  # Failure here means workflow syntax cannot be checked locally or in CI.
  install_actionlint_release \
    || fail_install "failed to install actionlint"

  local cargo_audit_path
  cargo_audit_path=$(installed_tool_path cargo-audit) \
    || fail_install "cargo-audit was installed but is not on PATH"
  show_installed_tool "$("$cargo_audit_path" --version)"
  local action_validator_path
  action_validator_path=$(installed_tool_path action-validator) \
    || fail_install "action-validator was installed but is not on PATH"
  show_installed_tool "$("$action_validator_path" --version)"
  local actionlint_path
  actionlint_path=$(installed_tool_path actionlint) \
    || fail_install "actionlint was installed but is not on PATH"
  show_installed_tool "actionlint $("$actionlint_path" -version | head -1)"
  printf '\n'
}

install_dependency_tools "$@"
