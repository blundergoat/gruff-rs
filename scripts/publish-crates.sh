#!/usr/bin/env bash
# scripts/publish-crates.sh - verify and optionally publish gruff-rs to crates.io.
#
# Run without arguments for an interactive release prompt. Real uploads still
# require explicit confirmation, or --publish --yes for non-interactive release
# automation.
# The script never bumps versions, commits, tags, or pushes.

set -u
set -o pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CARGO_TOML="$REPO_ROOT/Cargo.toml"

PUBLISH=0
YES=0
ALLOW_DIRTY=0
SKIP_PREFLIGHT=0
SHOW_PACKAGE_LIST=1
EXPECTED_VERSION=""
INTERACTIVE=0

if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
  BOLD=$'\033[1m'
  DIM=$'\033[2m'
  GREEN=$'\033[32m'
  YELLOW=$'\033[33m'
  RESET=$'\033[0m'
else
  BOLD=""
  DIM=""
  GREEN=""
  YELLOW=""
  RESET=""
fi

usage() {
  cat <<'USAGE'
Usage: scripts/publish-crates.sh [options]

Run without options for an interactive prompt. The script verifies the gruff-rs
crate package, runs `cargo publish --dry-run --locked`, and can then upload the
current Cargo.toml version to crates.io after confirmation.

Options:
  --publish            Upload to crates.io after verification.
  --yes                Skip the interactive typed confirmation. Only valid
                       with --publish.
  --version X.Y.Z      Require Cargo.toml to contain this package version.
  --allow-dirty        Permit publishing from a dirty git worktree.
  --skip-preflight     Skip scripts/preflight-checks.sh.
  --no-package-list    Skip printing `cargo package --list --locked`.
  -h, --help           Show this help.

The script never bumps versions, commits, tags, or pushes.
USAGE
}

die() {
  printf 'publish-crates: %s\n' "$*" >&2
  exit 2
}

info() { printf '  %s%s%s\n' "$DIM" "$*" "$RESET"; }
ok()   { printf '  %s%s%s\n' "$GREEN" "$*" "$RESET"; }
warn() { printf '  %s%s%s\n' "$YELLOW" "$*" "$RESET"; }

prompt_yes_no() {
  local prompt=$1
  local default=$2
  local suffix
  local answer

  case "$default" in
    yes) suffix="[Y/n]" ;;
    no)  suffix="[y/N]" ;;
    *) die "invalid prompt default: $default" ;;
  esac

  while true; do
    printf '  %s %s ' "$prompt" "$suffix"
    IFS= read -r answer || return 1
    answer=${answer,,}

    if [[ -z "$answer" ]]; then
      [[ "$default" == "yes" ]]
      return
    fi

    case "$answer" in
      y|yes) return 0 ;;
      n|no)  return 1 ;;
      *)     warn "answer yes or no" ;;
    esac
  done
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "$1 is not available on PATH"
}

validate_semver() {
  local v=$1
  [[ "$v" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] \
    || die "version must look like X.Y.Z (got: $v)"
}

package_field() {
  local field=$1

  awk -v field="$field" '
    /^\[package\]/ { in_pkg = 1; next }
    /^\[/          { in_pkg = 0 }
    in_pkg && $0 ~ ("^" field "[[:space:]]*=") {
      sub("^[^=]+=[[:space:]]*\"", "")
      sub("\".*$", "")
      print
      exit
    }
  ' "$CARGO_TOML"
}

git_is_dirty() {
  git -C "$REPO_ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1 \
    || return 1

  [[ -n "$(git -C "$REPO_ROOT" status --porcelain)" ]]
}

run() {
  info "$*"
  (cd "$REPO_ROOT" && "$@")
}

interactive_setup() {
  local crate=$1
  local version=$2

  if ! prompt_yes_no "Use $crate v$version from Cargo.toml?" yes; then
    die "update Cargo.toml first, or pass --version X.Y.Z to require a specific version"
  fi

  if prompt_yes_no "Publish to crates.io after verification?" no; then
    PUBLISH=1
  else
    PUBLISH=0
  fi

  if ! prompt_yes_no "Run full preflight checks?" yes; then
    SKIP_PREFLIGHT=1
  fi

  if ! prompt_yes_no "Print package file list?" yes; then
    SHOW_PACKAGE_LIST=0
  fi
}

confirm_publish() {
  local crate=$1
  local version=$2
  local expected="publish $crate v$version"
  local answer

  if ((YES)); then
    return 0
  fi

  if [[ ! -t 0 ]]; then
    die "non-interactive publish requires --yes"
  fi

  printf '\n'
  warn "This uploads $crate v$version to crates.io."
  warn "Published crate versions cannot be overwritten or deleted."
  printf '  Type %s%s%s to continue: ' "$BOLD" "$expected" "$RESET"
  IFS= read -r answer

  [[ "$answer" == "$expected" ]] \
    || die "confirmation did not match; aborting publish"
}

main() {
  if (($# == 0)) && [[ -t 0 ]]; then
    INTERACTIVE=1
  fi

  while (($#)); do
    case "$1" in
      --publish)         PUBLISH=1;          shift ;;
      --yes)             YES=1;              shift ;;
      --version)
        [[ $# -ge 2 ]] || die "--version requires a value"
        EXPECTED_VERSION=$2
        shift 2
        ;;
      --allow-dirty)     ALLOW_DIRTY=1;      shift ;;
      --skip-preflight)  SKIP_PREFLIGHT=1;   shift ;;
      --no-package-list) SHOW_PACKAGE_LIST=0; shift ;;
      -h|--help)         usage; return 0 ;;
      *) die "unknown argument: $1 (try --help)" ;;
    esac
  done

  if ((YES && ! PUBLISH)); then
    die "--yes is only valid with --publish"
  fi

  [[ -f "$CARGO_TOML" ]] || die "Cargo.toml not found at $CARGO_TOML"
  require_cmd cargo

  local crate
  local version
  crate=$(package_field name) || die "failed to read package name"
  version=$(package_field version) || die "failed to read package version"
  [[ -n "$crate" ]] || die "could not find [package] name in Cargo.toml"
  [[ -n "$version" ]] || die "could not find [package] version in Cargo.toml"
  validate_semver "$version"

  if [[ -n "$EXPECTED_VERSION" ]]; then
    validate_semver "$EXPECTED_VERSION"
    [[ "$version" == "$EXPECTED_VERSION" ]] \
      || die "Cargo.toml version is $version, expected $EXPECTED_VERSION"
  fi

  printf '\n  %scrates.io publish%s\n' "$BOLD" "$RESET"
  info "crate:   $crate"
  info "version: $version"

  if ((INTERACTIVE)); then
    interactive_setup "$crate" "$version"
  fi

  if git_is_dirty && ((ALLOW_DIRTY == 0)); then
    if ((INTERACTIVE)); then
      warn "working tree is dirty"
      git -C "$REPO_ROOT" status --short | sed 's/^/    /'
      if prompt_yes_no "Continue with the dirty worktree?" no; then
        ALLOW_DIRTY=1
      else
        die "commit/stash changes before publishing, or rerun and allow the dirty tree"
      fi
    else
      die "working tree is dirty; commit/stash changes or pass --allow-dirty"
    fi
  fi

  if ((SKIP_PREFLIGHT == 0)); then
    [[ -x "$REPO_ROOT/scripts/preflight-checks.sh" ]] \
      || die "scripts/preflight-checks.sh is not executable"
    run bash scripts/preflight-checks.sh || die "preflight checks failed"
    ok "preflight checks passed"
  else
    warn "skipping preflight checks"
  fi

  if ((SHOW_PACKAGE_LIST)); then
    run cargo package --list --locked || die "cargo package --list failed"
    ok "package list generated"
  fi

  run cargo publish --dry-run --locked || die "cargo publish dry run failed"
  ok "publish dry run passed"

  if ((PUBLISH == 0)); then
    printf '\n  %sDry run complete%s\n' "$BOLD" "$RESET"
    info "To publish interactively: scripts/publish-crates.sh"
    info "Automation: scripts/publish-crates.sh --publish --version $version"
    printf '\n'
    return 0
  fi

  confirm_publish "$crate" "$version"
  run cargo publish --locked || die "cargo publish failed"
  ok "published $crate v$version"

  printf '\n  %sNext steps%s\n' "$BOLD" "$RESET"
  info "  cargo install $crate --locked"
  info "  git tag v$version"
  printf '\n'
}

main "$@"
