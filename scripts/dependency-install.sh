#!/usr/bin/env bash
# scripts/dependency-install.sh - install local tool dependencies for checks.
#
# This installs developer/CI tools only. It does not change Cargo.toml,
# Cargo.lock, source files, commits, tags, or pushes.

set -u
set -o pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

FORCE=0
INSTALL_ROOT=""

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

usage() {
  cat <<'USAGE'
Usage: scripts/dependency-install.sh [options]

Installs local tool dependencies used by preflight and CI checks.

Tools installed:
  cargo-audit  RustSec vulnerability audit for Cargo.lock.

Options:
  --force      Reinstall tools even when Cargo thinks they are current.
  --root PATH  Install tools under PATH instead of Cargo's default install root.
  -h, --help   Show this help.

The script never edits project files.
USAGE
}

die() {
  printf 'dependency-install: %s\n' "$*" >&2
  exit 2
}

info() { printf '  %s%s%s\n' "$DIM" "$*" "$RESET"; }
ok()   { printf '  %s%s%s\n' "$GREEN" "$*" "$RESET"; }

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "$1 is not available on PATH"
}

run() {
  info "$*"
  (cd "$REPO_ROOT" && "$@")
}

install_cargo_tool() {
  local crate=$1
  local args=(install "$crate" --locked)

  if ((FORCE)); then
    args+=(--force)
  fi
  if [[ -n "$INSTALL_ROOT" ]]; then
    args+=(--root "$INSTALL_ROOT")
  fi

  run cargo "${args[@]}"
}

tool_path() {
  local binary=$1

  if [[ -n "$INSTALL_ROOT" && -x "$INSTALL_ROOT/bin/$binary" ]]; then
    printf '%s/bin/%s\n' "$INSTALL_ROOT" "$binary"
    return 0
  fi

  command -v "$binary"
}

main() {
  while (($#)); do
    case "$1" in
      --force)
        FORCE=1
        shift
        ;;
      --root)
        [[ $# -ge 2 ]] || die "--root requires a path"
        INSTALL_ROOT=$2
        shift 2
        ;;
      -h|--help)
        usage
        return 0
        ;;
      *)
        die "unknown argument: $1 (try --help)"
        ;;
    esac
  done

  require_cmd cargo

  printf '\n  %sDependency Tool Install%s\n' "$BOLD" "$RESET"
  install_cargo_tool cargo-audit || die "failed to install cargo-audit"

  local cargo_audit
  cargo_audit=$(tool_path cargo-audit) || die "cargo-audit was installed but is not on PATH"
  ok "$("$cargo_audit" --version)"
  printf '\n'
}

main "$@"
