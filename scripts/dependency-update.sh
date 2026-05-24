#!/usr/bin/env bash
# scripts/dependency-update.sh - refresh Rust dependencies and local tool deps.
#
# By default this updates Cargo.lock, reinstalls cargo-based developer tools,
# and runs cargo-audit. It never commits, tags, or pushes.

set -u
set -o pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

SKIP_LOCK=0
SKIP_TOOLS=0
SKIP_AUDIT=0
TOOL_ROOT=""

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
Usage: scripts/dependency-update.sh [options]

Refreshes dependency state for this repository:
  - cargo update
  - scripts/dependency-install.sh --force
  - cargo-audit scan

Options:
  --skip-lock   Do not run cargo update.
  --skip-tools  Do not reinstall local tool dependencies.
  --skip-audit  Do not run cargo-audit after updates.
  --tool-root PATH
               Install tools under PATH instead of Cargo's default install root.
  -h, --help    Show this help.

The script may edit Cargo.lock. It never commits, tags, or pushes.
USAGE
}

die() {
  printf 'dependency-update: %s\n' "$*" >&2
  exit 2
}

info() { printf '  %s%s%s\n' "$DIM" "$*" "$RESET"; }
ok()   { printf '  %s%s%s\n' "$GREEN" "$*" "$RESET"; }
warn() { printf '  %s%s%s\n' "$YELLOW" "$*" "$RESET"; }

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "$1 is not available on PATH"
}

run() {
  info "$*"
  (cd "$REPO_ROOT" && "$@")
}

cargo_audit_path() {
  if [[ -n "$TOOL_ROOT" && -x "$TOOL_ROOT/bin/cargo-audit" ]]; then
    printf '%s/bin/cargo-audit\n' "$TOOL_ROOT"
    return 0
  fi

  command -v cargo-audit
}

install_tools() {
  local args=(--force)

  if [[ -n "$TOOL_ROOT" ]]; then
    args+=(--root "$TOOL_ROOT")
  fi

  run bash "$SCRIPT_DIR/dependency-install.sh" "${args[@]}"
}

run_audit() {
  local cargo_audit

  cargo_audit=$(cargo_audit_path) || die "cargo-audit is not available; run scripts/dependency-install.sh first"
  run "$cargo_audit" audit
}

main() {
  while (($#)); do
    case "$1" in
      --skip-lock)
        SKIP_LOCK=1
        shift
        ;;
      --skip-tools)
        SKIP_TOOLS=1
        shift
        ;;
      --skip-audit)
        SKIP_AUDIT=1
        shift
        ;;
      --tool-root)
        [[ $# -ge 2 ]] || die "--tool-root requires a path"
        TOOL_ROOT=$2
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

  printf '\n  %sDependency Update%s\n' "$BOLD" "$RESET"

  if ((SKIP_LOCK == 0)); then
    run cargo update || die "cargo update failed"
    ok "updated Cargo.lock"
  else
    warn "skipping Cargo.lock update"
  fi

  if ((SKIP_TOOLS == 0)); then
    install_tools || die "tool dependency update failed"
    ok "updated tool dependencies"
  else
    warn "skipping tool dependency update"
  fi

  if ((SKIP_AUDIT == 0)); then
    run_audit || die "dependency audit failed"
    ok "dependency audit passed"
  else
    warn "skipping dependency audit"
  fi

  printf '\n  %sNext steps%s\n' "$BOLD" "$RESET"
  info "  git diff Cargo.lock"
  info "  bash scripts/preflight-checks.sh"
  printf '\n'
}

main "$@"
