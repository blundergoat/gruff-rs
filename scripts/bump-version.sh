#!/usr/bin/env bash
# scripts/bump-version.sh - bump the gruff-rs crate version in Cargo.toml,
# refresh Cargo.lock, and optionally prepend a CHANGELOG.md entry.
#
# The script never commits, tags, or pushes; it edits local files only and
# prints the suggested next steps.
#
# See `--help` for usage.

set -u
set -o pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

CARGO_TOML="$REPO_ROOT/Cargo.toml"
CARGO_LOCK="$REPO_ROOT/Cargo.lock"
CHANGELOG="$REPO_ROOT/CHANGELOG.md"

DRY_RUN=0
SKIP_LOCK=0
WRITE_CHANGELOG=0
BUMP_KIND=""
EXPLICIT_VERSION=""

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
Usage: scripts/bump-version.sh <patch|minor|major> [options]
       scripts/bump-version.sh --version <X.Y.Z>   [options]

Bumps the gruff-rs crate version in Cargo.toml (the source of truth) and
keeps Cargo.lock in sync. Optionally prepends a CHANGELOG.md entry.

Arguments:
  patch | minor | major   Increment the matching SemVer component.

Options:
  --version X.Y.Z         Set an explicit version. Mutually exclusive with
                          the bump argument.
  --changelog             Prepend a "## X.Y.Z - YYYY-MM-DD" entry to
                          CHANGELOG.md (off by default).
  --no-lock               Skip the cargo step that refreshes Cargo.lock.
  --dry-run               Show planned changes without writing files.
  -h, --help              Show this help.

Files touched: Cargo.toml, Cargo.lock (and CHANGELOG.md with --changelog).
The script never runs git; commit and tag yourself.
USAGE
}

die() {
  printf 'bump-version: %s\n' "$*" >&2
  exit 2
}

info() { printf '  %s%s%s\n' "$DIM" "$*" "$RESET"; }
ok()   { printf '  %s%s%s\n' "$GREEN" "$*" "$RESET"; }
warn() { printf '  %s%s%s\n' "$YELLOW" "$*" "$RESET"; }

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "$1 is not available on PATH"
}

validate_semver() {
  local v=$1
  [[ "$v" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] \
    || die "version must look like X.Y.Z (got: $v)"
}

current_version() {
  # First `version = "..."` line inside the [package] table.
  awk '
    /^\[package\]/ { in_pkg = 1; next }
    /^\[/          { in_pkg = 0 }
    in_pkg && /^version[[:space:]]*=/ {
      sub(/^version[[:space:]]*=[[:space:]]*"/, "")
      sub(/".*$/, "")
      print
      exit
    }
  ' "$CARGO_TOML"
}

bumped_version() {
  local current=$1 kind=$2 major minor patch
  IFS=. read -r major minor patch <<<"$current"
  case "$kind" in
    major) major=$((major + 1)); minor=0; patch=0 ;;
    minor) minor=$((minor + 1)); patch=0 ;;
    patch) patch=$((patch + 1)) ;;
    *) die "unknown bump kind: $kind" ;;
  esac
  printf '%d.%d.%d\n' "$major" "$minor" "$patch"
}

update_cargo_toml() {
  local new=$1 tmp="$CARGO_TOML.tmp"

  awk -v new="$new" '
    BEGIN { in_pkg = 0; replaced = 0 }
    /^\[package\]/                    { in_pkg = 1; print; next }
    /^\[/ && !/^\[package\]/          { in_pkg = 0; print; next }
    in_pkg && !replaced && /^version[[:space:]]*=/ {
      printf "version = \"%s\"\n", new
      replaced = 1
      next
    }
    { print }
    END { if (!replaced) exit 1 }
  ' "$CARGO_TOML" >"$tmp" || { rm -f "$tmp"; return 1; }

  mv "$tmp" "$CARGO_TOML"
}

sync_cargo_lock() {
  require_cmd cargo
  # --workspace refreshes lockfile entries for workspace members (just
  # gruff-rs here) without disturbing external dependency versions.
  ( cd "$REPO_ROOT" && cargo update --workspace --quiet ) \
    || die "cargo update --workspace failed; resolve and re-run"
}

prepend_changelog() {
  local new=$1 tmp="$CHANGELOG.tmp" today heading
  today=$(date '+%Y-%m-%d')
  heading="## $new - $today"

  if [[ ! -f "$CHANGELOG" ]]; then
    warn "CHANGELOG.md not found - skipping entry"
    return 0
  fi

  if grep -qF "$heading" "$CHANGELOG"; then
    warn "CHANGELOG.md already contains '$heading' - leaving as is"
    return 0
  fi

  awk -v heading="$heading" '
    BEGIN { inserted = 0 }
    /^# Changelog/ && !inserted {
      print
      print ""
      print heading
      print ""
      print "_TODO: summarise the changes for this release._"
      inserted = 1
      next
    }
    { print }
    END {
      if (!inserted) {
        print "# Changelog"
        print ""
        print heading
        print ""
        print "_TODO: summarise the changes for this release._"
      }
    }
  ' "$CHANGELOG" >"$tmp" || { rm -f "$tmp"; return 1; }

  mv "$tmp" "$CHANGELOG"
}

main() {
  while (($#)); do
    case "$1" in
      patch|minor|major)
        [[ -z "$BUMP_KIND" ]] || die "bump kind already set to $BUMP_KIND"
        BUMP_KIND=$1
        shift
        ;;
      --version)
        [[ $# -ge 2 ]] || die "--version requires a value"
        EXPLICIT_VERSION=$2
        shift 2
        ;;
      --changelog)   WRITE_CHANGELOG=1; shift ;;
      --no-lock)     SKIP_LOCK=1;       shift ;;
      --dry-run)     DRY_RUN=1;         shift ;;
      -h|--help)     usage; return 0 ;;
      *) die "unknown argument: $1 (try --help)" ;;
    esac
  done

  if [[ -n "$BUMP_KIND" && -n "$EXPLICIT_VERSION" ]]; then
    die "use either a bump kind or --version, not both"
  fi
  if [[ -z "$BUMP_KIND" && -z "$EXPLICIT_VERSION" ]]; then
    usage >&2
    return 2
  fi

  [[ -f "$CARGO_TOML" ]] || die "Cargo.toml not found at $CARGO_TOML"

  local current new
  current=$(current_version) || die "failed to read current version"
  [[ -n "$current" ]] || die "could not find a [package] version in Cargo.toml"
  validate_semver "$current"

  if [[ -n "$EXPLICIT_VERSION" ]]; then
    new=$EXPLICIT_VERSION
  else
    new=$(bumped_version "$current" "$BUMP_KIND")
  fi
  validate_semver "$new"

  [[ "$new" != "$current" ]] \
    || die "new version equals current version ($current); nothing to do"

  printf '\n  %sgruff-rs version bump%s\n' "$BOLD" "$RESET"
  info "Cargo.toml: $CARGO_TOML"
  info "current:    $current"
  ok   "new:        $new"

  if ((DRY_RUN)); then
    warn "dry run - no files changed"
    return 0
  fi

  update_cargo_toml "$new" || die "failed to update Cargo.toml"
  ok "updated Cargo.toml"

  if ((SKIP_LOCK == 0)); then
    if [[ -f "$CARGO_LOCK" ]]; then
      sync_cargo_lock
      ok "refreshed Cargo.lock"
    else
      warn "Cargo.lock not found - skipping lock refresh"
    fi
  fi

  if ((WRITE_CHANGELOG)); then
    prepend_changelog "$new" || die "failed to update CHANGELOG.md"
    ok "prepended CHANGELOG.md entry"
  fi

  printf '\n  %sNext steps%s\n' "$BOLD" "$RESET"
  info "  bash scripts/preflight-checks.sh"
  info "  git diff Cargo.toml Cargo.lock${WRITE_CHANGELOG:+ CHANGELOG.md}"
  info "  git commit -m 'chore: release v$new'"
  info "  git tag v$new"
  printf '\n'
}

main "$@"
