#!/usr/bin/env bash
# Run the local quality gate that contributors and hosted CI share.
# Developers use its named PASS/FAIL lines to find the first broken contract
# before requesting review or preparing a release. It covers shell, Rust, CLI,
# dependency, workflow, documentation, and gruff-rs dogfood behavior.

set -u
set -o pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
GRUFF_RS_RELEASE_CHECK="${GRUFF_RS_RELEASE_CHECK:-0}"
WORK_DIR=""
CARGO_AUDIT_VERSION=0.22.2
ACTION_VALIDATOR_VERSION=0.9.0
ACTIONLINT_VERSION=1.7.12

TOTAL=0
PASSED=0
FAILED=0
FAILURES=()
SKIPPED=()
START_TIME=$(date +%s%N)

# Interactive users get readable status colours; redirected CI logs stay plain.
if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
  BOLD=$'\033[1m'
  DIM=$'\033[2m'
  GREEN=$'\033[32m'
  RED=$'\033[31m'
  YELLOW=$'\033[33m'
  BLUE=$'\033[34m'
  RESET=$'\033[0m'
else
  BOLD=""
  DIM=""
  GREEN=""
  RED=""
  YELLOW=""
  BLUE=""
  RESET=""
fi

PASS="${GREEN}PASS${RESET}"
FAIL="${RED}FAIL${RESET}"
SKIP="${YELLOW}SKIP${RESET}"
ARROW="${BLUE}>${RESET}"

# Show contributors every check, option, and environment switch in this gate.
usage() {
  cat <<'USAGE'
Usage: scripts/preflight-checks.sh [options]

Runs the local gruff-rs preflight suite:
  - bash syntax check for tracked and untracked shell scripts
  - shellcheck for shell scripts when shellcheck is installed
  - cargo fmt, clippy, and tests
  - crate version consistency between Cargo.toml and Cargo.lock
  - RustSec dependency audit, auto-installing cargo-audit when missing
  - pinned action.yml and GitHub Actions workflow validators
  - exact-path GitHub workflow and composite-action security scan without project config
  - rule-listing, summary, fixture JSON/SARIF, patch, selector, exclusion, and custom-rule smokes
  - gruff-rs dogfood scan (analyse the whole project, gated by minimumSeverity.analyse in .gruff-rs.yaml)
  - documentation drift guard (architecture.md schema string and CLI command list match the code)

Options:
  --release-check  Also require the crate version to be newer than the latest
                   local vX.Y.Z git tag and present in CHANGELOG.md.
  -h, --help       Show this help.

Environment:
  GRUFF_RS_RELEASE_CHECK  Set to 1/true/yes/on to enable --release-check.
USAGE
}

# Stop before checks start when the requested preflight setup is invalid.
fail_preflight_setup() {
  printf 'preflight-checks: %s\n' "$*" >&2
  exit 2
}

# Remove reports created for this run so developers are not left with gate debris.
remove_preflight_workspace() {
  # A non-empty, existing workspace is safe to remove after the visible summary.
  if [[ -n "$WORK_DIR" && -d "$WORK_DIR" ]]; then
    rm -rf "$WORK_DIR"
  fi
}

# Draw the short divider that separates the check list from its user summary.
show_section_rule() {
  printf '  %s\n' "${DIM}--------------------------------------------${RESET}"
}

# Format one check's elapsed time so slow feedback is visible to contributors.
elapsed_since() {
  local started_at=$1
  local finished_at
  local elapsed_ms
  local seconds
  local minutes
  local remainder
  local frac

  finished_at=$(date +%s%N)
  elapsed_ms=$(((finished_at - started_at) / 1000000))

  # Sub-second checks are clearest to users in milliseconds.
  if ((elapsed_ms < 1000)); then
    printf '%dms' "$elapsed_ms"
    return
  fi

  seconds=$((elapsed_ms / 1000))
  frac=$(((elapsed_ms % 1000) / 100))

  # Checks under a minute fit on the status line as seconds and tenths.
  if ((seconds < 60)); then
    printf '%d.%ds' "$seconds" "$frac"
    return
  fi

  minutes=$((seconds / 60))
  remainder=$((seconds % 60))
  printf '%dm %02d.%ds' "$minutes" "$remainder" "$frac"
}

# Show contributors which workspace and release-check mode this run will use.
show_preflight_header() {
  printf '\n'
  printf '  %sPreflight Check%s\n' "$BOLD" "$RESET"
  printf '  %s%s%s\n' "$DIM" "$(date '+%Y-%m-%d %H:%M:%S')" "$RESET"
  printf '  %sroot:%s %s\n' "$DIM" "$RESET" "$REPO_ROOT"
  printf '  %srelease version check:%s %s\n' "$DIM" "$RESET" "$(release_check_label)"
  printf '  %sdependency audit:%s required (auto-install cargo-audit)\n' "$DIM" "$RESET"
  show_section_rule
  printf '\n'
}

# Begin one named check line before its command runs.
start_check_line() {
  local label=$1

  TOTAL=$((TOTAL + 1))
  printf '  %s %-38s' "$ARROW" "$label"
}

# Complete the current check line with PASS and any useful command summary.
show_check_passed() {
  local detail=${1:-}

  PASSED=$((PASSED + 1))
  # A non-empty detail tells the user what passed without opening raw logs.
  if [[ -n "$detail" ]]; then
    printf '%s  %s%s%s\n' "$PASS" "$DIM" "$detail" "$RESET"
  else
    printf '%s\n' "$PASS"
  fi
}

# Complete the current check line with FAIL and remember it for the final summary.
show_check_failed() {
  local label=$1

  FAILED=$((FAILED + 1))
  FAILURES+=("$label")
  printf '%s\n' "$FAIL"
}

# Complete the current check line with the practical reason it could not run.
show_check_skipped() {
  local reason=${1:-skipped}

  SKIPPED+=("$reason")
  printf '%s  %s%s%s\n' "$SKIP" "$DIM" "$reason" "$RESET"
}

# Indent failed command output so users can distinguish evidence from check labels.
show_indented_output() {
  # Each output line is preserved while being grouped under its failed check.
  while IFS= read -r line; do
    printf '    %s%s%s\n' "$DIM" "$line" "$RESET"
  done
}

# Trim display-only whitespace from a command's one-line success summary.
trim_line() {
  printf '%s' "$1" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//'
}

# Pick the most useful success line so the preflight list stays readable.
compact_output() {
  local output=$1
  local summary_line

  # Empty command output means PASS and elapsed time are enough for the user.
  if [[ -z "$output" ]]; then
    return 0
  fi

  summary_line=$(printf '%s\n' "$output" | grep 'test result:' | tail -1 || true)
  # Test commands expose their strongest user signal in the final result line.
  if [[ -n "$summary_line" ]]; then
    trim_line "$summary_line"
    return 0
  fi

  summary_line=$(printf '%s\n' "$output" | grep -E '^Score:' | tail -1 || true)
  # Analyzer commands expose their strongest user signal in the score line.
  if [[ -n "$summary_line" ]]; then
    trim_line "$summary_line"
    return 0
  fi

  summary_line=$(printf '%s\n' "$output" | grep -E "Finished \`[^\`]+\` profile" | tail -1 || true)
  # Cargo commands expose their strongest user signal in the finished line.
  if [[ -n "$summary_line" ]]; then
    trim_line "$summary_line"
    return 0
  fi

  trim_line "$(printf '%s\n' "$output" | sed '/^[[:space:]]*$/d' | tail -1)"
}

# Show the final pass/fail result and every check a contributor must revisit.
show_preflight_summary() {
  local elapsed

  elapsed=$(elapsed_since "$START_TIME")
  printf '\n'
  show_section_rule
  printf '\n'

  # Skipped checks stay visible so users know which optional evidence is absent.
  if ((${#SKIPPED[@]} > 0)); then
    printf '  %sSkipped:%s\n' "$YELLOW" "$RESET"
    printf '    - %s\n' "${SKIPPED[@]}"
    printf '\n'
  fi

  # Zero failures gives contributors the single literal line used as gate evidence.
  if ((FAILED == 0)); then
    printf '  %sAll %d/%d checks passed%s  %s(%s)%s\n' "$GREEN$BOLD" "$PASSED" "$TOTAL" "$RESET" "$DIM" "$elapsed" "$RESET"
    printf '\n'
    return 0
  fi

  printf '  %s%d/%d checks failed%s  %s(%s)%s\n' "$RED$BOLD" "$FAILED" "$TOTAL" "$RESET" "$DIM" "$elapsed" "$RESET"
  printf '\n'
  # Each failed label gives the user a concise repair checklist.
  for failure in "${FAILURES[@]}"; do
    printf '    %s  %s\n' "$FAIL" "$failure"
  done
  printf '\n'

  return 1
}

# List tracked and new workspace files so local checks cover what users will review.
workspace_files() {
  local pattern="$1"

  # Git worktrees include tracked and untracked reviewable files without ignored output.
  if git -C "$REPO_ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    {
      git -C "$REPO_ROOT" ls-files -- "$pattern"
      git -C "$REPO_ROOT" ls-files --others --exclude-standard -- "$pattern"
    } | sort -u
  else
    (cd "$REPO_ROOT" && find . -type f -name "$pattern" -print | sed 's#^\./##')
  fi
}

# Mark an unavailable optional check without turning the whole user gate red.
show_skipped_check() {
  show_check_skipped "$1"
}

# Run one check and turn its command output into a stable contributor-facing line.
run_preflight_check() {
  local check_name="$1"
  shift
  local output
  local detail
  local status
  local started_at
  local elapsed

  start_check_line "$check_name"
  started_at=$(date +%s%N)
  output=$("$@" 2>&1)
  status=$?
  elapsed=$(elapsed_since "$started_at")

  # A zero exit code means the named contract is safe to show as passed.
  if ((status == 0)); then
    detail="$(compact_output "$output")"
    show_check_passed "${detail:+$detail | }$elapsed"
  else
    show_check_failed "$check_name"
    # Non-empty failure output gives the user the last actionable diagnostic lines.
    if [[ -n "$output" ]]; then
      printf '%s\n' "$output" | tail -20 | show_indented_output
    fi
    printf '    %sexit %d after %s%s\n' "$DIM" "$status" "$elapsed" "$RESET"
  fi

  return "$status"
}

# Reject mistyped release-check settings before users trust a weaker-than-requested run.
validate_release_check() {
  case "$GRUFF_RS_RELEASE_CHECK" in
    0|1|false|true|no|yes|off|on) ;;
    *) fail_preflight_setup "invalid GRUFF_RS_RELEASE_CHECK value: $GRUFF_RS_RELEASE_CHECK" ;;
  esac
}

# Report whether this run includes the extra version/tag/changelog release contract.
release_check_enabled() {
  case "$GRUFF_RS_RELEASE_CHECK" in
    1|true|yes|on) return 0 ;;
    *) return 1 ;;
  esac
}

# Turn the release-check state into the short label shown in the preflight header.
release_check_label() {
  # Enabled mode tells users this run also checked release-only version metadata.
  if release_check_enabled; then
    printf 'on'
  else
    printf 'off'
  fi
}

# Accept only the X.Y.Z release shape users see in Cargo metadata and Git tags.
is_release_semver() {
  [[ "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]
}

# Read the version users would package from Cargo.toml's package section.
manifest_package_version() {
  awk '
    /^\[package\]/ { in_pkg = 1; next }
    /^\[/          { in_pkg = 0 }
    in_pkg && /^version[[:space:]]*=/ {
      sub(/^version[[:space:]]*=[[:space:]]*"/, "")
      sub(/".*$/, "")
      print
      exit
    }
  ' "$REPO_ROOT/Cargo.toml"
}

# Read the gruff-rs version locked into the package graph contributors will test.
lockfile_package_version() {
  awk -v package_name="gruff-rs" '
    function maybe_print() {
      # A named package with a non-empty version is the lockfile entry users will build.
      if (name == package_name && version != "") {
        print version
        found = 1
        exit
      }
    }
    /^\[\[package\]\]/ {
      maybe_print()
      name = ""
      version = ""
      next
    }
    /^name[[:space:]]*=/ {
      name = $0
      sub(/^name[[:space:]]*=[[:space:]]*"/, "", name)
      sub(/".*$/, "", name)
      next
    }
    /^version[[:space:]]*=/ {
      version = $0
      sub(/^version[[:space:]]*=[[:space:]]*"/, "", version)
      sub(/".*$/, "", version)
      next
    }
    END {
      # The final package block has no following header, so emit its matching version here.
      if (!found && name == package_name && version != "") {
        print version
      }
    }
  ' "$REPO_ROOT/Cargo.lock"
}

# Find the newest exact release tag used to reject stale release-check versions.
latest_release_tag_version() {
  local tag
  local version

  # Tags are version-sorted so the first valid X.Y.Z entry is what users last released.
  while IFS= read -r tag; do
    version=${tag#v}
    # Non-release tags are ignored because they do not represent a published user version.
    if is_release_semver "$version"; then
      printf '%s\n' "$version"
      return 0
    fi
  done < <(git -C "$REPO_ROOT" tag --list 'v[0-9]*.[0-9]*.[0-9]*' --sort=-v:refname)

  return 1
}

# Compare two X.Y.Z versions to prove a candidate advances past the user release.
release_version_is_newer() {
  local left=$1 right=$2
  local left_major left_minor left_patch
  local right_major right_minor right_patch

  IFS=. read -r left_major left_minor left_patch <<<"$left"
  IFS=. read -r right_major right_minor right_patch <<<"$right"

  ((left_major > right_major)) && return 0
  ((left_major < right_major)) && return 1
  ((left_minor > right_minor)) && return 0
  ((left_minor < right_minor)) && return 1
  ((left_patch > right_patch))
}

# Keep manifest, lockfile, tag, and changelog versions aligned for users and publishers.
version_metadata_check() {
  local manifest_version
  local lock_version
  local latest_tag_version

  manifest_version=$(manifest_package_version)
  # An empty version means Cargo.toml cannot identify what users would install.
  if [[ -z "$manifest_version" ]]; then
    printf 'could not read [package] version from Cargo.toml\n' >&2
    return 1
  fi
  # A non-X.Y.Z version cannot map cleanly to the release tags and archive names.
  if ! is_release_semver "$manifest_version"; then
    printf 'Cargo.toml version must look like X.Y.Z (got: %s)\n' "$manifest_version" >&2
    return 1
  fi

  # When a lockfile is committed, its package identity must match what users package.
  if [[ -f "$REPO_ROOT/Cargo.lock" ]]; then
    lock_version=$(lockfile_package_version)
    # An empty lockfile result means the committed graph lost the gruff-rs package entry.
    if [[ -z "$lock_version" ]]; then
      printf 'could not read gruff-rs package version from Cargo.lock\n' >&2
      return 1
    fi
    # Different versions would make local tests and published package metadata disagree.
    if [[ "$manifest_version" != "$lock_version" ]]; then
      printf 'Cargo.toml version %s does not match Cargo.lock gruff-rs version %s\n' "$manifest_version" "$lock_version" >&2
      return 1
    fi
  fi

  # Release mode adds Git/tag/changelog evidence beyond the everyday contributor gate.
  if release_check_enabled; then
    # Without a worktree, the user has no local release tags to compare safely.
    if ! git -C "$REPO_ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
      printf '%s\n' '--release-check requires a git worktree' >&2
      return 1
    fi

    latest_tag_version=$(latest_release_tag_version || true)
    # A non-empty prior tag requires the candidate to advance the installed user version.
    if [[ -n "$latest_tag_version" ]] \
      && ! release_version_is_newer "$manifest_version" "$latest_tag_version"; then
      printf 'Cargo.toml version %s must be greater than latest release tag v%s\n' "$manifest_version" "$latest_tag_version" >&2
      return 1
    fi

    # Escape the version's dots so the heading match is literal, not a regex wildcard.
    local changelog_version="${manifest_version//./\\.}"
    # An existing changelog must tell users what changed in this exact release version.
    if [[ -f "$REPO_ROOT/CHANGELOG.md" ]] \
      && ! grep -qE "^##[[:space:]]+v?${changelog_version}[[:space:]]+-[[:space:]]+[0-9]{4}-[0-9]{2}-[0-9]{2}" "$REPO_ROOT/CHANGELOG.md"; then
      printf 'CHANGELOG.md is missing a release heading for %s\n' "$manifest_version" >&2
      return 1
    fi
  fi

  # The success detail tells reviewers whether release-only evidence was included.
  if release_check_enabled; then
    printf 'Cargo.toml/Cargo.lock %s; release check on\n' "$manifest_version"
  else
    printf 'Cargo.toml/Cargo.lock %s\n' "$manifest_version"
  fi
}

# Check every reviewable shell script parses before a user or CI job executes it.
check_shell_syntax() {
  local shell_files=()
  local existing_shell_files=()
  local shell_file
  mapfile -t shell_files < <(workspace_files '*.sh')

  # Removed files can still appear in Git output, so only runnable files reach Bash.
  for shell_file in "${shell_files[@]}"; do
    # An existing path is a shell script users can actually execute from this checkout.
    if [[ -f "$shell_file" ]]; then
      existing_shell_files+=("$shell_file")
    fi
  done
  shell_files=("${existing_shell_files[@]}")

  # No shell files means this optional language-specific check has nothing to inspect.
  if ((${#shell_files[@]} == 0)); then
    show_skipped_check "shell syntax (no shell scripts)"
    return 0
  fi

  bash -n "${shell_files[@]}"
}

# Run shellcheck when available so contributors see risky shell behavior before review.
check_shellcheck() {
  local shell_files=()
  local existing_shell_files=()
  local shell_file
  mapfile -t shell_files < <(workspace_files '*.sh')

  # Removed files can still appear in Git output, so only reviewable files reach shellcheck.
  for shell_file in "${shell_files[@]}"; do
    # An existing path is a shell script users can actually execute from this checkout.
    if [[ -f "$shell_file" ]]; then
      existing_shell_files+=("$shell_file")
    fi
  done
  shell_files=("${existing_shell_files[@]}")

  # No shell files means this optional language-specific check has nothing to inspect.
  if ((${#shell_files[@]} == 0)); then
    show_skipped_check "shellcheck (no shell scripts)"
    return 0
  fi

  # A missing optional shellcheck is visible as SKIP rather than a false project failure.
  if ! command -v shellcheck >/dev/null 2>&1; then
    show_skipped_check "shellcheck (not installed)"
    return 0
  fi

  shellcheck "${shell_files[@]}"
}

# Require Cargo before any Rust, package, or analyzer check starts for the user.
require_cargo_for_preflight() {
  command -v cargo >/dev/null 2>&1 \
    || fail_preflight_setup "cargo is not available on PATH"
}

# Resolve the Cargo bin directory where a developer's installed audit tool lives.
resolved_cargo_install_root() {
  # CI may provide a dedicated install root for cached check binaries.
  if [[ -n "${CARGO_INSTALL_ROOT:-}" ]]; then
    printf '%s\n' "$CARGO_INSTALL_ROOT"
  # A custom Cargo home means its bin directory is the user's expected location.
  elif [[ -n "${CARGO_HOME:-}" ]]; then
    printf '%s\n' "$CARGO_HOME"
  else
    printf '%s\n' "$HOME/.cargo"
  fi
}

# Find cargo-audit on PATH or in Cargo's install root for this contributor.
installed_cargo_audit_path() {
  local cargo_install_root
  local cargo_audit_path

  # A PATH result is what the user's next cargo-audit command would execute.
  if cargo_audit_path=$(command -v cargo-audit 2>/dev/null); then
    printf '%s\n' "$cargo_audit_path"
    return 0
  fi

  cargo_install_root=$(resolved_cargo_install_root)
  cargo_audit_path="$cargo_install_root/bin/cargo-audit"
  # Cargo's bin path covers users whose shell PATH has not been refreshed yet.
  if [[ -x "$cargo_audit_path" ]]; then
    printf '%s\n' "$cargo_audit_path"
    return 0
  fi

  return 1
}

# Report whether the discovered audit binary is the exact reviewed release.
installed_cargo_audit_matches() {
  local cargo_audit_path=$1
  local reported_version

  # A missing executable cannot provide the dependency gate users requested.
  if [[ ! -x "$cargo_audit_path" ]]; then
    return 1
  fi
  reported_version=$("$cargo_audit_path" --version 2>/dev/null)
  [[ $reported_version == *" $CARGO_AUDIT_VERSION" ]]
}

# Reuse or install the exact cargo-audit release before checking user dependencies.
ensure_pinned_cargo_audit() {
  local cargo_audit_path

  # A matching audit binary makes this gate repeatable without reinstalling it.
  if cargo_audit_path=$(installed_cargo_audit_path) \
    && installed_cargo_audit_matches "$cargo_audit_path"; then
    printf '%s\n' "$cargo_audit_path"
    return 0
  fi

  printf 'cargo-audit %s is missing; installing the exact locked release\n' \
    "$CARGO_AUDIT_VERSION" >&2
  cargo install cargo-audit \
    --version "$CARGO_AUDIT_VERSION" \
    --locked \
    --force || return $?

  # The installed binary must report the reviewed version before users trust its audit.
  if cargo_audit_path=$(installed_cargo_audit_path) \
    && installed_cargo_audit_matches "$cargo_audit_path"; then
    printf '%s\n' "$cargo_audit_path"
    return 0
  fi

  printf 'cargo-audit %s was not found at %s/bin/cargo-audit or on PATH\n' \
    "$CARGO_AUDIT_VERSION" \
    "$(resolved_cargo_install_root)" >&2
  return 1
}

# Audit the committed dependency graph users will build for known RustSec advisories.
dependency_audit_check() {
  local cargo_audit_path

  cargo_audit_path=$(ensure_pinned_cargo_audit) || return $?
  "$cargo_audit_path" audit
}

# Validate the composite action surface users call from their own workflows.
action_metadata_validation() {
  local action_validator_path
  local reported_version

  # A missing validator tells developers exactly which setup command restores the gate.
  action_validator_path=$(command -v action-validator) || {
    printf 'action-validator is missing; run bash scripts/dependency-install.sh\n' >&2
    return 1
  }
  reported_version=$("$action_validator_path" --version 2>/dev/null)
  # A different release could accept metadata that hosted CI or users reject.
  [[ $reported_version == "action-validator $ACTION_VALIDATOR_VERSION" ]] || {
    printf 'action-validator %s is required (got: %s)\n' \
      "$ACTION_VALIDATOR_VERSION" \
      "$reported_version" >&2
    return 1
  }
  "$action_validator_path" action.yml
}

# Validate hosted workflows with the same exact actionlint release contributors install.
workflow_validation() {
  local actionlint_path
  local reported_version

  # A missing validator tells developers exactly which setup command restores the gate.
  actionlint_path=$(command -v actionlint) || {
    printf 'actionlint is missing; run bash scripts/dependency-install.sh\n' >&2
    return 1
  }
  reported_version=$("$actionlint_path" -version 2>/dev/null | head -1)
  # A different release could make local workflow feedback disagree with hosted CI.
  [[ $reported_version == "$ACTIONLINT_VERSION" ]] || {
    printf 'actionlint %s is required (got: %s)\n' \
      "$ACTIONLINT_VERSION" \
      "$reported_version" >&2
    return 1
  }
  "$actionlint_path"
}

# Scan live GitHub metadata that ordinary config-aware dogfood intentionally ignores.
# Contributors reach this check through preflight; exact paths keep the bypass visible
# and prevent recursive discovery of arbitrary local actions.
focused_github_metadata_scan() {
  local report_file="$WORK_DIR/github-metadata.json"
  local metadata_paths=()
  local workflow_paths=()
  local workflow_path
  local expected_file_count
  local actual_file_count
  local github_rule_pattern='"ruleId": "(ci\.github-event-shell-interpolation|security\.github-actions-(broad-permissions|pull-request-target|remote-shell|secrets-in-pr|unpinned-action))"'

  shopt -s nullglob
  workflow_paths=(.github/workflows/*.yml .github/workflows/*.yaml)
  shopt -u nullglob

  # Each root workflow is named explicitly so no hidden directory traversal is widened.
  for workflow_path in "${workflow_paths[@]}"; do
    metadata_paths+=("$workflow_path")
  done

  # No workflow paths means the security gate lost the hosted automation it promises to scan.
  if ((${#metadata_paths[@]} == 0)); then
    printf 'GitHub metadata scan found no .github/workflows/*.yml or *.yaml files\n' >&2
    return 1
  fi
  # A missing root action means downstream workflow users would have no action metadata to scan.
  if [[ ! -f action.yml ]]; then
    printf 'GitHub metadata scan expected root action.yml\n' >&2
    return 1
  fi
  metadata_paths+=(action.yml)
  expected_file_count=${#metadata_paths[@]}

  cargo run --quiet -- analyse "${metadata_paths[@]}" \
    --no-config \
    --no-baseline \
    --format json \
    --fail-on none >"$report_file" || return $?

  actual_file_count=$(sed -n \
    's/.*"analysedFiles": \([0-9][0-9]*\).*/\1/p' \
    "$report_file" | head -1)
  # An absent count means the report no longer proves which requested files reached analysis.
  if [[ -z "$actual_file_count" ]]; then
    printf 'GitHub metadata scan could not read paths.analysedFiles\n' >&2
    return 1
  fi
  # A count mismatch means a named workflow or action was silently skipped.
  if ((actual_file_count != expected_file_count)); then
    printf 'GitHub metadata scan analysed %s of %s expected paths\n' \
      "$actual_file_count" \
      "$expected_file_count" >&2
    return 1
  fi
  # Ignored or missing entries mean the exact-path config bypass did not reach every user file.
  if ! grep -q '"ignoredPaths": \[\]' "$report_file" \
    || ! grep -q '"ignoredPathDetails": \[\]' "$report_file" \
    || ! grep -q '"missingPaths": \[\]' "$report_file"; then
    printf 'GitHub metadata scan reported an ignored or missing exact path\n' >&2
    return 1
  fi
  # Any applicable finding means checked-in automation failed its own focused security scan.
  if grep -Eq "$github_rule_pattern" "$report_file"; then
    printf 'GitHub metadata scan reported applicable findings:\n' >&2
    grep -E "$github_rule_pattern" "$report_file" >&2
    return 1
  fi

  printf 'analysed exact GitHub metadata paths: %s\n' "${metadata_paths[*]}"
}

# Prove users can request deterministic JSON findings from the fixture project.
fixture_json_smoke() {
  cargo run --quiet -- analyse fixtures --format json --fail-on none >"$WORK_DIR/fixtures.json"
}

# Prove users can request SARIF suitable for a code-scanning upload step.
fixture_sarif_smoke() {
  cargo run --quiet -- analyse fixtures --format sarif --fail-on none >"$WORK_DIR/fixtures.sarif"
}

# Prove integrations can enumerate the complete rule registry as JSON.
list_rules_json_smoke() {
  cargo run --quiet -- list-rules --format json >"$WORK_DIR/list-rules.json"
}

# Prove users can inspect only Security rules through the selector surface.
security_selector_listing_smoke() {
  cargo run --quiet -- list-rules --selector Security >"$WORK_DIR/security-rules.txt"
}

# Prove summary users receive the current schema and ranked rule data.
summary_json_smoke() {
  local summary_file="$WORK_DIR/summary.json"

  cargo run --quiet -- summary fixtures --format json --top 5 --include-ignored >"$summary_file" || return $?
  grep -Eq '"schemaVersion"[[:space:]]*:[[:space:]]*"gruff\.summary\.v2"' "$summary_file" || return $?
  grep -q '"topRules":' "$summary_file"
}

# Prove a user-provided patch limits findings to the changed source region.
patch_diff_smoke() {
  local patch_file="$WORK_DIR/fixture.patch"
  local full_report="$WORK_DIR/fixture-full.txt"
  local patch_report="$WORK_DIR/fixture-patch.txt"
  local full_findings
  local patch_findings

  cat >"$patch_file" <<'PATCH'
diff --git a/fixtures/sample.rs b/fixtures/sample.rs
--- a/fixtures/sample.rs
+++ b/fixtures/sample.rs
@@ -11,1 +11,1 @@
+        std::process::Command::new(command).arg(url).spawn().unwrap();
PATCH

  # --no-config so the smoke exercises --diff-patch mechanics independent of the
  # project's paths.ignore (which excludes fixtures/** — authoritative even for
  # explicit file args per ADR-018).
  cargo run --quiet -- analyse fixtures/sample.rs --no-config --format text --fail-on none --no-baseline >"$full_report" || return $?
  cargo run --quiet -- analyse fixtures/sample.rs --no-config --format text --fail-on none --no-baseline --diff-patch "$patch_file" >"$patch_report" || return $?

  full_findings="$(grep -c '^- \[' "$full_report" || true)"
  patch_findings="$(grep -c '^- \[' "$patch_report" || true)"
  # A patch with one changed line must reduce what the user needs to review.
  if ((patch_findings >= full_findings)); then
    printf 'patch diff smoke did not reduce findings: full=%s patch=%s\n' "$full_findings" "$patch_findings" >&2
    return 1
  fi

  grep -q 'patch-filter' "$patch_report"
}

# Prove an explicit rule selector excludes unrelated findings from the user report.
selector_smoke() {
  local config_file="$WORK_DIR/selector.yaml"
  local report_file="$WORK_DIR/selector.txt"

  cat >"$config_file" <<'YAML'
schemaVersion: gruff-rs.config.v1
rules:
  select: ["security.process-command"]
YAML

  cargo run --quiet -- analyse fixtures/sample.rs --format text --fail-on none --no-baseline --config "$config_file" >"$report_file" || return $?
  grep -q 'security.process-command' "$report_file" || return $?
  # Seeing an unselected rule would violate the allow-list the user requested.
  if grep -q 'sensitive-data.aws-access-key' "$report_file"; then
    printf 'selector smoke reported a rule outside the explicit allow-list\n' >&2
    return 1
  fi
}

# Prove a documented exclusion removes findings and remains visible in the report.
exclusion_smoke() {
  local config_file="$WORK_DIR/exclude.yaml"
  local full_report="$WORK_DIR/exclude-full.txt"
  local filtered_report="$WORK_DIR/exclude-filtered.txt"
  local full_findings
  local filtered_findings

  cat >"$config_file" <<'YAML'
schemaVersion: gruff-rs.config.v1
exclude:
  - rule: security.process-command
    reason: fixture command accepted for smoke testing
YAML

  cargo run --quiet -- analyse fixtures/sample.rs --format text --fail-on none --no-baseline --no-config >"$full_report" || return $?
  cargo run --quiet -- analyse fixtures/sample.rs --format text --fail-on none --no-baseline --config "$config_file" >"$filtered_report" || return $?

  full_findings="$(grep -c '^- \[' "$full_report" || true)"
  filtered_findings="$(grep -c '^- \[' "$filtered_report" || true)"
  # A configured exclusion must reduce the findings the user has to review.
  if ((filtered_findings >= full_findings)); then
    printf 'exclusion smoke did not reduce findings: full=%s filtered=%s\n' "$full_findings" "$filtered_findings" >&2
    return 1
  fi

  grep -q 'Suppressed findings:' "$filtered_report"
}

# Prove users can list and run one configuration-defined text rule end to end.
custom_rule_smoke() {
  local config_file="$WORK_DIR/custom.yaml"
  local rules_file="$WORK_DIR/custom-rules.json"
  local report_file="$WORK_DIR/custom-analysis.txt"

  cat >"$config_file" <<'YAML'
schemaVersion: gruff-rs.config.v1
custom_rules:
  - id: custom.fixture-marker
    pillar: Documentation
    severity: advisory
    message: Fixture marker
    scope: text
    pattern: SampleAnalyzer
YAML

  cargo run --quiet -- list-rules --format json --config "$config_file" >"$rules_file" || return $?
  grep -q '"id": "custom.fixture-marker"' "$rules_file" || return $?
  cargo run --quiet -- analyse fixtures/sample.rs --format text --fail-on none --no-baseline --config "$config_file" >"$report_file" || return $?
  grep -q 'custom.fixture-marker' "$report_file"
}

# Keep orientation docs aligned with the schema and commands users actually receive.
docs_drift_check() {
  local architecture_doc="$REPO_ROOT/.goat-flow/architecture.md"
  local glossary_doc="$REPO_ROOT/.goat-flow/glossary.md"
  local analysis_source="$REPO_ROOT/src/analysis.rs"
  local backtick='`'
  local live_schema
  local orientation_doc
  local document_schema
  local cli_command
  local help_text
  local checked_command_count=0
  local stale_schemas=()
  local missing_commands=()

  # Missing orientation inputs mean reviewers cannot compare docs with live behavior.
  [[ -f "$architecture_doc" \
    && -f "$glossary_doc" \
    && -f "$analysis_source" ]] || {
    printf 'docs drift: expected architecture.md, glossary.md, and src/analysis.rs\n' >&2
    return 1
  }

  # Schema-version drift: the orientation docs must not name a stale
  # gruff.analysis.v* that differs from the live schema string in the code.
  live_schema=$(grep -oE 'gruff\.analysis\.v[0-9]+' "$analysis_source" | sort -u | head -1)
  # An empty schema means the gate cannot tell users which report contract is current.
  if [[ -z "$live_schema" ]]; then
    printf 'docs drift: could not read live analysis schema from src/analysis.rs\n' >&2
    return 1
  fi
  # Both orientation documents must name only the report schema users receive now.
  for orientation_doc in "$architecture_doc" "$glossary_doc"; do
    # Every schema mention is compared independently so the failure names its document.
    while IFS= read -r document_schema; do
      # Empty grep output has no contract, while the live schema is already correct.
      if [[ -z "$document_schema" || "$document_schema" == "$live_schema" ]]; then
        continue
      fi
      stale_schemas+=("${orientation_doc##*/}:$document_schema")
    done < <(grep -oE 'gruff\.analysis\.v[0-9]+' "$orientation_doc" | sort -u)
  done

  # Command-surface drift: every command the binary exposes must be named in
  # architecture.md (the System Overview enumerates the user-facing modes).
  help_text=$(cargo run --quiet -- help 2>/dev/null) || {
    printf 'docs drift: could not run gruff-rs help for command enumeration\n' >&2
    return 1
  }
  # Each command from --help must appear in the architecture overview users consult.
  while IFS= read -r cli_command; do
    # Empty parser output and the help pseudo-command are not runnable product modes.
    if [[ -z "$cli_command" || "$cli_command" == "help" ]]; then
      continue
    fi
    checked_command_count=$((checked_command_count + 1))
    grep -qF "${backtick}${cli_command}${backtick}" "$architecture_doc" \
      || missing_commands+=("$cli_command")
  done < <(printf '%s\n' "$help_text" | awk '/^Available commands:/{f=1;next} f&&/^$/{f=0} f&&/^  [a-z]/{print $1}')

  # Any stale schema or missing command would mislead a user reading orientation docs.
  if ((${#stale_schemas[@]} > 0 || ${#missing_commands[@]} > 0)); then
    # Stale schema entries tell maintainers which report-contract references to update.
    if ((${#stale_schemas[@]} > 0)); then
      printf 'docs drift: stale analysis schema (live=%s): %s\n' \
        "$live_schema" \
        "${stale_schemas[*]}" >&2
    fi
    # Missing commands tell maintainers which user-visible mode lacks orientation.
    if ((${#missing_commands[@]} > 0)); then
      printf 'docs drift: commands missing from architecture.md: %s\n' \
        "${missing_commands[*]}" >&2
    fi
    return 1
  fi

  printf '%s + %d CLI commands match orientation docs\n' \
    "$live_schema" \
    "$checked_command_count"
}

# Analyse gruff-rs itself so contributors see the same quality gate as downstream users.
dogfood_scan() {
  bin/gruff-rs analyse . --format text --no-baseline
}

# Parse user options and run the complete preflight suite in its stable display order.
run_preflight_suite() {
  # Each option adjusts the gate before any potentially long check begins.
  while (($#)); do
    case "$1" in
      --release-check)
        GRUFF_RS_RELEASE_CHECK=1
        shift
        ;;
      -h|--help)
        usage
        return 0
        ;;
      *)
        fail_preflight_setup "unknown argument: $1"
        ;;
    esac
  done

  validate_release_check
  require_cargo_for_preflight
  WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/gruff-rs-preflight.XXXXXX")"
  trap remove_preflight_workspace EXIT

  cd "$REPO_ROOT" || return 1

  show_preflight_header

  run_preflight_check "shell syntax" check_shell_syntax
  run_preflight_check "shellcheck" check_shellcheck
  run_preflight_check "version metadata" version_metadata_check
  run_preflight_check "dependency audit" dependency_audit_check
  run_preflight_check "action metadata" action_metadata_validation
  run_preflight_check "workflow validation" workflow_validation
  run_preflight_check "GitHub metadata scan" focused_github_metadata_scan
  run_preflight_check "cargo fmt" cargo fmt --check
  run_preflight_check "cargo clippy" cargo clippy --all-targets -- -D warnings
  run_preflight_check "cargo test" cargo test
  run_preflight_check "list-rules JSON" list_rules_json_smoke
  run_preflight_check "Security selector listing" security_selector_listing_smoke
  run_preflight_check "summary JSON" summary_json_smoke
  run_preflight_check "fixture JSON scan" fixture_json_smoke
  run_preflight_check "fixture SARIF scan" fixture_sarif_smoke
  run_preflight_check "patch diff smoke" patch_diff_smoke
  run_preflight_check "selector smoke" selector_smoke
  run_preflight_check "exclusion smoke" exclusion_smoke
  run_preflight_check "custom rule smoke" custom_rule_smoke
  run_preflight_check "docs drift" docs_drift_check
  run_preflight_check "gruff-rs dogfood scan" dogfood_scan

  show_preflight_summary
}

run_preflight_suite "$@"
