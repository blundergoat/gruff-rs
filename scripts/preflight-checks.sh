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
PREFLIGHT_MODE=full
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
  - deny-dangerous hook policy self-test (smoke tier)
  - post-turn safety hook exit-contract self-test
  - cargo fmt, clippy, and tests
  - crate version consistency between Cargo.toml and Cargo.lock
  - RustSec dependency audit, auto-installing cargo-audit when missing
  - pinned action.yml and GitHub Actions workflow validators
  - exact-path GitHub workflow and composite-action security scan without project config
  - rule-listing, summary, fixture JSON/SARIF, patch, selector, exclusion, and custom-rule smokes
  - gruff-rs dogfood scan (analyse the whole project, gated by minimumSeverity.analyse in .gruff-rs.yaml)
  - documentation drift guards for release examples, built-in rules, schemas, and CLI commands

Options:
  --release-check        Also require the crate version to be newer than the
                         latest local vX.Y.Z tag and present in CHANGELOG.md.
  --docs-drift-check     Run only the live documentation drift check.
  --docs-drift-fixtures  Run only the deterministic drift-check fixture harness.
  -h, --help             Show this help.

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

  summary_line=$(printf '%s\n' "$output" | grep -E '^Composite:' | tail -1 || true)
  # Analyzer commands expose their strongest user signal in the composite line.
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

  # Zero failures gives contributors the single literal line used as gate evidence. The skip count
  # is named in that same line because it is quoted on its own as proof: without it, a run where an
  # optional linter was absent is indistinguishable from one where every check executed.
  if ((FAILED == 0)); then
    if ((${#SKIPPED[@]} > 0)); then
      printf '  %sAll %d/%d checks passed, %d skipped%s  %s(%s)%s\n' \
        "$GREEN$BOLD" "$PASSED" "$TOTAL" "${#SKIPPED[@]}" "$RESET" "$DIM" "$elapsed" "$RESET"
    else
      printf '  %sAll %d/%d checks passed%s  %s(%s)%s\n' "$GREEN$BOLD" "$PASSED" "$TOTAL" "$RESET" "$DIM" "$elapsed" "$RESET"
    fi
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

# Security fixes this repository carries on top of the managed goat-flow hook templates, as "hook<TAB>anchor<TAB>reason"
# rows. Each upgrade has silently reverted at least one of them, so presence is asserted rather than assumed. Anchors
# are semantic on purpose: byte comparison would trip on an upstream reflow and would also fail once upstream adopts a
# fix, which is the outcome we want to keep passing - so `goat-flow audit --check-drift` reporting these hooks as
# drifted is the expected state, not a repair signal. Every reason states what breaks without the fix, because this
# table is the only place that harm is recorded; the hook files themselves are tracked, so git is the recovery source.
MANAGED_HOOK_DELTAS=(
  $'post-turn-safety.sh\tis_line_allowlisted\tline-scoped goat-flow-allow-secret marker (ADR-022); without it every turn touching fixtures/sample.rs blocks on a calibration token the repository must keep'
  $'post-turn-safety.sh\t"@@ "*)\tonly a real hunk header is skipped; without it an added line rendering as "+++" under --unified=0 is dropped and a credential on it ends the turn with exit 0'
  $'run-with-bash.mjs\tsymlinkFreePath\tlauncher resolves symlinks before comparing its own path; without it a symlinked project directory loads the launcher, runs no hook, and exits 0 as "guard passed"'
  $'deny-dangerous.sh\twatch --any-unknown-flag\tan unknown watch option skips instead of abandoning normalisation; without it "watch --any-unknown-flag rm -rf /" reaches the policy modules as a bare watch call and is allowed'
  $'deny-dangerous.sh\tparallel --any-unknown-flag\tan unknown parallel option skips instead of abandoning normalisation; without it "parallel --any-unknown-flag rm -rf /" is allowed for the same reason'
  $'deny-dangerous/deny-dangerous-self-test.sh\twatch unknown long option\tregression cases pinning the two wrapper repairs above; without them a reverted wrapper parser still passes --self-test=full'
)

# Prove every local hook delta is still present in the installed managed hooks. A goat-flow install or hooks sync
# restores these files from the template, which silently removes each fix; this check is what notices.
managed_hook_deltas_present() {
  local hooks_dir="${1:-$REPO_ROOT/.goat-flow/hooks}"
  local -a missing=()
  local row hook_name anchor reason

  for row in "${MANAGED_HOOK_DELTAS[@]}"; do
    IFS=$'\t' read -r hook_name anchor reason <<<"$row"
    # An absent hook file means the managed install is broken in a way a grep cannot describe.
    if [[ ! -f "$hooks_dir/$hook_name" ]]; then
      printf 'managed hook deltas: %s is missing from %s\n' "$hook_name" "$hooks_dir" >&2
      return 1
    fi
    # A missing anchor means an upgrade reverted this fix and the repository is running unprotected.
    if ! grep -qF -- "$anchor" "$hooks_dir/$hook_name"; then
      missing+=("$hook_name: $reason (anchor: $anchor)")
    fi
  done

  # Naming the fix, its harm, and its anchor lets the reader restore it from git without re-deriving what was lost.
  if ((${#missing[@]} > 0)); then
    printf 'managed hook deltas: reverted by an install or sync; restore with: git checkout <rev-before-the-install> -- .goat-flow/hooks/\n' >&2
    printf '  %s\n' "${missing[@]}" >&2
    return 1
  fi

  printf '%s local hook deltas present\n' "${#MANAGED_HOOK_DELTAS[@]}"
}

# Correctness fixes this repository carries on top of the managed goat-flow skill docs, as "doc<TAB>anchor<TAB>reason"
# rows, in the same shape and for the same reason as MANAGED_HOOK_DELTAS above. `goat-flow install` rewrites these files
# from the template, so a repair that is right for this repository but not yet upstream needs an assertion or it leaves
# silently. Anchors are semantic; every reason states what breaks without the fix.
MANAGED_DOC_DELTAS=(
  $'skill-docs/playbooks/gruff-code-quality.md\t"bin/$target"\tthe availability probe checks the repo-local wrapper first; without it the probe returns empty inside gruff-rs and an agent following CLAUDE.md READ declares the analyzer unavailable in its own repository'
  $'skill-docs/playbooks/gruff-code-quality.md\trather than assuming a spelling\tthe threshold guidance sends the reader to analyse --help instead of naming a flag; without it an agent runs the suggested --min-severity, which this port does not expose, and reads the exit 2 as a config fault'
)

# Prove every local skill-doc delta is still present in the installed managed docs. Same failure mode as the hook
# deltas: the template wins on reinstall and nothing else notices the loss.
managed_doc_deltas_present() {
  local docs_dir="${1:-$REPO_ROOT/.goat-flow}"
  local -a missing=()
  local row doc_name anchor reason

  for row in "${MANAGED_DOC_DELTAS[@]}"; do
    IFS=$'\t' read -r doc_name anchor reason <<<"$row"
    # An absent doc means the managed install is broken in a way a grep cannot describe.
    if [[ ! -f "$docs_dir/$doc_name" ]]; then
      printf 'managed doc deltas: %s is missing from %s\n' "$doc_name" "$docs_dir" >&2
      return 1
    fi
    # A missing anchor means an install reverted this fix and the doc is guiding agents wrongly again.
    if ! grep -qF -- "$anchor" "$docs_dir/$doc_name"; then
      missing+=("$doc_name: $reason (anchor: $anchor)")
    fi
  done

  if ((${#missing[@]} > 0)); then
    printf 'managed doc deltas: reverted by an install; restore with: git checkout <rev-before-the-install> -- .goat-flow/skill-docs/\n' >&2
    printf '  %s\n' "${missing[@]}" >&2
    return 1
  fi

  printf '%s local doc deltas present\n' "${#MANAGED_DOC_DELTAS[@]}"
}

# Rule forms Claude never matches in permissions.deny/allow/ask. Such a rule warns at launch and enforces nothing, so
# it reads as protection that does not exist. See ADR-023.
INERT_PERMISSION_TOOLS='["Write","MultiEdit","NotebookEdit","Glob"]'

# Prove the agent settings still pair Read with Edit on every secret path and carry no inert rule form. An Edit deny
# already refuses the Write tool, so pairing - not one entry per tool name - is the invariant worth guarding.
permission_rule_hygiene() {
  local settings_file="${1:-$REPO_ROOT/.claude/settings.json}"
  local inert
  local unpaired

  require_jq_for_preflight

  # Absent settings would leave every secret-path deny unverified for this repository.
  if [[ ! -f "$settings_file" ]]; then
    printf 'permission rule hygiene: %s is missing\n' "$settings_file" >&2
    return 1
  fi
  # Malformed JSON cannot establish which paths the agent actually refuses.
  if ! jq -e 'type == "object"' "$settings_file" >/dev/null 2>&1; then
    printf 'permission rule hygiene: %s is not valid JSON\n' "$settings_file" >&2
    return 1
  fi

  # An unmatched tool prefix anywhere in deny/allow/ask is the regression this check exists to catch.
  inert=$(jq -r --argjson inert_tools "$INERT_PERMISSION_TOOLS" '
    (.permissions // {})
    | ((.deny // []) + (.allow // []) + (.ask // []))
    | map(select(type == "string"))
    | map(select(. as $rule | ($inert_tools | index($rule | split("(")[0])) != null))
    | unique
    | .[]
  ' "$settings_file") || {
    printf 'permission rule hygiene: could not read permissions from %s\n' "$settings_file" >&2
    return 1
  }
  # Naming each offending rule lets the reader delete it without re-deriving which forms are inert.
  if [[ -n "$inert" ]]; then
    printf 'permission rule hygiene: inert rule forms (never matched; use Read/Edit instead, see ADR-023):\n' >&2
    printf '%s\n' "$inert" | sed 's/^/  /' >&2
    return 1
  fi

  # A path denied for reading but not editing (or the reverse) is a real one-sided hole in the deny list.
  unpaired=$(jq -r '
    (.permissions.deny // []) as $deny
    | ([$deny[] | select(startswith("Read(")) | .[5:-1]] | sort) as $read_paths
    | ([$deny[] | select(startswith("Edit(")) | .[5:-1]] | sort) as $edit_paths
    | (($read_paths - $edit_paths) | map("denied for Read but not Edit: " + .))
      + (($edit_paths - $read_paths) | map("denied for Edit but not Read: " + .))
    | .[]
  ' "$settings_file") || {
    printf 'permission rule hygiene: could not compare Read and Edit denies in %s\n' "$settings_file" >&2
    return 1
  }
  # An unpaired path is reported verbatim so the fix is a copy of the missing line.
  if [[ -n "$unpaired" ]]; then
    printf 'permission rule hygiene: unpaired secret-path denies:\n' >&2
    printf '%s\n' "$unpaired" | sed 's/^/  /' >&2
    return 1
  fi

  printf 'Read/Edit denies paired on %s paths; no inert rule forms\n' \
    "$(jq -r '[(.permissions.deny // [])[] | select(startswith("Read("))] | length' "$settings_file")"
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

# Exercise the deny hook's policy corpus so a regression in the command guard
# fails the build rather than silently widening what agents may run. Smoke is the
# per-change tier; run --self-test=full when the hook or its policy modules change.
deny_dangerous_self_test() {
  bash "$REPO_ROOT/.goat-flow/hooks/deny-dangerous.sh" --self-test=smoke
}

# Exercise the Stop-hook fail-closed contract in isolated temporary repositories.
post_turn_safety_self_test() {
  bash "$REPO_ROOT/.goat-flow/hooks/post-turn-safety/post-turn-safety-self-test.sh"
}

# Require Cargo before any Rust, package, or analyzer check starts for the user.
require_cargo_for_preflight() {
  command -v cargo >/dev/null 2>&1 \
    || fail_preflight_setup "cargo is not available on PATH"
}

# Require the structured JSON reader used to compare docs with live rule metadata.
require_jq_for_preflight() {
  command -v jq >/dev/null 2>&1 \
    || fail_preflight_setup "jq is required for documentation drift checks; install jq and rerun preflight"
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

  # Package verification can leave a same-version binary built from target/package sources.
  # A distinct fingerprint makes this security scan compile the live contributor workspace.
  CARGO_INCREMENTAL=0 cargo run --quiet -- analyse "${metadata_paths[@]}" \
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
  cargo run --quiet -- list-rules --format json --no-config >"$WORK_DIR/list-rules.json"
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

# Read the package version that release examples must match from Cargo metadata.
package_version_for_docs() {
  local metadata
  local package_version

  # A malformed manifest prevents the docs gate from knowing which release users install.
  metadata=$(cargo metadata --format-version 1 --no-deps) || {
    printf 'docs drift: cargo metadata could not read the package version\n' >&2
    return 1
  }
  # Exactly one gruff-rs package row identifies the version every labelled example must use.
  package_version=$(printf '%s\n' "$metadata" | jq -er '
    [.packages[] | select(.name == "gruff-rs") | .version]
    | select(length == 1)
    | .[0]
  ') || {
    printf 'docs drift: Cargo metadata package.version actual=<missing> expected=one gruff-rs version\n' >&2
    return 1
  }

  printf '%s\n' "$package_version"
}

# Return one explicitly labelled documentation block for contract comparison.
read_single_docs_block() {
  local doc_file=$1
  local block_name=$2
  local begin_marker="<!-- gruff-docs:begin $block_name -->"
  local end_marker="<!-- gruff-docs:end $block_name -->"
  local begin_count
  local end_count

  begin_count=$(grep -Fxc "$begin_marker" "$doc_file" || true)
  end_count=$(grep -Fxc "$end_marker" "$doc_file" || true)

  # Missing or repeated start anchors leave maintainers unsure which value is machine-owned.
  if ((begin_count != 1)); then
    printf "docs drift: %s: '%s' marker count actual=%s expected=1\n" \
      "$doc_file" \
      "$begin_marker" \
      "$begin_count" >&2
    return 1
  fi
  # Missing or repeated end anchors can make unrelated prose part of the generated contract.
  if ((end_count != 1)); then
    printf "docs drift: %s: '%s' marker count actual=%s expected=1\n" \
      "$doc_file" \
      "$end_marker" \
      "$end_count" >&2
    return 1
  fi

  awk -v begin_marker="$begin_marker" -v end_marker="$end_marker" '
    $0 == begin_marker { inside = 1; next }
    $0 == end_marker { inside = 0; next }
    inside { print }
  ' "$doc_file"
}

# Compare one labelled value and name the stale value, expected value, and document.
assert_docs_value() {
  local doc_file=$1
  local label=$2
  local actual=$3
  local expected=$4
  local actual_display=$actual

  # A missing parse result tells the maintainer the labelled line changed shape or vanished.
  if [[ -z "$actual_display" ]]; then
    actual_display='<missing>'
  fi
  actual_display=${actual_display//$'\n'/,}

  # Drift failures show the exact edit needed instead of only reporting inequality.
  if [[ "$actual" != "$expected" ]]; then
    printf "docs drift: %s: %s actual='%s' expected='%s'\n" \
      "$doc_file" \
      "$label" \
      "$actual_display" \
      "$expected" >&2
    return 1
  fi
}

# Turn tabular pillar evidence into one readable value for a failed preflight line.
pillar_table_summary() {
  local table=$1
  local summary=${table//$'\t'/=}

  summary=${summary//$'\n'/,}
  printf '%s' "$summary"
}

# Validate labelled release examples and structured rule references against live metadata.
release_docs_drift_check() {
  local docs_root=$1
  local catalogue_file=$2
  local package_version=$3
  local readme_doc="$docs_root/README.md"
  local rules_doc="$docs_root/docs/rules.md"
  local release_status_block
  local install_version_block
  local action_version_block
  local release_line_block
  local rule_catalogue_block
  local rule_examples_block
  local release_status_version
  local install_version
  local action_comment_version
  local action_input_version
  local release_line
  local expected_release_line="${package_version%.*}.x"
  local documented_rule_count
  local expected_rule_count
  local documented_pillars
  local expected_pillars
  local registered_rule_ids
  local rule_id
  local marked_rule_count=0
  local table_rule_count=0
  local drift_found=0

  # Missing docs leave contributors without the release and catalogue surfaces this gate owns.
  for doc_file in "$readme_doc" "$rules_doc"; do
    # Each named document must exist before its labelled values can be trusted.
    if [[ ! -f "$doc_file" ]]; then
      printf "docs drift: %s actual='<missing>' expected='documentation file'\n" "$doc_file" >&2
      return 1
    fi
  done
  # Invalid or incomplete catalogue JSON cannot establish the built-in rule truth.
  if ! jq -e '
    type == "array"
    and length > 0
    and all(.[]; (.id | type == "string") and (.pillar | type == "string"))
  ' "$catalogue_file" >/dev/null 2>&1; then
    printf "docs drift: %s: catalogue JSON actual='invalid' expected='non-empty list-rules array'\n" \
      "$catalogue_file" >&2
    return 1
  fi

  release_status_block=$(read_single_docs_block "$readme_doc" release-status) || return $?
  install_version_block=$(read_single_docs_block "$readme_doc" install-version) || return $?
  action_version_block=$(read_single_docs_block "$readme_doc" action-version) || return $?
  release_line_block=$(read_single_docs_block "$readme_doc" release-line) || return $?
  rule_catalogue_block=$(read_single_docs_block "$readme_doc" rule-catalogue) || return $?
  rule_examples_block=$(read_single_docs_block "$readme_doc" rule-id-examples) || return $?

  release_status_version=$(printf '%s\n' "$release_status_block" \
    | sed -n "s/^| Release line | Published \`\([^\`]*\)\` package line |$/\1/p")
  install_version=$(printf '%s\n' "$install_version_block" \
    | sed -n 's/^cargo install gruff-rs --locked --version \([^ ]*\) --root .*$/\1/p')
  action_comment_version=$(printf '%s\n' "$action_version_block" \
    | sed -n 's/^[[:space:]]*- uses: .* # v\([0-9][0-9.]*\)$/\1/p')
  action_input_version=$(printf '%s\n' "$action_version_block" \
    | sed -n 's/^[[:space:]]*version: \([0-9][0-9.]*\)$/\1/p')
  release_line=$(printf '%s\n' "$release_line_block" \
    | sed -n "s/^\`\([^\`]*\)\` is the active release line\..*/\1/p")

  # Every stale release value is shown together so one preflight run gives the full edit list.
  assert_docs_value "$readme_doc" 'published release version' \
    "$release_status_version" "$package_version" || drift_found=1
  assert_docs_value "$readme_doc" 'Cargo install example version' \
    "$install_version" "$package_version" || drift_found=1
  assert_docs_value "$readme_doc" 'action release-version comment' \
    "$action_comment_version" "$package_version" || drift_found=1
  assert_docs_value "$readme_doc" 'action binary-version input' \
    "$action_input_version" "$package_version" || drift_found=1
  assert_docs_value "$readme_doc" 'active release line' \
    "$release_line" "$expected_release_line" || drift_found=1

  expected_rule_count=$(jq -r 'length' "$catalogue_file")
  documented_rule_count=$(printf '%s\n' "$rule_catalogue_block" \
    | sed -n 's/^The catalogue contains \([0-9][0-9]*\) rules:$/\1/p')
  assert_docs_value "$readme_doc" 'built-in rule count' \
    "$documented_rule_count" "$expected_rule_count" || drift_found=1

  expected_pillars=$(jq -r '
    sort_by(.pillar)
    | group_by(.pillar)[]
    | "\(.[0].pillar)\t\(length)"
  ' "$catalogue_file")
  documented_pillars=$(printf '%s\n' "$rule_catalogue_block" \
    | sed -n "s/^| \`\([^\`]*\)\` | \([0-9][0-9]*\) |$/\1\t\2/p")
  # A changed pillar table must name both the documented and registry-derived totals.
  if [[ "$documented_pillars" != "$expected_pillars" ]]; then
    printf "docs drift: %s: pillar table actual='%s' expected='%s'\n" \
      "$readme_doc" \
      "$(pillar_table_summary "$documented_pillars")" \
      "$(pillar_table_summary "$expected_pillars")" >&2
    drift_found=1
  fi

  registered_rule_ids=$(jq -r '.[].id' "$catalogue_file" | sort -u)
  # Only explicitly marked examples are registry-owned; normal dotted prose stays reviewer-owned.
  while IFS= read -r rule_id; do
    # Empty extraction means this iteration has no candidate rule for the user-facing block.
    if [[ -z "$rule_id" ]]; then
      continue
    fi
    marked_rule_count=$((marked_rule_count + 1))
    # A phantom marked example sends users to a rule the CLI cannot list or explain.
    if ! grep -Fqx "$rule_id" <<<"$registered_rule_ids"; then
      printf "docs drift: %s: marked rule ID actual='%s' expected='registered built-in rule ID'\n" \
        "$readme_doc" \
        "$rule_id" >&2
      return 1
    fi
  done < <({ grep -oE "\`[a-z][a-z0-9-]*(\.[a-z0-9-]+)+\`" <<<"$rule_examples_block" || true; } \
    | tr -d '`' \
    | sort -u)
  # An empty marked block would make the rule-example contract appear protected without evidence.
  if ((marked_rule_count == 0)); then
    printf "docs drift: %s: marked rule ID count actual=0 expected='at least 1'\n" \
      "$readme_doc" >&2
    return 1
  fi

  # First-column rule IDs in docs/rules.md tables are structured catalogue references.
  while IFS= read -r rule_id; do
    table_rule_count=$((table_rule_count + 1))
    # A phantom table row gives maintainers a threshold for a rule that does not ship.
    if ! grep -Fqx "$rule_id" <<<"$registered_rule_ids"; then
      printf "docs drift: %s: table rule ID actual='%s' expected='registered built-in rule ID'\n" \
        "$rules_doc" \
        "$rule_id" >&2
      return 1
    fi
  done < <(sed -n "s/^| \`\([^\`]*\)\` |.*/\1/p" "$rules_doc")
  # No structured rule rows would silently remove the catalogue comparison reviewers expect.
  if ((table_rule_count == 0)); then
    printf "docs drift: %s: table rule ID count actual=0 expected='at least 1'\n" \
      "$rules_doc" >&2
    return 1
  fi

  # Any collected mismatch keeps preflight red after all actionable values are printed.
  if ((drift_found != 0)); then
    return 1
  fi

  printf 'README release %s and %s built-in rules match labelled docs\n' \
    "$package_version" \
    "$expected_rule_count"
}

# Write the smallest valid docs set used by deterministic negative drift checks.
write_valid_docs_drift_fixture() {
  local fixture_root=$1
  local catalogue_file=$2
  local package_version=$3
  local release_line="${package_version%.*}.x"
  local rule_count
  local example_rule

  rule_count=$(jq -r 'length' "$catalogue_file")
  example_rule=$(jq -r '.[0].id' "$catalogue_file")
  mkdir -p "$fixture_root/docs"

  {
    printf '# Synthetic documentation drift fixture\n\n'
    printf '<!-- gruff-docs:begin release-status -->\n'
    printf '| Field | Value |\n| --- | --- |\n'
    printf "| Release line | Published \`%s\` package line |\n" "$package_version"
    printf '<!-- gruff-docs:end release-status -->\n\n'
    printf '<!-- gruff-docs:begin install-version -->\n'
    printf "\`\`\`bash\ncargo install gruff-rs --locked --version %s --root ./.cargo-tools\n\`\`\`\n" \
      "$package_version"
    printf '<!-- gruff-docs:end install-version -->\n\n'
    printf '<!-- gruff-docs:begin action-version -->\n'
    printf '```yaml\n      - uses: example/gruff-rs@FULL_40_CHARACTER_COMMIT_SHA # v%s\n' \
      "$package_version"
    printf '        with:\n          version: %s\n```\n' "$package_version"
    printf '<!-- gruff-docs:end action-version -->\n\n'
    printf '<!-- gruff-docs:begin release-line -->\n'
    printf "\`%s\` is the active release line.\n" "$release_line"
    printf '<!-- gruff-docs:end release-line -->\n\n'
    printf '<!-- gruff-docs:begin rule-catalogue -->\n'
    printf 'The catalogue contains %s rules:\n\n' "$rule_count"
    printf '| Pillar | Rules |\n| --- | ---: |\n'
    # Each registry pillar becomes one exact machine-owned README table row.
    while IFS=$'\t' read -r pillar count; do
      printf "| \`%s\` | %s |\n" "$pillar" "$count"
    done < <(jq -r '
      sort_by(.pillar)
      | group_by(.pillar)[]
      | "\(.[0].pillar)\t\(length)"
    ' "$catalogue_file")
    printf '<!-- gruff-docs:end rule-catalogue -->\n\n'
    printf "Normal prose may mention \`phantom.unmarked\` without becoming generated data.\n\n"
    printf '<!-- gruff-docs:begin rule-id-examples -->\n'
    printf "Generated example rules: \`%s\`.\n" "$example_rule"
    printf '<!-- gruff-docs:end rule-id-examples -->\n'
  } >"$fixture_root/README.md"

  {
    printf '# Synthetic rules table\n\n'
    printf '| Rule | Default | Note |\n| --- | --- | --- |\n'
    printf "| \`%s\` | fixture | Registered example. |\n" "$example_rule"
  } >"$fixture_root/docs/rules.md"
}

# Copy a known-good fixture so each negative case changes only one contract.
copy_docs_drift_fixture() {
  local source_root=$1
  local target_root=$2

  mkdir -p "$target_root/docs"
  cp "$source_root/README.md" "$target_root/README.md"
  cp "$source_root/docs/rules.md" "$target_root/docs/rules.md"
}

# Replace one exact fixture line without platform-specific in-place editing flags.
replace_docs_fixture_line() {
  local doc_file=$1
  local expected_line=$2
  local replacement_line=$3
  local rewritten_file="$doc_file.rewritten"

  awk -v expected_line="$expected_line" -v replacement_line="$replacement_line" '
    $0 == expected_line { print replacement_line; replacements += 1; next }
    { print }
    # Exactly one replacement proves the intended stale fixture was constructed.
    END { exit(replacements == 1 ? 0 : 3) }
  ' "$doc_file" >"$rewritten_file" || {
    # A malformed test fixture must fail before it can create misleading green evidence.
    rm -f "$rewritten_file"
    printf "docs drift fixture: could not replace '%s' in %s\n" "$expected_line" "$doc_file" >&2
    return 1
  }
  mv "$rewritten_file" "$doc_file"
}

# Remove or duplicate one marker to exercise anchor-cardinality diagnostics.
rewrite_docs_fixture_marker() {
  local doc_file=$1
  local marker=$2
  local operation=$3
  local rewritten_file="$doc_file.rewritten"

  awk -v marker="$marker" -v operation="$operation" '
    $0 == marker {
      matches += 1
      # Duplicate mode emits two anchors; remove mode emits none for its negative case.
      if (operation == "duplicate") { print; print }
      next
    }
    { print }
    # One source marker keeps the negative fixture focused on cardinality alone.
    END { exit(matches == 1 ? 0 : 3) }
  ' "$doc_file" >"$rewritten_file" || {
    # A missing source marker means the intended negative case was never constructed.
    rm -f "$rewritten_file"
    printf "docs drift fixture: could not %s marker '%s' in %s\n" \
      "$operation" \
      "$marker" \
      "$doc_file" >&2
    return 1
  }
  mv "$rewritten_file" "$doc_file"
}

# Require one synthetic docs tree to fail for the intended actionable reason.
expect_docs_drift_failure() {
  local case_name=$1
  local expected_diagnostic=$2
  local fixture_root=$3
  local catalogue_file=$4
  local package_version=$5
  local output
  local status

  output=$(release_docs_drift_check "$fixture_root" "$catalogue_file" "$package_version" 2>&1)
  status=$?
  # A zero exit means the stale synthetic document escaped the contributor gate.
  if ((status == 0)); then
    printf 'docs drift fixture: %s unexpectedly passed\n' "$case_name" >&2
    return 1
  fi
  # A different error would not prove the named stale value is diagnosed usefully.
  if ! grep -Fq "$expected_diagnostic" <<<"$output"; then
    printf "docs drift fixture: %s failed for the wrong reason; expected '%s', got:\n%s\n" \
      "$case_name" \
      "$expected_diagnostic" \
      "$output" >&2
    return 1
  fi

  printf 'PASS: docs drift fixture %s rejected with %s\n' "$case_name" "$expected_diagnostic"
}

# Exercise every negative drift shape without mutating the real documentation.
docs_drift_fixture_harness() {
  local catalogue_file="$WORK_DIR/list-rules.json"
  local harness_root="$WORK_DIR/docs-drift-fixtures"
  local valid_root="$harness_root/valid"
  local stale_count_root="$harness_root/stale-count"
  local stale_version_root="$harness_root/stale-version"
  local missing_anchor_root="$harness_root/missing-anchor"
  local duplicate_anchor_root="$harness_root/duplicate-anchor"
  local invalid_json_root="$harness_root/invalid-json"
  local phantom_rule_root="$harness_root/phantom-rule"
  local invalid_catalogue="$invalid_json_root/catalogue.json"
  local custom_config="$harness_root/custom-rule.yaml"
  local custom_catalogue="$harness_root/custom-rules.json"
  local package_version
  local rule_count
  local example_rule
  local valid_output
  local custom_rule_count

  package_version=$(package_version_for_docs) || return $?
  rule_count=$(jq -r 'length' "$catalogue_file")
  example_rule=$(jq -r '.[0].id' "$catalogue_file")
  write_valid_docs_drift_fixture "$valid_root" "$catalogue_file" "$package_version"

  # The valid synthetic docs include an unmarked phantom phrase that must stay reviewer-owned.
  if ! valid_output=$(release_docs_drift_check \
    "$valid_root" \
    "$catalogue_file" \
    "$package_version" 2>&1); then
    printf 'docs drift fixture: valid base failed:\n%s\n' "$valid_output" >&2
    return 1
  fi

  copy_docs_drift_fixture "$valid_root" "$stale_count_root"
  replace_docs_fixture_line "$stale_count_root/README.md" \
    "The catalogue contains $rule_count rules:" \
    "The catalogue contains $((rule_count + 1)) rules:" || return $?
  expect_docs_drift_failure stale-count 'built-in rule count' \
    "$stale_count_root" "$catalogue_file" "$package_version" || return $?

  copy_docs_drift_fixture "$valid_root" "$stale_version_root"
  replace_docs_fixture_line "$stale_version_root/README.md" \
    "| Release line | Published \`$package_version\` package line |" \
    "| Release line | Published \`0.0.0\` package line |" || return $?
  expect_docs_drift_failure stale-version 'published release version' \
    "$stale_version_root" "$catalogue_file" "$package_version" || return $?

  copy_docs_drift_fixture "$valid_root" "$missing_anchor_root"
  rewrite_docs_fixture_marker "$missing_anchor_root/README.md" \
    '<!-- gruff-docs:begin release-status -->' remove || return $?
  expect_docs_drift_failure missing-anchor 'marker count actual=0 expected=1' \
    "$missing_anchor_root" "$catalogue_file" "$package_version" || return $?

  copy_docs_drift_fixture "$valid_root" "$duplicate_anchor_root"
  rewrite_docs_fixture_marker "$duplicate_anchor_root/README.md" \
    '<!-- gruff-docs:begin release-status -->' duplicate || return $?
  expect_docs_drift_failure duplicate-anchor 'marker count actual=2 expected=1' \
    "$duplicate_anchor_root" "$catalogue_file" "$package_version" || return $?

  copy_docs_drift_fixture "$valid_root" "$invalid_json_root"
  printf '{ invalid catalogue\n' >"$invalid_catalogue"
  expect_docs_drift_failure invalid-json 'catalogue JSON' \
    "$invalid_json_root" "$invalid_catalogue" "$package_version" || return $?

  copy_docs_drift_fixture "$valid_root" "$phantom_rule_root"
  replace_docs_fixture_line "$phantom_rule_root/README.md" \
    "Generated example rules: \`$example_rule\`." \
    "Generated example rules: \`phantom.marked\`." || return $?
  expect_docs_drift_failure phantom-marked-rule 'marked rule ID' \
    "$phantom_rule_root" "$catalogue_file" "$package_version" || return $?

  cat >"$custom_config" <<'YAML'
schemaVersion: gruff-rs.config.v1
custom_rules:
  - id: custom.docs-drift-probe
    pillar: Documentation
    severity: advisory
    message: Docs drift probe
    scope: text
    pattern: docs-drift-probe
YAML
  cargo run --quiet -- list-rules --format json --config "$custom_config" >"$custom_catalogue" \
    || return $?
  custom_rule_count=$(jq -r 'length' "$custom_catalogue")
  # A valid project custom rule must not alter the no-config built-in count used by docs.
  if ((custom_rule_count != rule_count + 1)); then
    printf 'docs drift fixture: custom catalogue count actual=%s expected=%s\n' \
      "$custom_rule_count" \
      "$((rule_count + 1))" >&2
    return 1
  fi

  printf 'PASS: custom config reports %s rules while documented built-ins remain %s\n' \
    "$custom_rule_count" \
    "$rule_count"
  printf 'PASS: docs drift fixture harness rejected every intended negative case\n'
}

# Keep release, catalogue, schema, and command docs aligned with live behavior.
docs_drift_check() {
  local architecture_doc="$REPO_ROOT/.goat-flow/architecture.md"
  local glossary_doc="$REPO_ROOT/.goat-flow/glossary.md"
  local analysis_source="$REPO_ROOT/src/analysis.rs"
  local catalogue_file="$WORK_DIR/list-rules.json"
  local backtick='`'
  local package_version
  local live_schema
  local orientation_doc
  local document_schema
  local cli_command
  local help_text
  local checked_command_count=0
  local stale_schemas=()
  local missing_commands=()

  package_version=$(package_version_for_docs) || return $?
  release_docs_drift_check "$REPO_ROOT" "$catalogue_file" "$package_version" || return $?

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
        # Release mode adds tag and changelog checks to the normal contributor suite.
        GRUFF_RS_RELEASE_CHECK=1
        shift
        ;;
      --docs-drift-check)
        # Focused mode gives maintainers the live docs failure without running the full suite.
        if [[ "$PREFLIGHT_MODE" != full ]]; then
          fail_preflight_setup "choose only one focused preflight mode"
        fi
        PREFLIGHT_MODE=docs-drift-check
        shift
        ;;
      --docs-drift-fixtures)
        # Fixture mode proves negative diagnostics without editing real documentation.
        if [[ "$PREFLIGHT_MODE" != full ]]; then
          fail_preflight_setup "choose only one focused preflight mode"
        fi
        PREFLIGHT_MODE=docs-drift-fixtures
        shift
        ;;
      -h|--help)
        # Help users see prerequisites and modes without starting any build or scan.
        usage
        return 0
        ;;
      *)
        # Unknown input fails before a user could mistake a weaker run for full preflight.
        fail_preflight_setup "unknown argument: $1"
        ;;
    esac
  done

  validate_release_check
  require_cargo_for_preflight
  require_jq_for_preflight
  # Release-only metadata has no meaning when the user requested a docs-only mode.
  if [[ "$PREFLIGHT_MODE" != full ]] && release_check_enabled; then
    fail_preflight_setup "--release-check cannot be combined with a focused docs mode"
  fi
  WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/gruff-rs-preflight.XXXXXX")"
  trap remove_preflight_workspace EXIT

  cd "$REPO_ROOT" || return 1

  # Focused modes stop after their named contract so red/green evidence stays concise.
  case "$PREFLIGHT_MODE" in
    docs-drift-check)
      # Live mode checks the actual README and docs against one built-in catalogue capture.
      list_rules_json_smoke || return $?
      docs_drift_check
      return $?
      ;;
    docs-drift-fixtures)
      # Fixture mode exercises synthetic failures without touching real documentation.
      list_rules_json_smoke || return $?
      docs_drift_fixture_harness
      return $?
      ;;
  esac

  show_preflight_header

  run_preflight_check "shell syntax" check_shell_syntax
  run_preflight_check "shellcheck" check_shellcheck
  run_preflight_check "deny-dangerous policy" deny_dangerous_self_test
  run_preflight_check "post-turn safety" post_turn_safety_self_test
  run_preflight_check "permission rule hygiene" permission_rule_hygiene
  run_preflight_check "managed hook deltas" managed_hook_deltas_present
  run_preflight_check "managed doc deltas" managed_doc_deltas_present
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
  run_preflight_check "docs drift fixtures" docs_drift_fixture_harness
  run_preflight_check "gruff-rs dogfood scan" dogfood_scan

  show_preflight_summary
}

run_preflight_suite "$@"
