#!/usr/bin/env bash
# Local release gate: shell checks, Rust checks, CLI smokes, and dogfood scan.

set -u
set -o pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
GRUFF_RS_FAIL_ON="${GRUFF_RS_FAIL_ON:-advisory}"
GRUFF_RS_RELEASE_CHECK="${GRUFF_RS_RELEASE_CHECK:-0}"
WORK_DIR=""

TOTAL=0
PASSED=0
FAILED=0
FAILURES=()
SKIPPED=()
START_TIME=$(date +%s%N)

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

usage() {
  cat <<'USAGE'
Usage: scripts/preflight-checks.sh [options]

Runs the local gruff-rs preflight suite:
  - bash syntax check for tracked and untracked shell scripts
  - shellcheck for shell scripts when shellcheck is installed
  - cargo fmt, clippy, and tests
  - crate version consistency between Cargo.toml and Cargo.lock
  - RustSec dependency audit, auto-installing cargo-audit when missing
  - rule-listing, summary, fixture JSON/SARIF, patch, selector, exclusion, and custom-rule smokes
  - gruff-rs dogfood scan of src/

Options:
  --fail-on LEVEL  Fail dogfood analysis at none, advisory, warning, or error.
                   Defaults to GRUFF_RS_FAIL_ON, or advisory when unset.
  --release-check  Also require the crate version to be newer than the latest
                   local vX.Y.Z git tag and present in CHANGELOG.md.
  -h, --help       Show this help.

Environment:
  GRUFF_RS_FAIL_ON        Dogfood scan threshold (default: advisory).
  GRUFF_RS_RELEASE_CHECK  Set to 1/true/yes/on to enable --release-check.
USAGE
}

die() {
  printf 'preflight-checks: %s\n' "$*" >&2
  exit 2
}

cleanup() {
  if [[ -n "$WORK_DIR" && -d "$WORK_DIR" ]]; then
    rm -rf "$WORK_DIR"
  fi
}

rule() {
  printf '  %s\n' "${DIM}--------------------------------------------${RESET}"
}

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

  if ((elapsed_ms < 1000)); then
    printf '%dms' "$elapsed_ms"
    return
  fi

  seconds=$((elapsed_ms / 1000))
  frac=$(((elapsed_ms % 1000) / 100))

  if ((seconds < 60)); then
    printf '%d.%ds' "$seconds" "$frac"
    return
  fi

  minutes=$((seconds / 60))
  remainder=$((seconds % 60))
  printf '%dm %02d.%ds' "$minutes" "$remainder" "$frac"
}

header() {
  printf '\n'
  printf '  %sPreflight Check%s\n' "$BOLD" "$RESET"
  printf '  %s%s%s\n' "$DIM" "$(date '+%Y-%m-%d %H:%M:%S')" "$RESET"
  printf '  %sroot:%s %s\n' "$DIM" "$RESET" "$REPO_ROOT"
  printf '  %sdogfood fail threshold:%s %s\n' "$DIM" "$RESET" "$GRUFF_RS_FAIL_ON"
  printf '  %srelease version check:%s %s\n' "$DIM" "$RESET" "$(release_check_label)"
  printf '  %sdependency audit:%s required (auto-install cargo-audit)\n' "$DIM" "$RESET"
  rule
  printf '\n'
}

step() {
  local label=$1

  TOTAL=$((TOTAL + 1))
  printf '  %s %-38s' "$ARROW" "$label"
}

pass_step() {
  local detail=${1:-}

  PASSED=$((PASSED + 1))
  if [[ -n "$detail" ]]; then
    printf '%s  %s%s%s\n' "$PASS" "$DIM" "$detail" "$RESET"
  else
    printf '%s\n' "$PASS"
  fi
}

fail_step() {
  local label=$1

  FAILED=$((FAILED + 1))
  FAILURES+=("$label")
  printf '%s\n' "$FAIL"
}

skip_line() {
  local reason=${1:-skipped}

  SKIPPED+=("$reason")
  printf '%s  %s%s%s\n' "$SKIP" "$DIM" "$reason" "$RESET"
}

indent_output() {
  while IFS= read -r line; do
    printf '    %s%s%s\n' "$DIM" "$line" "$RESET"
  done
}

trim_line() {
  printf '%s' "$1" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//'
}

compact_output() {
  local output=$1
  local summary_line

  [[ -n "$output" ]] || return 0

  summary_line=$(printf '%s\n' "$output" | grep 'test result:' | tail -1 || true)
  if [[ -n "$summary_line" ]]; then
    trim_line "$summary_line"
    return 0
  fi

  summary_line=$(printf '%s\n' "$output" | grep -E '^Score:' | tail -1 || true)
  if [[ -n "$summary_line" ]]; then
    trim_line "$summary_line"
    return 0
  fi

  summary_line=$(printf '%s\n' "$output" | grep -E "Finished \`[^\`]+\` profile" | tail -1 || true)
  if [[ -n "$summary_line" ]]; then
    trim_line "$summary_line"
    return 0
  fi

  trim_line "$(printf '%s\n' "$output" | sed '/^[[:space:]]*$/d' | tail -1)"
}

summary() {
  local elapsed

  elapsed=$(elapsed_since "$START_TIME")
  printf '\n'
  rule
  printf '\n'

  if ((${#SKIPPED[@]} > 0)); then
    printf '  %sSkipped:%s\n' "$YELLOW" "$RESET"
    printf '    - %s\n' "${SKIPPED[@]}"
    printf '\n'
  fi

  if ((FAILED == 0)); then
    printf '  %sAll %d/%d checks passed%s  %s(%s)%s\n' "$GREEN$BOLD" "$PASSED" "$TOTAL" "$RESET" "$DIM" "$elapsed" "$RESET"
    printf '\n'
    return 0
  fi

  printf '  %s%d/%d checks failed%s  %s(%s)%s\n' "$RED$BOLD" "$FAILED" "$TOTAL" "$RESET" "$DIM" "$elapsed" "$RESET"
  printf '\n'
  for failure in "${FAILURES[@]}"; do
    printf '    %s  %s\n' "$FAIL" "$failure"
  done
  printf '\n'

  return 1
}

repo_files() {
  local pattern="$1"

  if git -C "$REPO_ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    {
      git -C "$REPO_ROOT" ls-files -- "$pattern"
      git -C "$REPO_ROOT" ls-files --others --exclude-standard -- "$pattern"
    } | sort -u
  else
    (cd "$REPO_ROOT" && find . -type f -name "$pattern" -print | sed 's#^\./##')
  fi
}

skip_step() {
  skip_line "$1"
}

run_step() {
  local name="$1"
  shift
  local output
  local detail
  local status
  local started_at
  local elapsed

  step "$name"
  started_at=$(date +%s%N)
  output=$("$@" 2>&1)
  status=$?
  elapsed=$(elapsed_since "$started_at")

  if ((status == 0)); then
    detail="$(compact_output "$output")"
    pass_step "${detail:+$detail | }$elapsed"
  else
    fail_step "$name"
    if [[ -n "$output" ]]; then
      printf '%s\n' "$output" | tail -20 | indent_output
    fi
    printf '    %sexit %d after %s%s\n' "$DIM" "$status" "$elapsed" "$RESET"
  fi

  return "$status"
}

validate_fail_on() {
  case "$GRUFF_RS_FAIL_ON" in
    none|advisory|warning|error) ;;
    *) die "invalid --fail-on value: $GRUFF_RS_FAIL_ON" ;;
  esac
}

validate_release_check() {
  case "$GRUFF_RS_RELEASE_CHECK" in
    0|1|false|true|no|yes|off|on) ;;
    *) die "invalid GRUFF_RS_RELEASE_CHECK value: $GRUFF_RS_RELEASE_CHECK" ;;
  esac
}

release_check_enabled() {
  case "$GRUFF_RS_RELEASE_CHECK" in
    1|true|yes|on) return 0 ;;
    *) return 1 ;;
  esac
}

release_check_label() {
  if release_check_enabled; then
    printf 'on'
  else
    printf 'off'
  fi
}

is_core_semver() {
  [[ "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]
}

cargo_toml_version() {
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

cargo_lock_version() {
  awk -v package_name="gruff-rs" '
    function maybe_print() {
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
      if (!found && name == package_name && version != "") {
        print version
      }
    }
  ' "$REPO_ROOT/Cargo.lock"
}

latest_release_tag_version() {
  local tag
  local version

  while IFS= read -r tag; do
    version=${tag#v}
    if is_core_semver "$version"; then
      printf '%s\n' "$version"
      return 0
    fi
  done < <(git -C "$REPO_ROOT" tag --list 'v[0-9]*.[0-9]*.[0-9]*' --sort=-v:refname)

  return 1
}

semver_gt() {
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

version_metadata_check() {
  local manifest_version
  local lock_version
  local latest_tag_version

  manifest_version=$(cargo_toml_version)
  if [[ -z "$manifest_version" ]]; then
    printf 'could not read [package] version from Cargo.toml\n' >&2
    return 1
  fi
  if ! is_core_semver "$manifest_version"; then
    printf 'Cargo.toml version must look like X.Y.Z (got: %s)\n' "$manifest_version" >&2
    return 1
  fi

  if [[ -f "$REPO_ROOT/Cargo.lock" ]]; then
    lock_version=$(cargo_lock_version)
    if [[ -z "$lock_version" ]]; then
      printf 'could not read gruff-rs package version from Cargo.lock\n' >&2
      return 1
    fi
    if [[ "$manifest_version" != "$lock_version" ]]; then
      printf 'Cargo.toml version %s does not match Cargo.lock gruff-rs version %s\n' "$manifest_version" "$lock_version" >&2
      return 1
    fi
  fi

  if release_check_enabled; then
    if ! git -C "$REPO_ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
      printf '%s\n' '--release-check requires a git worktree' >&2
      return 1
    fi

    latest_tag_version=$(latest_release_tag_version || true)
    if [[ -n "$latest_tag_version" ]] && ! semver_gt "$manifest_version" "$latest_tag_version"; then
      printf 'Cargo.toml version %s must be greater than latest release tag v%s\n' "$manifest_version" "$latest_tag_version" >&2
      return 1
    fi

    if [[ -f "$REPO_ROOT/CHANGELOG.md" ]] \
      && ! grep -qE "^##[[:space:]]+${manifest_version}[[:space:]]+-[[:space:]]+[0-9]{4}-[0-9]{2}-[0-9]{2}" "$REPO_ROOT/CHANGELOG.md"; then
      printf 'CHANGELOG.md is missing a release heading for %s\n' "$manifest_version" >&2
      return 1
    fi
  fi

  if release_check_enabled; then
    printf 'Cargo.toml/Cargo.lock %s; release check on\n' "$manifest_version"
  else
    printf 'Cargo.toml/Cargo.lock %s\n' "$manifest_version"
  fi
}

check_shell_syntax() {
  local files=()
  local existing_files=()
  local file
  mapfile -t files < <(repo_files '*.sh')

  for file in "${files[@]}"; do
    [[ -f "$file" ]] && existing_files+=("$file")
  done
  files=("${existing_files[@]}")

  if ((${#files[@]} == 0)); then
    skip_step "shell syntax (no shell scripts)"
    return 0
  fi

  bash -n "${files[@]}"
}

check_shellcheck() {
  local files=()
  local existing_files=()
  local file
  mapfile -t files < <(repo_files '*.sh')

  for file in "${files[@]}"; do
    [[ -f "$file" ]] && existing_files+=("$file")
  done
  files=("${existing_files[@]}")

  if ((${#files[@]} == 0)); then
    skip_step "shellcheck (no shell scripts)"
    return 0
  fi

  if ! command -v shellcheck >/dev/null 2>&1; then
    skip_step "shellcheck (not installed)"
    return 0
  fi

  shellcheck "${files[@]}"
}

require_cargo() {
  command -v cargo >/dev/null 2>&1 || die "cargo is not available on PATH"
}

cargo_install_root() {
  if [[ -n "${CARGO_INSTALL_ROOT:-}" ]]; then
    printf '%s\n' "$CARGO_INSTALL_ROOT"
  elif [[ -n "${CARGO_HOME:-}" ]]; then
    printf '%s\n' "$CARGO_HOME"
  else
    printf '%s\n' "$HOME/.cargo"
  fi
}

resolve_cargo_audit() {
  local install_root
  local cargo_audit

  if cargo_audit=$(command -v cargo-audit 2>/dev/null); then
    printf '%s\n' "$cargo_audit"
    return 0
  fi

  install_root=$(cargo_install_root)
  cargo_audit="$install_root/bin/cargo-audit"
  if [[ -x "$cargo_audit" ]]; then
    printf '%s\n' "$cargo_audit"
    return 0
  fi

  return 1
}

ensure_cargo_audit() {
  local cargo_audit

  if cargo_audit=$(resolve_cargo_audit); then
    printf '%s\n' "$cargo_audit"
    return 0
  fi

  printf 'cargo-audit is not installed; installing with cargo install cargo-audit --locked\n' >&2
  cargo install cargo-audit --locked || return $?

  if cargo_audit=$(resolve_cargo_audit); then
    printf '%s\n' "$cargo_audit"
    return 0
  fi

  printf 'cargo-audit installed but was not found at %s/bin/cargo-audit or on PATH\n' "$(cargo_install_root)" >&2
  return 1
}

dependency_audit_check() {
  local cargo_audit

  cargo_audit=$(ensure_cargo_audit) || return $?
  "$cargo_audit" audit
}

fixture_json_smoke() {
  cargo run --quiet -- analyse fixtures --format json --fail-on none >"$WORK_DIR/fixtures.json"
}

fixture_sarif_smoke() {
  cargo run --quiet -- analyse fixtures --format sarif --fail-on none >"$WORK_DIR/fixtures.sarif"
}

list_rules_json_smoke() {
  cargo run --quiet -- list-rules --format json >"$WORK_DIR/list-rules.json"
}

security_selector_listing_smoke() {
  cargo run --quiet -- list-rules --selector Security >"$WORK_DIR/security-rules.txt"
}

summary_json_smoke() {
  local summary_file="$WORK_DIR/summary.json"

  cargo run --quiet -- summary fixtures --format json --top 5 --include-ignored >"$summary_file" || return $?
  grep -q '"schemaVersion": "gruff.summary.v2"' "$summary_file" || return $?
  grep -q '"topRules":' "$summary_file"
}

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

  cargo run --quiet -- analyse fixtures/sample.rs --format text --fail-on none --no-baseline >"$full_report" || return $?
  cargo run --quiet -- analyse fixtures/sample.rs --format text --fail-on none --no-baseline --diff-patch "$patch_file" >"$patch_report" || return $?

  full_findings="$(grep -c '^- \[' "$full_report" || true)"
  patch_findings="$(grep -c '^- \[' "$patch_report" || true)"
  if ((patch_findings >= full_findings)); then
    printf 'patch diff smoke did not reduce findings: full=%s patch=%s\n' "$full_findings" "$patch_findings" >&2
    return 1
  fi

  grep -q 'patch-filter' "$patch_report"
}

selector_smoke() {
  local config_file="$WORK_DIR/selector.yaml"
  local report_file="$WORK_DIR/selector.txt"

  cat >"$config_file" <<'YAML'
rules:
  select: ["security.process-command"]
YAML

  cargo run --quiet -- analyse fixtures/sample.rs --format text --fail-on none --no-baseline --config "$config_file" >"$report_file" || return $?
  grep -q 'security.process-command' "$report_file" || return $?
  if grep -q 'sensitive-data.aws-access-key' "$report_file"; then
    printf 'selector smoke reported a rule outside the explicit allow-list\n' >&2
    return 1
  fi
}

exclusion_smoke() {
  local config_file="$WORK_DIR/exclude.yaml"
  local full_report="$WORK_DIR/exclude-full.txt"
  local filtered_report="$WORK_DIR/exclude-filtered.txt"
  local full_findings
  local filtered_findings

  cat >"$config_file" <<'YAML'
exclude:
  - rule: security.process-command
    reason: fixture command accepted for smoke testing
YAML

  cargo run --quiet -- analyse fixtures/sample.rs --format text --fail-on none --no-baseline --no-config >"$full_report" || return $?
  cargo run --quiet -- analyse fixtures/sample.rs --format text --fail-on none --no-baseline --config "$config_file" >"$filtered_report" || return $?

  full_findings="$(grep -c '^- \[' "$full_report" || true)"
  filtered_findings="$(grep -c '^- \[' "$filtered_report" || true)"
  if ((filtered_findings >= full_findings)); then
    printf 'exclusion smoke did not reduce findings: full=%s filtered=%s\n' "$full_findings" "$filtered_findings" >&2
    return 1
  fi

  grep -q 'Suppressed findings:' "$filtered_report"
}

custom_rule_smoke() {
  local config_file="$WORK_DIR/custom.yaml"
  local rules_file="$WORK_DIR/custom-rules.json"
  local report_file="$WORK_DIR/custom-analysis.txt"

  cat >"$config_file" <<'YAML'
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

dogfood_failure_pattern() {
  case "$GRUFF_RS_FAIL_ON" in
    advisory) printf '%s\n' '^- \[(advisory|warning|error)\]' ;;
    warning) printf '%s\n' '^- \[(warning|error)\]' ;;
    error) printf '%s\n' '^- \[error\]' ;;
    none) printf '%s\n' '^$' ;;
  esac
}

dogfood_source_scan() {
  local report_file="$WORK_DIR/src-self-scan.txt"
  local status=0
  local pattern

  cargo run --quiet -- analyse src --format text --fail-on "$GRUFF_RS_FAIL_ON" --no-baseline >"$report_file" 2>&1 || status=$?

  grep -m1 '^Score:' "$report_file" || true

  if ((status != 0)); then
    pattern="$(dogfood_failure_pattern)"
    printf 'Dogfood scan failed at --fail-on %s. First matching findings:\n' "$GRUFF_RS_FAIL_ON"
    grep -E "$pattern" "$report_file" | sed -n '1,20p' || true
  fi

  return "$status"
}

main() {
  while (($#)); do
    case "$1" in
      --fail-on)
        [[ $# -ge 2 ]] || die "--fail-on requires a value"
        GRUFF_RS_FAIL_ON="$2"
        shift 2
        ;;
      --release-check)
        GRUFF_RS_RELEASE_CHECK=1
        shift
        ;;
      -h|--help)
        usage
        return 0
        ;;
      *)
        die "unknown argument: $1"
        ;;
    esac
  done

  validate_fail_on
  validate_release_check
  require_cargo
  WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/gruff-rs-preflight.XXXXXX")"
  trap cleanup EXIT

  cd "$REPO_ROOT" || return 1

  header

  run_step "shell syntax" check_shell_syntax
  run_step "shellcheck" check_shellcheck
  run_step "version metadata" version_metadata_check
  run_step "dependency audit" dependency_audit_check
  run_step "cargo fmt" cargo fmt --check
  run_step "cargo clippy" cargo clippy --all-targets -- -D warnings
  run_step "cargo test" cargo test
  run_step "list-rules JSON" list_rules_json_smoke
  run_step "Security selector listing" security_selector_listing_smoke
  run_step "summary JSON" summary_json_smoke
  run_step "fixture JSON scan" fixture_json_smoke
  run_step "fixture SARIF scan" fixture_sarif_smoke
  run_step "patch diff smoke" patch_diff_smoke
  run_step "selector smoke" selector_smoke
  run_step "exclusion smoke" exclusion_smoke
  run_step "custom rule smoke" custom_rule_smoke
  run_step "gruff-rs dogfood scan" dogfood_source_scan

  summary
}

main "$@"
