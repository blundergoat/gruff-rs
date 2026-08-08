#!/usr/bin/env bash
# Execution boundary for the gruff-rs composite GitHub Action.
# Workflow authors use it to resolve one exact release and pass argv, working
# directory, and report paths without shell reparsing. It keeps all user paths
# inside the checked-out workspace and preserves the analyzer's exit status.

set -euo pipefail

# Show one actionable workflow error and stop before user input reaches the CLI.
fail_action() {
  printf 'gruff-rs action: %s\n' "$*" >&2
  exit 2
}

# Accept exact SemVer releases and reject moving or malformed version labels.
version_is_valid() {
  local candidate_version=$1
  local semver_regex='^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-([0-9A-Za-z-]+)(\.[0-9A-Za-z-]+)*)?(\+([0-9A-Za-z-]+)(\.[0-9A-Za-z-]+)*)?$'
  local version_without_build
  local prerelease_identifiers
  local prerelease_identifier

  [[ $candidate_version =~ $semver_regex ]] || return 1
  version_without_build=${candidate_version%%+*}
  [[ $version_without_build == *-* ]] || return 0
  prerelease_identifiers=${version_without_build#*-}
  # Prerelease identifiers need an extra SemVer leading-zero check.
  while [[ -n $prerelease_identifiers ]]; do
    prerelease_identifier=${prerelease_identifiers%%.*}
    # A version such as rc.01 cannot identify an exact SemVer release.
    if [[ $prerelease_identifier =~ ^[0-9]+$ && ${#prerelease_identifier} -gt 1 \
      && $prerelease_identifier == 0* ]]; then
      return 1
    fi
    # More dotted identifiers mean the user's prerelease still needs checking.
    if [[ $prerelease_identifiers == *.* ]]; then
      prerelease_identifiers=${prerelease_identifiers#*.}
    else
      prerelease_identifiers=""
    fi
  done
}

# Give workflow authors one version error before any release URL is constructed.
require_valid_version() {
  local candidate_version=$1

  version_is_valid "$candidate_version" \
    || fail_action "version must be an exact semantic version"
}

# Resolve a tag or explicit input into the exact binary version shown to users.
resolve_version() {
  local requested_version=${GRUFF_INPUT_VERSION:-}
  local action_reference=${GRUFF_ACTION_REF:-}
  local action_release_version=""

  # An empty input may be inferred only from a visible exact release tag.
  if [[ -z $requested_version ]]; then
    [[ $action_reference == v* ]] \
      || fail_action "version is required when the action ref is not an exact vX.Y.Z release tag"
    requested_version=${action_reference#v}
    version_is_valid "$requested_version" \
      || fail_action "version is required when the action ref is not an exact vX.Y.Z release tag"
  else
    require_valid_version "$requested_version"
    action_release_version=${action_reference#v}
    # An exact action tag and explicit binary version must describe one release.
    if [[ $action_reference == v* ]] && version_is_valid "$action_release_version" \
      && [[ $requested_version != "$action_release_version" ]]; then
      fail_action "version $requested_version does not match action release tag $action_reference"
    fi
  fi
  require_valid_version "$requested_version"
  # An empty command-file path means the install step cannot receive the version.
  [[ -n ${GITHUB_OUTPUT:-} ]] || fail_action "GITHUB_OUTPUT is required while resolving the version"
  printf 'value=%s\n' "$requested_version" >>"$GITHUB_OUTPUT"
}

# Explain the v0.5 migration when a workflow still supplies the retired args.
legacy_args_error() {
  cat >&2 <<'ERROR'
gruff-rs action: input 'args' is no longer supported; use 'argv' with one literal argument per non-empty line, for example:
argv: |
  analyse
  .
  --format
  sarif
ERROR
  exit 2
}

# Detect input that could split one workflow field into multiple path records.
contains_line_break() {
  [[ $1 == *$'\n'* || $1 == *$'\r'* ]]
}

# Check that a resolved user path stays inside the checked-out workspace.
path_is_within() {
  local candidate=$1
  local root=$2

  [[ $root == "/" || $candidate == "$root" || $candidate == "$root/"* ]]
}

# Reports whether a value is a rooted native Windows path: a drive root such as `D:\x` or `D:/x`, or a UNC share such as
# `\\server\share`. A drive-relative value such as `C:x` is deliberately excluded, because it names no root this action
# could resolve, and guessing one would silently relocate the user's scan.
is_windows_rooted_path() {
  local value=$1
  local windows_rooted_regex='^([A-Za-z]:[\/]|\\\\)'

  [[ $value =~ $windows_rooted_regex ]]
}

# Convert a rooted native Windows path into the POSIX form Bash can open.
#
# Every path the action compares must share one notation. GitHub sets GITHUB_WORKSPACE to a native path on Windows
# runners, so converting a user's input without converting the workspace would compare `/d/a/...` against `D:\a\...` and
# reject every absolute path as an escape. Converting both keeps containment meaningful. Relative inputs are returned
# untouched so they keep their workspace-rooted meaning, and non-Windows runners are never rewritten.
to_posix_path() {
  local value=$1
  local label=$2
  local converted

  if [[ ${RUNNER_OS:-} != Windows ]] || ! is_windows_rooted_path "$value"; then
    printf '%s\n' "$value"
    return 0
  fi
  command -v cygpath >/dev/null 2>&1 \
    || fail_action "$label needs cygpath to convert a Windows path: $value"
  converted=$(cygpath -u "$value") \
    || fail_action "unable to convert $label for bash: $value"
  # An empty conversion would silently become a relative path below.
  [[ -n $converted ]] || fail_action "unable to convert $label for bash: $value"
  printf '%s\n' "$converted"
}

# Resolve an existing directory so symlink escapes are visible to the user.
canonical_existing_directory() {
  local candidate=$1
  local label=$2
  local canonical

  [[ -d $candidate ]] || fail_action "$label is not an existing directory: $candidate"
  canonical=$(cd -- "$candidate" && pwd -P) \
    || fail_action "unable to canonicalize $label: $candidate"
  printf '%s\n' "$canonical"
}

# Resolve where the user's analysis runs without leaving GITHUB_WORKSPACE.
resolve_working_directory() {
  local workspace=$1
  local working_directory_input=${GRUFF_INPUT_WORKING_DIRECTORY:-}
  local resolved_input
  local candidate
  local canonical

  contains_line_break "$working_directory_input" \
    && fail_action "working-directory must not contain line breaks"
  # A Windows runner supplies native paths; resolve to one notation before use. The original input is kept for messages
  # so users see what they wrote.
  resolved_input=$(to_posix_path "$working_directory_input" "working-directory")
  # An empty field means the user wants to analyse the workspace root.
  if [[ -z $resolved_input ]]; then
    candidate=$workspace
  elif [[ $resolved_input == /* ]]; then
    candidate=$resolved_input
  else
    candidate=$workspace/$resolved_input
  fi
  canonical=$(canonical_existing_directory "$candidate" "working-directory")
  path_is_within "$canonical" "$workspace" \
    || fail_action "working-directory escapes GITHUB_WORKSPACE: $working_directory_input"
  printf '%s\n' "$canonical"
}

# Create only report-parent directories that resolve inside the workspace.
canonicalize_output_parent() {
  local requested_parent=$1
  local workspace=$2
  local cursor=$requested_parent
  local existing
  local component
  local next
  local -a missing=()

  # Walk upward until the requested report path reaches an existing directory.
  while [[ ! -e $cursor ]]; do
    component=$(basename -- "$cursor")
    # Empty, dot, or parent components would make a user's report path ambiguous.
    [[ -n $component && $component != "." && $component != ".." ]] \
      || fail_action "output-file contains an invalid parent component: $requested_parent"
    missing=("$component" "${missing[@]}")
    next=$(dirname -- "$cursor")
    [[ $next != "$cursor" ]] \
      || fail_action "unable to resolve output-file parent: $requested_parent"
    cursor=$next
  done

  existing=$(canonical_existing_directory "$cursor" "output-file parent")
  path_is_within "$existing" "$workspace" \
    || fail_action "output-file escapes GITHUB_WORKSPACE: ${GRUFF_INPUT_OUTPUT_FILE:-}"

  # Each missing folder is created and rechecked before the next user path part.
  for component in "${missing[@]}"; do
    next=$existing/$component
    # A missing folder is the normal case for a new reports/ output path.
    if [[ ! -e $next ]]; then
      mkdir -- "$next"
    fi
    existing=$(canonical_existing_directory "$next" "output-file parent")
    path_is_within "$existing" "$workspace" \
      || fail_action "output-file parent escaped GITHUB_WORKSPACE during creation"
  done

  printf '%s\n' "$existing"
}

# Resolve an optional report filename without following a user-created symlink.
resolve_output_file() {
  local workspace=$1
  local working_directory=$2
  local output_file_input=${GRUFF_INPUT_OUTPUT_FILE:-}
  local resolved_input
  local candidate
  local requested_parent
  local canonical_parent
  local filename
  local output_path

  # An empty output-file means the user wants analyzer output in the job log.
  [[ -n $output_file_input ]] || return 0
  contains_line_break "$output_file_input" && fail_action "output-file must not contain line breaks"
  # Same notation reconciliation as working-directory; messages keep the original.
  resolved_input=$(to_posix_path "$output_file_input" "output-file")
  # An absolute path is allowed only when its resolved parent remains in scope.
  if [[ $resolved_input == /* ]]; then
    candidate=$resolved_input
  else
    candidate=$working_directory/$resolved_input
  fi
  filename=$(basename -- "$candidate")
  # An empty or directory-like basename cannot represent the requested report.
  [[ -n $filename && $filename != "." && $filename != ".." ]] \
    || fail_action "output-file must name a file: $output_file_input"
  requested_parent=$(dirname -- "$candidate")
  canonical_parent=$(canonicalize_output_parent "$requested_parent" "$workspace")
  output_path=$canonical_parent/$filename
  path_is_within "$output_path" "$workspace" \
    || fail_action "output-file escapes GITHUB_WORKSPACE: $output_file_input"
  [[ ! -L $output_path ]] \
    || fail_action "output-file must not be a symbolic link: $output_file_input"
  [[ ! -d $output_path ]] || fail_action "output-file names a directory: $output_file_input"
  printf '%s\n' "$output_path"
}

# Convert one-argument-per-line action input into the exact CLI argv array.
parse_argv() {
  local legacy_args=${GRUFF_INPUT_ARGS:-}
  local argv_text=${GRUFF_INPUT_ARGV:-}
  local argv_argument

  # A non-empty legacy command string always shows the migration instructions.
  [[ -z $legacy_args ]] || legacy_args_error
  # YAML block scalars normally carry one terminal newline. It terminates the
  # final argument; a second terminal newline still becomes a rejected blank.
  argv_text=${argv_text%$'\n'}
  # Empty argv gives the CLI no user-selected operation to perform.
  [[ -n $argv_text ]] || fail_action "input 'argv' must contain at least one argument"
  ACTION_ARGV=()
  # Each YAML line becomes one literal argument visible to gruff-rs.
  while IFS= read -r argv_argument; do
    # A blank line is ambiguous, so ask the user to remove it explicitly.
    [[ -n $argv_argument ]] || fail_action "input 'argv' must not contain blank lines"
    ACTION_ARGV+=("$argv_argument")
  done <<<"$argv_text"
}

# Run the user's selected analysis and preserve its quality-gate exit status.
run_gruff() {
  local workspace_input=${GITHUB_WORKSPACE:-}
  local workspace
  local working_directory
  local output_file
  local analyzer_exit_status

  # Reject the retired command-string surface before any path lookup or
  # filesystem side effect so every non-empty legacy value gets one contract.
  parse_argv
  # An empty workspace means the action cannot contain the user's file paths.
  [[ -n $workspace_input ]] || fail_action "GITHUB_WORKSPACE is required"
  contains_line_break "$workspace_input" && fail_action "GITHUB_WORKSPACE must not contain line breaks"
  # GitHub sets this to a native path on Windows runners. Convert it first so the workspace and the user's paths are
  # compared in one notation.
  workspace_input=$(to_posix_path "$workspace_input" "GITHUB_WORKSPACE")
  workspace=$(canonical_existing_directory "$workspace_input" "GITHUB_WORKSPACE")
  working_directory=$(resolve_working_directory "$workspace")
  output_file=$(resolve_output_file "$workspace" "$working_directory")

  cd -- "$working_directory"
  # A report path sends stdout to the requested file instead of the job log.
  if [[ -n $output_file ]]; then
    # A successful analysis returns immediately with its normal zero status.
    if gruff-rs "${ACTION_ARGV[@]}" >"$output_file"; then
      return 0
    else
      analyzer_exit_status=$?
    fi
  else
    # Without a report file, users see analyzer output directly in the job log.
    if gruff-rs "${ACTION_ARGV[@]}"; then
      return 0
    else
      analyzer_exit_status=$?
    fi
  fi
  printf 'gruff-rs action: execution stage failed with exit status %d\n' \
    "$analyzer_exit_status" >&2
  return "$analyzer_exit_status"
}

# Dispatch the small set of modes invoked by action.yml steps.
dispatch_action_command() {
  case ${1:-} in
    resolve-version) resolve_version ;;
    run) run_gruff ;;
    *) fail_action "expected one mode: resolve-version or run" ;;
  esac
}

dispatch_action_command "$@"
