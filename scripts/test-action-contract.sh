#!/usr/bin/env bash
# Adversarial contract harness for the composite action's production scripts.
# Use it before publishing the action to see the same argument, path, version,
# download, checksum, and archive failures that a workflow author would see.
# Network traffic is replaced with local fixtures so each result is repeatable.

set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
RUNNER=$SCRIPT_DIR/action-run.sh
INSTALLER=$SCRIPT_DIR/action-install.sh
TARGET_CONTRACT=$SCRIPT_DIR/release-targets.sh
REAL_TAR=$(command -v tar)
WORK_DIR=""

# Stop the harness with one user-facing contract failure.
fail() {
  printf 'action contract test: %s\n' "$*" >&2
  exit 1
}

# Remove the private workflow simulation after each local test run.
cleanup() {
  # An empty path means setup failed before the user workspace was created.
  if [[ -n $WORK_DIR && -d $WORK_DIR ]]; then
    rm -rf -- "$WORK_DIR"
  fi
}

# Create harmless command stubs so hostile user inputs cannot touch real tools.
write_stubs() {
  local bin_dir=$1

  mkdir -p -- "$bin_dir"
  cat >"$bin_dir/gruff-rs" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
: "${STUB_ARGV_FILE:?}"
: "${STUB_CWD_FILE:?}"
printf '%s\0' "$@" >"$STUB_ARGV_FILE"
printf '%s\0' "$PWD" >"$STUB_CWD_FILE"
printf 'stub-output\n'
# A failing analyzer models a workflow whose configured quality gate was hit.
if [[ ${STUB_EXIT_STATUS:-0} -ne 0 ]]; then
  exit "$STUB_EXIT_STATUS"
fi
STUB
  cat >"$bin_dir/curl" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
: "${STUB_CURL_MODE:?}"
: "${STUB_CURL_LOG:?}"

output=""
headers=""
url=""

# Read only the curl options used by the production installer.
while (($#)); do
  case $1 in
    --output|--dump-header|--write-out|--proto|--proto-redir|--max-redirs)
      # A missing option value means the simulated workflow call is malformed.
      [[ $# -ge 2 ]] || exit 64
      case $1 in
        --output) output=$2 ;;
        --dump-header) headers=$2 ;;
      esac
      shift 2
      ;;
    --disable|--silent|--show-error|--tlsv1.2)
      shift
      ;;
    *)
      url=$1
      shift
      ;;
  esac
done

# Empty destinations mean a future installer edit changed the curl contract.
[[ -n $output && -n $headers && -n $url ]] || exit 64
printf '%s\n' "$url" >>"$STUB_CURL_LOG"

# A network outage can happen before GitHub returns any response headers.
if [[ $STUB_CURL_MODE == network-failure ]]; then
  printf 'curl: simulated network failure\n' >&2
  exit 7
fi

url_without_query=${url%%\?*}
asset_name=${url_without_query##*/}
case $url in
  https://github.com/blundergoat/gruff-rs/releases/download/*)
    # This case models the normal GitHub redirect or a compromised redirect.
    if [[ $STUB_CURL_MODE == redirect-outside ]]; then
      location=https://example.invalid/hostile-release
    else
      location=https://release-assets.githubusercontent.com/test/$asset_name
    fi
    # Duplicate locations model an ambiguous or malicious proxy response.
    if [[ $STUB_CURL_MODE == duplicate-location ]]; then
      printf 'HTTP/1.1 302 Found\r\nLocation: %s\r\nLocation: %s\r\n\r\n' \
        "$location" "https://example.invalid/second" >"$headers"
    else
      printf 'HTTP/1.1 302 Found\r\nLocation: %s\r\n\r\n' "$location" >"$headers"
    fi
    printf '302'
    ;;
  https://release-assets.githubusercontent.com/*)
    # A missing sidecar tells the workflow author the release is incomplete.
    if [[ $STUB_CURL_MODE == missing-sidecar && $asset_name == *.sha256 ]]; then
      printf 'HTTP/1.1 404 Not Found\r\n\r\n' >"$headers"
      printf 'missing\n' >"$output"
      printf '404'
      exit 0
    fi
    case $asset_name in
      *.sha256)
        case $STUB_CURL_MODE in
          checksum-mismatch) source_file=$STUB_MISMATCH_SIDECAR ;;
          unexpected-member) source_file=$STUB_UNEXPECTED_SIDECAR ;;
          symlink-member) source_file=$STUB_SYMLINK_SIDECAR ;;
          malformed-sidecar) source_file=$STUB_MALFORMED_SIDECAR ;;
          wrong-sidecar-filename) source_file=$STUB_WRONG_FILENAME_SIDECAR ;;
          *) source_file=$STUB_VALID_SIDECAR ;;
        esac
        ;;
      *)
        case $STUB_CURL_MODE in
          unexpected-member) source_file=$STUB_UNEXPECTED_ARCHIVE ;;
          symlink-member) source_file=$STUB_SYMLINK_ARCHIVE ;;
          *) source_file=$STUB_VALID_ARCHIVE ;;
        esac
        ;;
    esac
    cp "$source_file" "$output"
    printf 'HTTP/1.1 200 OK\r\n\r\n' >"$headers"
    printf '200'
    ;;
  *)
    exit 64
    ;;
esac
STUB
  cat >"$bin_dir/tar" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
: "${REAL_TAR:?}"

# Recording tar calls proves a bad checksum never reaches archive handling.
if [[ -n ${STUB_TAR_LOG:-} ]]; then
  printf '%s\0' "$@" >>"$STUB_TAR_LOG"
fi
exec "$REAL_TAR" "$@"
STUB
  chmod +x "$bin_dir/gruff-rs" "$bin_dir/curl" "$bin_dir/tar"
}

# Decode the exact argument boundaries a workflow author supplied through argv.
read_nul_values() {
  local file=$1
  local value

  NUL_VALUES=()
  # Each record is one literal CLI argument, including spaces and punctuation.
  while IFS= read -r -d '' value; do
    NUL_VALUES+=("$value")
  done <"$file"
}

# Compare captured arguments without allowing the shell to split them again.
assert_nul_values() {
  local file=$1
  shift
  local -a expected=("$@")
  local index

  read_nul_values "$file"
  [[ ${#NUL_VALUES[@]} -eq ${#expected[@]} ]] \
    || fail "argument count mismatch: got ${#NUL_VALUES[@]}, expected ${#expected[@]}"
  # Each mismatch identifies the argument position visible to the CLI user.
  for ((index = 0; index < ${#expected[@]}; index++)); do
    [[ ${NUL_VALUES[index]} == "${expected[index]}" ]] \
      || fail "argument $index mismatch: got <${NUL_VALUES[index]}>, expected <${expected[index]}>"
  done
}

# Run the production execution boundary with inputs shaped like action fields.
run_action() {
  local argv=$1
  # Omitted optional paths model an action user accepting the documented defaults.
  local working_directory=${2:-}
  local output_file=${3:-}

  GRUFF_INPUT_ARGS="" \
    GRUFF_INPUT_ARGV=$argv \
    GRUFF_INPUT_WORKING_DIRECTORY=$working_directory \
    GRUFF_INPUT_OUTPUT_FILE=$output_file \
    GITHUB_WORKSPACE=$WORKSPACE \
    STUB_ARGV_FILE=$ARGV_FILE \
    STUB_CWD_FILE=$CWD_FILE \
    PATH=$STUB_BIN:$PATH \
    "$RUNNER" run
}

# Prove the no-input action still gives users the documented SARIF scan.
assert_default_argv() {
  local default_argv=$'analyse\n.\n--format\nsarif\n--fail-on\nwarning\n--no-baseline\n'

  run_action "$default_argv" >/dev/null
  assert_nul_values "$ARGV_FILE" analyse . --format sarif --fail-on warning --no-baseline
}

# Prove pasted shell punctuation stays plain text in a user's CLI argument.
assert_hostile_argv_is_literal() {
  local -a expected=(
    analyse
    .
    '--label=literal space'
    -leading-dash
    '; touch m03-semicolon'
    "\$(touch m03-substitution)"
    "\`touch m03-backtick\`"
    '"double" and '\''single'\'' quotes'
    '>m03-redirected'
    '*'
    first-line
    second-line
  )
  local argv

  touch "$WORKSPACE/glob-target"
  printf -v argv '%s\n' "${expected[@]}"
  run_action "$argv" >/dev/null
  assert_nul_values "$ARGV_FILE" "${expected[@]}"
  # These marker files would exist if a user's argument had executed as shell.
  for marker in m03-semicolon m03-substitution m03-backtick m03-redirected; do
    [[ ! -e $WORKSPACE/$marker ]] || fail "shell syntax executed: $marker"
  done
}

# Keep the retired command-string input on one actionable migration error.
assert_legacy_args_fail_closed() {
  local error_file=$WORK_DIR/legacy-error
  local marker=$WORKSPACE/m03-pwned
  local expected_error
  local actual_error
  local status

  expected_error=$(cat <<'ERROR'
gruff-rs action: input 'args' is no longer supported; use 'argv' with one literal argument per non-empty line, for example:
argv: |
  analyse
  .
  --format
  sarif
ERROR
)
  rm -f -- "$ARGV_FILE" "$marker"
  set +e
  GRUFF_INPUT_ARGS="analyse .; printf injected > \"$marker\"" \
    GRUFF_INPUT_ARGV=$'analyse\n.' \
    GRUFF_INPUT_WORKING_DIRECTORY="../outside" \
    GRUFF_INPUT_OUTPUT_FILE="created/by-legacy/out.sarif" \
    GITHUB_WORKSPACE=$WORKSPACE \
    STUB_ARGV_FILE=$ARGV_FILE \
    STUB_CWD_FILE=$CWD_FILE \
    PATH=$STUB_BIN:$PATH \
    "$RUNNER" run >"$WORK_DIR/legacy-output" 2>"$error_file"
  status=$?
  set -e
  [[ $status -eq 2 ]] || fail "legacy args exited $status instead of 2"
  actual_error=$(<"$error_file")
  [[ $actual_error == "$expected_error" ]] || fail "legacy migration error drifted"
  [[ ! -e $ARGV_FILE && ! -e $marker && ! -e $WORKSPACE/created ]] \
    || fail "legacy args reached execution or path side effects"
}

# Explain an accidental blank YAML line instead of silently changing argv.
assert_blank_argv_line_is_rejected() {
  local status

  set +e
  run_action $'analyse\n\n.' >"$WORK_DIR/blank-output" 2>"$WORK_DIR/blank-error"
  status=$?
  set -e
  [[ $status -eq 2 ]] || fail "blank argv line exited $status instead of 2"
  grep -q "must not contain blank lines" "$WORK_DIR/blank-error" \
    || fail "blank argv rejection message missing"
}

# Keep user-selected work and report paths inside the checked-out workspace.
assert_working_and_output_paths_are_contained() {
  local working='nested dir'
  local hostile_output="reports/-result ;\$()\`\"' > [*].sarif"
  local expected_output=$WORKSPACE/$working/$hostile_output
  local outside=$WORK_DIR/outside
  local status

  mkdir -p -- "$WORKSPACE/$working" "$outside"
  run_action $'analyse\n.' "$working" "$hostile_output" >/dev/null
  [[ $(<"$expected_output") == "stub-output" ]] || fail "hostile output filename was not written literally"
  assert_nul_values "$CWD_FILE" "$WORKSPACE/$working"

  set +e
  run_action $'analyse\n.' ".." >"$WORK_DIR/work-escape-output" 2>"$WORK_DIR/work-escape-error"
  status=$?
  set -e
  [[ $status -eq 2 ]] || fail "working-directory .. escape was accepted"

  ln -s -- "$outside" "$WORKSPACE/outside-link"
  set +e
  run_action $'analyse\n.' "outside-link" >"$WORK_DIR/work-link-output" 2>"$WORK_DIR/work-link-error"
  status=$?
  set -e
  [[ $status -eq 2 ]] || fail "working-directory symlink escape was accepted"

  set +e
  run_action $'analyse\n.' "" "../outside.sarif" >"$WORK_DIR/output-escape-output" 2>"$WORK_DIR/output-escape-error"
  status=$?
  set -e
  [[ $status -eq 2 ]] || fail "output-file .. escape was accepted"

  set +e
  run_action $'analyse\n.' "" "outside-link/result.sarif" >"$WORK_DIR/output-link-output" 2>"$WORK_DIR/output-link-error"
  status=$?
  set -e
  [[ $status -eq 2 ]] || fail "output-file symlink escape was accepted"

  ln -s -- "$outside/result.sarif" "$WORKSPACE/output-link.sarif"
  set +e
  run_action $'analyse\n.' "" "output-link.sarif" >"$WORK_DIR/output-target-output" 2>"$WORK_DIR/output-target-error"
  status=$?
  set -e
  [[ $status -eq 2 ]] || fail "output-file target symlink was accepted"
}

# Resolve only exact release versions before the installer constructs URLs.
assert_version_transport_is_structured() {
  local github_output=$WORK_DIR/github-output
  local status

  GRUFF_INPUT_VERSION="" GRUFF_ACTION_REF=v0.5.0 GITHUB_OUTPUT=$github_output \
    "$RUNNER" resolve-version
  [[ $(<"$github_output") == "value=0.5.0" ]] || fail "action ref version did not resolve"

  rm -f -- "$WORKSPACE/version-injected"
  set +e
  GRUFF_INPUT_VERSION="\$(touch version-injected)" GRUFF_ACTION_REF=v0.5.0 GITHUB_OUTPUT=$github_output \
    "$RUNNER" resolve-version >"$WORK_DIR/version-output" 2>"$WORK_DIR/version-error"
  status=$?
  set -e
  [[ $status -eq 2 && ! -e $WORKSPACE/version-injected ]] \
    || fail "hostile version was not rejected inertly"
  [[ $(<"$WORK_DIR/version-error") == "gruff-rs action: version must be an exact semantic version" ]] \
    || fail "invalid version value leaked into workflow guidance"

  rm -f -- "$github_output"
  set +e
  GRUFF_INPUT_VERSION="" GRUFF_ACTION_REF=0123456789012345678901234567890123456789 \
    GITHUB_OUTPUT=$github_output "$RUNNER" resolve-version \
    >"$WORK_DIR/sha-version-output" 2>"$WORK_DIR/sha-version-error"
  status=$?
  set -e
  [[ $status -eq 2 && ! -e $github_output ]] \
    || fail "full-SHA action ref inferred a binary version"
  grep -q "version is required" "$WORK_DIR/sha-version-error" \
    || fail "full-SHA version guidance is missing"

  set +e
  GRUFF_INPUT_VERSION=latest GRUFF_ACTION_REF=v0.5.0 GITHUB_OUTPUT=$github_output \
    "$RUNNER" resolve-version >"$WORK_DIR/latest-output" 2>"$WORK_DIR/latest-error"
  status=$?
  set -e
  [[ $status -eq 2 ]] || fail "latest version remained executable"

  set +e
  GRUFF_INPUT_VERSION=0.4.0 GRUFF_ACTION_REF=v0.5.0 GITHUB_OUTPUT=$github_output \
    "$RUNNER" resolve-version >"$WORK_DIR/mismatch-output" 2>"$WORK_DIR/mismatch-error"
  status=$?
  set -e
  [[ $status -eq 2 ]] || fail "mismatched action and binary versions were accepted"
  grep -q "does not match action release tag" "$WORK_DIR/mismatch-error" \
    || fail "mismatched version guidance is missing"

  GRUFF_INPUT_VERSION=0.5.0-rc.1 GRUFF_ACTION_REF="" GITHUB_OUTPUT=$github_output \
    "$RUNNER" resolve-version
  [[ $(<"$github_output") == "value=0.5.0-rc.1" ]] \
    || fail "explicit prerelease version did not resolve"
}

# Calculate a fixture checksum with the same portable tools used in production.
sha256_of() {
  local file=$1
  local output

  # Linux users normally have sha256sum; macOS users normally have shasum.
  if command -v sha256sum >/dev/null 2>&1; then
    output=$(sha256sum "$file")
  else
    output=$(shasum -a 256 "$file")
  fi
  printf '%s\n' "${output%% *}"
}

# Build a release-shaped archive that represents what a workflow downloads.
create_archive_fixture() {
  local fixture_name=$1
  local archive_file=$2
  # An omitted variant models the valid archive a normal workflow user downloads.
  local archive_variant=${3:-valid}
  local fixture_root=$FIXTURE_DIR/$fixture_name
  local archive_root=gruff-rs-0.5.0-x86_64-unknown-linux-gnu

  mkdir -p -- "$fixture_root/$archive_root"
  cat >"$fixture_root/$archive_root/gruff-rs" <<'BINARY'
#!/usr/bin/env bash
# This harmless fixture is what a user runs after a successful local install.
printf 'verified fixture binary\n'
BINARY
  chmod +x "$fixture_root/$archive_root/gruff-rs"
  printf 'fixture readme\n' >"$fixture_root/$archive_root/README.md"
  printf 'fixture MIT license\n' >"$fixture_root/$archive_root/LICENSE-MIT"
  printf 'fixture Apache license\n' >"$fixture_root/$archive_root/LICENSE-APACHE"
  printf 'fixture changelog\n' >"$fixture_root/$archive_root/CHANGELOG.md"
  case $archive_variant in
    valid) ;;
    unexpected-member)
      printf 'unexpected\n' >"$fixture_root/$archive_root/SURPRISE.txt"
      ;;
    symlink-member)
      rm -f -- "$fixture_root/$archive_root/gruff-rs"
      ln -s README.md "$fixture_root/$archive_root/gruff-rs"
      ;;
    *) fail "unknown archive fixture variant: $archive_variant" ;;
  esac
  (cd -- "$fixture_root" && "$REAL_TAR" -czf "$archive_file" "$archive_root")
}

# Write the exact one-line checksum sidecar published beside a release archive.
write_sidecar() {
  local archive_file=$1
  local sidecar_file=$2
  local archive_basename=${archive_file##*/}

  printf '%s  %s\n' "$(sha256_of "$archive_file")" "$archive_basename" >"$sidecar_file"
}

# Invoke the production installer with deterministic runner and network fields.
invoke_installer() {
  local mode=$1
  # Omitted runner fields model the action's common Linux x64 environment.
  local runner_os=${2:-Linux}
  local runner_arch=${3:-X64}

  : >"$GITHUB_PATH_FILE"
  : >"$CURL_LOG"
  : >"$TAR_LOG"
  set +e
  GRUFF_RESOLVED_VERSION=0.5.0 \
    RUNNER_OS=$runner_os \
    RUNNER_ARCH=$runner_arch \
    RUNNER_TEMP=$RUNNER_TEMP_DIR \
    GITHUB_PATH=$GITHUB_PATH_FILE \
    STUB_CURL_MODE=$mode \
    STUB_CURL_LOG=$CURL_LOG \
    STUB_VALID_ARCHIVE=$VALID_ARCHIVE \
    STUB_VALID_SIDECAR=$VALID_SIDECAR \
    STUB_MISMATCH_SIDECAR=$MISMATCH_SIDECAR \
    STUB_UNEXPECTED_ARCHIVE=$UNEXPECTED_ARCHIVE \
    STUB_UNEXPECTED_SIDECAR=$UNEXPECTED_SIDECAR \
    STUB_SYMLINK_ARCHIVE=$SYMLINK_ARCHIVE \
    STUB_SYMLINK_SIDECAR=$SYMLINK_SIDECAR \
    STUB_MALFORMED_SIDECAR=$MALFORMED_SIDECAR \
    STUB_WRONG_FILENAME_SIDECAR=$WRONG_FILENAME_SIDECAR \
    STUB_TAR_LOG=$TAR_LOG \
    REAL_TAR=$REAL_TAR \
    PATH=$STUB_BIN:$PATH \
    "$INSTALLER" >"$INSTALL_OUTPUT" 2>"$INSTALL_ERROR"
  INSTALL_STATUS=$?
  set -e
}

# Prove a valid release becomes the only new executable path for the user.
assert_verified_install_succeeds() {
  local installed_bin_dir

  invoke_installer success
  [[ $INSTALL_STATUS -eq 0 ]] \
    || fail "verified install exited $INSTALL_STATUS: $(<"$INSTALL_ERROR")"
  [[ $(wc -l <"$GITHUB_PATH_FILE") -eq 1 ]] \
    || fail "verified install did not append exactly one path"
  installed_bin_dir=$(<"$GITHUB_PATH_FILE")
  [[ $installed_bin_dir == "$RUNNER_TEMP_DIR"/gruff-rs-action.*/bin ]] \
    || fail "verified binary directory was not private under RUNNER_TEMP"
  [[ -x $installed_bin_dir/gruff-rs && ! -L $installed_bin_dir/gruff-rs ]] \
    || fail "verified gruff-rs binary was not installed"
  [[ $("$installed_bin_dir"/gruff-rs) == "verified fixture binary" ]] \
    || fail "installed fixture binary was not runnable"
  grep -q "checksum stage: verified" "$INSTALL_OUTPUT" \
    || fail "successful checksum stage was not visible"
  grep -q "install stage: installed verified" "$INSTALL_OUTPUT" \
    || fail "successful install stage was not visible"
}

# Reject runner combinations for which the release workflow publishes no asset.
assert_unknown_target_is_rejected() {
  invoke_installer success Windows ARM64
  [[ $INSTALL_STATUS -eq 2 ]] || fail "unknown target exited $INSTALL_STATUS instead of 2"
  grep -q "unsupported runner target: Windows/ARM64" "$INSTALL_ERROR" \
    || fail "unknown target guidance is missing"
  [[ ! -s $CURL_LOG ]] || fail "unknown target reached the network"
}

# Prove every supported action runner selects an archive the release matrix builds.
assert_release_target_contract_covers_action_runners() {
  local -a expected_runner_records=(
    'Linux|X64|x86_64-unknown-linux-gnu|tar.gz|gruff-rs'
    'Linux|ARM64|aarch64-unknown-linux-gnu|tar.gz|gruff-rs'
    'macOS|X64|x86_64-apple-darwin|tar.gz|gruff-rs'
    'macOS|ARM64|aarch64-apple-darwin|tar.gz|gruff-rs'
    'Windows|X64|x86_64-pc-windows-msvc|zip|gruff-rs.exe'
  )
  local expected_runner_record
  local runner_os
  local runner_arch
  local expected_target
  local expected_archive_kind
  local expected_binary_name
  local actual_target_record
  local build_count
  local asset_count

  # Each user-visible runner must resolve to its reviewed release asset fields.
  for expected_runner_record in "${expected_runner_records[@]}"; do
    IFS='|' read -r runner_os runner_arch expected_target expected_archive_kind \
      expected_binary_name <<<"$expected_runner_record"
    actual_target_record=$(bash "$TARGET_CONTRACT" resolve-runner "$runner_os" "$runner_arch")
    [[ $actual_target_record == "$expected_target|$expected_archive_kind|$expected_binary_name" ]] \
      || fail "release target drifted for $runner_os/$runner_arch: $actual_target_record"
  done

  build_count=$(bash "$TARGET_CONTRACT" matrix-json | grep -o '"target":' | wc -l)
  [[ $build_count -eq 5 ]] || fail "release matrix contains $build_count builds instead of 5"
  asset_count=$(bash "$TARGET_CONTRACT" expected-assets 0.5.0 | wc -l)
  [[ $asset_count -eq 10 ]] || fail "release contract contains $asset_count assets instead of 10"
}

# Tell users when a release exists without its required checksum sidecar.
assert_missing_sidecar_is_rejected() {
  invoke_installer missing-sidecar
  [[ $INSTALL_STATUS -eq 2 ]] || fail "missing sidecar exited $INSTALL_STATUS instead of 2"
  grep -q "install stage: download returned HTTP 404" "$INSTALL_ERROR" \
    || fail "missing sidecar stage is unclear"
  [[ ! -s $GITHUB_PATH_FILE ]] || fail "missing sidecar changed the workflow path"
}

# Prove checksum failure happens before any archive listing or extraction.
assert_checksum_mismatch_stops_before_archive_use() {
  invoke_installer checksum-mismatch
  [[ $INSTALL_STATUS -eq 2 ]] || fail "checksum mismatch exited $INSTALL_STATUS instead of 2"
  grep -q "checksum stage: SHA-256 mismatch" "$INSTALL_ERROR" \
    || fail "checksum mismatch stage is unclear"
  [[ ! -s $TAR_LOG ]] || fail "checksum mismatch reached archive handling"
  [[ ! -s $GITHUB_PATH_FILE ]] || fail "checksum mismatch changed the workflow path"
}

# Reject a correctly checksummed archive whose contents exceed the contract.
assert_unexpected_archive_member_is_rejected() {
  invoke_installer unexpected-member
  [[ $INSTALL_STATUS -eq 2 ]] || fail "unexpected member exited $INSTALL_STATUS instead of 2"
  grep -q "archive stage: unexpected archive member" "$INSTALL_ERROR" \
    || fail "unexpected member stage is unclear"
  ! grep -q "SURPRISE.txt" "$INSTALL_ERROR" \
    || fail "untrusted archive member leaked into workflow guidance"
  [[ -s $TAR_LOG ]] || fail "unexpected member test never inspected the archive"
  [[ ! -s $GITHUB_PATH_FILE ]] || fail "unexpected member changed the workflow path"
}

# Reject an expected binary name when the publisher stored it as a symlink.
assert_archive_symlink_is_rejected() {
  invoke_installer symlink-member
  [[ $INSTALL_STATUS -eq 2 ]] || fail "archive symlink exited $INSTALL_STATUS instead of 2"
  grep -q "links and special archive members are forbidden" "$INSTALL_ERROR" \
    || fail "archive symlink stage is unclear"
  [[ ! -s $GITHUB_PATH_FILE ]] || fail "archive symlink changed the workflow path"
}

# Reject extra sidecar lines rather than guessing which checksum the user meant.
assert_malformed_sidecar_is_rejected() {
  invoke_installer malformed-sidecar
  [[ $INSTALL_STATUS -eq 2 ]] || fail "malformed sidecar exited $INSTALL_STATUS instead of 2"
  grep -q "sidecar must contain exactly one line" "$INSTALL_ERROR" \
    || fail "malformed sidecar guidance is missing"
  [[ ! -s $TAR_LOG ]] || fail "malformed sidecar reached archive handling"
}

# Reject a sidecar that tries to select any filename except the requested asset.
assert_sidecar_filename_is_bound() {
  invoke_installer wrong-sidecar-filename
  [[ $INSTALL_STATUS -eq 2 ]] || fail "wrong sidecar filename exited $INSTALL_STATUS instead of 2"
  grep -q "expected archive basename" "$INSTALL_ERROR" \
    || fail "wrong sidecar filename guidance is missing"
  [[ ! -s $TAR_LOG ]] || fail "wrong sidecar filename reached archive handling"
}

# Surface a transport outage as installation failure without a partial path.
assert_network_failure_is_rejected() {
  invoke_installer network-failure
  [[ $INSTALL_STATUS -eq 2 ]] || fail "network failure exited $INSTALL_STATUS instead of 2"
  grep -q "install stage: download failed" "$INSTALL_ERROR" \
    || fail "network failure stage is unclear"
  [[ ! -s $GITHUB_PATH_FILE ]] || fail "network failure changed the workflow path"
}

# Reject a redirect to any host outside GitHub's reviewed release-asset policy.
assert_redirect_outside_policy_is_rejected() {
  invoke_installer redirect-outside
  [[ $INSTALL_STATUS -eq 2 ]] || fail "hostile redirect exited $INSTALL_STATUS instead of 2"
  grep -q "outside the allowed HTTPS hosts" "$INSTALL_ERROR" \
    || fail "hostile redirect guidance is missing"
  ! grep -q "example.invalid" "$INSTALL_ERROR" \
    || fail "untrusted redirect URL leaked into workflow guidance"
  [[ ! -s $GITHUB_PATH_FILE ]] || fail "hostile redirect changed the workflow path"
}

# Reject ambiguous redirect headers before curl can choose a hidden second URL.
assert_duplicate_redirect_is_rejected() {
  invoke_installer duplicate-location
  [[ $INSTALL_STATUS -eq 2 ]] || fail "duplicate redirect exited $INSTALL_STATUS instead of 2"
  grep -q "exactly one Location header" "$INSTALL_ERROR" \
    || fail "duplicate redirect guidance is missing"
  [[ ! -s $GITHUB_PATH_FILE ]] || fail "duplicate redirect changed the workflow path"
}

# Preserve the analyzer's quality-gate status while naming execution failure.
assert_execution_failure_is_staged() {
  local status

  set +e
  STUB_EXIT_STATUS=1 run_action $'analyse\n.' \
    >"$WORK_DIR/execution-output" 2>"$WORK_DIR/execution-error"
  status=$?
  set -e
  [[ $status -eq 1 ]] || fail "analyzer failure status changed from 1 to $status"
  grep -q "execution stage failed with exit status 1" "$WORK_DIR/execution-error" \
    || fail "analyzer execution stage is unclear"
}

# Assemble the simulated workflow and run every user-visible action contract.
run_action_contract_suite() {
  [[ -x $RUNNER ]] || fail "runner is not executable: $RUNNER"
  [[ -x $INSTALLER ]] || fail "installer is not executable: $INSTALLER"
  # A developer without TMPDIR still gets an isolated local action simulation.
  WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/gruff-rs-action-contract.XXXXXX")
  trap cleanup EXIT
  WORKSPACE=$WORK_DIR/'workspace with spaces'
  STUB_BIN=$WORK_DIR/bin
  ARGV_FILE=$WORK_DIR/argv
  CWD_FILE=$WORK_DIR/cwd
  FIXTURE_DIR=$WORK_DIR/fixtures
  RUNNER_TEMP_DIR=$WORK_DIR/runner-temp
  GITHUB_PATH_FILE=$WORK_DIR/github-path
  CURL_LOG=$WORK_DIR/curl-log
  TAR_LOG=$WORK_DIR/tar-log
  INSTALL_OUTPUT=$WORK_DIR/install-output
  INSTALL_ERROR=$WORK_DIR/install-error
  VALID_ARCHIVE=$FIXTURE_DIR/gruff-rs-0.5.0-x86_64-unknown-linux-gnu.tar.gz
  VALID_SIDECAR=$VALID_ARCHIVE.sha256
  MISMATCH_SIDECAR=$FIXTURE_DIR/checksum-mismatch.sha256
  UNEXPECTED_ARCHIVE=$FIXTURE_DIR/unexpected-gruff-rs-0.5.0-x86_64-unknown-linux-gnu.tar.gz
  UNEXPECTED_SIDECAR=$FIXTURE_DIR/unexpected.sha256
  SYMLINK_ARCHIVE=$FIXTURE_DIR/symlink-gruff-rs-0.5.0-x86_64-unknown-linux-gnu.tar.gz
  SYMLINK_SIDECAR=$FIXTURE_DIR/symlink.sha256
  MALFORMED_SIDECAR=$FIXTURE_DIR/malformed.sha256
  WRONG_FILENAME_SIDECAR=$FIXTURE_DIR/wrong-filename.sha256
  mkdir -p -- "$WORKSPACE" "$FIXTURE_DIR" "$RUNNER_TEMP_DIR"
  write_stubs "$STUB_BIN"
  create_archive_fixture valid "$VALID_ARCHIVE" valid
  write_sidecar "$VALID_ARCHIVE" "$VALID_SIDECAR"
  printf '%064d  %s\n' 0 "${VALID_ARCHIVE##*/}" >"$MISMATCH_SIDECAR"
  create_archive_fixture unexpected "$UNEXPECTED_ARCHIVE" unexpected-member
  printf '%s  %s\n' "$(sha256_of "$UNEXPECTED_ARCHIVE")" "${VALID_ARCHIVE##*/}" \
    >"$UNEXPECTED_SIDECAR"
  create_archive_fixture symlink "$SYMLINK_ARCHIVE" symlink-member
  printf '%s  %s\n' "$(sha256_of "$SYMLINK_ARCHIVE")" "${VALID_ARCHIVE##*/}" \
    >"$SYMLINK_SIDECAR"
  printf '%s  %s\nextra line\n' "$(sha256_of "$VALID_ARCHIVE")" "${VALID_ARCHIVE##*/}" \
    >"$MALFORMED_SIDECAR"
  printf '%s  %s\n' "$(sha256_of "$VALID_ARCHIVE")" "../../other-asset.tar.gz" \
    >"$WRONG_FILENAME_SIDECAR"

  assert_default_argv
  assert_hostile_argv_is_literal
  assert_legacy_args_fail_closed
  assert_blank_argv_line_is_rejected
  assert_working_and_output_paths_are_contained
  assert_version_transport_is_structured
  assert_release_target_contract_covers_action_runners
  assert_verified_install_succeeds
  assert_unknown_target_is_rejected
  assert_missing_sidecar_is_rejected
  assert_checksum_mismatch_stops_before_archive_use
  assert_unexpected_archive_member_is_rejected
  assert_archive_symlink_is_rejected
  assert_malformed_sidecar_is_rejected
  assert_sidecar_filename_is_bound
  assert_network_failure_is_rejected
  assert_redirect_outside_policy_is_rejected
  assert_duplicate_redirect_is_rejected
  assert_execution_failure_is_staged
  printf 'PASS: composite action preserves argv and installs only exact checksum-verified releases\n'
}

run_action_contract_suite "$@"
