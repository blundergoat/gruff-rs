#!/usr/bin/env bash
# Composite-action installer for one exact gruff-rs release.
# Workflow authors use this indirectly through action.yml; it selects their
# runner asset, verifies the published checksum and members, then exposes only
# the verified binary to the later analysis step.

set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
RELEASE_ORIGIN=https://github.com/blundergoat/gruff-rs
RELEASE_TARGET_CONTRACT=$SCRIPT_DIR/release-targets.sh
INSTALL_ROOT=""
DOWNLOAD_DIR=""
EXTRACT_DIR=""
INSTALL_SUCCEEDED=0

# Show a concise staged error in the workflow log and stop the action.
fail_install() {
  printf 'gruff-rs action: %s\n' "$*" >&2
  exit 2
}

# Remove failed downloads, while retaining only a successful binary directory.
cleanup_private_install() {
  # No directory means the workflow failed before private storage was created.
  if [[ -z $INSTALL_ROOT || ! -d $INSTALL_ROOT ]]; then
    return
  fi
  # A successful workflow keeps its binary until GitHub cleans RUNNER_TEMP.
  if ((INSTALL_SUCCEEDED)); then
    rm -rf -- "$DOWNLOAD_DIR" "$EXTRACT_DIR"
  else
    rm -rf -- "$INSTALL_ROOT"
  fi
}

# Fail early when the runner lacks a tool needed for a safe installation.
require_install_command() {
  command -v "$1" >/dev/null 2>&1 \
    || fail_install "install stage: required command is unavailable: $1"
}

# Detect line breaks that could corrupt a workflow command file or URL field.
contains_line_break() {
  [[ $1 == *$'\n'* || $1 == *$'\r'* ]]
}

# Accept an exact SemVer release and reject moving labels such as latest.
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
    # A numeric value such as rc.01 is not a valid exact SemVer prerelease.
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

# Map the current runner through the same target contract used by publication.
select_release_target() {
  local runner_os=$1
  local runner_arch=$2
  local target_selection
  local unexpected_field

  # An unsupported runner means no reviewed release asset can be installed.
  if ! target_selection=$(bash "$RELEASE_TARGET_CONTRACT" resolve-runner \
    "$runner_os" "$runner_arch" 2>/dev/null); then
    fail_install "install stage: unsupported runner target: $runner_os/$runner_arch"
  fi
  IFS='|' read -r TARGET ARCHIVE_KIND BINARY_NAME unexpected_field <<<"$target_selection"
  # Empty or extra fields mean the publication and installation contract drifted.
  [[ -n $TARGET && -n $ARCHIVE_KIND && -n $BINARY_NAME && -z $unexpected_field ]] \
    || fail_install "install stage: release target contract returned an invalid record"
}

# Limit every download hop to the fixed project origin or GitHub asset host.
download_url_is_allowed() {
  # Raw whitespace or controls never belong in GitHub's signed asset URL.
  [[ $1 != *[[:space:][:cntrl:]]* ]] || return 1
  case $1 in
    "$RELEASE_ORIGIN"/releases/download/*) return 0 ;;
    https://release-assets.githubusercontent.com/*) return 0 ;;
    *) return 1 ;;
  esac
}

# Read one redirect target so users never follow an ambiguous Location header.
read_redirect_location() {
  local response_headers_file=$1
  local response_header
  local redirect_url=""
  local location_header_count=0

  # Each response header is data; only the single Location field is retained.
  while IFS= read -r response_header || [[ -n $response_header ]]; do
    response_header=${response_header%$'\r'}
    case $response_header in
      [Ll][Oo][Cc][Aa][Tt][Ii][Oo][Nn]:*)
        redirect_url=${response_header#*:}
        # Header whitespace is presentation, not part of the download URL.
        while [[ $redirect_url == ' '* || $redirect_url == $'\t'* ]]; do
          redirect_url=${redirect_url#?}
        done
        location_header_count=$((location_header_count + 1))
        ;;
    esac
  done <"$response_headers_file"
  # Empty or repeated locations give the workflow no trustworthy next hop.
  [[ $location_header_count -eq 1 && -n $redirect_url ]] || return 1
  printf '%s\n' "$redirect_url"
}

# Download one release file while validating every HTTPS redirect hop.
download_release_file() {
  local initial_url=$1
  local destination_file=$2
  local current_url=$initial_url
  local response_headers_file=$DOWNLOAD_DIR/headers
  local partial_download_file=$destination_file.partial
  local http_status
  local redirect_url
  local redirect_count=0

  # Each pass represents one GitHub response visible in the redirect chain.
  while :; do
    download_url_is_allowed "$current_url" \
      || fail_install "install stage: rejected redirect outside the allowed HTTPS hosts"
    : >"$response_headers_file"
    # A transport error means the user received no complete release file.
    if ! http_status=$(curl --disable --silent --show-error \
      --proto '=https' --proto-redir '=https' --tlsv1.2 \
      --max-redirs 0 --output "$partial_download_file" \
      --dump-header "$response_headers_file" \
      --write-out '%{http_code}' "$current_url"); then
      fail_install "install stage: download failed for $initial_url"
    fi
    [[ $http_status =~ ^[0-9][0-9][0-9]$ ]] \
      || fail_install "install stage: download returned an invalid HTTP status for $initial_url"
    case $http_status in
      200)
        mv "$partial_download_file" "$destination_file"
        return 0
        ;;
      301|302|303|307|308)
        ((redirect_count < 5)) \
          || fail_install "install stage: download exceeded five redirects for $initial_url"
        redirect_url=$(read_redirect_location "$response_headers_file") \
          || fail_install "install stage: redirect did not contain exactly one Location header"
        current_url=$redirect_url
        redirect_count=$((redirect_count + 1))
        ;;
      *)
        fail_install "install stage: download returned HTTP $http_status for $initial_url"
        ;;
    esac
  done
}

# Parse the publisher's one-line checksum without trusting it to name a path.
parse_checksum_sidecar() {
  local sidecar_file=$1
  local expected_basename=$2
  local sidecar_line=""
  local current_sidecar_line
  local sidecar_line_count=0
  local published_checksum

  # More than one line could let a release select an unintended checksum entry.
  while IFS= read -r current_sidecar_line || [[ -n $current_sidecar_line ]]; do
    sidecar_line_count=$((sidecar_line_count + 1))
    sidecar_line=$current_sidecar_line
  done <"$sidecar_file"
  [[ $sidecar_line_count -eq 1 ]] \
    || fail_install "checksum stage: sidecar must contain exactly one line"
  published_checksum=${sidecar_line:0:64}
  [[ $published_checksum =~ ^[0-9a-f]{64}$ \
    && $sidecar_line == "$published_checksum  $expected_basename" ]] \
    || fail_install "checksum stage: sidecar must contain one lowercase SHA-256 and the expected archive basename"
  EXPECTED_SHA256=$published_checksum
}

# Compare the downloaded archive with the exact checksum shown in its sidecar.
verify_archive_checksum() {
  local expected_checksum=$1
  local archive_file=$2
  local checksum_output
  local actual_checksum

  # Linux and macOS expose different names for the same user-visible check.
  if command -v sha256sum >/dev/null 2>&1; then
    checksum_output=$(sha256sum "$archive_file") \
      || fail_install "checksum stage: unable to hash $ARCHIVE_BASENAME"
  # A macOS action runner normally offers shasum instead of sha256sum.
  elif command -v shasum >/dev/null 2>&1; then
    checksum_output=$(shasum -a 256 "$archive_file") \
      || fail_install "checksum stage: unable to hash $ARCHIVE_BASENAME"
  else
    fail_install "checksum stage: sha256sum or shasum is required"
  fi
  actual_checksum=${checksum_output%% *}
  [[ $actual_checksum == "$expected_checksum" ]] \
    || fail_install "checksum stage: SHA-256 mismatch for $ARCHIVE_BASENAME"
}

# Require the exact files documented for a gruff-rs release archive.
validate_release_member_list() {
  local member_listing_file=$1
  local archive_root=$2
  local binary_name=$3
  local archive_member
  local root_seen=0
  local binary_seen=0
  local readme_seen=0
  local mit_seen=0
  local apache_seen=0
  local changelog_seen=0

  # Every publisher-provided member must match one user-reviewed release file.
  while IFS= read -r archive_member || [[ -n $archive_member ]]; do
    archive_member=${archive_member//\\//}
    [[ $archive_member != "$archive_root" ]] || archive_member=$archive_member/
    case $archive_member in
      "$archive_root/")
        ((root_seen == 0)) || fail_install "archive stage: duplicate archive root member"
        root_seen=1
        ;;
      "$archive_root/$binary_name")
        ((binary_seen == 0)) || fail_install "archive stage: duplicate binary member"
        binary_seen=1
        ;;
      "$archive_root/README.md")
        ((readme_seen == 0)) || fail_install "archive stage: duplicate README member"
        readme_seen=1
        ;;
      "$archive_root/LICENSE-MIT")
        ((mit_seen == 0)) || fail_install "archive stage: duplicate MIT license member"
        mit_seen=1
        ;;
      "$archive_root/LICENSE-APACHE")
        ((apache_seen == 0)) || fail_install "archive stage: duplicate Apache license member"
        apache_seen=1
        ;;
      "$archive_root/CHANGELOG.md")
        ((changelog_seen == 0)) || fail_install "archive stage: duplicate changelog member"
        changelog_seen=1
        ;;
      *)
        fail_install "archive stage: unexpected archive member"
        ;;
    esac
  done <"$member_listing_file"

  [[ $root_seen -eq 1 && $binary_seen -eq 1 \
    && $readme_seen -eq 1 && $mit_seen -eq 1 && $apache_seen -eq 1 \
    && $changelog_seen -eq 1 ]] \
    || fail_install "archive stage: archive member set is incomplete"
}

# Validate Unix archive names and types before extracting the user's binary.
validate_tar_archive() {
  local archive_file=$1
  local archive_root=$2
  local binary_name=$3
  local member_listing_file=$DOWNLOAD_DIR/archive-members
  local member_types_file=$DOWNLOAD_DIR/archive-member-types
  local verbose_member_line
  local directory_count=0
  local file_count=0

  tar -tzf "$archive_file" >"$member_listing_file" \
    || fail_install "archive stage: unable to list $ARCHIVE_BASENAME"
  validate_release_member_list "$member_listing_file" "$archive_root" "$binary_name"
  tar -tvzf "$archive_file" >"$member_types_file" \
    || fail_install "archive stage: unable to inspect $ARCHIVE_BASENAME member types"
  # A link or device could redirect extraction away from the expected binary.
  while IFS= read -r verbose_member_line || [[ -n $verbose_member_line ]]; do
    case ${verbose_member_line:0:1} in
      d) directory_count=$((directory_count + 1)) ;;
      -) file_count=$((file_count + 1)) ;;
      *) fail_install "archive stage: links and special archive members are forbidden" ;;
    esac
  done <"$member_types_file"
  [[ $directory_count -eq 1 && $file_count -eq 5 ]] \
    || fail_install "archive stage: archive member types do not match the release contract"
}

# Validate the Windows release archive before exposing its executable to PATH.
validate_zip_archive() {
  local archive_file=$1
  local archive_root=$2
  local binary_name=$3
  local archive_metadata_file=$DOWNLOAD_DIR/archive-metadata
  local member_listing_file=$DOWNLOAD_DIR/archive-members

  7z l -ba -slt "$archive_file" >"$archive_metadata_file" \
    || fail_install "archive stage: unable to inspect $ARCHIVE_BASENAME"
  sed -n 's/^Path = //p' "$archive_metadata_file" >"$member_listing_file"
  validate_release_member_list "$member_listing_file" "$archive_root" "$binary_name"
  # A user should never receive a binary member that resolves through a link.
  if grep -Eq '^(Symbolic Link|Hard Link) = |^Attributes = .*l[rwx-]{9}' \
    "$archive_metadata_file"; then
    fail_install "archive stage: links in release archives are forbidden"
  fi
}

# Extract only the verified platform binary, never the archive's documentation.
extract_verified_binary() {
  local archive_file=$1
  local archive_root=$2
  local binary_name=$3
  local extracted_binary=$EXTRACT_DIR/$archive_root/$binary_name

  case $ARCHIVE_KIND in
    tar.gz)
      validate_tar_archive "$archive_file" "$archive_root" "$binary_name"
      tar -xzf "$archive_file" -C "$EXTRACT_DIR" "$archive_root/$binary_name" \
        || fail_install "archive stage: unable to extract the expected binary member"
      ;;
    zip)
      validate_zip_archive "$archive_file" "$archive_root" "$binary_name"
      7z x -y -o"$EXTRACT_DIR" "$archive_file" "$archive_root/$binary_name" >/dev/null \
        || fail_install "archive stage: unable to extract the expected binary member"
      ;;
    *)
      fail_install "archive stage: unsupported archive kind: $ARCHIVE_KIND"
      ;;
  esac
  [[ -f $extracted_binary && ! -L $extracted_binary ]] \
    || fail_install "archive stage: extracted binary is not a regular non-link file"
  EXTRACTED_BINARY=$extracted_binary
}

# Install the release selected by action.yml for this workflow runner.
install_release_for_workflow() {
  # Missing action context stays empty so the staged checks can explain it clearly.
  local release_version=${GRUFF_RESOLVED_VERSION:-}
  local runner_os=${RUNNER_OS:-}
  local runner_arch=${RUNNER_ARCH:-}
  local runner_temp_input=${RUNNER_TEMP:-}
  local github_path_input=${GITHUB_PATH:-}
  local runner_temp
  local github_path_file=$github_path_input
  local path_entry
  local archive_root
  local archive_url
  local sidecar_url
  local archive_file
  local sidecar_file
  local verified_binary_directory

  # An empty version means a full-SHA caller forgot the required version input.
  [[ -n $release_version ]] || fail_install "install stage: resolved version is empty"
  version_is_valid "$release_version" \
    || fail_install "install stage: version must be an exact semantic version"
  # Empty runner fields mean this script was not invoked in a supported action.
  [[ -n $runner_os && -n $runner_arch ]] \
    || fail_install "install stage: RUNNER_OS and RUNNER_ARCH are required"
  contains_line_break "$runner_os$runner_arch" \
    && fail_install "install stage: runner metadata must not contain line breaks"
  select_release_target "$runner_os" "$runner_arch"
  # Empty temp storage leaves nowhere private to inspect the release asset.
  [[ -n $runner_temp_input ]] \
    || fail_install "install stage: RUNNER_TEMP is required"
  contains_line_break "$runner_temp_input" \
    && fail_install "install stage: RUNNER_TEMP must not contain line breaks"
  # An empty command-file path means later workflow steps cannot find the tool.
  [[ -n $github_path_input ]] || fail_install "install stage: GITHUB_PATH is required"
  contains_line_break "$github_path_input" \
    && fail_install "install stage: GITHUB_PATH must not contain line breaks"

  require_install_command curl
  require_install_command mktemp
  require_install_command sed
  [[ -f $RELEASE_TARGET_CONTRACT ]] \
    || fail_install "install stage: release target contract is unavailable"
  case $ARCHIVE_KIND in
    tar.gz) require_install_command tar ;;
    zip) require_install_command 7z ;;
  esac

  # Windows action fields need conversion before Bash can safely open them.
  if [[ $runner_os == Windows ]]; then
    require_install_command cygpath
    runner_temp_input=$(cygpath -u "$runner_temp_input") \
      || fail_install "install stage: unable to convert RUNNER_TEMP for bash"
    github_path_file=$(cygpath -u "$github_path_input") \
      || fail_install "install stage: unable to convert GITHUB_PATH for bash"
  fi
  # After Windows conversion, the user's runner temp must be a real directory.
  [[ -d $runner_temp_input ]] \
    || fail_install "install stage: RUNNER_TEMP must name an existing directory"
  runner_temp=$(cd -- "$runner_temp_input" && pwd -P) \
    || fail_install "install stage: unable to canonicalize RUNNER_TEMP"
  umask 077
  INSTALL_ROOT=$(mktemp -d "$runner_temp/gruff-rs-action.XXXXXX") \
    || fail_install "install stage: unable to create a private install directory"
  DOWNLOAD_DIR=$INSTALL_ROOT/download
  EXTRACT_DIR=$INSTALL_ROOT/extract
  verified_binary_directory=$INSTALL_ROOT/bin
  mkdir -p -- "$DOWNLOAD_DIR" "$EXTRACT_DIR" "$verified_binary_directory"
  trap cleanup_private_install EXIT

  archive_root=gruff-rs-$release_version-$TARGET
  ARCHIVE_BASENAME=$archive_root.$ARCHIVE_KIND
  archive_url=$RELEASE_ORIGIN/releases/download/v$release_version/$ARCHIVE_BASENAME
  sidecar_url=$archive_url.sha256
  archive_file=$DOWNLOAD_DIR/$ARCHIVE_BASENAME
  sidecar_file=$archive_file.sha256

  printf 'gruff-rs action: install stage: selecting v%s %s\n' "$release_version" "$TARGET"
  download_release_file "$sidecar_url" "$sidecar_file"
  parse_checksum_sidecar "$sidecar_file" "$ARCHIVE_BASENAME"
  download_release_file "$archive_url" "$archive_file"
  verify_archive_checksum "$EXPECTED_SHA256" "$archive_file"
  printf 'gruff-rs action: checksum stage: verified %s\n' "$ARCHIVE_BASENAME"
  extract_verified_binary "$archive_file" "$archive_root" "$BINARY_NAME"
  cp -- "$EXTRACTED_BINARY" "$verified_binary_directory/$BINARY_NAME"
  chmod 0755 "$verified_binary_directory/$BINARY_NAME"
  [[ -f $verified_binary_directory/$BINARY_NAME \
    && ! -L $verified_binary_directory/$BINARY_NAME ]] \
    || fail_install "install stage: verified binary installation failed"

  path_entry=$verified_binary_directory
  # GitHub's Windows runner reads native paths from its workflow command file.
  if [[ $runner_os == Windows ]]; then
    path_entry=$(cygpath -w "$verified_binary_directory") \
      || fail_install "install stage: unable to convert the verified binary path"
  fi
  printf '%s\n' "$path_entry" >>"$github_path_file" \
    || fail_install "install stage: unable to append the verified binary directory to GITHUB_PATH"
  INSTALL_SUCCEEDED=1
  printf 'gruff-rs action: install stage: installed verified %s\n' "$BINARY_NAME"
}

install_release_for_workflow "$@"
