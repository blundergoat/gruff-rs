#!/usr/bin/env bash

# post-turn-safety-self-test.sh
#
# Proves the Stop-hook exit contract in isolated repositories:
#   - unavailable scanning blocks with exit 2;
#   - an empty Git repository exits 0;
#   - a changed file containing conflict markers blocks with exit 2;
#   - a tracked modification whose added source line starts with "++" blocks, including the "++ " form that renders
#     exactly like a "+++ path" header;
#   - a line-scoped allow marker passes while the same token without one blocks;
#   - untracked text above the byte cap is reported as unread rather than passing as clean;
#   - an oversized blob that exists only in the index is still scanned, so a credential staged and then shrunk or
#     deleted in the worktree cannot slip through;
#   - a binary changed path is reported as unread, because it carries no text hunks for the detectors.
#
# Every case runs twice, once per dispatch path: the Bash 4+ `main` and the Bash 3 `fallback_main` reached via
# GOAT_FLOW_POST_TURN_SAFETY_FORCE_BASH3_FALLBACK. Testing only the host's default shell hid a fail-open in the fallback
# branch.
#
# The "++" cases need a committed baseline. An untracked file takes the whole-file scan path, which never sees a diff
# stream, so only a tracked modification exercises the header-versus-content decision being tested.
#
# Hazard tokens are composed from parts at run time. A literal AWS key in this file would make the Stop hook flag the
# self-test itself whenever it changes.

set -euo pipefail

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
HOOK="${GOAT_POST_TURN_SAFETY_HOOK:-$SCRIPT_DIR/../post-turn-safety.sh}"
WORK_DIR=""
HOOK_OUTPUT=""
HOOK_STATUS=0

cleanup_post_turn_safety_test() {
  if [[ -n "$WORK_DIR" && -d "$WORK_DIR" ]]; then
    find "$WORK_DIR" -depth -delete
  fi
}

fail_post_turn_safety_test() {
  printf 'FAIL: post-turn safety %s\n' "$*" >&2
  exit 1
}

run_hook_in() {
  local repository=$1
  local force_fallback=$2
  local max_bytes=${3:-}
  local -a hook_environment=("GOAT_FLOW_POST_TURN_SAFETY_FORCE_BASH3_FALLBACK=$force_fallback")

  # Byte-cap cases pass a small cap so their fixtures stay a few kilobytes. Padding past the 1 MiB default would make
  # this self-test slow for no extra coverage: the gate compares sizes, it does not care how large the file is.
  if [[ -n $max_bytes ]]; then
    hook_environment+=("GOAT_FLOW_POST_TURN_SAFETY_MAX_BYTES=$max_bytes")
  fi

  set +e
  HOOK_OUTPUT="$(cd "$repository" && env "${hook_environment[@]}" bash "$HOOK" 2>&1)"
  HOOK_STATUS=$?
  set -e
}

expect_hook_status() {
  local expected_status=$1
  local label=$2

  if [[ $HOOK_STATUS -ne $expected_status ]]; then
    fail_post_turn_safety_test "$label expected exit $expected_status, got $HOOK_STATUS: $HOOK_OUTPUT"
  fi
}

# Split so this file never contains a string matching the AWS access-key regex.
HAZARD_TOKEN="AKIA""1111111111111111"

# Byte cap handed to the byte-cap cases. Small on purpose; see the note in run_hook_in.
OVERSIZE_CAP_BYTES=512

# Commits a baseline so the repository has the committed HEAD that tracked and staged diffs need.
commit_self_test_baseline() {
  local repository=$1

  printf 'baseline\n' >"$repository/seed.txt"
  git -C "$repository" add seed.txt
  git -C "$repository" \
    -c user.email=self-test@goat-flow.invalid \
    -c user.name='goat-flow self-test' \
    -c commit.gpgsign=false \
    commit -q -m 'baseline'
}

# Writes a text file well past OVERSIZE_CAP_BYTES that also carries a hazard token, so a gate that silently skipped it
# would be hiding a real credential rather than merely skipping bulk. Padding is plain text so the binary gate cannot
# reclassify the file and change which branch the case exercises.
write_oversized_text_file() {
  local path=$1

  printf 'let api_key = "%s";\n' "$HAZARD_TOKEN" >"$path"
  head -c "$((OVERSIZE_CAP_BYTES * 4))" /dev/zero | tr '\0' 'x' >>"$path"
  printf '\n' >>"$path"
}

# Creates a repository whose index holds an oversized blob while the worktree copy is small or absent. Before goat-flow
# 1.15.1 this shape ended the turn with exit 0 on the Bash 4+ path: the whole-file gate never saw index-only content.
init_staged_oversized_repo() {
  local repository=$1
  local worktree_state=$2

  mkdir -p "$repository"
  git -C "$repository" init -q
  commit_self_test_baseline "$repository"
  write_oversized_text_file "$repository/staged.txt"
  git -C "$repository" add staged.txt
  # Shrinking or deleting the worktree copy leaves the credential reachable only through the index.
  case $worktree_state in
    shrunk) printf 'small\n' >"$repository/staged.txt" ;;
    deleted) rm -f "$repository/staged.txt" ;;
    *) fail_post_turn_safety_test "unknown worktree state: $worktree_state" ;;
  esac
}

# Creates a repository whose only staged change is binary, which has no added text hunks for the detectors to read.
init_binary_change_repo() {
  local repository=$1

  mkdir -p "$repository"
  git -C "$repository" init -q
  commit_self_test_baseline "$repository"
  printf '\000\001\002\003payload\000\007' >"$repository/asset.bin"
  git -C "$repository" add asset.bin
}

# Creates a repository whose only change is one added line in a tracked file, so the hook must reach it through a diff
# stream rather than a whole-file scan.
init_tracked_change_repo() {
  local repository=$1
  local added_line=$2

  mkdir -p "$repository"
  git -C "$repository" init -q
  printf 'baseline\n' >"$repository/changed.txt"
  git -C "$repository" add changed.txt
  git -C "$repository" \
    -c user.email=self-test@goat-flow.invalid \
    -c user.name='goat-flow self-test' \
    -c commit.gpgsign=false \
    commit -q -m 'baseline'
  printf 'baseline\n%s\n' "$added_line" >"$repository/changed.txt"
}

[[ -f "$HOOK" ]] || fail_post_turn_safety_test "hook not found: $HOOK"

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/gruff-rs-post-turn-safety.XXXXXX")"
trap cleanup_post_turn_safety_test EXIT

mkdir -p "$WORK_DIR/no-git"

mkdir -p "$WORK_DIR/clean"
git -C "$WORK_DIR/clean" init -q

mkdir -p "$WORK_DIR/hazard"
git -C "$WORK_DIR/hazard" init -q
{
  printf '%s\n' '<<<<<<< HEAD'
  printf '%s\n' 'local content'
  printf '%s\n' '======='
  printf '%s\n' 'incoming content'
  printf '%s\n' '>>>>>>> branch'
} >"$WORK_DIR/hazard/conflict.txt"

# A source line starting with "++" renders as "+++..." in a --unified=0 stream.
init_tracked_change_repo "$WORK_DIR/plusplus" "++$HAZARD_TOKEN"

# A source line starting with "++ " renders as "+++ ..." - byte-identical in shape to a real "+++ b/path" destination
# header. Only position after a `diff --git` section start distinguishes them.
init_tracked_change_repo "$WORK_DIR/plusplus-space" "++ $HAZARD_TOKEN"

# The repository's own calibration fixture carries a secret-looking token on purpose. A line-scoped marker must pass it,
# while the identical token without a marker must still block, so the exception cannot widen to a whole directory.
init_tracked_change_repo "$WORK_DIR/fixture-marked" \
  "        let api_key = \"$HAZARD_TOKEN\"; // goat-flow-allow-secret"
init_tracked_change_repo "$WORK_DIR/fixture-bare" \
  "        let api_key = \"$HAZARD_TOKEN\";"

# Untracked text above the cap takes the whole-file gate, which must record it as unread. Reporting it as scanned is
# how a padded credential file once ended the turn clean.
mkdir -p "$WORK_DIR/oversized-untracked"
git -C "$WORK_DIR/oversized-untracked" init -q
write_oversized_text_file "$WORK_DIR/oversized-untracked/big.txt"

# Index-only oversized content, with the worktree copy shrunk and removed. Both must still reach the credential.
init_staged_oversized_repo "$WORK_DIR/staged-oversized-shrunk" shrunk
init_staged_oversized_repo "$WORK_DIR/staged-oversized-deleted" deleted

# A binary changed path has no text hunks, so it is unread by definition and must say so.
init_binary_change_repo "$WORK_DIR/binary-change"

for dispatch in default bash3-fallback; do
  if [[ $dispatch == bash3-fallback ]]; then
    force_fallback=1
  else
    force_fallback=0
  fi

  run_hook_in "$WORK_DIR/no-git" "$force_fallback"
  expect_hook_status 2 "unavailable scan [$dispatch]"
  # Releases word this differently ("git repository root unavailable; cannot scan changed content" through 1.15.0,
  # "scan incomplete (git repository root unavailable)" from 1.15.1), so assert the reason the user is shown rather
  # than one release's phrasing. Blocking itself is already pinned by the exit status above.
  [[ $HOOK_OUTPUT == *"git repository root unavailable"* ]] \
    || fail_post_turn_safety_test "unavailable scan [$dispatch] did not explain the missing Git root"

  run_hook_in "$WORK_DIR/clean" "$force_fallback"
  expect_hook_status 0 "clean repository [$dispatch]"

  run_hook_in "$WORK_DIR/hazard" "$force_fallback"
  expect_hook_status 2 "merge conflict [$dispatch]"
  # The paths word this differently ("blocked merge conflict marker in X" versus
  # "merge conflict marker in X (Bash 3 compatibility scan)"), so assert the
  # finding family and the offending file, which both must name. Blocking itself
  # is already pinned by the exit status above.
  [[ $HOOK_OUTPUT == *"merge conflict marker in conflict.txt"* ]] \
    || fail_post_turn_safety_test "merge conflict [$dispatch] did not report its finding family"

  run_hook_in "$WORK_DIR/plusplus" "$force_fallback"
  expect_hook_status 2 "++ prefixed added line [$dispatch]"
  [[ $HOOK_OUTPUT == *"AWS access key in changed.txt"* ]] \
    || fail_post_turn_safety_test "++ prefixed added line [$dispatch] did not report its finding family"

  run_hook_in "$WORK_DIR/plusplus-space" "$force_fallback"
  expect_hook_status 2 "header-shaped added line [$dispatch]"
  [[ $HOOK_OUTPUT == *"AWS access key in changed.txt"* ]] \
    || fail_post_turn_safety_test "header-shaped added line [$dispatch] did not report its finding family"

  run_hook_in "$WORK_DIR/fixture-marked" "$force_fallback"
  expect_hook_status 0 "line-scoped allow marker [$dispatch]"

  run_hook_in "$WORK_DIR/fixture-bare" "$force_fallback"
  expect_hook_status 2 "unmarked intentional token [$dispatch]"

  run_hook_in "$WORK_DIR/oversized-untracked" "$force_fallback" "$OVERSIZE_CAP_BYTES"
  expect_hook_status 2 "oversized untracked text [$dispatch]"
  # Assert the reason, not just the status. Oversized and binary both exit 2, so a status-only test would pass straight
  # through a change that reclassified one as the other.
  [[ $HOOK_OUTPUT == *"oversized untracked text not scanned in big.txt"* ]] \
    || fail_post_turn_safety_test "oversized untracked text [$dispatch] did not report unread coverage"

  # Staged blobs are streamed as added hunks with no whole-file cap, so the credential must be found outright rather
  # than merely counted as unread. The paths word findings differently, so assert the family and the file.
  run_hook_in "$WORK_DIR/staged-oversized-shrunk" "$force_fallback" "$OVERSIZE_CAP_BYTES"
  expect_hook_status 2 "staged oversized with shrunk worktree copy [$dispatch]"
  [[ $HOOK_OUTPUT == *"AWS access key in staged.txt"* ]] \
    || fail_post_turn_safety_test "staged oversized with shrunk worktree copy [$dispatch] did not reach the credential"

  run_hook_in "$WORK_DIR/staged-oversized-deleted" "$force_fallback" "$OVERSIZE_CAP_BYTES"
  expect_hook_status 2 "staged oversized with deleted worktree copy [$dispatch]"
  [[ $HOOK_OUTPUT == *"AWS access key in staged.txt"* ]] \
    || fail_post_turn_safety_test "staged oversized with deleted worktree copy [$dispatch] did not reach the credential"

  run_hook_in "$WORK_DIR/binary-change" "$force_fallback"
  expect_hook_status 2 "binary changed path [$dispatch]"
  [[ $HOOK_OUTPUT == *"binary changed path not scanned in asset.bin"* ]] \
    || fail_post_turn_safety_test "binary changed path [$dispatch] did not report unread coverage"
done

printf 'PASS: post-turn safety blocks unavailable scans, every reachable added-line prefix, hazards, oversized and binary unread content, and index-only credentials, while allowing clean repositories and line-scoped allow markers on both dispatch paths\n'
