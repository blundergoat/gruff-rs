#!/usr/bin/env bash

# post-turn-safety-self-test.sh
#
# Proves the Stop-hook exit contract in isolated repositories:
#   - unavailable scanning blocks with exit 2;
#   - an empty Git repository exits 0;
#   - a changed file containing conflict markers blocks with exit 2;
#   - a tracked modification whose added source line starts with "++" blocks, including the "++ " form that renders
#     exactly like a "+++ path" header;
#   - a line-scoped allow marker passes while the same token without one blocks.
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

  set +e
  HOOK_OUTPUT="$(cd "$repository" \
    && GOAT_FLOW_POST_TURN_SAFETY_FORCE_BASH3_FALLBACK="$force_fallback" bash "$HOOK" 2>&1)"
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

for dispatch in default bash3-fallback; do
  if [[ $dispatch == bash3-fallback ]]; then
    force_fallback=1
  else
    force_fallback=0
  fi

  run_hook_in "$WORK_DIR/no-git" "$force_fallback"
  expect_hook_status 2 "unavailable scan [$dispatch]"
  [[ $HOOK_OUTPUT == *"git repository root unavailable; cannot scan changed content"* ]] \
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
done

printf 'PASS: post-turn safety blocks unavailable scans, every reachable added-line prefix, and hazards, while allowing clean repositories and line-scoped allow markers on both dispatch paths\n'
