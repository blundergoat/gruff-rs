#!/usr/bin/env bash

# post-turn-safety-self-test.sh
#
# Proves the Stop-hook exit contract in isolated repositories:
#   - unavailable scanning blocks with exit 2;
#   - an empty Git repository exits 0;
#   - a changed file containing conflict markers blocks with exit 2.
#
# Every case runs twice, once per dispatch path: the Bash 4+ `main` and the
# Bash 3 `fallback_main` reached via GOAT_FLOW_POST_TURN_SAFETY_FORCE_BASH3_FALLBACK.
# Testing only the host's default shell hid a fail-open in the fallback branch.

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
done

printf 'PASS: post-turn safety blocks unavailable scans and hazards while allowing clean repositories on both dispatch paths\n'
