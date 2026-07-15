#!/usr/bin/env bash

# post-turn-safety-self-test.sh
#
# Proves the Stop-hook exit contract in isolated repositories:
#   - unavailable scanning blocks with exit 2;
#   - an empty Git repository exits 0;
#   - a changed file containing conflict markers blocks with exit 2.

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

  set +e
  HOOK_OUTPUT="$(cd "$repository" && bash "$HOOK" 2>&1)"
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
run_hook_in "$WORK_DIR/no-git"
expect_hook_status 2 "unavailable scan"
[[ $HOOK_OUTPUT == *"git repository root unavailable; cannot scan changed content"* ]] \
  || fail_post_turn_safety_test "unavailable scan did not explain the missing Git root"

mkdir -p "$WORK_DIR/clean"
git -C "$WORK_DIR/clean" init -q
run_hook_in "$WORK_DIR/clean"
expect_hook_status 0 "clean repository"

mkdir -p "$WORK_DIR/hazard"
git -C "$WORK_DIR/hazard" init -q
{
  printf '%s\n' '<<<<<<< HEAD'
  printf '%s\n' 'local content'
  printf '%s\n' '======='
  printf '%s\n' 'incoming content'
  printf '%s\n' '>>>>>>> branch'
} >"$WORK_DIR/hazard/conflict.txt"
run_hook_in "$WORK_DIR/hazard"
expect_hook_status 2 "merge conflict"
[[ $HOOK_OUTPUT == *"blocked merge conflict marker"* ]] \
  || fail_post_turn_safety_test "merge conflict did not report its finding family"

printf 'PASS: post-turn safety blocks unavailable scans and hazards while allowing clean repositories\n'
