#!/usr/bin/env bash
set -euo pipefail

HOST="${GRUFF_HOST:-127.0.0.1}"
PORT="${GRUFF_PORT:-8766}"
PROJECT_ROOT="${GRUFF_PROJECT_ROOT:-$(pwd)}"

cargo run -- dashboard --host "$HOST" --port "$PORT" --project-root "$PROJECT_ROOT"
