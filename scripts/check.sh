#!/usr/bin/env bash
set -euo pipefail

cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo run --quiet -- list-rules --format json >/tmp/gruff-rs-list-rules.json
cargo run --quiet -- analyse fixtures --format json --fail-on none >/tmp/gruff-rs-fixtures.json
cargo run --quiet -- analyse src --format json --fail-on none >/tmp/gruff-rs-src.json
