#!/usr/bin/env bash
set -euo pipefail

cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo run --quiet -- list-rules --format json >/tmp/gruff-rs-list-rules.json
cargo run --quiet -- analyse fixtures --format json --fail-on none >/tmp/gruff-rs-fixtures.json
cargo run --quiet -- analyse fixtures --format sarif --fail-on none >/tmp/gruff-rs-fixtures.sarif
cat >/tmp/gruff-rs-fixture.patch <<'PATCH'
diff --git a/fixtures/sample.rs b/fixtures/sample.rs
--- a/fixtures/sample.rs
+++ b/fixtures/sample.rs
@@ -11,1 +11,1 @@
+        std::process::Command::new(command).arg(url).spawn().unwrap();
PATCH
cargo run --quiet -- analyse fixtures/sample.rs --format text --fail-on none --no-baseline >/tmp/gruff-rs-fixture-full.txt
cargo run --quiet -- analyse fixtures/sample.rs --format text --fail-on none --no-baseline --diff-patch /tmp/gruff-rs-fixture.patch >/tmp/gruff-rs-fixture-patch.txt
full_findings="$(grep -c '^- \[' /tmp/gruff-rs-fixture-full.txt || true)"
patch_findings="$(grep -c '^- \[' /tmp/gruff-rs-fixture-patch.txt || true)"
if (( patch_findings >= full_findings )); then
    printf 'patch diff smoke did not reduce findings: full=%s patch=%s\n' "$full_findings" "$patch_findings" >&2
    exit 1
fi
grep -q 'patch-filter' /tmp/gruff-rs-fixture-patch.txt
cargo run --quiet -- analyse src --format json --fail-on none >/tmp/gruff-rs-src.json
