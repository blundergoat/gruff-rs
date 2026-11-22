# Analyzer Fixtures

Files in this directory are intentionally noisy analyzer inputs. They are not examples of recommended Rust code.

`sample.rs` preserves the original v0.1 identity contract for existing rule ids and fingerprints. `rubric.rs` exercises the expanded complexity, naming, size, documentation, and design rubric in the normal fixture scan.

Run fixture coverage explicitly, without the project config:

```bash
./bin/gruff-rs analyse fixtures --no-config --format json --fail-on none
```

`.gruff-rs.yaml` ignores `fixtures/**` so the project's own dogfood scan skips these files, and config ignores apply to explicit paths too (ADR-018). Without `--no-config` the scan analyses zero files and still exits 0.

Do not clean up fixture findings as if they were product debt. If a rule is
renamed, reworded, or recalibrated, update the fixture and the corresponding
contract tests in the same change so the v0.1 report identity story stays
intentional.
