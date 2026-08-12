# Local hook deltas

Security fixes this repository carries on top of the managed goat-flow hook templates. They are
checked in because `goat-flow install` and `goat-flow hooks sync` restore managed hooks from the
template, and each upgrade has silently reverted them at least once.

**Taken against goat-flow 1.15.1.** Regenerate after any goat-flow upgrade:

```bash
TPL="$(npm root -g)/@blundergoat/goat-flow/workflow/hooks"
for f in post-turn-safety.sh run-with-bash.mjs deny-dangerous.sh; do
  diff -u "$TPL/$f" ".goat-flow/hooks/$f" > ".goat-flow/hooks/local-deltas/$f.patch"
done
```

`scripts/preflight-checks.sh` (search: `managed hook deltas`) fails when any delta below is missing
from the installed hook. It greps for a semantic anchor rather than comparing bytes, so an upstream
reflow does not trip it and upstream *adopting* a fix keeps it passing.

## Why byte-identity is not the goal

`goat-flow audit . --harness --check-drift` will keep reporting these two files as drifted, and that
is expected. ADR-022 makes the line-scoped allow marker a permanent local addition with no upstream
equivalent, so the installed copy can never equal the template while that decision stands. A
previous attempt reached byte-identity by patching the template inside the global `node_modules`
install; that path is unversioned, unshared with CI and teammates, and was erased by the next minor
release. The delta check below is what actually protects the fixes.

## The deltas

### `post-turn-safety.sh` — 22 lines, two fixes

| Anchor | What it does | What breaks without it |
| --- | --- | --- |
| `is_line_allowlisted` | Honours a line-scoped `goat-flow-allow-secret` marker on both scan paths | Every turn touching `fixtures/sample.rs` blocks on a calibration token the repository is required to keep. See ADR-022. |
| the `"@@ "*` case in the diff walk | Skips only a real hunk header, not any line starting with `+++` | An added source line beginning with `++` renders as `+++…` under `--unified=0` and is dropped, so a credential on it ends the turn with exit 0. Pinned by the `plusplus` and `plusplus-space` self-test cases. |

### `run-with-bash.mjs` — 25 lines, one fix

| Anchor | What it does | What breaks without it |
| --- | --- | --- |
| `symlinkFreePath` | Resolves both sides of the launcher's self-identity comparison before comparing | A symlinked project directory reaching the launcher through the `CLAUDE_PROJECT_DIR` fallback makes it load, run no hook, and exit 0 — which every supported host reads as "guard passed". |

### `deny-dangerous.sh` — 10 lines, two fixes

| Anchor | What it does | What breaks without it |
| --- | --- | --- |
| `watch --any-unknown-flag` | An option `strip_watch_payload_command` does not recognise is skipped rather than aborting normalisation | `watch --any-unknown-flag rm -rf /` reaches the policy modules as a `watch` invocation, matches nothing, and is allowed. Pinned by the `watch unknown long option` and `watch unknown short option` self-test cases. |
| `parallel --any-unknown-flag` | Same repair in `strip_parallel_payload_command` | `parallel --any-unknown-flag rm -rf /` is allowed for the same reason. `strip_xargs_payload_command` already skipped unknown options, so this restores agreement between the three wrapper parsers. Pinned by the two `parallel unknown … option` self-test cases. |

Both fixes belong upstream; send them there and drop this delta once a release carries them.

## Files upstream owns outright

The `patterns-*.sh` modules, `deny-dangerous-self-test.sh` (apart from the four wrapper cases noted
above), `gruff-code-quality.sh`, `hook-launch-runtime.mjs`, and `hook-provider-adapters.mjs` are
byte-identical to the 1.15.1 templates. Do not patch them here; send fixes upstream.
