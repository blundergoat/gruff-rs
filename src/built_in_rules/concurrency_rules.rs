//! Concurrency rules inspect parsed Rust function slices without executing code.
//! They report narrow async, channel, and lock-lifetime source shapes while
//! keeping type-dependent conclusions at medium confidence for human review.

use super::*;

/// Runs the async-only concurrency rules on one parsed function.
///
/// `unit` supplies the file and its full source, `block` is the parsed function, and `searchable_body` is its body text the rules search.
/// Blocking-call and lock-across-await findings are appended to `findings`; a `block` that is not async adds nothing.
pub(crate) fn analyse_concurrency_block(
    unit: &SourceUnit<'_>,
    block: &FunctionBlock,
    searchable_body: &str,
    findings: &mut Vec<Finding>,
) {
    let file = unit.file;
    if block.is_async {
        analyse_async_blocking_calls(file, block, searchable_body, findings);
        analyse_lock_across_await(unit, block, searchable_body, findings);
    }
}

/// Reports at most one blocking standard-library path that appears as text in an async function's block text, comments included.
///
/// `searchable_body` is checked by substring for blocking `std` paths in a fixed order, such as `std::thread::sleep` and `std::fs::read`.
/// The caller passes the function's block text with string literals masked and comments kept, so a path written in a comment counts.
///
/// The first path found adds one `concurrency.blocking-call-in-async` warning to `findings`, naming `block` from `file` as async.
/// A longer path such as `std::fs::read_dir` also matches `std::fs::read`, and no call syntax is checked.
pub(crate) fn analyse_async_blocking_calls(
    file: &SourceFile,
    block: &FunctionBlock,
    searchable_body: &str,
    findings: &mut Vec<Finding>,
) {
    let blocking_patterns = [
        ("std::thread::sleep", "std::thread::sleep"),
        ("std::fs::read_to_string", "std::fs::read_to_string"),
        ("std::fs::read", "std::fs::read"),
        ("std::fs::write", "std::fs::write"),
        ("std::process::Command::new", "std::process::Command::new"),
    ];
    for (pattern, label) in blocking_patterns {
        if searchable_body.contains(pattern) {
            findings.push(block_finding_with_extras(
                    BlockFindingDescriptor {
                        rule_id: "concurrency.blocking-call-in-async",
                        message: format!(
                            "Async function `{}` calls blocking API `{label}`.",
                            block.name
                        ),
                        file,
                        block,
                        severity: Severity::Warning,
                        pillar: Pillar::Maintainability,
                    },
                    BlockFindingExtras {
                        confidence: Confidence::Medium,
                        remediation: Some(
                            "Use an async equivalent or move blocking work behind a dedicated blocking task."
                                .to_string(),
                        ),
                        metadata: json!({ "pattern": label }),
                    },
                ));
            break;
        }
    }
}

/// Reports a guard binding that remains lexically live when a later await begins.
/// Source comments and strings are masked before acquisition evidence is inspected.
///
/// `searchable_body` is the function text scanned line by line, and `unit` also supplies the whole file for struct-field lock evidence.
/// At most one `concurrency.lock-across-await` finding naming `block` is appended to `findings`.
pub(crate) fn analyse_lock_across_await(
    unit: &SourceUnit<'_>,
    block: &FunctionBlock,
    searchable_body: &str,
    findings: &mut Vec<Finding>,
) {
    let code_only_body = strip_rust_comments_after_string_mask(searchable_body);
    let lines: Vec<&str> = code_only_body.lines().collect();
    let sources = LockEvidenceSources {
        function_source: &code_only_body,
        file_source: unit.source,
        masked_file: OnceLock::new(),
    };
    // An absent match means every acquisition was non-lock-shaped, dropped, or scoped out.
    if let Some(guard) = find_lock_guard_held_across_await(&lines, &sources) {
        findings.push(lock_across_await_finding(unit.file, block, &guard));
    }
}

/// Source views that can tie a receiver to a lock type. The function body is checked first;
/// the whole file supplies the declaration for a guard reached through a struct field, which
/// is where async services usually keep shared state.
struct LockEvidenceSources<'a> {
    function_source: &'a str,
    file_source: &'a str,
    masked_file: OnceLock<String>,
}

impl LockEvidenceSources<'_> {
    /// Whether the file mentions a lock type at all. Masking only removes text, so a raw
    /// source without either token cannot produce a masked one that has them; checking here
    /// keeps every lock-free file out of the masking path entirely.
    fn file_has_lock_type(&self) -> bool {
        self.file_source.contains("Mutex") || self.file_source.contains("RwLock")
    }

    /// Mask strings and comments once, and only when a function-scoped lookup came up empty,
    /// so an ordinary async function never pays to scan its whole file.
    ///
    /// Returns the file source with string literals and comments masked, computed on the first call and cached afterwards.
    fn masked_file(&self) -> &str {
        self.masked_file.get_or_init(|| {
            strip_rust_comments_after_string_mask(&strip_rust_string_literals(self.file_source))
        })
    }
}

/// Returns the first qualifying guard because the rule emits one function finding.
/// The full function slice supplies receiver-linked type or constructor evidence.
///
/// `lines` are the comment-stripped function lines checked for `let` guard bindings, and `sources` supplies lock evidence.
/// A binding qualifies when `is_guard_held_across_await` accepts the lines after it; None means no binding qualified.
fn find_lock_guard_held_across_await(
    lines: &[&str],
    sources: &LockEvidenceSources<'_>,
) -> Option<String> {
    let lock_binding = static_regex(
        &LOCK_BINDING_REGEX,
        r"\blet\s+(?:mut\s+)?(?P<guard>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<rhs>[^;]*);",
    );
    let mut depth = 0usize;
    // Walk bindings in source order so the reported guard is deterministic.
    for (line_index, line) in lines.iter().enumerate() {
        let depth_before_line = depth;
        depth = brace_depth_after_line(depth, line);
        // Ordinary source lines do not begin a candidate guard lifetime.
        let Some(captures) = lock_binding.captures(line) else {
            continue;
        };
        let guard = captures
            .name("guard")
            .expect("lock-binding regex always captures the guard")
            .as_str();
        // A malformed capture cannot describe the assigned acquisition expression.
        let Some(rhs) = captures.name("rhs") else {
            continue;
        };
        // I/O calls, domain methods, and value-extraction chains are not guard bindings.
        if !rhs_is_lock_guard_binding(rhs.as_str(), sources) {
            continue;
        }
        let later_lines = &lines[line_index + 1..];
        // A guard only matters when no drop or scope exit precedes the next await.
        if is_guard_held_across_await(later_lines, guard, depth_before_line, depth) {
            return Some(guard.to_string());
        }
    }
    None
}

/// Classifies a bound RHS as a zero-argument, guard-preserving lock acquisition.
/// Ambiguous read/write methods additionally need evidence tied to their receiver.
///
/// `rhs` is the text after `=` in a `let` binding, and `sources` supplies receiver evidence for `read` and `write` calls.
/// Returns true when a zero-argument `lock`, `read` or `write` call on an identifier has a guard-preserving tail and lock evidence.
fn rhs_is_lock_guard_binding(rhs: &str, sources: &LockEvidenceSources<'_>) -> bool {
    static LOCK_CALL_REGEX: OnceLock<Regex> = OnceLock::new();
    let lock_call = static_regex(
        &LOCK_CALL_REGEX,
        r"\b(?P<receiver>[A-Za-z_][A-Za-z0-9_]*)\s*\.\s*(?P<method>lock|read|write)\s*\(\s*\)",
    );
    // A chained RHS may contain more than one named call; accept only a call whose tail
    // preserves the returned guard and whose receiver supplies the required lock signal.
    lock_call.captures_iter(rhs).any(|captures| {
        let found = captures
            .get(0)
            .expect("lock-call regex always captures the complete call");
        let receiver = captures
            .name("receiver")
            .expect("lock-call regex always captures the receiver")
            .as_str();
        let method = captures
            .name("method")
            .expect("lock-call regex always captures the method")
            .as_str();
        lock_suffix_is_guard_preserving(&rhs[found.end()..])
            && acquisition_has_lock_evidence(method, receiver, sources)
    })
}

/// Keeps `.lock()` as the explicit lock-named heuristic used by mutex APIs.
/// Read/write methods need receiver-linked evidence because I/O uses the same names.
///
/// `method` is the called method, `receiver` the identifier it was called on, and `sources` the text searched for evidence.
/// Returns true for `lock`, or when `receiver` has a `Mutex` or `RwLock` type or constructor in the function text or the masked file.
fn acquisition_has_lock_evidence(
    method: &str,
    receiver: &str,
    sources: &LockEvidenceSources<'_>,
) -> bool {
    // A zero-argument method literally named `lock` is the rule's documented heuristic.
    if method == "lock" {
        return true;
    }
    // A guard bound beside its lock carries its own evidence. A guard taken from `self.state`
    // is declared as a struct field elsewhere in the file, so that declaration is the evidence.
    receiver_has_local_lock_evidence(sources.function_source, receiver)
        || (sources.file_has_lock_type()
            && receiver_has_local_lock_evidence(sources.masked_file(), receiver))
}

/// Finds a receiver type containing `Mutex`/`RwLock` or a local lock constructor.
/// This text check does not resolve type aliases; run over the masked file, it also matches a struct field declared with a lock type.
///
/// `function_source` is the text searched, the function body or the masked whole file, and `receiver` is the identifier to match.
/// Returns true when `receiver` is typed with `Mutex` or `RwLock`, or bound by `let` to a `Mutex::new` or `RwLock::new` call, else false.
fn receiver_has_local_lock_evidence(function_source: &str, receiver: &str) -> bool {
    // Neither receiver-specific pattern can match without a lock type token.
    if !function_source.contains("Mutex") && !function_source.contains("RwLock") {
        return false;
    }

    // Both patterns capture the bound name instead of interpolating the receiver, so they compile
    // once for the process rather than twice per candidate binding. Comparing the captured name is
    // equivalent to the previous word-bounded interpolation: a longer identifier ending in the
    // receiver text captures its own full name and fails the equality check.
    static TYPED_LOCK_RECEIVER_REGEX: OnceLock<Regex> = OnceLock::new();
    static CONSTRUCTED_LOCK_RECEIVER_REGEX: OnceLock<Regex> = OnceLock::new();
    let typed_receiver = static_regex(
        &TYPED_LOCK_RECEIVER_REGEX,
        r"(?s)\b([A-Za-z_][A-Za-z0-9_]*)\s*:\s*[^=;{}]*\b(?:Mutex|RwLock)\b",
    );
    let constructed_receiver = static_regex(
        &CONSTRUCTED_LOCK_RECEIVER_REGEX,
        r"(?s)\blet\s+(?:mut\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*(?::[^=;{}]+)?=\s*[^;{}]*\b(?:Mutex|RwLock)\s*::\s*new\s*\(",
    );
    let names_receiver = |captures: regex::Captures<'_>| {
        captures
            .get(1)
            .is_some_and(|bound_name| bound_name.as_str() == receiver)
    };
    typed_receiver
        .captures_iter(function_source)
        .any(names_receiver)
        || constructed_receiver
            .captures_iter(function_source)
            .any(names_receiver)
}

/// Checks that the text after a lock call only awaits or unwraps the guard instead of chaining another call on it.
///
/// Returns true when `suffix` is empty or made only of `.await`, `.unwrap()`, `?` and `.expect(` steps, in any order and number.
/// An `.expect(` step ends at its first `)`, so an argument with its own parentheses makes the result false.
fn lock_suffix_is_guard_preserving(mut suffix: &str) -> bool {
    loop {
        suffix = suffix.trim_start();
        if suffix.is_empty() {
            return true;
        }
        if let Some(rest) = suffix.strip_prefix(".await") {
            suffix = rest;
            continue;
        }
        if let Some(rest) = suffix.strip_prefix(".unwrap()") {
            suffix = rest;
            continue;
        }
        if let Some(rest) = strip_expect_suffix(suffix) {
            suffix = rest;
            continue;
        }
        if let Some(rest) = suffix.strip_prefix('?') {
            suffix = rest;
            continue;
        }
        return false;
    }
}

/// Removes one leading `.expect(...)` call from the text that follows a lock acquisition.
///
/// Returns the text after the first `)` past `.expect(`, or None when `suffix` lacks that prefix or a closing parenthesis.
fn strip_expect_suffix(suffix: &str) -> Option<&str> {
    let rest = suffix.strip_prefix(".expect(")?;
    let close = rest.find(')')?;
    Some(&rest[close + 1..])
}

/// Applies a line-based heuristic to decide whether a lock guard is still held when a later line awaits.
///
/// `later_lines` are the function lines after the binding of `guard`, the bound name searched for in a `drop` call.
/// `scope_depth` is the brace depth before the binding line and `depth` the depth after it, updated after each line without an await.
///
/// Returns true at the first line containing `.await` if the depth carried into that line is at least `scope_depth`.
/// Braces on the await line itself are not counted, so a `}` before the await on that line does not end the scope.
///
/// A line holding the exact whitespace-free text of a `drop` call on `guard` gives false first, even on the await line.
/// An earlier line that takes the depth below `scope_depth`, or running out of lines without an await, also gives false.
fn is_guard_held_across_await(
    later_lines: &[&str],
    guard: &str,
    scope_depth: usize,
    mut depth: usize,
) -> bool {
    let drop_call = format!("drop({guard})");
    for line in later_lines {
        if line.contains(&drop_call) {
            return false;
        }
        if line.contains(".await") {
            return depth >= scope_depth;
        }
        depth = brace_depth_after_line(depth, line);
        if depth < scope_depth {
            return false;
        }
    }
    false
}

/// Tracks lexical nesting by counting the braces on one source line.
///
/// `depth` is the nesting before `line`; each `{` adds one and each `}` removes one, never going below zero.
/// Returns the depth after every brace character in `line` is counted.
fn brace_depth_after_line(mut depth: usize, line: &str) -> usize {
    for character in line.chars() {
        match character {
            '{' => depth += 1,
            '}' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    depth
}

/// Builds the finding for an async function that holds a lock guard across an await.
///
/// `file` and `block` locate the function, and `guard` is the binding name placed in the message and metadata.
/// Returns a medium-confidence `concurrency.lock-across-await` warning advising to drop the guard or use an async-aware lock.
fn lock_across_await_finding(file: &SourceFile, block: &FunctionBlock, guard: &str) -> Finding {
    block_finding_with_extras(
        BlockFindingDescriptor {
            rule_id: "concurrency.lock-across-await",
            message: format!(
                "Async function `{}` appears to hold lock guard `{guard}` across await.",
                block.name
            ),
            file,
            block,
            severity: Severity::Warning,
            pillar: Pillar::Maintainability,
        },
        BlockFindingExtras {
            confidence: Confidence::Medium,
            remediation: Some(
                "Drop the guard before awaiting or use an async-aware lock.".to_string(),
            ),
            metadata: json!({ "guard": guard }),
        },
    )
}
