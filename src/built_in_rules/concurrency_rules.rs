//! Concurrency rules inspect parsed Rust function slices without executing code.
//! They report narrow async, channel, and lock-lifetime source shapes while
//! keeping type-dependent conclusions at medium confidence for human review.

use super::*;

pub(crate) fn analyse_concurrency_block(
    file: &SourceFile,
    block: &FunctionBlock,
    searchable_body: &str,
    findings: &mut Vec<Finding>,
) {
    if block.is_async {
        analyse_async_blocking_calls(file, block, searchable_body, findings);
        analyse_lock_across_await(file, block, searchable_body, findings);
    }

    if static_regex(
            &UNBOUNDED_CHANNEL_REGEX,
            r"\b(std::sync::mpsc::channel|mpsc::unbounded_channel|unbounded_channel)(?:\s*::\s*<[^>]+>)?\s*\(",
        )
            .is_match(searchable_body)
        {
            findings.push(block_finding_with_extras(
                BlockFindingDescriptor {
                    rule_id: "concurrency.unbounded-channel",
                    message: format!(
                        "Function `{}` creates an unbounded channel.",
                        block.name
                    ),
                    file,
                    block,
                    severity: Severity::Advisory,
                    pillar: Pillar::Maintainability,
                },
                BlockFindingExtras {
                    confidence: Confidence::Medium,
                    remediation: Some(
                        "Prefer a bounded channel or document the producer/consumer backpressure policy. If the unbounded channel is in a test harness, add the host path to `paths.ignore` in `.gruff-rs.yaml`."
                            .to_string(),
                    ),
                    metadata: json!({ "pattern": "unbounded-channel" }),
                },
            ));
        }
}

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
pub(crate) fn analyse_lock_across_await(
    file: &SourceFile,
    block: &FunctionBlock,
    searchable_body: &str,
    findings: &mut Vec<Finding>,
) {
    let code_only_body = strip_rust_comments_after_string_mask(searchable_body);
    let lines: Vec<&str> = code_only_body.lines().collect();
    // An absent match means every acquisition was non-lock-shaped, dropped, or scoped out.
    if let Some(guard) = find_lock_guard_held_across_await(&lines, &code_only_body) {
        findings.push(lock_across_await_finding(file, block, &guard));
    }
}

/// Returns the first qualifying guard because the rule emits one function finding.
/// The full function slice supplies receiver-linked type or constructor evidence.
fn find_lock_guard_held_across_await(lines: &[&str], function_source: &str) -> Option<String> {
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
        if !rhs_is_lock_guard_binding(rhs.as_str(), function_source) {
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
fn rhs_is_lock_guard_binding(rhs: &str, function_source: &str) -> bool {
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
            && acquisition_has_lock_evidence(method, receiver, function_source)
    })
}

/// Keeps `.lock()` as the explicit lock-named heuristic used by mutex APIs.
/// Read/write methods need receiver-linked evidence because I/O uses the same names.
fn acquisition_has_lock_evidence(method: &str, receiver: &str, function_source: &str) -> bool {
    // A zero-argument method literally named `lock` is the rule's documented heuristic.
    if method == "lock" {
        return true;
    }
    receiver_has_local_lock_evidence(function_source, receiver)
}

/// Finds a receiver type containing `Mutex`/`RwLock` or a local lock constructor.
/// This same-function text check intentionally does not resolve aliases or struct fields.
fn receiver_has_local_lock_evidence(function_source: &str, receiver: &str) -> bool {
    // Neither receiver-specific pattern can match without a lock type token.
    if !function_source.contains("Mutex") && !function_source.contains("RwLock") {
        return false;
    }

    let escaped_receiver = regex::escape(receiver);
    let typed_receiver = Regex::new(&format!(
        r"(?s)\b{escaped_receiver}\s*:\s*[^=;{{}}]*\b(?:Mutex|RwLock)\b"
    ))
    .expect("escaped Rust receiver keeps the typed-lock regex valid");
    let constructed_receiver = Regex::new(&format!(
        r"(?s)\blet\s+(?:mut\s+)?{escaped_receiver}\s*(?::[^=;{{}}]+)?=\s*[^;{{}}]*\b(?:Mutex|RwLock)\s*::\s*new\s*\("
    ))
    .expect("escaped Rust receiver keeps the lock-constructor regex valid");
    typed_receiver.is_match(function_source) || constructed_receiver.is_match(function_source)
}

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

fn strip_expect_suffix(suffix: &str) -> Option<&str> {
    let rest = suffix.strip_prefix(".expect(")?;
    let close = rest.find(')')?;
    Some(&rest[close + 1..])
}

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
