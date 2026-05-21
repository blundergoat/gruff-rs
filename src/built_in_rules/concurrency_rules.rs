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
                    pillar: Pillar::Waste,
                },
                BlockFindingExtras {
                    confidence: Confidence::Medium,
                    remediation: Some(
                        "Prefer a bounded channel or document the producer/consumer backpressure policy."
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
                        pillar: Pillar::Waste,
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

pub(crate) fn analyse_lock_across_await(
    file: &SourceFile,
    block: &FunctionBlock,
    searchable_body: &str,
    findings: &mut Vec<Finding>,
) {
    let lines: Vec<&str> = searchable_body.lines().collect();
    if let Some(guard) = find_lock_guard_held_across_await(&lines) {
        findings.push(lock_across_await_finding(file, block, &guard));
    }
}

fn find_lock_guard_held_across_await(lines: &[&str]) -> Option<String> {
    let lock_binding = static_regex(
        &LOCK_BINDING_REGEX,
        r"\blet\s+(?:mut\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*[^;]*\.(?:lock|read|write)\s*\([^;]*;",
    );
    for (line_index, line) in lines.iter().enumerate() {
        let Some(captures) = lock_binding.captures(line) else {
            continue;
        };
        let guard = captures
            .get(1)
            .map(|guard| guard.as_str())
            .unwrap_or("guard");
        let later_lines = &lines[line_index + 1..];
        if is_guard_held_across_await(later_lines, guard) {
            return Some(guard.to_string());
        }
    }
    None
}

fn is_guard_held_across_await(later_lines: &[&str], guard: &str) -> bool {
    let any_await = later_lines
        .iter()
        .any(|candidate| candidate.contains(".await"));
    if !any_await {
        return false;
    }
    let dropped_before_await = later_lines
        .iter()
        .take_while(|candidate| !candidate.contains(".await"))
        .any(|candidate| candidate.contains(&format!("drop({guard})")));
    !dropped_before_await
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
            pillar: Pillar::Waste,
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
