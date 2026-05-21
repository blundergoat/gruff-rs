use super::*;

pub(crate) fn analyse_performance_block(
    file: &SourceFile,
    block: &FunctionBlock,
    searchable_body: &str,
    findings: &mut Vec<Finding>,
) {
    for check in PERFORMANCE_CHECKS {
        let occurrences =
            loop_pattern_count(searchable_body, static_regex(check.regex, check.pattern));
        if occurrences > 0 {
            push_performance_finding(file, block, check, occurrences, findings);
        }
    }
}

pub(crate) fn push_performance_finding(
    file: &SourceFile,
    block: &FunctionBlock,
    check: &PerformanceCheck,
    occurrences: usize,
    findings: &mut Vec<Finding>,
) {
    findings.push(block_finding_with_extras(
        BlockFindingDescriptor {
            rule_id: check.rule_id,
            message: format!(
                "Function `{}` calls {} inside a loop {} time(s).",
                block.name, check.label, occurrences
            ),
            file,
            block,
            severity: check.severity,
            pillar: Pillar::Waste,
        },
        BlockFindingExtras {
            confidence: check.confidence,
            remediation: Some(check.remediation.to_string()),
            metadata: json!({ "pattern": check.label, "occurrences": occurrences }),
        },
    ));
}

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
        if guard_outlives_await(later_lines, guard) {
            return Some(guard.to_string());
        }
    }
    None
}

fn guard_outlives_await(later_lines: &[&str], guard: &str) -> bool {
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

pub(crate) fn analyse_test_block(
    file: &SourceFile,
    block: &FunctionBlock,
    config: &Config,
    findings: &mut Vec<Finding>,
) {
    analyse_ignored_test(file, block, findings);
    analyse_test_size(file, block, config, findings);
    let searchable_body = strip_rust_string_literals(&block.body);
    analyse_test_assertions(file, block, &searchable_body, findings);
    analyse_test_regex_checks(file, block, &searchable_body, findings);
}

pub(crate) fn analyse_ignored_test(
    file: &SourceFile,
    block: &FunctionBlock,
    findings: &mut Vec<Finding>,
) {
    if block.ignore_without_reason {
        findings.push(block_finding(BlockFindingDescriptor {
            rule_id: "test-quality.ignored-without-reason",
            message: format!(
                "Ignored test `{}` does not explain why it is skipped.",
                block.name
            ),
            file,
            block,
            severity: Severity::Advisory,
            pillar: Pillar::TestQuality,
        }));
    }
}

pub(crate) fn analyse_test_size(
    file: &SourceFile,
    block: &FunctionBlock,
    config: &Config,
    findings: &mut Vec<Finding>,
) {
    let rule_id = "test-quality.long-test";
    let threshold = config.threshold(rule_id, 80.0) as usize;
    if block.line_count > threshold {
        findings.push(block_finding_with_metadata(
            BlockFindingDescriptor {
                rule_id,
                message: format!(
                    "Test `{}` has {} lines, above the threshold of {threshold}.",
                    block.name, block.line_count
                ),
                file,
                block,
                severity: config.severity(rule_id, Severity::Advisory),
                pillar: Pillar::TestQuality,
            },
            json!({ "lines": block.line_count }),
        ));
    }
}

pub(crate) fn analyse_test_assertions(
    file: &SourceFile,
    block: &FunctionBlock,
    searchable_body: &str,
    findings: &mut Vec<Finding>,
) {
    if has_trivial_assertion(searchable_body) {
        findings.push(block_finding(BlockFindingDescriptor {
            rule_id: "test-quality.trivial-assertion",
            message: format!("Test `{}` contains a trivial assertion.", block.name),
            file,
            block,
            severity: Severity::Warning,
            pillar: Pillar::TestQuality,
        }));
    }

    if !static_regex(
        &TEST_ASSERTION_REGEX,
        r"\b(assert!|assert_eq!|assert_ne!|matches!|panic!|assert_[A-Za-z0-9_]*\s*\()",
    )
    .is_match(searchable_body)
    {
        findings.push(block_finding(BlockFindingDescriptor {
            rule_id: "test-quality.no-assertions",
            message: format!(
                "Test `{}` does not appear to make an assertion.",
                block.name
            ),
            file,
            block,
            severity: Severity::Warning,
            pillar: Pillar::TestQuality,
        }));
    }
}

pub(crate) fn analyse_test_regex_checks(
    file: &SourceFile,
    block: &FunctionBlock,
    searchable_body: &str,
    findings: &mut Vec<Finding>,
) {
    for rule in TEST_CHECKS {
        if static_regex(rule.regex, rule.pattern).is_match(searchable_body) {
            findings.push(block_finding(BlockFindingDescriptor {
                rule_id: rule.rule_id,
                message: rule.message.into(),
                file,
                block,
                severity: Severity::Advisory,
                pillar: Pillar::TestQuality,
            }));
        }
    }
}

pub(crate) fn analyse_line_rules(
    file: &SourceFile,
    source: &str,
    blocks: &[FunctionBlock],
    findings: &mut Vec<Finding>,
) {
    let searchable_source = strip_rust_string_literals(source);
    let raw_lines: Vec<&str> = searchable_source.lines().collect();
    let code_only_source = strip_rust_comments_after_string_mask(&searchable_source);
    let code_only_lines: Vec<&str> = code_only_source.lines().collect();
    let test_context_ranges: Vec<(usize, usize)> = blocks
        .iter()
        .filter(|block| block.is_test_context())
        .map(|block| (block.start_line, block.start_line + block.line_count))
        .collect();
    let context = LineRuleContext {
        file,
        raw_lines: &raw_lines,
        code_only_lines: &code_only_lines,
        test_context_ranges: &test_context_ranges,
    };

    for line_index in 0..raw_lines.len() {
        context.analyse_line(line_index, findings);
    }

    analyse_unreachable(file, &searchable_source, findings);
}

pub(crate) struct LineRuleContext<'a> {
    file: &'a SourceFile,
    raw_lines: &'a [&'a str],
    code_only_lines: &'a [&'a str],
    test_context_ranges: &'a [(usize, usize)],
}

impl LineRuleContext<'_> {
    fn analyse_line(&self, line_index: usize, findings: &mut Vec<Finding>) {
        let line_number = line_index + 1;
        let raw_line = self.raw_lines[line_index];
        let code_only_line = self.code_only_lines[line_index];
        self.analyse_safety_line(raw_line, line_index, line_number, findings);
        self.analyse_waste_line(code_only_line, line_number, findings);
    }

    fn line_is_in_test_context(&self, line_number: usize) -> bool {
        self.test_context_ranges
            .iter()
            .any(|(start, end)| line_number >= *start && line_number < *end)
    }
}

/// Returns true when the line contains a `.clone()` whose result is
/// immediately consumed by an ownership-taking method (M33 exemptions:
/// `unwrap_or*`, `into*`, `collect*`, `?` propagation) or is being used
/// in a position where the surrounding code requires owned data (struct
/// field initialisation, `Entry::*` insertion). In those cases the clone
/// is not avoidable, so the candidate rule should stay silent.
pub(crate) fn clone_is_consumed_or_owned(line: &str) -> bool {
    static CONSUMER_REGEX: OnceLock<Regex> = OnceLock::new();
    let regex = static_regex(
        &CONSUMER_REGEX,
        r"\.clone\(\)\s*(?:\?|\.(?:unwrap_or_else|unwrap_or_default|unwrap_or|into_iter|into|collect)\b)",
    );
    if regex.is_match(line) {
        return true;
    }
    static STRUCT_FIELD_REGEX: OnceLock<Regex> = OnceLock::new();
    let field_regex = static_regex(
        &STRUCT_FIELD_REGEX,
        r"^\s*[A-Za-z_][A-Za-z0-9_]*\s*:\s+[^=]*\.clone\(\)\s*,?\s*$",
    );
    if field_regex.is_match(line) {
        return true;
    }
    static ENTRY_REGEX: OnceLock<Regex> = OnceLock::new();
    let entry_regex = static_regex(
        &ENTRY_REGEX,
        r"\.entry\([^)]*\.clone\(\)\s*\)|\.insert\([^,]*\.clone\(\)",
    );
    if entry_regex.is_match(line) {
        return true;
    }
    false
}

impl LineRuleContext<'_> {
    fn analyse_safety_line(
        &self,
        line: &str,
        line_index: usize,
        line_number: usize,
        findings: &mut Vec<Finding>,
    ) {
        let has_unsafe = static_regex(&UNSAFE_BLOCK_REGEX, r"\bunsafe\s*\{").is_match(line);
        if !has_unsafe {
            return;
        }
        match find_nearby_safety_rationale(self.raw_lines, line_index) {
            None => findings.push(finding(SimpleFindingDescriptor {
                rule_id: "security.unsafe-block",
                message: "Unsafe block lacks a nearby SAFETY rationale.".into(),
                file: self.file,
                line: Some(line_number),
                severity: Severity::Warning,
                pillar: Pillar::Security,
            })),
            Some(rationale) if is_weak_safety_rationale(&rationale) => {
                findings.push(Finding::new(FindingDescriptor {
                        rule_id: "docs.weak-safety-rationale".to_string(),
                        message: format!(
                            "Unsafe block's SAFETY rationale is too short or vague: `{}`.",
                            rationale.trim()
                        ),
                        file_path: self.file.display_path.clone(),
                        line: Some(line_number),
                        severity: Severity::Advisory,
                        pillar: Pillar::Documentation,
                        confidence: Confidence::Medium,
                        symbol: None,
                        remediation: Some(
                            "Explain the invariants the caller must uphold or why the operation is sound."
                                .to_string(),
                        ),
                        metadata: json!({ "rationale": rationale.trim() }),
                    }));
            }
            Some(_) => {}
        }
    }

    fn analyse_waste_line(&self, line: &str, line_number: usize, findings: &mut Vec<Finding>) {
        if static_regex(&UNWRAP_EXPECT_CALL_REGEX, r"\.(unwrap|expect)\s*\(").is_match(line)
            && !line.contains("#[test]")
            && !self.line_is_in_test_context(line_number)
        {
            findings.push(finding(SimpleFindingDescriptor {
                rule_id: "waste.unwrap-expect",
                message: "unwrap()/expect() can turn recoverable errors into panics.".into(),
                file: self.file,
                line: Some(line_number),
                severity: Severity::Advisory,
                pillar: Pillar::Waste,
            }));
        }

        if static_regex(&CLONE_CALL_REGEX, r"\.clone\(\)").is_match(line)
            && !clone_is_consumed_or_owned(line)
            && !line.contains("#[test]")
            && !self.line_is_in_test_context(line_number)
        {
            findings.push(finding(SimpleFindingDescriptor {
                rule_id: "waste.unnecessary-clone-candidate",
                message: "clone() call may be avoidable; confirm ownership requires it.".into(),
                file: self.file,
                line: Some(line_number),
                severity: Severity::Advisory,
                pillar: Pillar::Waste,
            }));
        }
    }
}

pub(crate) fn analyse_process_commands(
    file: &SourceFile,
    source: &str,
    findings: &mut Vec<Finding>,
) {
    let command_regex = static_regex(
        &PROCESS_COMMAND_REGEX,
        r"(std::process::Command|Command)::new\s*\(",
    );
    let searchable = strip_rust_string_literals(source);
    for (line_index, line) in searchable.lines().enumerate() {
        if command_regex.is_match(line) {
            findings.push(finding(SimpleFindingDescriptor {
                    rule_id: "security.process-command",
                    message: "Process command execution is used; validate command arguments are not user-controlled.".into(),
                    file,
                    line: Some(line_index + 1),
                    severity: Severity::Warning,
                    pillar: Pillar::Security,
                }));
        }
    }
}
