use super::*;

pub(crate) fn analyse_performance_block(
    file: &SourceFile,
    block: &FunctionBlock,
    searchable_body: &str,
    findings: &mut Vec<Finding>,
) {
    for check in PERFORMANCE_CHECKS {
        let regex = static_regex(check.regex, check.pattern);
        let occurrences = loop_pattern_count_filtered(searchable_body, regex, |line| {
            should_count_perf_line(check.rule_id, line)
        });
        if occurrences > 0 {
            push_performance_finding(file, block, check, occurrences, findings);
        }
    }
}

/// Returns true when the line genuinely represents a wasteful in-loop
/// call. Lines that look structural (struct-field initialisers, owned
/// API arguments, `Finding::new(...)` builders, format-as-message
/// constructors) are excluded so the rule fires only on real per-tick
/// allocations. Distinct from the broader `waste.*` guard: per-iteration
/// `let _owned = value.clone();` IS the canonical hoist-able waste this
/// rule is designed to catch.
fn should_count_perf_line(rule_id: &str, line: &str) -> bool {
    match rule_id {
        "performance.clone-in-loop" => !clone_is_structural_in_loop(line),
        "performance.format-in-loop" => !format_is_owned_value(line),
        _ => true,
    }
}

/// Narrower clone exemption for `performance.clone-in-loop`. Only the
/// strictly structural patterns (struct field, `Some()` wrap, hashmap
/// key, multi-line method-chain continuation) are skipped — let-bindings
/// and standalone clones in the loop body still fire.
fn clone_is_structural_in_loop(line: &str) -> bool {
    PERF_CLONE_STRUCTURAL_PATTERNS
        .iter()
        .any(|pattern| pattern.matches(line))
}

static PERF_FIELD_REGEX: OnceLock<Regex> = OnceLock::new();
static PERF_SOME_REGEX: OnceLock<Regex> = OnceLock::new();
static PERF_LOOKUP_REGEX: OnceLock<Regex> = OnceLock::new();
static PERF_CHAIN_REGEX: OnceLock<Regex> = OnceLock::new();

const PERF_CLONE_STRUCTURAL_PATTERNS: &[CloneOwnershipPattern] = &[
    CloneOwnershipPattern {
        cell: &PERF_FIELD_REGEX,
        pattern: r"^\s*[A-Za-z_][A-Za-z0-9_]*\s*:\s+[^=]*\.clone\(\)\s*\)*\s*,?\s*$",
    },
    CloneOwnershipPattern {
        cell: &PERF_SOME_REGEX,
        pattern: r"\bSome\(\s*[^()]*\.clone\(\)\s*\)",
    },
    CloneOwnershipPattern {
        cell: &PERF_LOOKUP_REGEX,
        pattern: r"\.(?:entry|insert)\(\s*&?\s*\(?[^=;]*\.clone\(\)[^;]*\)",
    },
    CloneOwnershipPattern {
        cell: &PERF_CHAIN_REGEX,
        pattern: r"^\s*\.clone\(\)\s*$",
    },
];

/// Returns true when a `format!()` call sits in a position whose caller
/// requires an owned `String` (struct field initialiser, error message
/// returned via `Err(format!(...))`, `return` expression, or
/// `String::push_str(&format!())` text-buffer growth). These uses are
/// not avoidable: each iteration legitimately produces a distinct owned
/// string and there is no shared buffer to hoist into. Note that
/// `Vec::push(format!())` IS still flagged — that pattern usually
/// signals collecting per-item strings that could be hoisted to
/// `.iter().map(...).collect()`.
fn format_is_owned_value(line: &str) -> bool {
    FORMAT_OWNED_VALUE_PATTERNS
        .iter()
        .any(|pattern| pattern.matches(line))
}

static FORMAT_FIELD_REGEX: OnceLock<Regex> = OnceLock::new();
static FORMAT_ERR_REGEX: OnceLock<Regex> = OnceLock::new();
static FORMAT_RETURN_REGEX: OnceLock<Regex> = OnceLock::new();
static FORMAT_PUSH_STR_REGEX: OnceLock<Regex> = OnceLock::new();

const FORMAT_OWNED_VALUE_PATTERNS: &[CloneOwnershipPattern] = &[
    CloneOwnershipPattern {
        cell: &FORMAT_FIELD_REGEX,
        pattern: r"^\s*[A-Za-z_][A-Za-z0-9_]*\s*:\s+[^=]*format!\s*\(",
    },
    CloneOwnershipPattern {
        cell: &FORMAT_ERR_REGEX,
        pattern: r"\bErr\(\s*format!\s*\(",
    },
    CloneOwnershipPattern {
        cell: &FORMAT_RETURN_REGEX,
        pattern: r"^\s*return\s+format!\s*\(",
    },
    CloneOwnershipPattern {
        cell: &FORMAT_PUSH_STR_REGEX,
        pattern: r"\.(?:push_str|insert_str|write_str|write_all|write_fmt)\s*\(\s*&?\s*format!\s*\(",
    },
];

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
        if !static_regex(rule.regex, rule.pattern).is_match(searchable_body) {
            continue;
        }
        if is_test_rule_exempt(rule.rule_id, searchable_body) {
            continue;
        }
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

/// Returns true when a per-test regex rule should stay silent because
/// the matched pattern is a recognised idiom. Today: `loop-in-test`
/// skips table-driven iteration over array literals, ranges, and
/// `cases()`-style functions; `conditional-logic` skips `cfg!(...)`
/// platform branches.
fn is_test_rule_exempt(rule_id: &str, body: &str) -> bool {
    match rule_id {
        "test-quality.loop-in-test" => loop_is_table_driven(body),
        "test-quality.conditional-logic" => conditional_is_platform_gate(body),
        _ => false,
    }
}

fn loop_is_table_driven(body: &str) -> bool {
    static LOGIC_LOOP_REGEX: OnceLock<Regex> = OnceLock::new();
    let logic_loop = static_regex(&LOGIC_LOOP_REGEX, r"\b(while|loop)\b");
    if logic_loop.is_match(body) {
        return false;
    }
    static FOR_LOOP_OPEN_REGEX: OnceLock<Regex> = OnceLock::new();
    let for_loop_open = static_regex(&FOR_LOOP_OPEN_REGEX, r"\bfor\s+[^{};]+\s+in\s+[^{};]+\s*\{");
    for capture in for_loop_open.find_iter(body) {
        let body_start = capture.end();
        let Some(body_end) = matching_close_brace(body, body_start) else {
            continue;
        };
        let loop_body = &body[body_start..body_end];
        if !loop_body_is_assertions_only(loop_body) {
            return false;
        }
    }
    true
}

/// Returns the byte index of the `}` that matches the `{` immediately
/// before `start`. Treats `{` and `}` literally (the input is already
/// string-stripped by upstream, so braces inside string literals do not
/// appear here).
fn matching_close_brace(body: &str, start: usize) -> Option<usize> {
    let bytes = body.as_bytes();
    let mut depth = 1usize;
    for (offset, byte) in bytes[start..].iter().enumerate() {
        depth = update_brace_depth(depth, *byte);
        if depth == 0 {
            return Some(start + offset);
        }
    }
    None
}

fn update_brace_depth(depth: usize, byte: u8) -> usize {
    match byte {
        b'{' => depth + 1,
        b'}' => depth.saturating_sub(1),
        _ => depth,
    }
}

fn loop_body_is_assertions_only(body: &str) -> bool {
    let trimmed = body.trim();
    if trimmed.is_empty() {
        return false;
    }
    static ASSERT_REGEX: OnceLock<Regex> = OnceLock::new();
    let assert_call = static_regex(&ASSERT_REGEX, r"\bassert[a-z_]*!\s*\(");
    assert_call.is_match(trimmed)
}

fn conditional_is_platform_gate(body: &str) -> bool {
    static CFG_GATE_REGEX: OnceLock<Regex> = OnceLock::new();
    let cfg_gate = static_regex(&CFG_GATE_REGEX, r"\bif\s+cfg!\s*\(");
    cfg_gate.is_match(body)
}

pub(crate) fn analyse_line_rules(
    file: &SourceFile,
    source: &str,
    blocks: &[FunctionBlock],
    findings: &mut Vec<Finding>,
) {
    let source_lines: Vec<&str> = source.lines().collect();
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
        source_lines: &source_lines,
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
    source_lines: &'a [&'a str],
    raw_lines: &'a [&'a str],
    code_only_lines: &'a [&'a str],
    test_context_ranges: &'a [(usize, usize)],
}

impl LineRuleContext<'_> {
    fn analyse_line(&self, line_index: usize, findings: &mut Vec<Finding>) {
        let line_number = line_index + 1;
        let raw_line = self.raw_lines[line_index];
        let source_line = self.source_lines[line_index];
        let code_only_line = self.code_only_lines[line_index];
        self.analyse_safety_line(raw_line, line_index, line_number, findings);
        self.analyse_waste_line(code_only_line, source_line, line_number, findings);
    }

    fn line_is_in_test_context(&self, line_number: usize) -> bool {
        if file_path_is_test_code(&self.file.display_path) {
            return true;
        }
        self.test_context_ranges
            .iter()
            .any(|(start, end)| line_number >= *start && line_number < *end)
    }
}

/// Returns true when `display_path` lives under a conventional test
/// directory (`tests/`, `src/tests/`) or ends in a `_test`/`_tests`
/// segment. Lets `waste.unwrap-expect` and
/// `waste.unnecessary-clone-candidate` stay silent inside test trees
/// even when individual functions are not marked `#[test]` (a common
/// shape for shared test fixture helpers).
fn file_path_is_test_code(display_path: &str) -> bool {
    let normalized = display_path.replace('\\', "/");
    if normalized.starts_with("tests/") || normalized.contains("/tests/") {
        return true;
    }
    let stem = std::path::Path::new(&normalized)
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or("");
    stem.ends_with("_test") || stem.ends_with("_tests")
}

/// Returns true when the line contains a `.clone()` whose result is
/// immediately consumed by an ownership-taking method (M33 exemptions:
/// `unwrap_or*`, `into*`, `collect*`, `?` propagation) or is being used
/// in a position where the surrounding code requires owned data (struct
/// field initialisation, `Some(_)` field wrap, `Entry::*` insertion,
/// tuple keys for entry/insert, `.map(...).collect()` chains). In those
/// cases the clone is not avoidable, so the candidate rule should stay
/// silent.
pub(crate) fn clone_is_consumed_or_owned(line: &str) -> bool {
    CLONE_OWNERSHIP_PATTERNS
        .iter()
        .any(|pattern| pattern.matches(line))
}

struct CloneOwnershipPattern {
    cell: &'static OnceLock<Regex>,
    pattern: &'static str,
}

impl CloneOwnershipPattern {
    fn matches(&self, line: &str) -> bool {
        static_regex(self.cell, self.pattern).is_match(line)
    }
}

static CONSUMER_REGEX: OnceLock<Regex> = OnceLock::new();
static STRUCT_FIELD_REGEX: OnceLock<Regex> = OnceLock::new();
static LOOKUP_REGEX: OnceLock<Regex> = OnceLock::new();
static SOME_WRAP_REGEX: OnceLock<Regex> = OnceLock::new();
static MAP_COLLECT_REGEX: OnceLock<Regex> = OnceLock::new();
static MAP_CLOSURE_LINE_REGEX: OnceLock<Regex> = OnceLock::new();
static LET_BINDING_REGEX: OnceLock<Regex> = OnceLock::new();
static MULTILINE_CHAIN_REGEX: OnceLock<Regex> = OnceLock::new();

const CLONE_OWNERSHIP_PATTERNS: &[CloneOwnershipPattern] = &[
    CloneOwnershipPattern {
        cell: &CONSUMER_REGEX,
        pattern: r"\.clone\(\)\s*(?:\?|\.(?:unwrap_or_else|unwrap_or_default|unwrap_or|into_iter|into|collect)\b)",
    },
    CloneOwnershipPattern {
        cell: &STRUCT_FIELD_REGEX,
        pattern: r"^\s*[A-Za-z_][A-Za-z0-9_]*\s*:\s+[^=]*\.clone\(\)\s*\)*\s*,?\s*$",
    },
    CloneOwnershipPattern {
        cell: &LOOKUP_REGEX,
        pattern: r"\.(?:entry|insert|get|contains|contains_key|remove)\(\s*&?\s*\(?[^=;]*\.clone\(\)[^;]*\)",
    },
    CloneOwnershipPattern {
        cell: &SOME_WRAP_REGEX,
        pattern: r"\bSome\(\s*[^()]*\.clone\(\)\s*\)",
    },
    CloneOwnershipPattern {
        cell: &MAP_COLLECT_REGEX,
        pattern: r"\.map\([^)]*\.clone\(\)[^)]*\)\s*\.?\s*\)*\.?\s*(?:collect|\)\s*\.collect)\(\)",
    },
    CloneOwnershipPattern {
        cell: &MAP_CLOSURE_LINE_REGEX,
        pattern: r"^\s*\.map\(\|[^|]*\|\s*[^=;]+\.clone\(\)\s*\)\s*$",
    },
    CloneOwnershipPattern {
        cell: &LET_BINDING_REGEX,
        pattern: r"^\s*let\s+(?:mut\s+)?[A-Za-z_][A-Za-z0-9_]*(?:\s*:\s*[^=]+)?\s*=\s*[^=;]+\.clone\(\)\s*;\s*$",
    },
    CloneOwnershipPattern {
        cell: &MULTILINE_CHAIN_REGEX,
        pattern: r"^\s*\.clone\(\)\s*$",
    },
];

/// Returns true when a `.expect("...")` call carries a substantive
/// rationale string (≥15 characters of non-whitespace content). The
/// waste rule accepts these because the author has already declared why
/// the unwrap is safe; trivial rationales like `.expect("ok")` still
/// fire.
fn expect_has_substantive_rationale(line: &str) -> bool {
    static EXPECT_RATIONALE_REGEX: OnceLock<Regex> = OnceLock::new();
    let regex = static_regex(&EXPECT_RATIONALE_REGEX, r#"\.expect\(\s*"([^"]*)"\s*\)"#);
    regex.captures_iter(line).any(|captures| {
        captures
            .get(1)
            .map(|rationale| rationale.as_str().trim().len() >= 15)
            .unwrap_or(false)
    })
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

    fn analyse_waste_line(
        &self,
        line: &str,
        raw_line: &str,
        line_number: usize,
        findings: &mut Vec<Finding>,
    ) {
        if static_regex(&UNWRAP_EXPECT_CALL_REGEX, r"\.(unwrap|expect)\s*\(").is_match(line)
            && !expect_has_substantive_rationale(raw_line)
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
