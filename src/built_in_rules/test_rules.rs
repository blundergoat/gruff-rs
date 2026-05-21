use super::*;

static TEST_ASSERTION_REGEX: OnceLock<Regex> = OnceLock::new();
static SLEEP_IN_TEST_REGEX: OnceLock<Regex> = OnceLock::new();
static LOOP_IN_TEST_REGEX: OnceLock<Regex> = OnceLock::new();
static CONDITIONAL_LOGIC_REGEX: OnceLock<Regex> = OnceLock::new();
static UNWRAP_IN_TEST_REGEX: OnceLock<Regex> = OnceLock::new();

const TEST_CHECKS: &[RegexRule] = &[
    RegexRule {
        rule_id: "test-quality.sleep-in-test",
        regex: &SLEEP_IN_TEST_REGEX,
        pattern: r"(std::thread::sleep|tokio::time::sleep)",
        message: "Test sleeps instead of synchronising on behaviour.",
    },
    RegexRule {
        rule_id: "test-quality.loop-in-test",
        regex: &LOOP_IN_TEST_REGEX,
        pattern: r"\b(for|while|loop)\b",
        message: "Test contains loop logic.",
    },
    RegexRule {
        rule_id: "test-quality.conditional-logic",
        regex: &CONDITIONAL_LOGIC_REGEX,
        pattern: r"\b(if|match)\b",
        message: "Test contains conditional logic.",
    },
    RegexRule {
        rule_id: "test-quality.unwrap-in-test",
        regex: &UNWRAP_IN_TEST_REGEX,
        pattern: r"\.unwrap\(\)",
        message: "Test uses unwrap(), which can hide setup intent.",
    },
];

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
