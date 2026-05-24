use super::*;

pub(crate) static UNSAFE_FN_SIGNATURE_REGEX: OnceLock<Regex> = OnceLock::new();

pub(crate) fn analyse_public_function_doc(
    file: &SourceFile,
    block: &FunctionBlock,
    findings: &mut Vec<Finding>,
) {
    if block.is_externally_public && !has_doc_comment_before(&block.body) {
        findings.push(block_finding(BlockFindingDescriptor {
            rule_id: "docs.missing-public-doc",
            message: format!(
                "Public function `{}` is missing a Rust doc comment.",
                block.name
            ),
            file,
            block,
            severity: Severity::Advisory,
            pillar: Pillar::Documentation,
        }));
    }
}

/// Externally-public functions returning syntactic `Result<...>` should
/// document the error contract. The rule fires when the preceding rustdoc
/// (if any) does not contain `# Errors` or `## Errors`. Type-alias `Result`
/// shapes are intentionally not detected - see `fn returns_result`.
pub(crate) fn analyse_missing_errors_section(
    file: &SourceFile,
    block: &FunctionBlock,
    findings: &mut Vec<Finding>,
) {
    if !block.is_externally_public || !block.returns_result {
        return;
    }
    if doc_comment_text(&block.body).contains_section("Errors") {
        return;
    }
    findings.push(block_finding_with_extras(
        BlockFindingDescriptor {
            rule_id: "docs.missing-errors-section",
            message: format!(
                "Public function `{}` returns Result but its rustdoc lacks a `# Errors` section.",
                block.name
            ),
            file,
            block,
            severity: Severity::Advisory,
            pillar: Pillar::Documentation,
        },
        BlockFindingExtras {
            confidence: Confidence::High,
            remediation: Some(
                "Add a `# Errors` rustdoc section describing when this function returns Err."
                    .to_string(),
            ),
            metadata: json!({}),
        },
    ));
}

/// Public functions that can panic should declare `# Panics` in rustdoc.
/// "Can panic" is approximated by `panic!`, `unwrap`, or `expect` in the
/// body. Fires only on `pub` items so private helpers and test scaffolding
/// are not noisy.
pub(crate) fn analyse_missing_panics_section(
    file: &SourceFile,
    block: &FunctionBlock,
    findings: &mut Vec<Finding>,
) {
    if !block.is_externally_public || block.is_test || block.test_context {
        return;
    }
    if path_is_test_infrastructure(&file.display_path) {
        return;
    }
    if !block_body_can_panic(&block.body) {
        return;
    }
    let docs = doc_comment_text(&block.body);
    if docs.is_empty() || docs.contains_section("Panics") {
        return;
    }
    findings.push(missing_panics_section_finding(file, block));
}

fn block_body_can_panic(body: &str) -> bool {
    let stripped = strip_rust_string_literals(body);
    let code_only = strip_rust_comments_after_string_mask(&stripped);
    static_regex(&PANIC_MACRO_REGEX, r"\bpanic!\s*\(").is_match(&code_only)
        || static_regex(&UNWRAP_EXPECT_CALL_REGEX, r"\.(unwrap|expect)\s*\(").is_match(&code_only)
}

fn missing_panics_section_finding(file: &SourceFile, block: &FunctionBlock) -> Finding {
    block_finding_with_extras(
        BlockFindingDescriptor {
            rule_id: "docs.missing-panics-section",
            message: format!(
                "Public function `{}` can panic but its rustdoc lacks a `# Panics` section.",
                block.name
            ),
            file,
            block,
            severity: Severity::Advisory,
            pillar: Pillar::Documentation,
        },
        BlockFindingExtras {
            confidence: Confidence::High,
            remediation: Some(
                "Add a `# Panics` rustdoc section explaining the conditions under which this function panics."
                    .to_string(),
            ),
            metadata: json!({}),
        },
    )
}

/// Public `unsafe fn` requires a `# Safety` rustdoc section explaining the
/// caller invariants. The unsafe-ness is detected from the signature line
/// in `block.body` (which includes the `fn` line and preceding attrs).
pub(crate) fn analyse_missing_safety_section(
    file: &SourceFile,
    block: &FunctionBlock,
    findings: &mut Vec<Finding>,
) {
    if !block.is_externally_public {
        return;
    }
    let is_unsafe_fn =
        static_regex(&UNSAFE_FN_SIGNATURE_REGEX, r"\bunsafe\s+fn\s+").is_match(&block.body);
    if !is_unsafe_fn {
        return;
    }
    let docs = doc_comment_text(&block.body);
    if docs.contains_section("Safety") {
        return;
    }
    findings.push(block_finding_with_extras(
        BlockFindingDescriptor {
            rule_id: "docs.missing-safety-section",
            message: format!(
                "Public unsafe function `{}` lacks a `# Safety` rustdoc section.",
                block.name
            ),
            file,
            block,
            severity: Severity::Warning,
            pillar: Pillar::Documentation,
        },
        BlockFindingExtras {
            confidence: Confidence::High,
            remediation: Some(
                "Add a `# Safety` rustdoc section describing the invariants the caller must uphold."
                    .to_string(),
            ),
            metadata: json!({}),
        },
    ));
}

/// Public functions whose rustdoc does not mention each parameter by name
/// produce a finding. Skips empty rustdoc, bridge-macro fns, and
/// underscore-prefixed parameters.
pub(crate) fn analyse_missing_param_doc(
    file: &SourceFile,
    block: &FunctionBlock,
    findings: &mut Vec<Finding>,
) {
    if !is_documentable_block(block) || has_frontend_bridge_attr(&block.body) {
        return;
    }
    if block.param_count == 0 {
        return;
    }
    let docs = doc_comment_text(&block.body);
    if docs.is_empty() {
        return;
    }
    let undocumented = collect_undocumented_params(&block.body, &docs);
    if undocumented.is_empty() {
        return;
    }
    findings.push(missing_param_doc_finding(file, block, undocumented));
}

fn collect_undocumented_params(body: &str, docs: &DocCommentText) -> Vec<String> {
    extract_param_names(body)
        .into_iter()
        .filter(|name| !name.starts_with('_'))
        .filter(|name| !docs.has_identifier_mention(name))
        .collect()
}

fn missing_param_doc_finding(
    file: &SourceFile,
    block: &FunctionBlock,
    undocumented: Vec<String>,
) -> Finding {
    let first = undocumented[0].clone();
    block_finding_with_extras(
        BlockFindingDescriptor {
            rule_id: "docs.missing-param-doc",
            message: format!(
                "Public function `{}` rustdoc does not document parameter `{}`.",
                block.name, first
            ),
            file,
            block,
            severity: Severity::Advisory,
            pillar: Pillar::Documentation,
        },
        BlockFindingExtras {
            confidence: Confidence::Medium,
            remediation: Some(
                "Mention each parameter by name in the rustdoc, ideally with `# Arguments` or per-parameter prose."
                    .to_string(),
            ),
            metadata: json!({ "undocumented": undocumented }),
        },
    )
}

/// Public functions whose rustdoc does not describe their return value
/// produce a finding. Skips Result-returning fns, bridge-macro fns, and
/// empty rustdocs.
pub(crate) fn analyse_missing_return_doc(
    file: &SourceFile,
    block: &FunctionBlock,
    findings: &mut Vec<Finding>,
) {
    if !is_documentable_block(block) || has_frontend_bridge_attr(&block.body) {
        return;
    }
    if block.returns_result || !signature_has_return_type(&block.body) {
        return;
    }
    let docs = doc_comment_text(&block.body);
    if docs.is_empty() || docs.has_returns_section() {
        return;
    }
    findings.push(missing_return_doc_finding(file, block));
}

fn missing_return_doc_finding(file: &SourceFile, block: &FunctionBlock) -> Finding {
    block_finding_with_extras(
        BlockFindingDescriptor {
            rule_id: "docs.missing-return-doc",
            message: format!(
                "Public function `{}` returns a value but rustdoc does not describe what it returns.",
                block.name
            ),
            file,
            block,
            severity: Severity::Advisory,
            pillar: Pillar::Documentation,
        },
        BlockFindingExtras {
            confidence: Confidence::Medium,
            remediation: Some(
                "Add a `# Returns` rustdoc section or describe the return value in prose (e.g. \"Returns the ...\")."
                    .to_string(),
            ),
            metadata: json!({}),
        },
    )
}

fn is_documentable_block(block: &FunctionBlock) -> bool {
    block.is_externally_public && !block.is_test && !block.test_context
}

/// Returns the concatenated text of `///` and `//!` doc-comment lines that
/// appear before the `fn ` keyword in `block_body`, with the marker bytes
/// stripped. Used to look for rustdoc sections like `# Errors`.
pub(crate) fn doc_comment_text(block_body: &str) -> DocCommentText {
    let mut text = String::new();
    for line in block_body.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("///") {
            text.push_str(trimmed.trim_start_matches("///").trim());
            text.push('\n');
        } else if trimmed.starts_with("//!") {
            text.push_str(trimmed.trim_start_matches("//!").trim());
            text.push('\n');
        } else if trimmed.contains("fn ") {
            break;
        }
    }
    DocCommentText(text)
}

pub(crate) struct DocCommentText(String);

impl DocCommentText {
    pub(crate) fn contains_section(&self, heading: &str) -> bool {
        self.0.lines().any(|line| {
            let trimmed = line.trim();
            let with_one = format!("# {heading}");
            let with_two = format!("## {heading}");
            let with_three = format!("### {heading}");
            trimmed.starts_with(&with_one)
                || trimmed.starts_with(&with_two)
                || trimmed.starts_with(&with_three)
        })
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.0.trim().is_empty()
    }

    pub(crate) fn has_identifier_mention(&self, name: &str) -> bool {
        let lower = self.0.to_ascii_lowercase();
        let needle = name.to_ascii_lowercase();
        let bytes = lower.as_bytes();
        let pattern_len = needle.len();
        let mut index = 0usize;
        while let Some(found) = lower[index..].find(needle.as_str()) {
            let absolute = index + found;
            if is_word_boundary_match(bytes, absolute, pattern_len) {
                return true;
            }
            index = absolute + pattern_len;
        }
        false
    }

    pub(crate) fn has_returns_section(&self) -> bool {
        if self.contains_section("Returns") {
            return true;
        }
        let lower = self.0.to_ascii_lowercase();
        lower.contains("returns ") || lower.contains("returning ") || lower.contains("yields ")
    }
}

fn is_word_boundary_match(bytes: &[u8], absolute: usize, pattern_len: usize) -> bool {
    let before_ok = absolute == 0 || !is_word_char(bytes[absolute - 1]);
    let after_pos = absolute + pattern_len;
    let after_ok = match bytes.get(after_pos) {
        None => true,
        Some(byte) => !is_word_char(*byte),
    };
    before_ok && after_ok
}

fn is_word_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}
