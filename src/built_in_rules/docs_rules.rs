use super::*;

pub(crate) static UNSAFE_FN_SIGNATURE_REGEX: OnceLock<Regex> = OnceLock::new();

pub(crate) fn analyse_public_function_doc(
    file: &SourceFile,
    block: &FunctionBlock,
    findings: &mut Vec<Finding>,
) {
    if block.is_externally_public && !has_doc_comment_before(&block.body) {
        findings.push(block_finding_with_extras(
            BlockFindingDescriptor {
                rule_id: "docs.missing-public-doc",
                message: format!(
                    "Public function `{}` needs a brief intent description above its signature (one plain-English line, not a restatement of the type signature).",
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
                    "Add a one-line `/// Description.` above the function. This rule wants content, not boilerplate - if your project policy is 'no comments', that policy is about avoiding comments that restate code, not about removing documentation. The description should answer 'what is this for, what does it return at the edge values, what must the caller satisfy'."
                        .to_string(),
                ),
                metadata: json!({}),
            },
        ));
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
    let docs = doc_comment_text(&block.body);
    if docs.contains_section("Errors") || docs.has_error_contract_prose() {
        return;
    }
    findings.push(block_finding_with_extras(
        BlockFindingDescriptor {
            rule_id: "docs.missing-errors-section",
            message: format!(
                "Public function `{}` returns Result; its rustdoc needs a `# Errors` section describing when each Err variant fires.",
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
                "Add a `# Errors` section explaining the conditions that produce each Err (input validation, IO failure, resource exhaustion, etc.). The rule wants content, not boilerplate - each entry should answer 'what triggers this error and what should the caller do about it'."
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
    if docs.is_empty() || docs.contains_section("Panics") || docs.has_panic_contract_prose() {
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
                "Public function `{}` contains code that can panic (`panic!`, `unwrap`, or `expect`); its rustdoc needs a `# Panics` section.",
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
                "Add a `# Panics` section describing the inputs or runtime states that cause the panic so callers can avoid them or wrap the call defensively. The rule wants content, not boilerplate - each entry should answer 'which input or state triggers the panic'."
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
    let code = body_without_doc_comments(&block.body);
    let is_unsafe_fn =
        static_regex(&UNSAFE_FN_SIGNATURE_REGEX, r"\bunsafe\s+fn\s+").is_match(&code);
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
                "Public `unsafe fn` `{}` needs a `# Safety` rustdoc section listing the invariants the caller must uphold.",
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
                "Add a `# Safety` section listing every invariant the caller must guarantee before calling this function (pointer validity, type provenance, thread state, lifetime of borrowed data, etc.). This is the API contract for unsafe code, not boilerplate - missing invariants here become real soundness bugs."
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
    let params: Vec<String> = extract_param_names(body)
        .into_iter()
        .filter(|name| !name.starts_with('_'))
        .collect();
    if params.len() == 1 && docs.has_single_parameter_contract_prose() {
        return Vec::new();
    }
    params
        .into_iter()
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
                "Public function `{}` rustdoc does not mention parameter `{}` by name.",
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
                "Mention each parameter by name in the rustdoc - either in prose or in an `# Arguments` section. The mention should answer 'what does this value represent and what range/shape is the function expecting', not restate the type signature."
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
                "Public function `{}` returns a value; its rustdoc does not describe what the return value represents.",
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
                "Describe the return value in the rustdoc - either in prose (e.g. `Returns the count of ...`) or in a `# Returns` section. The description should answer 'what does this represent at the edge values, when might it be empty/None/zero' rather than restating the return type."
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
        lower.contains("returns ")
            || lower.contains("returning ")
            || lower.contains("yields ")
            || lower.contains("produces ")
            || lower.contains("provides ")
    }

    fn has_error_contract_prose(&self) -> bool {
        let normalized = normalized_contract_text(&self.0);
        contains_any_phrase(
            &normalized,
            &[
                "returns err",
                "returns an error",
                "return error",
                "fails when",
                "fails if",
                "fail when",
                "fail if",
                "errors when",
                "errors if",
                "error when",
                "error if",
            ],
        )
    }

    fn has_panic_contract_prose(&self) -> bool {
        let normalized = normalized_contract_text(&self.0);
        if contains_any_phrase(
            &normalized,
            &[
                "never panic",
                "never panics",
                "does not panic",
                "doesnt panic",
            ],
        ) {
            return false;
        }
        contains_any_phrase(
            &normalized,
            &[
                "panics when",
                "panics if",
                "panic when",
                "panic if",
                "will panic when",
                "will panic if",
            ],
        )
    }

    fn has_single_parameter_contract_prose(&self) -> bool {
        let normalized = normalized_contract_text(&self.0);
        contains_any_phrase(
            &normalized,
            &[
                "input",
                "argument",
                "parameter",
                "payload",
                "request",
                "source",
                "target",
                "path",
                "name",
                "identifier",
                "buffer",
                "bytes",
                "text",
                "slice",
            ],
        )
    }
}

fn normalized_contract_text(input: &str) -> String {
    let raw: String = input
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character.to_ascii_lowercase()
            } else {
                ' '
            }
        })
        .collect();
    raw.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn contains_any_phrase(haystack: &str, phrases: &[&str]) -> bool {
    let padded = format!(" {haystack} ");
    phrases
        .iter()
        .any(|phrase| padded.contains(&format!(" {phrase} ")))
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
