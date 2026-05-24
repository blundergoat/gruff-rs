use super::*;

pub(crate) fn analyse_placeholder_block_name(
    file: &SourceFile,
    block: &FunctionBlock,
    config: &Config,
    findings: &mut Vec<Finding>,
) {
    let extras = config.string_array_option("naming.placeholder-identifier", "extraPlaceholders");
    let extra_match = extras.contains(&block.name);
    if is_placeholder_identifier(&block.name) || extra_match {
        findings.push(block_finding_with_extras(
            BlockFindingDescriptor {
                rule_id: "naming.placeholder-identifier",
                message: format!(
                    "Function `{}` uses a placeholder name instead of domain language.",
                    block.name
                ),
                file,
                block,
                severity: Severity::Advisory,
                pillar: Pillar::Naming,
            },
            BlockFindingExtras {
                confidence: Confidence::Medium,
                remediation: None,
                metadata: json!({}),
            },
        ));
    }
}

pub(crate) fn analyse_error_handling_block(
    file: &SourceFile,
    block: &FunctionBlock,
    searchable_body: &str,
    findings: &mut Vec<Finding>,
) {
    analyse_panic_block(file, block, searchable_body, findings);
    analyse_placeholder_block(file, block, searchable_body, findings);
    analyse_public_unwrap_block(file, block, searchable_body, findings);
}

/// Public functions that can panic should declare `# Panics` in rustdoc.
/// "Can panic" is approximated by the same regex set used by other
/// error-handling rules: `panic!`, `unwrap`, or `expect` in the body.
/// Fires only on `pub` items so private helpers and test scaffolding are
/// not noisy.
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
    let body_no_strings = strip_rust_string_literals(&block.body);
    let body_code_only = strip_rust_comments_after_string_mask(&body_no_strings);
    let has_panic = static_regex(&PANIC_MACRO_REGEX, r"\bpanic!\s*\(").is_match(&body_code_only)
        || static_regex(&UNWRAP_EXPECT_CALL_REGEX, r"\.(unwrap|expect)\s*\(")
            .is_match(&body_code_only);
    if !has_panic {
        return;
    }
    let docs = doc_comment_text(&block.body);
    if docs.is_empty() || docs.contains_section("Panics") {
        return;
    }
    findings.push(block_finding_with_extras(
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
    ));
}

/// Public `unsafe fn` requires a `# Safety` rustdoc section explaining the
/// caller invariants. The unsafe-ness is detected from the signature line
/// in `block.body` (which always includes the `fn` line and preceding
/// attrs/docs), avoiding the need to thread extra fields through the block
/// representation.
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
/// produce a finding. Skips functions whose rustdoc is empty (covered by
/// `docs.missing-public-doc`) and functions whose only parameter is
/// `self` / `&self` / `&mut self`. Underscore-prefixed parameters are
/// considered intentionally unused and are skipped. Frontend-bridge
/// macros (`#[tauri::command]`, `#[wasm_bindgen]`, `#[pyfunction]`) skip
/// the check because their rustdoc convention describes the user-facing
/// action rather than enumerating Rust API parameters.
pub(crate) fn analyse_missing_param_doc(
    file: &SourceFile,
    block: &FunctionBlock,
    findings: &mut Vec<Finding>,
) {
    if !block.is_externally_public || block.is_test || block.test_context {
        return;
    }
    if block.param_count == 0 {
        return;
    }
    if has_frontend_bridge_attr(&block.body) {
        return;
    }
    let docs = doc_comment_text(&block.body);
    if docs.is_empty() {
        return;
    }
    let params = extract_param_names(&block.body);
    let undocumented: Vec<String> = params
        .into_iter()
        .filter(|name| !name.starts_with('_'))
        .filter(|name| !docs.mentions_identifier(name))
        .collect();
    if undocumented.is_empty() {
        return;
    }
    findings.push(block_finding_with_extras(
        BlockFindingDescriptor {
            rule_id: "docs.missing-param-doc",
            message: format!(
                "Public function `{}` rustdoc does not document parameter `{}`.",
                block.name, undocumented[0]
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
    ));
}

/// Public functions whose rustdoc does not describe their return value
/// produce a finding. Skips functions with no explicit return type or that
/// return `Result<...>` (already covered by `docs.missing-errors-section`).
/// Skips functions whose rustdoc is empty (covered by
/// `docs.missing-public-doc`). Frontend-bridge macros
/// (`#[tauri::command]`, `#[wasm_bindgen]`, `#[pyfunction]`) skip the
/// check for the same reason as `docs.missing-param-doc`: their rustdoc
/// convention describes the user-facing action.
pub(crate) fn analyse_missing_return_doc(
    file: &SourceFile,
    block: &FunctionBlock,
    findings: &mut Vec<Finding>,
) {
    if !block.is_externally_public || block.is_test || block.test_context {
        return;
    }
    if block.returns_result {
        return;
    }
    if !signature_has_return_type(&block.body) {
        return;
    }
    if has_frontend_bridge_attr(&block.body) {
        return;
    }
    let docs = doc_comment_text(&block.body);
    if docs.is_empty() || docs.mentions_returns() {
        return;
    }
    findings.push(block_finding_with_extras(
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
    ));
}

/// Tests marked `#[should_panic]` without `expected = "..."` cannot
/// distinguish the intended panic from an unrelated panic that masks a
/// real bug. Fires only when the attribute appears without any
/// `expected` arg.
pub(crate) fn analyse_should_panic_without_expected(
    file: &SourceFile,
    block: &FunctionBlock,
    findings: &mut Vec<Finding>,
) {
    if !block.is_test {
        return;
    }
    let has_should_panic =
        static_regex(&SHOULD_PANIC_ATTR_REGEX, r"#\s*\[\s*should_panic\b").is_match(&block.body);
    if !has_should_panic {
        return;
    }
    let has_expected = static_regex(
        &SHOULD_PANIC_EXPECTED_REGEX,
        r"#\s*\[\s*should_panic\s*\([^)]*\bexpected\s*=",
    )
    .is_match(&block.body);
    if has_expected {
        return;
    }
    findings.push(block_finding_with_extras(
        BlockFindingDescriptor {
            rule_id: "test-quality.should-panic-without-expected",
            message: format!(
                "Test `{}` uses #[should_panic] without an `expected = \"...\"` clause.",
                block.name
            ),
            file,
            block,
            severity: Severity::Advisory,
            pillar: Pillar::TestQuality,
        },
        BlockFindingExtras {
            confidence: Confidence::High,
            remediation: Some(
                "Add `expected = \"message substring\"` so the test fails when an unrelated panic occurs."
                    .to_string(),
            ),
            metadata: json!({}),
        },
    ));
}

pub(crate) fn signature_has_return_type(body: &str) -> bool {
    static SIG_RETURN_REGEX: OnceLock<Regex> = OnceLock::new();
    static_regex(
        &SIG_RETURN_REGEX,
        r"fn\s+[A-Za-z_][A-Za-z0-9_]*[^{;]*->\s*[^{;]+\{",
    )
    .is_match(body)
}

/// True iff `body` carries a macro attribute that marks the function as a
/// frontend bridge: `#[tauri::command]`, `#[command]` (Tauri shorthand
/// after `use tauri::command`), `#[wasm_bindgen]`, or `#[pyfunction]`.
/// Bridge functions follow user-facing-summary rustdoc convention rather
/// than the Rust API contract style, so per-param and return-value
/// documentation rules stay silent on them.
pub(crate) fn has_frontend_bridge_attr(body: &str) -> bool {
    static BRIDGE_ATTR_REGEX: OnceLock<Regex> = OnceLock::new();
    static_regex(
        &BRIDGE_ATTR_REGEX,
        r"#\s*\[\s*(?:tauri\s*::\s*command|command|wasm_bindgen|pyfunction|pyo3\s*::\s*pyfunction)\b",
    )
    .is_match(body)
}

/// Best-effort parameter-name extraction from the signature line of a
/// function block. Source-only: parses the first `fn name(` ... `)` token
/// stream, splits on top-level commas, and pulls the leftmost identifier
/// before `:` in each chunk. Skips `self`, `&self`, `&mut self`, and
/// generic-only signatures where parens are unbalanced.
pub(crate) fn extract_param_names(body: &str) -> Vec<String> {
    let Some(fn_index) = body.find("fn ") else {
        return Vec::new();
    };
    let after_fn = &body[fn_index..];
    let Some(open_paren) = after_fn.find('(') else {
        return Vec::new();
    };
    let mut depth = 0i32;
    let mut close_offset = None;
    let bytes = after_fn.as_bytes();
    for (offset, byte) in bytes.iter().enumerate().skip(open_paren) {
        match byte {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    close_offset = Some(offset);
                    break;
                }
            }
            _ => {}
        }
    }
    let Some(close) = close_offset else {
        return Vec::new();
    };
    let inside = &after_fn[open_paren + 1..close];
    let mut params = Vec::new();
    let mut current = String::new();
    let mut depth = 0i32;
    for character in inside.chars() {
        match character {
            '<' | '(' | '[' | '{' => {
                depth += 1;
                current.push(character);
            }
            '>' | ')' | ']' | '}' => {
                depth -= 1;
                current.push(character);
            }
            ',' if depth == 0 => {
                if let Some(name) = parameter_name(&current) {
                    params.push(name);
                }
                current.clear();
            }
            _ => current.push(character),
        }
    }
    if let Some(name) = parameter_name(&current) {
        params.push(name);
    }
    params
}

fn parameter_name(chunk: &str) -> Option<String> {
    let trimmed = chunk.trim();
    if trimmed.is_empty() {
        return None;
    }
    if trimmed.starts_with("self")
        || trimmed.starts_with("&self")
        || trimmed.starts_with("&mut self")
        || trimmed == "_"
    {
        return None;
    }
    let until_colon = trimmed
        .split(':')
        .next()
        .unwrap_or(trimmed)
        .trim()
        .trim_start_matches("mut ")
        .trim_start_matches('&')
        .trim();
    let identifier: String = until_colon
        .chars()
        .take_while(|character| character.is_ascii_alphanumeric() || *character == '_')
        .collect();
    if identifier.is_empty() || identifier == "self" {
        None
    } else {
        Some(identifier)
    }
}

pub(crate) static UNSAFE_FN_SIGNATURE_REGEX: OnceLock<Regex> = OnceLock::new();
pub(crate) static SHOULD_PANIC_ATTR_REGEX: OnceLock<Regex> = OnceLock::new();
pub(crate) static SHOULD_PANIC_EXPECTED_REGEX: OnceLock<Regex> = OnceLock::new();

pub(crate) fn analyse_panic_block(
    file: &SourceFile,
    block: &FunctionBlock,
    searchable_body: &str,
    findings: &mut Vec<Finding>,
) {
    if block.is_test || block.test_context || path_is_test_infrastructure(&file.display_path) {
        return;
    }
    let has_panic = static_regex(&PANIC_MACRO_REGEX, r"\bpanic!\s*\(").is_match(searchable_body);
    if has_panic && !has_nearby_invariant_comment(searchable_body) {
        findings.push(block_finding_with_extras(
            BlockFindingDescriptor {
                rule_id: "error-handling.production-panic",
                message: format!("Function `{}` calls panic! in production code.", block.name),
                file,
                block,
                severity: Severity::Warning,
                pillar: Pillar::Maintainability,
            },
            BlockFindingExtras {
                confidence: Confidence::High,
                remediation: Some(
                    "Return an error or document the invariant that makes the panic unreachable."
                        .to_string(),
                ),
                metadata: json!({ "macro": "panic!" }),
            },
        ));
    }
}

pub(crate) fn analyse_placeholder_block(
    file: &SourceFile,
    block: &FunctionBlock,
    searchable_body: &str,
    findings: &mut Vec<Finding>,
) {
    if static_regex(&PLACEHOLDER_MACRO_REGEX, r"\b(todo!|unimplemented!)\s*\(")
        .is_match(searchable_body)
    {
        findings.push(block_finding_with_extras(
            BlockFindingDescriptor {
                rule_id: "error-handling.unimplemented-placeholder",
                message: format!(
                    "Function `{}` contains todo!/unimplemented! placeholder code.",
                    block.name
                ),
                file,
                block,
                severity: Severity::Warning,
                pillar: Pillar::Maintainability,
            },
            BlockFindingExtras {
                confidence: Confidence::High,
                remediation: Some(
                    "Replace the placeholder with implemented behavior before shipping."
                        .to_string(),
                ),
                metadata: json!({ "macros": ["todo!", "unimplemented!"] }),
            },
        ));
    }
}

pub(crate) fn analyse_public_unwrap_block(
    file: &SourceFile,
    block: &FunctionBlock,
    searchable_body: &str,
    findings: &mut Vec<Finding>,
) {
    let has_unwrap = static_regex(&UNWRAP_EXPECT_CALL_REGEX, r"\.(unwrap|expect)\s*\(")
        .is_match(searchable_body);
    if block.is_externally_public && has_unwrap {
        findings.push(block_finding_with_extras(
            BlockFindingDescriptor {
                rule_id: "error-handling.public-unwrap",
                message: format!(
                    "Public function `{}` uses unwrap()/expect() in its implementation.",
                    block.name
                ),
                file,
                block,
                severity: Severity::Warning,
                pillar: Pillar::Maintainability,
            },
            BlockFindingExtras {
                confidence: Confidence::High,
                remediation: Some(
                    "Return a Result or map the failure into the public API contract.".to_string(),
                ),
                metadata: json!({}),
            },
        ));
    }
}

pub(crate) fn analyse_metric_block(
    ctx: BlockAnalysisContext<'_>,
    searchable_body: &str,
    cyclomatic: usize,
    findings: &mut Vec<Finding>,
) {
    if path_is_calibration_fixture(&ctx.file.display_path) {
        return;
    }
    let metrics = function_metrics(searchable_body, cyclomatic);
    analyse_halstead_volume(
        BlockAnalysisContext {
            file: ctx.file,
            block: ctx.block,
            config: ctx.config,
        },
        &metrics,
        findings,
    );
    analyse_maintainability_pressure(
        BlockAnalysisContext {
            file: ctx.file,
            block: ctx.block,
            config: ctx.config,
        },
        &metrics,
        cyclomatic,
        findings,
    );
}

pub(crate) fn analyse_halstead_volume(
    ctx: BlockAnalysisContext<'_>,
    metrics: &FunctionMetrics,
    findings: &mut Vec<Finding>,
) {
    let volume_threshold = ctx.config.threshold("metrics.halstead-volume", 1500.0);
    if metrics.halstead_volume > volume_threshold {
        let rule_id = "metrics.halstead-volume";
        findings.push(block_finding_with_extras(
            BlockFindingDescriptor {
                rule_id,
                message: format!(
                    "Function `{}` has Halstead-style volume {:.1}, above the threshold of {:.1}.",
                    ctx.block.name, metrics.halstead_volume, volume_threshold
                ),
                file: ctx.file,
                block: ctx.block,
                severity: ctx.config.severity(rule_id, Severity::Advisory),
                pillar: Pillar::Complexity,
            },
            BlockFindingExtras {
                confidence: Confidence::Medium,
                remediation: Some(
                    "Split dense logic into smaller functions with simpler token flow.".to_string(),
                ),
                metadata: json!({
                    "totalTokens": metrics.total_tokens,
                    "uniqueTokens": metrics.unique_tokens,
                    "halsteadVolume": round_one_decimal(metrics.halstead_volume),
                    "threshold": volume_threshold
                }),
            },
        ));
    }
}

pub(crate) fn analyse_maintainability_pressure(
    ctx: BlockAnalysisContext<'_>,
    metrics: &FunctionMetrics,
    cyclomatic: usize,
    findings: &mut Vec<Finding>,
) {
    let minimum_score = ctx
        .config
        .threshold("metrics.maintainability-pressure", 45.0);
    if metrics.maintainability_score < minimum_score {
        let rule_id = "metrics.maintainability-pressure";
        findings.push(block_finding_with_extras(
                BlockFindingDescriptor {
                    rule_id,
                    message: format!(
                        "Function `{}` has maintainability pressure score {:.1}, below the minimum of {:.1}.",
                        ctx.block.name, metrics.maintainability_score, minimum_score
                    ),
                    file: ctx.file,
                    block: ctx.block,
                    severity: ctx.config.severity(rule_id, Severity::Advisory),
                    pillar: Pillar::Maintainability,
                },
                BlockFindingExtras {
                    confidence: Confidence::Medium,
                    remediation: Some(
                        "Reduce line count, branching, or token volume before relying on this function as stable hot-path code."
                            .to_string(),
                    ),
                    metadata: json!({
                        "score": round_one_decimal(metrics.maintainability_score),
                        "minimum": minimum_score,
                        "totalTokens": metrics.total_tokens,
                        "cyclomatic": cyclomatic,
                        "halsteadVolume": round_one_decimal(metrics.halstead_volume)
                    }),
                },
            ));
    }
}

pub(crate) struct PerformanceCheck {
    pub(crate) rule_id: &'static str,
    pub(crate) regex: &'static OnceLock<Regex>,
    pub(crate) pattern: &'static str,
    pub(crate) severity: Severity,
    pub(crate) confidence: Confidence,
    pub(crate) label: &'static str,
    pub(crate) remediation: &'static str,
}

pub(crate) const PERFORMANCE_CHECKS: &[PerformanceCheck] = &[
    PerformanceCheck {
        rule_id: "performance.regex-in-loop",
        regex: &PERF_REGEX_IN_LOOP_REGEX,
        pattern: r"\bRegex::new\s*\(",
        severity: Severity::Warning,
        confidence: Confidence::High,
        label: "Regex::new",
        remediation: "Move regex construction out of the loop or cache the compiled regex.",
    },
    PerformanceCheck {
        rule_id: "performance.format-in-loop",
        regex: &PERF_FORMAT_IN_LOOP_REGEX,
        pattern: r"\bformat!\s*\(",
        severity: Severity::Advisory,
        confidence: Confidence::Medium,
        label: "format!",
        remediation: "Reuse buffers or move formatting out of the loop when allocation matters.",
    },
    PerformanceCheck {
        rule_id: "performance.clone-in-loop",
        regex: &PERF_CLONE_IN_LOOP_REGEX,
        pattern: r"\.clone\s*\(",
        severity: Severity::Advisory,
        confidence: Confidence::Medium,
        label: "clone()",
        remediation: "Clone outside the loop or borrow values when ownership permits.",
    },
];
