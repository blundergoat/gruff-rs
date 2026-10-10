//! General deterministic text-rule orchestration and file-size checks.
//! The analyzer reaches this module after source discovery; GitHub workflow and
//! explicit action metadata checks are delegated to their focused sibling module.

#[path = "github_metadata_rules.rs"]
mod github_metadata_rules;

use self::github_metadata_rules::{
    analyse_ci_github_event_shell_interpolation, analyse_github_actions_rules,
};
use super::*;
use crate::custom_rules::rust_comment_scope_source;

/// Route one discovered text source through general and metadata-specific rules.
pub(crate) fn analyse_text_rules(
    unit: &SourceUnit<'_>,
    config: &Config,
    findings: &mut Vec<Finding>,
) {
    analyse_file_length(unit, config, findings);
    analyse_ci_github_event_shell_interpolation(unit, findings);
    analyse_github_actions_rules(unit, findings);
    analyse_sensitive_data(unit, config, findings);
    analyse_pii_test_fixture(unit, findings);
}

/// Report a source file whose substantive review surface exceeds the configured line threshold.
fn analyse_file_length(unit: &SourceUnit<'_>, config: &Config, findings: &mut Vec<Finding>) {
    // File length measures Rust source only; JSON, YAML, TOML and other text files are data, not logic
    // (FAMILY-CONTRACT section 12, search `Size and complexity findings in two bands`).
    if !unit.file.is_rust || file_length_is_exempt(&unit.file.display_path) {
        return;
    }
    // A Rust file counts code lines on the bounded path too (FAMILY-CONTRACT section 12, search `Code lines in
    // every line count`): the deep-scan budget removes deep analysis, not this count. Lines inside an inline
    // `#[cfg(test)]` module count apart, so unit tests never push production code toward the limit.
    let rust_lengths = unit.file.is_rust.then(|| rust_file_lengths(unit.source));
    let line_count = match &rust_lengths {
        Some(lengths) => lengths.production_lines,
        None => substantive_line_count(&unit.file.display_path, unit.source),
    };
    let test_modules = rust_lengths
        .map(|lengths| lengths.test_modules)
        .unwrap_or_default();
    let rule_id = "size.file-length";
    let threshold = config.threshold(rule_id) as usize;
    // Production code lines beyond the user's threshold add the file-level finding; an oversized test module reports separately below.
    if line_count > threshold {
        let mut metadata = threshold_metadata(line_count, threshold, "lines");
        // The test-module lines ride along, so a reader sees what the production count left out.
        if !test_modules.is_empty() {
            metadata["testModuleLines"] = json!(test_modules
                .iter()
                .map(|module| module.code_lines)
                .sum::<usize>());
        }
        let mut finding = finding_with_metadata(
            SimpleFindingDescriptor {
                rule_id,
                message: format!(
                    "File has {line_count} substantive lines, above the threshold of {threshold}."
                ),
                file: unit.file,
                line: Some(1),
                severity: config.severity(rule_id, rules::builtin_severity(rule_id)),
                pillar: Pillar::Size,
            },
            metadata,
        );
        apply_limit_band(
            &mut finding,
            line_count,
            config.threshold(rule_id),
            LOWER_BAND_FILE,
            SPLIT_FILE,
        );
        findings.push(finding);
    }
    push_oversized_test_module_findings(unit, config, &test_modules, findings);
}

/// Report each inline test module over the file-length threshold on its own `mod` line, so an oversized test module
/// stays visible; it is advisory unless the user configured the rule's severity. It carries no band key, and its
/// `testModule` key names the module, so a reader can tell it from the file's production finding without the message.
fn push_oversized_test_module_findings(
    unit: &SourceUnit<'_>,
    config: &Config,
    test_modules: &[InlineTestModule],
    findings: &mut Vec<Finding>,
) {
    let rule_id = "size.file-length";
    let threshold = config.threshold(rule_id) as usize;
    for module in test_modules
        .iter()
        .filter(|module| module.code_lines > threshold)
    {
        let mut metadata = threshold_metadata(module.code_lines, threshold, "lines");
        metadata["testModule"] = json!(module.name);
        findings.push(finding_with_metadata(
            SimpleFindingDescriptor {
                rule_id,
                message: format!(
                    "Inline test module `{}` has {} substantive lines, above the threshold of {threshold}.",
                    module.name, module.code_lines
                ),
                file: unit.file,
                line: Some(module.mod_line + 1),
                severity: config.severity(rule_id, Severity::Advisory),
                pillar: Pillar::Size,
            },
            metadata,
        ));
    }
}

/// Code-line counts for one Rust file: the lines outside its inline `#[cfg(test)]` modules, and each module's own.
struct RustFileLengths {
    production_lines: usize,
    test_modules: Vec<InlineTestModule>,
}

/// One inline `#[cfg(test)]` module: its name, the 0-based line of its `mod` keyword, and its code lines.
struct InlineTestModule {
    name: String,
    mod_line: usize,
    code_lines: usize,
}

/// Split a Rust file's code lines between production code and its inline test modules, from one projection.
fn rust_file_lengths(source: &str) -> RustFileLengths {
    let comment_projection = rust_comment_scope_source(source);
    let code_view = rust_code_view(source, &comment_projection);
    let code_lines = code_line_flags(source, &comment_projection, &code_view);
    let count_code = |span: &[bool]| span.iter().filter(|is_code| **is_code).count();
    let test_modules: Vec<InlineTestModule> = inline_test_module_spans(source, &code_view)
        .into_iter()
        .map(|span| InlineTestModule {
            name: span.name,
            mod_line: span.mod_line,
            code_lines: code_lines
                .get(span.first_line..=span.last_line)
                .map_or(0, count_code),
        })
        .collect();
    let module_lines: usize = test_modules.iter().map(|module| module.code_lines).sum();
    RustFileLengths {
        production_lines: count_code(&code_lines).saturating_sub(module_lines),
        test_modules,
    }
}

/// Where one inline `#[cfg(test)]` module sits, as 0-based lines from its attribute to its closing brace.
struct InlineTestModuleSpan {
    name: String,
    first_line: usize,
    mod_line: usize,
    last_line: usize,
}

/// Find each inline `#[cfg(test)]` module in the code view, where comments and literals cannot open or close one.
/// A test module nested inside one already found is part of it. A `mod tests;` declaration has no inline body.
fn inline_test_module_spans(source: &str, code_view: &str) -> Vec<InlineTestModuleSpan> {
    static CFG_TEST_MODULE: OnceLock<Regex> = OnceLock::new();
    let pattern = static_regex(
        &CFG_TEST_MODULE,
        r"#\s*\[\s*cfg\s*\(\s*test\s*\)\s*\](?:\s*#\s*\[[^\]]*\])*\s*(?:pub(?:\s*\([^)]*\))?\s+)?(mod)\s+(?:r#)?([A-Za-z_][A-Za-z0-9_]*)\s*\{",
    );
    let starts = line_starts(source);
    let line_of = |byte: usize| byte_line_from_starts(&starts, byte).saturating_sub(1);
    let mut spans = Vec::new();
    let mut resume_at = 0usize;
    for captures in pattern.captures_iter(code_view) {
        let (Some(whole), Some(keyword), Some(name)) =
            (captures.get(0), captures.get(1), captures.get(2))
        else {
            continue;
        };
        if whole.start() < resume_at {
            continue;
        }
        // A module whose braces never close is left to the production count.
        let Some(close) = matching_brace(code_view.as_bytes(), whole.end() - 1) else {
            continue;
        };
        spans.push(InlineTestModuleSpan {
            name: name.as_str().to_string(),
            first_line: line_of(whole.start()),
            mod_line: line_of(keyword.start()),
            last_line: line_of(close),
        });
        resume_at = close;
    }
    spans
}

/// Byte index of the brace that closes the one at `open`, counting only the braces the code view keeps.
fn matching_brace(code: &[u8], open: usize) -> Option<usize> {
    let mut depth = 0usize;
    for (index, byte) in code.iter().enumerate().skip(open) {
        match byte {
            b'{' => depth += 1,
            b'}' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some(index);
                }
            }
            _ => {}
        }
    }
    None
}

/// Count lines that carry code or data: blank lines and comment-only lines are free (family
/// ratification, 2026-08-05), so required documentation cannot push a file over the size bar.
/// Rust sources drop `//` lines and nested `/* */` blocks via the string-aware comment
/// projection; hash-comment formats drop full-line `#` (and `;` for ini-style) comments; other
/// formats count every non-blank line.
fn substantive_line_count(display_path: &str, source: &str) -> usize {
    let normalized = display_path.replace('\\', "/").to_ascii_lowercase();
    if normalized.ends_with(".rs") {
        return rust_substantive_line_count(source);
    }
    let hash_comments = normalized.ends_with(".yaml")
        || normalized.ends_with(".yml")
        || normalized.ends_with(".toml");
    let semicolon_comments = normalized.ends_with(".ini");
    source
        .lines()
        .filter(|line| {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                return false;
            }
            if hash_comments && trimmed.starts_with('#') {
                return false;
            }
            if semicolon_comments && (trimmed.starts_with(';') || trimmed.starts_with('#')) {
                return false;
            }
            true
        })
        .count()
}

/// Rust-aware count of the code lines `rust_code_line_flags` marks.
fn rust_substantive_line_count(source: &str) -> usize {
    rust_code_line_flags(source)
        .into_iter()
        .filter(|is_code| *is_code)
        .count()
}

/// Mark which lines of a Rust source hold code (FAMILY-CONTRACT section 12, search `Code lines in every line count`).
///
/// A line is code when it carries a byte outside every comment and outside every attribute (`#[...]` or `#![...]`),
/// so blank, comment-only, doc-comment and attribute-only lines are free. The custom-rule comment projection is
/// string- and raw-string-aware and tracks nested block comments, so a comment marker inside a string stays code and
/// a trailing comment cannot hide the statement in front of it. A line inside a multi-line string literal is data and
/// stays code. Callers pass a lexically whole slice, such as a file or one function's lines.
pub(crate) fn rust_code_line_flags(source: &str) -> Vec<bool> {
    let comment_projection = rust_comment_scope_source(source);
    let code_view = rust_code_view(source, &comment_projection);
    code_line_flags(source, &comment_projection, &code_view)
}

/// Per-line code flags from a source, its comment projection and its code view, which share every byte position.
/// An attribute's bracket depth is carried across lines, so a multi-line attribute is free on every line it spans.
fn code_line_flags(source: &str, comment_projection: &str, code_view: &str) -> Vec<bool> {
    let mut attribute_depth = 0usize;
    source
        .lines()
        .zip(comment_projection.lines())
        .zip(code_view.lines())
        .map(|((source_line, comment_line), code_line)| {
            line_has_code(
                source_line.as_bytes(),
                comment_line.as_bytes(),
                code_line.as_bytes(),
                &mut attribute_depth,
            )
        })
        .collect()
}

/// True when one line has a non-whitespace byte outside every comment and attribute. Attribute brackets are read
/// from the code view, where string bytes are blank, so a bracket inside an attribute's string cannot end it early.
fn line_has_code(source: &[u8], comments: &[u8], code: &[u8], attribute_depth: &mut usize) -> bool {
    let mut has_code = false;
    let mut index = 0usize;
    while index < source.len() {
        let in_comment = comments.get(index).is_some_and(|byte| *byte != b' ');
        if source[index].is_ascii_whitespace() || in_comment {
            index += 1;
            continue;
        }
        index += if *attribute_depth > 0 {
            track_attribute_bracket(code.get(index), attribute_depth);
            1
        } else if let Some(opener) = attribute_opener_len(code.get(index..).unwrap_or_default()) {
            *attribute_depth = 1;
            opener
        } else {
            has_code = true;
            1
        };
    }
    has_code
}

/// Move an open attribute's bracket depth past one of its bytes; the closing bracket ends the attribute.
fn track_attribute_bracket(byte: Option<&u8>, attribute_depth: &mut usize) {
    match byte {
        Some(b'[') => *attribute_depth += 1,
        Some(b']') => *attribute_depth -= 1,
        _ => {}
    }
}

/// The length of the attribute opener (`#[` or `#![`) at the start of `rest`, when one starts there.
fn attribute_opener_len(rest: &[u8]) -> Option<usize> {
    if rest.starts_with(b"#[") {
        Some(2)
    } else if rest.starts_with(b"#![") {
        Some(3)
    } else {
        None
    }
}

/// The source with every comment byte and every string or char literal byte blanked, byte for byte, so structure
/// read from it (attribute brackets, module braces) cannot be opened or closed by text inside either.
fn rust_code_view(source: &str, comment_projection: &str) -> String {
    let bytes: Vec<u8> = strip_rust_string_literals(source)
        .bytes()
        .zip(comment_projection.bytes())
        .map(|(code, comment)| {
            if comment == b' ' || comment == b'\n' {
                code
            } else {
                b' '
            }
        })
        .collect();
    String::from_utf8_lossy(&bytes).into_owned()
}

/// Identify file shapes whose length is not a useful source-review signal.
fn file_length_is_exempt(display_path: &str) -> bool {
    let normalized = display_path.replace('\\', "/");
    // `rsplit` always yields one segment; the fallback names an unexpected empty iterator safely.
    let file_name = normalized
        .rsplit('/')
        .next()
        .unwrap_or(&normalized)
        .to_ascii_lowercase();
    file_name_is_lockfile(&file_name)
        || file_name_is_markdown(&file_name)
        || file_name.ends_with(".sh")
        || path_is_rule_definition_table(&normalized)
        || path_is_calibration_case_table(&normalized)
        || path_is_agent_hook(&normalized)
}

/// Recognise dependency lockfiles governed by their package manager.
fn file_name_is_lockfile(file_name: &str) -> bool {
    matches!(
        file_name,
        "cargo.lock" | "package-lock.json" | "yarn.lock" | "pnpm-lock.yaml"
    ) || file_name.ends_with(".lock")
}

/// Recognise Markdown prose governed by documentation review.
fn file_name_is_markdown(file_name: &str) -> bool {
    file_name.ends_with(".md") || file_name.ends_with(".markdown")
}

/// Recognise declarative rule tables that intentionally centralise many entries.
fn path_is_rule_definition_table(normalized: &str) -> bool {
    normalized.starts_with("src/rules/") && normalized.ends_with("_definitions.rs")
}

/// Recognise calibration case tables whose repeated fixtures are intentional.
fn path_is_calibration_case_table(normalized: &str) -> bool {
    normalized.starts_with("src/tests/calibration/") && normalized.ends_with("_cases.rs")
}

/// Recognise agent hook scripts governed by shell and hook-specific checks.
fn path_is_agent_hook(normalized: &str) -> bool {
    normalized.contains("/.codex/hooks/")
        || normalized.contains("/.claude/hooks/")
        || normalized.starts_with(".codex/hooks/")
        || normalized.starts_with(".claude/hooks/")
}
