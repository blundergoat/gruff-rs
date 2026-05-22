use super::*;
use std::borrow::Cow;

pub(crate) fn analyse(unit: &SourceUnit<'_>, config: &Config) -> Vec<Finding> {
    let mut findings = Vec::new();
    for rule in &config.custom_rules {
        if !config.is_rule_enabled(&rule.id) || !custom_rule_matches_path(rule, unit.file) {
            continue;
        }
        let Some(scope_source) = scoped_source(rule.scope, unit) else {
            continue;
        };
        findings.extend(evaluate_rule(
            unit,
            rule,
            scope_source.as_ref(),
            unit.line_starts(),
        ));
    }
    findings
}

fn evaluate_rule(
    unit: &SourceUnit<'_>,
    rule: &CustomRule,
    source: &str,
    line_starts: &[usize],
) -> Vec<Finding> {
    rule.compiled_pattern
        .find_iter(source)
        .map(|matched| {
            Finding::new(FindingDescriptor {
                rule_id: rule.id.clone(),
                message: rule.message.clone(),
                file_path: unit.file.display_path.clone(),
                line: Some(finding_line_for_match(
                    source,
                    line_starts,
                    matched.start(),
                    matched.end(),
                )),
                severity: rule.severity,
                pillar: rule.pillar,
                confidence: rule.confidence,
                symbol: Some(format!("byte:{}", matched.start())),
                remediation: rule.remediation.clone(),
                metadata: json!({ "scope": rule.scope.as_str() }),
            })
        })
        .collect()
}

fn finding_line_for_match(source: &str, line_starts: &[usize], start: usize, end: usize) -> usize {
    let line_byte = source
        .as_bytes()
        .get(start..end)
        .and_then(|matched| {
            matched
                .iter()
                .position(|byte| !byte.is_ascii_whitespace())
                .map(|offset| start + offset)
        })
        .unwrap_or(start)
        .min(source.len());
    byte_line_from_starts(line_starts, line_byte)
}

fn custom_rule_matches_path(rule: &CustomRule, file: &SourceFile) -> bool {
    let path = normalize_report_path(&file.display_path);
    (rule.include_path_matchers.is_empty()
        || rule
            .include_path_matchers
            .iter()
            .any(|pattern| pattern.matches(&path)))
        && !rule
            .exclude_path_matchers
            .iter()
            .any(|pattern| pattern.matches(&path))
}

fn scoped_source<'a>(scope: CustomRuleScope, unit: &'a SourceUnit<'_>) -> Option<Cow<'a, str>> {
    match scope {
        CustomRuleScope::Text => Some(Cow::Borrowed(unit.source)),
        CustomRuleScope::RustCode => unit
            .file
            .is_rust
            .then(|| Cow::Owned(crate::parser::strip_rust_string_literals(unit.source))),
        CustomRuleScope::Comments => unit
            .file
            .is_rust
            .then(|| Cow::Owned(rust_comment_scope_source(unit.source))),
    }
}

fn rust_comment_scope_source(source: &str) -> String {
    let bytes = source.as_bytes();
    let mut output = build_blank_scope_output(bytes);
    let mut index = 0usize;
    while index < bytes.len() {
        index = advance_comment_scope(bytes, &mut output, index);
    }
    String::from_utf8(output).expect("comment scope source stays utf-8")
}

fn build_blank_scope_output(bytes: &[u8]) -> Vec<u8> {
    bytes
        .iter()
        .map(|byte| if *byte == b'\n' { b'\n' } else { b' ' })
        .collect()
}

fn advance_comment_scope(bytes: &[u8], output: &mut [u8], index: usize) -> usize {
    if let Some(raw_end) = crate::parser::raw_string_end(bytes, index) {
        return raw_end;
    }
    if bytes[index] == b'"' {
        return skip_quoted_string(bytes, index);
    }
    if starts_with_pair(bytes, index, b'/', b'/') {
        return copy_line_comment(bytes, output, index);
    }
    if starts_with_pair(bytes, index, b'/', b'*') {
        return copy_block_comment(bytes, output, index);
    }
    index + 1
}

fn starts_with_pair(bytes: &[u8], index: usize, first: u8, second: u8) -> bool {
    bytes[index] == first && bytes.get(index + 1) == Some(&second)
}

fn skip_quoted_string(bytes: &[u8], start: usize) -> usize {
    let mut index = start + 1;
    while index < bytes.len() {
        let byte = bytes[index];
        index += 1;
        if byte == b'\\' && index < bytes.len() {
            index += 1;
            continue;
        }
        if byte == b'"' {
            break;
        }
    }
    index
}

fn copy_line_comment(bytes: &[u8], output: &mut [u8], start: usize) -> usize {
    let mut index = start;
    while index < bytes.len() && bytes[index] != b'\n' {
        output[index] = bytes[index];
        index += 1;
    }
    index
}

fn copy_block_comment(bytes: &[u8], output: &mut [u8], start: usize) -> usize {
    let mut index = start;
    while index < bytes.len() {
        output[index] = bytes[index];
        if bytes[index] == b'*' && bytes.get(index + 1) == Some(&b'/') {
            output[index + 1] = bytes[index + 1];
            return index + 2;
        }
        index += 1;
    }
    index
}
