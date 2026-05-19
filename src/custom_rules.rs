use super::*;
use std::borrow::Cow;

pub(crate) fn analyse(unit: &SourceUnit<'_>, config: &Config) -> Vec<Finding> {
    let mut findings = Vec::new();
    let line_offsets = line_starts(unit.source);
    for rule in &config.custom_rules {
        if !config.rule_enabled(&rule.id) || !custom_rule_applies_to_path(rule, unit.file) {
            continue;
        }
        let Some(scope_source) = scoped_source(rule.scope, unit) else {
            continue;
        };
        findings.extend(evaluate_rule(
            unit,
            rule,
            scope_source.as_ref(),
            &line_offsets,
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
            Finding::new(
                &rule.id,
                rule.message.clone(),
                unit.file.display_path.clone(),
                Some(finding_line_for_match(
                    source,
                    line_starts,
                    matched.start(),
                    matched.end(),
                )),
                rule.severity,
                rule.pillar,
                rule.confidence,
                Some(format!("byte:{}", matched.start())),
                rule.remediation.clone(),
                json!({ "scope": rule.scope.as_str() }),
            )
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

fn custom_rule_applies_to_path(rule: &CustomRule, file: &SourceFile) -> bool {
    let path = normalize_report_path(&file.display_path);
    (rule.include_paths.is_empty()
        || rule
            .include_paths
            .iter()
            .any(|pattern| path_matches(pattern, &path)))
        && !rule
            .exclude_paths
            .iter()
            .any(|pattern| path_matches(pattern, &path))
}

fn scoped_source<'a>(scope: CustomRuleScope, unit: &'a SourceUnit<'_>) -> Option<Cow<'a, str>> {
    match scope {
        CustomRuleScope::Text => Some(Cow::Borrowed(unit.source)),
        CustomRuleScope::RustCode => unit
            .file
            .is_rust
            .then(|| Cow::Owned(built_in_rules::strip_rust_string_literals(unit.source))),
        CustomRuleScope::Comments => unit
            .file
            .is_rust
            .then(|| Cow::Owned(rust_comment_scope_source(unit.source))),
    }
}

fn rust_comment_scope_source(source: &str) -> String {
    let bytes = source.as_bytes();
    let mut output = bytes
        .iter()
        .map(|byte| if *byte == b'\n' { b'\n' } else { b' ' })
        .collect::<Vec<u8>>();
    let mut index = 0usize;
    while index < bytes.len() {
        if let Some(raw_end) = built_in_rules::raw_string_end(bytes, index) {
            index = raw_end;
            continue;
        }
        if bytes[index] == b'"' {
            index = skip_quoted_string(bytes, index);
            continue;
        }
        if bytes[index] == b'/' && bytes.get(index + 1) == Some(&b'/') {
            index = copy_line_comment(bytes, &mut output, index);
            continue;
        }
        if bytes[index] == b'/' && bytes.get(index + 1) == Some(&b'*') {
            index = copy_block_comment(bytes, &mut output, index);
            continue;
        }
        index += 1;
    }
    String::from_utf8(output).expect("comment scope source stays utf-8")
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
