use super::*;

static SQL_DYNAMIC_QUERY_REGEX: OnceLock<Regex> = OnceLock::new();
static SQL_DYNAMIC_QUERY_KEYWORD_REGEX: OnceLock<Regex> = OnceLock::new();
static TLS_VERIFICATION_DISABLED_REGEX: OnceLock<Regex> = OnceLock::new();

pub(crate) fn analyse_tls_verification_disabled(
    file: &SourceFile,
    source: &str,
    findings: &mut Vec<Finding>,
) {
    let searchable = strip_rust_comments_after_string_mask(&strip_rust_string_literals(source));
    let direct_regex = static_regex(
        &TLS_VERIFICATION_DISABLED_REGEX,
        r"\.(?:danger_accept_invalid_certs|accept_invalid_hostnames)\s*\(\s*true\s*\)",
    );
    // `let x = true;` bindings are tracked only within the function currently being
    // scanned: a new `fn` clears the set, and a binding counts only once it has
    // appeared above the sink. This stops a `true` binding in one function from
    // flagging a same-named parameter or shadowed binding in another (false positive).
    let mut true_bindings: BTreeSet<String> = BTreeSet::new();
    for (line_index, line) in searchable.lines().enumerate() {
        if is_function_start_line(line) {
            true_bindings.clear();
        }
        // Track which locals are currently bound to `true`. A later `let name = false;`
        // (or any non-`true` rebinding) clears it, so a shadowed binding no longer
        // looks like an explicit bypass at the sink.
        if let Some((name, is_true)) = boolean_let_binding(line) {
            if is_true {
                true_bindings.insert(name);
            } else {
                true_bindings.remove(&name);
            }
        }
        if direct_regex.is_match(line) || tls_bypass_uses_true_binding(line, &true_bindings) {
            findings.push(tls_verification_disabled_finding(file, line_index + 1));
        }
    }
}

fn tls_verification_disabled_finding(file: &SourceFile, line: usize) -> Finding {
    Finding::new(FindingDescriptor {
        rule_id: "security.tls-verification-disabled".to_string(),
        message: "TLS certificate or hostname verification is explicitly disabled.".to_string(),
        file_path: file.display_path.clone(),
        line: Some(line),
        severity: Severity::Warning,
        pillar: Pillar::Security,
        confidence: Confidence::High,
        symbol: None,
        remediation: Some(
            "Remove the TLS verification bypass or gate it behind non-production test code."
                .to_string(),
        ),
        metadata: json!({}),
    })
}

/// A line that opens a function body (`fn name`), used to scope `true` bindings to
/// a single function so they cannot leak into a later, unrelated function.
fn is_function_start_line(line: &str) -> bool {
    static FUNCTION_START_REGEX: OnceLock<Regex> = OnceLock::new();
    static_regex(&FUNCTION_START_REGEX, r"\bfn\s+[A-Za-z_]").is_match(line)
}

/// A `let name = <value>;` binding on this line: returns `(name, value_is_true)`.
/// Used to insert `true` bindings and to clear them when the same name is rebound
/// to a non-`true` value within the function.
fn boolean_let_binding(line: &str) -> Option<(String, bool)> {
    static LET_BINDING_REGEX: OnceLock<Regex> = OnceLock::new();
    let regex = static_regex(
        &LET_BINDING_REGEX,
        r"\blet\s+(?P<name>[a-z_][a-z0-9_]*)\s*(?::[^=]+)?=\s*(?P<value>[^;]+);",
    );
    let captures = regex.captures(line)?;
    let name = captures.name("name")?.as_str().to_string();
    let value = captures.name("value")?.as_str().trim();
    Some((name, value == "true"))
}

fn tls_bypass_uses_true_binding(line: &str, true_bindings: &BTreeSet<String>) -> bool {
    static TLS_BINDING_REGEX: OnceLock<Regex> = OnceLock::new();
    let regex = static_regex(
        &TLS_BINDING_REGEX,
        r"\.(?:danger_accept_invalid_certs|accept_invalid_hostnames)\s*\(\s*(?P<arg>[a-z_][a-z0-9_]*)\s*\)",
    );
    regex
        .captures(line)
        .and_then(|captures| captures.name("arg"))
        .is_some_and(|arg| true_bindings.contains(arg.as_str()))
}

pub(crate) fn analyse_sql_dynamic_query(
    file: &SourceFile,
    source: &str,
    findings: &mut Vec<Finding>,
) {
    let searchable = strip_rust_comments_after_string_mask(&strip_rust_string_literals(source));
    let starts = line_starts(source);
    let mut emitted = BTreeSet::new();
    push_direct_sql_dynamic_query_findings(
        file,
        source,
        &searchable,
        &starts,
        &mut emitted,
        findings,
    );
    push_bound_sql_dynamic_query_findings(
        file,
        source,
        &searchable,
        &starts,
        &mut emitted,
        findings,
    );
}

fn push_direct_sql_dynamic_query_findings(
    file: &SourceFile,
    source: &str,
    searchable: &str,
    starts: &[usize],
    emitted: &mut BTreeSet<usize>,
    findings: &mut Vec<Finding>,
) {
    let regex = static_regex(
        &SQL_DYNAMIC_QUERY_REGEX,
        r"(?:^|[^\w])(?P<method>query|execute|prepare)\s*\(\s*&?\s*format!\s*\(",
    );
    for captures in regex.captures_iter(searchable) {
        let Some(full_match) = captures.get(0) else {
            continue;
        };
        let method = captures
            .name("method")
            .map(|method| method.as_str())
            .unwrap_or("query");
        let Some(format_start) =
            format_start_in_match(source, full_match.start(), full_match.end())
        else {
            continue;
        };
        if !dynamic_sql_template_is_flaggable(source, format_start) {
            continue;
        }
        let line = byte_line_from_starts(starts, full_match.start());
        if emitted.insert(line) {
            findings.push(sql_dynamic_query_finding(file, line, method));
        }
    }
}

fn push_bound_sql_dynamic_query_findings(
    file: &SourceFile,
    source: &str,
    searchable: &str,
    starts: &[usize],
    emitted: &mut BTreeSet<usize>,
    findings: &mut Vec<Finding>,
) {
    // Track format!-bound locals per function (cleared at each `fn`, inserted only
    // once seen above the sink) so a dynamic binding in one function cannot flag a
    // same-named static or parameter binding in another - mirroring the TLS path.
    let mut dynamic_bindings: BTreeSet<String> = BTreeSet::new();
    for (line_index, line) in searchable.lines().enumerate() {
        if is_function_start_line(line) {
            dynamic_bindings.clear();
        }
        let line_start = starts.get(line_index).copied().unwrap_or_default();
        if let Some(name) = dynamic_format_binding_name(line, source, line_start) {
            dynamic_bindings.insert(name);
        }
        let Some((method, binding)) = sql_sink_binding(line) else {
            continue;
        };
        if !dynamic_bindings.contains(binding) {
            continue;
        }
        let line_number = line_index + 1;
        if emitted.insert(line_number) {
            findings.push(sql_dynamic_query_finding(file, line_number, method));
        }
    }
}

fn sql_dynamic_query_finding(file: &SourceFile, line: usize, method: &str) -> Finding {
    Finding::new(FindingDescriptor {
        rule_id: "security.sql-dynamic-query".to_string(),
        message: format!(
            "Direct dynamic SQL argument passed to `{method}(...)`; review query construction."
        ),
        file_path: file.display_path.clone(),
        line: Some(line),
        severity: Severity::Warning,
        pillar: Pillar::Security,
        confidence: Confidence::High,
        symbol: Some(method.to_string()),
        remediation: Some(
            "Use static SQL with bind parameters instead of formatting query text. If the formatted query is non-production (test fixture, migration scratch), add the host path to `paths.ignore` in `.gruff-rs.yaml`."
                .to_string(),
        ),
        metadata: json!({ "method": method }),
    })
}

fn dynamic_format_binding_name(line: &str, source: &str, line_start: usize) -> Option<String> {
    static SQL_FORMAT_BINDING_REGEX: OnceLock<Regex> = OnceLock::new();
    let regex = static_regex(
        &SQL_FORMAT_BINDING_REGEX,
        r"\blet\s+(?P<name>[a-z_][a-z0-9_]*)\s*(?::[^=]+)?=\s*&?\s*format!\s*\(",
    );
    let captures = regex.captures(line)?;
    let name = captures.name("name")?.as_str().to_string();
    let full_match = captures.get(0)?;
    let format_start = format_start_in_match(
        source,
        line_start + full_match.start(),
        line_start + full_match.end(),
    )?;
    if !dynamic_sql_template_is_flaggable(source, format_start) {
        return None;
    }
    Some(name)
}

fn sql_sink_binding(line: &str) -> Option<(&str, &str)> {
    static SQL_BINDING_SINK_REGEX: OnceLock<Regex> = OnceLock::new();
    let regex = static_regex(
        &SQL_BINDING_SINK_REGEX,
        r"(?:^|[^\w])(?P<method>query|execute|prepare)\s*\(\s*&?\s*(?P<arg>[a-z_][a-z0-9_]*)\s*\)",
    );
    let captures = regex.captures(line)?;
    Some((
        captures.name("method")?.as_str(),
        captures.name("arg")?.as_str(),
    ))
}

fn dynamic_sql_template_is_flaggable(source: &str, format_start: usize) -> bool {
    let Some(template) = format_template_at(source, format_start) else {
        return true;
    };
    template_is_flaggable(&template)
        && !fixed_placeholder_arity_is_safe(source, format_start, &template)
}

fn format_start_in_match(source: &str, match_start: usize, match_end: usize) -> Option<usize> {
    let bounded_end = match_end.min(source.len());
    source
        .get(match_start..bounded_end)?
        .find("format!")
        .map(|relative| match_start + relative)
}

fn template_is_flaggable(template: &str) -> bool {
    let literal_fragments = format_literal_fragments(template);
    static_regex(
        &SQL_DYNAMIC_QUERY_KEYWORD_REGEX,
        r"(?i)\b(?:SELECT|INSERT|UPDATE|DELETE|ALTER|DROP|CREATE|SHOW|FROM|WHERE|TRUNCATE|MERGE|GRANT|REVOKE|REPLACE|UPSERT|VACUUM)\b",
    )
    .is_match(&literal_fragments)
}

fn format_literal_fragments(template: &str) -> String {
    let mut output = String::with_capacity(template.len());
    let mut chars = template.chars().peekable();
    while let Some(character) = chars.next() {
        append_format_literal_fragment(character, &mut chars, &mut output);
    }
    output
}

fn append_format_literal_fragment(
    character: char,
    chars: &mut std::iter::Peekable<std::str::Chars<'_>>,
    output: &mut String,
) {
    match character {
        '{' if chars.peek() == Some(&'{') => push_escaped_format_brace(chars, output, '{'),
        '{' => skip_format_placeholder(chars, output),
        '}' if chars.peek() == Some(&'}') => push_escaped_format_brace(chars, output, '}'),
        '}' => output.push(' '),
        other => output.push(other),
    }
}

fn push_escaped_format_brace(
    chars: &mut std::iter::Peekable<std::str::Chars<'_>>,
    output: &mut String,
    brace: char,
) {
    chars.next();
    output.push(brace);
}

fn skip_format_placeholder(
    chars: &mut std::iter::Peekable<std::str::Chars<'_>>,
    output: &mut String,
) {
    for inner in chars.by_ref() {
        if inner == '}' {
            break;
        }
    }
    output.push(' ');
}

fn fixed_placeholder_arity_is_safe(source: &str, format_start: usize, template: &str) -> bool {
    let placeholders = placeholder_arg_names(template);
    // Every placeholder must be a simple identifier proven to be a fixed `?` list.
    // A positional `{}` or indexed `{0}` interpolates a value the exemption cannot
    // prove is a `?` list (it is formatted straight into the SQL text), so its
    // presence alongside a proven list must not suppress the finding.
    !placeholders.is_empty()
        && placeholders.iter().all(|name| {
            is_simple_identifier(name)
                && placeholder_binding_is_fixed_question_list(source, name, format_start)
        })
        && later_uses_params_from_iter(source, format_start)
}

/// Every `{...}` placeholder argument token in `template`, in order. A positional
/// `{}` yields an empty string and an indexed `{0}` yields its digits, so a caller
/// can reject placeholders that are not simple identifiers it can reason about by
/// name. Escaped `{{`/`}}` are skipped, and a format spec after `:` or `!` is
/// dropped so `{name:?}` yields `name`.
fn placeholder_arg_names(template: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut chars = template.chars().peekable();
    while let Some(character) = chars.next() {
        if character != '{' {
            continue;
        }
        if chars.peek() == Some(&'{') {
            chars.next();
            continue;
        }
        let mut raw = String::new();
        for inner in chars.by_ref() {
            if inner == '}' {
                break;
            }
            raw.push(inner);
        }
        let name = raw.split([':', '!']).next().unwrap_or_default().trim();
        names.push(name.to_string());
    }
    names
}

fn is_simple_identifier(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first == '_' || first.is_ascii_alphabetic())
        && chars.all(|character| character == '_' || character.is_ascii_alphanumeric())
}

fn placeholder_binding_is_fixed_question_list(
    source: &str,
    name: &str,
    format_start: usize,
) -> bool {
    let function_start = enclosing_function_start(source, format_start);
    source[function_start..format_start]
        .lines()
        .rev()
        .any(|line| {
            line_is_name_binding(line, name)
                && line.contains(".join(\",\")")
                && (line.contains("std::iter::repeat_n(\"?\"") || line.contains("vec![\"?\";"))
        })
}

/// Byte offset where the function enclosing `format_start` begins. Recognises
/// `fn`, `pub fn`, `async fn`, and indented `impl` methods via
/// `is_function_start_line`, not just a bare `fn` at column zero, so the
/// fixed-`?` proof window stays inside one function: a helper's `let x = ...`
/// binding must not vouch for a same-named parameter in a later public function.
fn enclosing_function_start(source: &str, format_start: usize) -> usize {
    let mut start = 0;
    let mut offset = 0;
    for line in source[..format_start].split_inclusive('\n') {
        if is_function_start_line(line) {
            start = offset;
        }
        offset += line.len();
    }
    start
}

/// True when `line` binds exactly `name` (`let name` / `let mut name`). A
/// non-identifier char must follow the name so `placeholders` does not match a
/// `placeholders_safe` binding.
fn line_is_name_binding(line: &str, name: &str) -> bool {
    let line = line.trim_start();
    ["let ", "let mut "].iter().any(|prefix| {
        line.strip_prefix(prefix)
            .and_then(|rest| rest.strip_prefix(name))
            .is_some_and(|after| {
                !after.starts_with(|character: char| {
                    character == '_' || character.is_ascii_alphanumeric()
                })
            })
    })
}

fn later_uses_params_from_iter(source: &str, format_start: usize) -> bool {
    source[format_start..]
        .lines()
        .take(12)
        .any(|line| line.contains("params_from_iter("))
}

fn format_template_at(source: &str, format_start: usize) -> Option<String> {
    source
        .get(format_start..)?
        .starts_with("format!")
        .then_some(())?;
    let mut index = format_start + "format!".len();
    index = skip_ascii_whitespace(source, index);
    (source.as_bytes().get(index) == Some(&b'(')).then_some(())?;
    index = skip_ascii_whitespace(source, index + 1);
    parse_rust_string_literal_at(source, index)
}

fn skip_ascii_whitespace(source: &str, mut index: usize) -> usize {
    while source
        .as_bytes()
        .get(index)
        .is_some_and(|byte| byte.is_ascii_whitespace())
    {
        index += 1;
    }
    index
}

fn parse_rust_string_literal_at(source: &str, index: usize) -> Option<String> {
    parse_raw_string_literal_at(source, index)
        .or_else(|| parse_double_quoted_string_literal_at(source, index))
}

fn parse_raw_string_literal_at(source: &str, index: usize) -> Option<String> {
    let bytes = source.as_bytes();
    (bytes.get(index) == Some(&b'r')).then_some(())?;
    let mut cursor = index + 1;
    while bytes.get(cursor) == Some(&b'#') {
        cursor += 1;
    }
    (bytes.get(cursor) == Some(&b'"')).then_some(())?;
    let hashes = cursor.saturating_sub(index + 1);
    let content_start = cursor + 1;
    let terminator = format!("\"{}", "#".repeat(hashes));
    let relative_end = source.get(content_start..)?.find(&terminator)?;
    Some(source[content_start..content_start + relative_end].to_string())
}

fn parse_double_quoted_string_literal_at(source: &str, index: usize) -> Option<String> {
    (source.as_bytes().get(index) == Some(&b'"')).then_some(())?;
    let mut content = String::new();
    let mut escaped = false;
    for (relative, character) in source[index + 1..].char_indices() {
        if escaped {
            content.push(character);
            escaped = false;
            continue;
        }
        match character {
            '\\' => escaped = true,
            '"' => {
                let _end = index + 1 + relative + character.len_utf8();
                return Some(content);
            }
            other => content.push(other),
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sql_template_keyword_gate_uses_literal_fragments_only() {
        assert!(template_is_flaggable("SELECT * FROM users WHERE id = {id}"));
        assert!(template_is_flaggable("select * from users where id = {id}"));
        assert!(template_is_flaggable("UPDATE t SET v = {v}"));
        assert!(template_is_flaggable("TRUNCATE TABLE {table}"));
        assert!(template_is_flaggable(
            "MERGE INTO {table} USING src ON id = {id}"
        ));
        assert!(template_is_flaggable("GRANT ALL ON {table} TO {user}"));
        assert!(!template_is_flaggable("//item[{idx}]"));
        assert!(!template_is_flaggable("--limit={n}"));
        assert!(!template_is_flaggable("{SELECT}"));
        assert!(!template_is_flaggable("{{literal}}"));
    }

    #[test]
    fn format_template_extraction_handles_raw_escaped_and_multiline_literals() {
        let source = r##"
fn probe(id: i64, table: &str) {
    let _normal = format!("SELECT \"quoted\" FROM users WHERE id = {id}");
    let _raw = format!(r#"SELECT * FROM {table} WHERE name = "sam""#);
    let _multiline = format!(
        "SELECT *
FROM users
WHERE id = {id}"
    );
}
"##;
        let normal = source.find("format!(\"SELECT").expect("normal format");
        let raw = source.find("format!(r#").expect("raw format");
        let multiline = source.find("format!(\n").expect("multiline format");

        assert_eq!(
            format_template_at(source, normal).as_deref(),
            Some("SELECT \"quoted\" FROM users WHERE id = {id}")
        );
        assert_eq!(
            format_template_at(source, raw).as_deref(),
            Some("SELECT * FROM {table} WHERE name = \"sam\"")
        );
        assert_eq!(
            format_template_at(source, multiline).as_deref(),
            Some("SELECT *\nFROM users\nWHERE id = {id}")
        );
    }
}
