//! TLS and dynamic-SQL detectors turn narrow Rust source shapes into security findings.
//! Operators reach them through normal project analysis when local calls expose a reviewable
//! bypass or formatted query, while bounded source evidence keeps the report deterministic.

use super::*;

static SQL_DYNAMIC_QUERY_REGEX: OnceLock<Regex> = OnceLock::new();
static SQL_DYNAMIC_QUERY_SHAPE_REGEX: OnceLock<Regex> = OnceLock::new();
static SQL_BLOCK_COMMENT_REGEX: OnceLock<Regex> = OnceLock::new();
static SQL_LINE_COMMENT_REGEX: OnceLock<Regex> = OnceLock::new();
static SQL_WHITESPACE_REGEX: OnceLock<Regex> = OnceLock::new();
static TLS_VERIFICATION_DISABLED_REGEX: OnceLock<Regex> = OnceLock::new();

/// Flag `danger_accept_invalid_certs` or `accept_invalid_hostnames` calls passed `true` directly or through a local bound to `true`.
///
/// `source` is the file text, scanned line by line with string literals and comments masked, and `file` is the file each finding names.
/// Per line, only the first non-`mut` `let` of a lowercase name updates the tracked set: `true` adds it, any other value removes it.
/// Each function-start line clears the set, and each matching line appends one `security.tls-verification-disabled` finding to `findings`.
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

/// Build the warning for an explicit TLS verification bypass.
///
/// `file` is the scanned file, and `line` is the one-based line of the bypass call.
/// Returns a high-confidence `security.tls-verification-disabled` warning with removal advice.
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
///
/// `line` is one source line, and the dynamic SQL checks use the same boundary.
/// Returns true when `line` contains the word `fn`, whitespace, and an ASCII letter or underscore, and false otherwise.
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

/// Detect a TLS bypass call whose argument is a local currently bound to `true`.
///
/// `line` is one masked source line, and `true_bindings` holds the names the caller recorded as bound to `true`, including on this line.
/// Returns true when the first bypass call on the line whose argument is a lowercase identifier passes one of those names, and false otherwise.
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

/// Flag `query`, `execute` or `prepare` calls given a `format!` string that `dynamic_sql_template_is_flaggable` accepts, inline or through a local.
/// That is a template that cannot be read, or a SQL-shaped one outside the fixed `?` list exemption.
///
/// `source` is the file text; calls are matched with string literals and comments masked, while templates are read from the original.
/// `file` is the file each finding names, and each flagged line appends one `security.sql-dynamic-query` finding to `findings`.
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

/// Flag `query`, `execute` or `prepare` calls whose argument is an inline `format!` that `dynamic_sql_template_is_flaggable` accepts.
///
/// `searchable` is the masked copy of `source` that is matched, `source` supplies the template text, and `starts` maps offsets to lines.
/// `emitted` holds the lines already reported and gains each new one; each new line appends one finding for `file` to `findings`.
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

/// Flag `query`, `execute` or `prepare` calls passed a local recorded since the last function-start line from a `format!` that
/// `dynamic_sql_template_is_flaggable` accepts.
///
/// `searchable` is the masked copy of `source` scanned line by line; `source` supplies template text and `starts` gives line byte offsets.
/// `emitted` holds the lines already reported and gains each new one; each new line appends one finding for `file` to `findings`.
/// A binding on the sink's own line counts, and a later `let` that rebinds the name to something else does not clear it.
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

/// Build the warning for a dynamic SQL string passed to a query sink.
///
/// `file` is the scanned file, `line` is the one-based line the caller reports, and `method` is the sink name: `query`, `execute` or `prepare`.
/// Returns a high-confidence `security.sql-dynamic-query` warning naming `method` in its message, symbol and metadata.
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
            "Review this SQL-shaped formatted value, then prefer static SQL with bind parameters. If the named sink is a reviewed non-SQL wrapper, rename it so it does not read as a SQL sink."
                .to_string(),
        ),
        metadata: json!({ "method": method }),
    })
}

/// Find the local a line binds to a `format!` value that `dynamic_sql_template_is_flaggable` accepts.
///
/// `line` is one masked source line, and `line_start` is its byte offset in `source`, the original text the template is read from.
/// Returns the name from the line's first `let name = format!(` binding, or None when there is none or its template is not flaggable.
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

/// Find a SQL sink call on one line whose single argument is a plain local name.
///
/// `line` is one masked source line.
/// Returns the method name (`query`, `execute` or `prepare`) and argument name of the first such call, or None when there is none.
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

/// Decide whether the `format!` template at an offset counts as dynamic SQL.
///
/// `source` is the original file text, and `format_start` is the byte offset of `format!` in it.
/// Returns true when the template cannot be read or has a SQL statement shape outside the fixed `?` list exemption, and false otherwise.
fn dynamic_sql_template_is_flaggable(source: &str, format_start: usize) -> bool {
    let Some(template) = format_template_at(source, format_start) else {
        return true;
    };
    template_is_flaggable(&template)
        && !fixed_placeholder_arity_is_safe(source, format_start, &template)
}

/// Locate the `format!` macro inside a regex match so its template can be read.
///
/// `source` is the original file text, and `match_start` and `match_end` bound the match, with `match_end` clamped to the text length.
/// Returns the byte offset of the first `format!` in that range, or None when there is none or the range is not a valid slice.
fn format_start_in_match(source: &str, match_start: usize, match_end: usize) -> Option<usize> {
    let bounded_end = match_end.min(source.len());
    source
        .get(match_start..bounded_end)?
        .find("format!")
        .map(|relative| match_start + relative)
}

/// English words that mark a sentence rather than a select list or update target. A real column
/// list is identifiers, commas, functions, stars, and aliases; it does not contain bare articles or
/// conjunctions. Only the clause between the verb and its partner keyword is inspected, so a
/// `WHERE` literal containing ordinary prose still leaves a genuine query flaggable.
const STATEMENT_CLAUSE_PROSE_WORDS: &[&str] = &[
    "the", "an", "of", "so", "about", "for", "this", "that", "your", "our", "please", "then",
];

/// Reports whether the clause between `SELECT`/`UPDATE` and its partner keyword reads as prose.
/// `Select the note from the archive` satisfies the bare keyword shape but is a user-facing string.
///
/// `sql_shape_text` is the normalised template text, with placeholders blanked and whitespace folded.
/// Returns true when a clause word matches a listed prose word, ignoring case, and false otherwise or when the text has no such clause.
fn statement_clause_is_prose(sql_shape_text: &str) -> bool {
    static STATEMENT_CLAUSE_REGEX: OnceLock<Regex> = OnceLock::new();
    let clause_regex = static_regex(
        &STATEMENT_CLAUSE_REGEX,
        r"(?is)^\s*(?:SELECT|UPDATE)\b(.*?)\b(?:FROM|SET)\b",
    );
    let Some(captures) = clause_regex.captures(sql_shape_text) else {
        return false;
    };
    let Some(clause) = captures.get(1) else {
        return false;
    };
    // Underscores stay inside a word so an identifier such as `the_table` is not read as an article.
    clause
        .as_str()
        .split(|character: char| !character.is_ascii_alphanumeric() && character != '_')
        .any(|word| {
            STATEMENT_CLAUSE_PROSE_WORDS
                .iter()
                .any(|prose_word| word.eq_ignore_ascii_case(prose_word))
        })
}

/// Reports whether a format template retains a supported SQL statement shape after placeholders.
///
/// `template` is the raw `format!` string; placeholders become spaces and SQL comments are removed before the shape check.
/// Returns true for a recognised SQL statement shape, and false for a prose-like `SELECT` or `UPDATE` clause or any other text.
fn template_is_flaggable(template: &str) -> bool {
    let sql_shape_text = normalise_sql_shape_text(&format_literal_fragments(template));
    // A sentence that merely opens with a statement verb is not a query the user is building.
    if statement_clause_is_prose(&sql_shape_text) {
        return false;
    }
    static_regex(
        &SQL_DYNAMIC_QUERY_SHAPE_REGEX,
        r"(?ix)^
        (?:
            SELECT\b.*\bFROM\b
          # A FROM-less SELECT is valid in PostgreSQL and SQLite. Placeholders
          # normalise to spaces, so requiring no literal word after SELECT keeps
          # an all-interpolated SELECT template visible without matching prose.
          | SELECT\b [\s,()*.]* $
          | INSERT\b.*\bINTO\b
          | UPDATE\b.*\bSET\b
          | DELETE(?:\s+[A-Z_][A-Z0-9_.$]*(?:\s*,\s*[A-Z_][A-Z0-9_.$]*)*)?\s+FROM\b
          | WITH\b.*\bAS\s*\(.*\)\s*(?:
                SELECT\b.*\bFROM\b
              | INSERT\b.*\bINTO\b
              | UPDATE\b.*\bSET\b
              | DELETE(?:\s+[A-Z_][A-Z0-9_.$]*(?:\s*,\s*[A-Z_][A-Z0-9_.$]*)*)?\s+FROM\b
              | MERGE\s+INTO\b
              | REPLACE\s+INTO\b
              | UPSERT\s+INTO\b
            )
          | ALTER(?:\s+(?:TABLE|DATABASE|SCHEMA|INDEX|VIEW|TYPE|USER|ROLE|SYSTEM|SEQUENCE|FUNCTION|PROCEDURE)\b|\s*$)
          | DROP(?:\s+(?:TABLE|DATABASE|SCHEMA|INDEX|(?:MATERIALIZED\s+)?VIEW|TYPE|USER|ROLE|SEQUENCE|FUNCTION|PROCEDURE|TRIGGER|EXTENSION)\b|\s*$)
          | CREATE(?:\s+(?:(?:OR\s+REPLACE|UNIQUE|TEMP|TEMPORARY)\s+)*(?:TABLE|DATABASE|SCHEMA|INDEX|(?:MATERIALIZED\s+)?VIEW|TYPE|USER|ROLE|SEQUENCE|FUNCTION|PROCEDURE|TRIGGER|EXTENSION)\b|\s*$)
          | SHOW(?:\s+(?:TABLES?|DATABASES?|SCHEMAS?|COLUMNS?|INDEX(?:ES)?|CREATE|GRANTS?|VARIABLES?|STATUS|CONFIG|SETTINGS?)\b|\s*$)
          | TRUNCATE(?:\s+TABLE\b|\s*$)
          | MERGE\s+INTO\b
          | GRANT\b(?:.*\bON\b.*\bTO\b|\s+[A-Z_][A-Z0-9_$]*\s+TO\b|\s+TO\b)
          | REVOKE\b(?:.*\bON\b.*\bFROM\b|\s+[A-Z_][A-Z0-9_$]*\s+FROM\b|\s+FROM\b)
          | REPLACE\s+INTO\b
          | UPSERT\s+INTO\b
          | VACUUM(?:\s+(?:FULL|FREEZE|VERBOSE|ANALYZE)\b|\s*$)
        )",
    )
    .is_match(&sql_shape_text)
}

/// Removes SQL comments and folds whitespace before the bounded statement-shape comparison.
///
/// `template` is the template text after placeholders were replaced.
/// Returns the text with `/* */` and `--` comments replaced by spaces, whitespace runs folded to one space, and both ends trimmed.
fn normalise_sql_shape_text(template: &str) -> String {
    let without_block_comments =
        static_regex(&SQL_BLOCK_COMMENT_REGEX, r"(?s)/\*.*?\*/").replace_all(template, " ");
    let without_line_comments = static_regex(&SQL_LINE_COMMENT_REGEX, r"(?m)--[^\r\n]*")
        .replace_all(&without_block_comments, " ");
    static_regex(&SQL_WHITESPACE_REGEX, r"\s+")
        .replace_all(&without_line_comments, " ")
        .trim()
        .to_string()
}

/// Reduce a `format!` template to its literal text so placeholder contents cannot form SQL keywords.
///
/// `template` is the template string as written.
/// Returns the text with each placeholder and each lone `}` replaced by a space, and each doubled brace collapsed to one.
fn format_literal_fragments(template: &str) -> String {
    let mut output = String::with_capacity(template.len());
    let mut chars = template.chars().peekable();
    while let Some(character) = chars.next() {
        append_format_literal_fragment(character, &mut chars, &mut output);
    }
    output
}

/// Translate one template character into literal-only output, consuming the rest of a placeholder or escaped brace.
///
/// `character` is the character just read, `chars` is the rest of the template, and `output` receives the translated text.
/// A doubled brace becomes one brace, a placeholder or lone `}` becomes one space, and `chars` is advanced past what was consumed.
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

/// Emit one literal brace for an escaped `{{` or `}}` pair.
///
/// `chars` is advanced past the second brace of the pair, and `brace` is the character pushed onto `output`.
fn push_escaped_format_brace(
    chars: &mut std::iter::Peekable<std::str::Chars<'_>>,
    output: &mut String,
    brace: char,
) {
    chars.next();
    output.push(brace);
}

/// Drop the contents of one placeholder from the literal-only output.
///
/// `chars` is advanced past the next `}`, or to the end when there is none, and `output` receives one space in place of the placeholder.
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

/// Apply the fixed `?` list exemption from textual markers near the template, without tracing data flow.
///
/// `source` is the original file text, `format_start` is the byte offset of the `format!`, and `template` is its string.
/// Returns true only when the template has placeholders, each a simple identifier passing the raw-text fixed `?` list check,
/// and the text `params_from_iter(` appears within twelve lines starting at the `format!`; false otherwise.
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

/// Check that a placeholder argument is a plain ASCII identifier.
///
/// `value` is the placeholder token, which is empty for a positional `{}`.
/// Returns true when it starts with an ASCII letter or `_` and continues with ASCII letters, digits or `_`, and false for empty or other text.
fn is_simple_identifier(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first == '_' || first.is_ascii_alphabetic())
        && chars.all(|character| character == '_' || character.is_ascii_alphanumeric())
}

/// Look for an earlier raw line that binds a placeholder local and carries comma-joined `?` list markers.
///
/// `source` is the original file text, `name` is the placeholder's local, and `format_start` is the `format!` offset that ends the search.
/// Returns true when a raw line since the last function-start line starts by binding `name` and contains `.join(",")` and a repetition marker,
/// either `std::iter::repeat_n("?"` or a `vec!` repeat of `"?"`, even inside a trailing comment; false otherwise.
///
/// A later rebinding of `name` before `format_start` is not checked.
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

/// Byte offset of the last function-start line before `format_start`. Recognises `fn`, `pub fn`, `async fn`, and indented `impl`
/// methods via `is_function_start_line`, not just a bare `fn` at column zero.
///
/// The fixed-`?` proof window therefore starts at the nearest function line: a helper's `let x = ...` binding must not vouch for
/// a same-named parameter in a later public function.
///
/// `source` is the original file text, searched up to `format_start`.
/// Returns the byte offset of the last function-start line in that text, or zero when there is none.
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
///
/// Returns true for such a binding after leading whitespace is trimmed, and false otherwise.
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

/// Search for the text `params_from_iter(` just after a formatted query.
///
/// `source` is the original file text, and `format_start` is the `format!` offset where the search begins.
/// Returns true when `params_from_iter(` appears in the twelve lines starting at `format_start`, and false otherwise.
fn later_uses_params_from_iter(source: &str, format_start: usize) -> bool {
    source[format_start..]
        .lines()
        .take(12)
        .any(|line| line.contains("params_from_iter("))
}

/// Read the template string literal passed as the first argument to `format!`.
///
/// `source` is the original file text, and `format_start` is the byte offset where `format!` begins.
/// Returns the literal's text, or None when `format!` is not followed by `(` and a complete plain or raw string literal.
/// In a plain literal each backslash escape is reduced to the character after it, so `\n` reads as `n`.
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

/// Advance past a run of ASCII whitespace bytes.
///
/// `source` is the text to scan, and `index` is the byte offset to start from.
/// Returns `index` moved past any ASCII whitespace, stopping at the first other byte or the end of the text.
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

/// Read a raw or plain Rust string literal that starts at a byte offset.
///
/// `source` is the original file text, and `index` is the offset of the literal's first character.
/// Returns the contents from the raw-string parser, else from the plain-string parser, or None when neither finds a literal there.
fn parse_rust_string_literal_at(source: &str, index: usize) -> Option<String> {
    parse_raw_string_literal_at(source, index)
        .or_else(|| parse_double_quoted_string_literal_at(source, index))
}

/// Read a raw string literal such as `r"..."` or `r#"..."#` starting at a byte offset.
///
/// `source` is the original file text, and `index` is the offset of the `r` prefix.
/// Returns the text between the opening quote and the first closing quote followed by the same number of `#` marks.
/// Returns None when `index` does not start an `r`, hashes and quote prefix, or the literal never closes.
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

/// Read a plain double-quoted string literal starting at a byte offset.
///
/// `source` is the original file text, and `index` is the offset of the opening quote.
/// Returns the contents with each backslash escape reduced to the character after it.
/// Returns None when there is no quote at `index` or the literal never closes.
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
    /// Keeps statement shapes visible after comments while rejecting placeholders and prose.
    fn sql_template_shape_gate_uses_literal_fragments_only() {
        assert!(template_is_flaggable("SELECT * FROM users WHERE id = {id}"));
        assert!(template_is_flaggable("select * from users where id = {id}"));
        assert!(template_is_flaggable("UPDATE t SET v = {v}"));
        assert!(template_is_flaggable(
            "DELETE target FROM {table} AS target WHERE target.id = {id}"
        ));
        assert!(template_is_flaggable(
            "-- tenant table\nSELECT id FROM {table} WHERE id = {id}"
        ));
        assert!(template_is_flaggable(
            "/* tenant table */ WITH rows AS (SELECT id FROM {table}) SELECT id FROM rows"
        ));
        assert!(template_is_flaggable("TRUNCATE TABLE {table}"));
        assert!(template_is_flaggable(
            "MERGE INTO {table} USING src ON id = {id}"
        ));
        assert!(template_is_flaggable("GRANT ALL ON {table} TO {user}"));
        // A sentence may open with a statement verb and still reach its partner keyword. Only the
        // clause between the two is inspected, so an identifier such as `the_id` stays flaggable.
        assert!(!template_is_flaggable(
            "Select the note from the archive about {topic}"
        ));
        assert!(!template_is_flaggable(
            "Update the settings so the profile name is set to {name}"
        ));
        assert!(template_is_flaggable("SELECT the_id FROM {table}"));
        assert!(!template_is_flaggable("Show the report from {source}"));
        assert!(!template_is_flaggable(
            "From the archive, select the note about {topic}"
        ));
        assert!(!template_is_flaggable(
            "from df | uniq `{column}` | take 500"
        ));
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
