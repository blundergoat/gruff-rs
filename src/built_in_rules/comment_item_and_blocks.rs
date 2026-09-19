use super::*;

pub(crate) fn analyse_comment_rules(file: &SourceFile, source: &str, findings: &mut Vec<Finding>) {
    let masked = strip_rust_string_literals(source);
    let comments = extract_rust_comments(&masked);
    for comment in &comments {
        analyse_stale_todo_comment(file, comment, findings);
    }
    if !is_ui_test_source(&masked) {
        analyse_commented_out_code(file, &comments, findings);
    }
}

pub(crate) fn analyse_stale_todo_comment(
    file: &SourceFile,
    comment: &RustComment,
    findings: &mut Vec<Finding>,
) {
    const MARKERS: &[&str] = &["TODO", "FIXME", "HACK", "XXX"];
    for marker in MARKERS {
        let Some((after, found_marker)) = find_marker(&comment.text, marker) else {
            continue;
        };
        if !has_durable_reference(after) {
            findings.push(stale_todo_finding(file, comment, &found_marker));
        }
        return;
    }
}

fn stale_todo_finding(file: &SourceFile, comment: &RustComment, found_marker: &str) -> Finding {
    Finding::new(FindingDescriptor {
        rule_id: "docs.stale-todo".to_string(),
        message: format!("{found_marker} comment lacks an owner, issue reference, or reason."),
        file_path: file.display_path.clone(),
        line: Some(comment.line),
        severity: Severity::Advisory,
        pillar: Pillar::Documentation,
        confidence: Confidence::High,
        symbol: None,
        remediation: Some(
            "Add an owner (@name), issue (#123 or URL), or a colon-prefixed reason.".to_string(),
        ),
        metadata: json!({ "marker": found_marker, "missingReference": true }),
    })
}

pub(crate) fn find_marker<'a>(text: &'a str, marker: &str) -> Option<(&'a str, String)> {
    let mut search_from = 0usize;
    while let Some(rel) = text[search_from..].find(marker) {
        let pos = search_from + rel;
        let before_ok = pos == 0 || {
            let byte = text.as_bytes()[pos - 1];
            !byte.is_ascii_alphanumeric() && byte != b'_'
        };
        let after_pos = pos + marker.len();
        let after_ok = match text.as_bytes().get(after_pos) {
            None => true,
            Some(byte) => !byte.is_ascii_alphanumeric() && *byte != b'_',
        };
        if before_ok && after_ok {
            return Some((&text[after_pos..], marker.to_string()));
        }
        search_from = pos + marker.len();
    }
    None
}

pub(crate) fn has_durable_reference(after_marker: &str) -> bool {
    let trimmed = after_marker.trim_start();
    if let Some(rest) = trimmed.strip_prefix('(') {
        return paren_reference_is_durable(rest);
    }
    if let Some(rest) = trimmed.strip_prefix('[') {
        return bracket_reference_is_durable(rest);
    }
    if let Some(rest) = trimmed.strip_prefix(':') {
        return rest.trim().len() >= 5;
    }
    false
}

fn paren_reference_is_durable(after_open_paren: &str) -> bool {
    let Some(end) = after_open_paren.find(')') else {
        return false;
    };
    let inner = &after_open_paren[..end];
    inner.contains('#')
        || inner.contains('@')
        || inner.starts_with("GH-")
        || inner.contains("://")
        || (inner.contains(':') && inner.trim().len() >= 3)
}

fn bracket_reference_is_durable(after_open_bracket: &str) -> bool {
    let Some(end) = after_open_bracket.find(']') else {
        return false;
    };
    let inner = &after_open_bracket[..end];
    inner.contains('#') || inner.contains('@') || inner.starts_with("GH-") || inner.contains("://")
}

/// Report non-doc comments holding disabled Rust code, one finding per line. A line must look like code by
/// [`is_disabled_rust_code`] and belong to a snippet that parses: its whole comment run, trimmed of prose
/// before the first code-looking line and after the last line that ends the way code does, or a window of
/// lines starting at it. A trailing `//` comment inside the disabled code is not part of it. A
/// Markdown-fenced example is documentation and placeholder pseudocode such as `if .. { insert }` is prose, so
/// neither is reported; the caller skips a clippy UI test file.
pub(crate) fn analyse_commented_out_code(
    file: &SourceFile,
    comments: &[RustComment],
    findings: &mut Vec<Finding>,
) {
    for block in contiguous_comment_blocks(comments) {
        let code: Vec<&str> = block
            .iter()
            .map(|comment| without_trailing_comment(&comment.text))
            .collect();
        let first_code = code
            .iter()
            .position(|line| is_disabled_rust_code(line))
            .unwrap_or(0);
        let last_code = code
            .iter()
            .rposition(|line| line.ends_with([';', '{', '}', ',', ')', ']']))
            .map_or(code.len(), |index| index + 1)
            .max(first_code + 1);
        let is_whole_snippet = is_snippet(&code[first_code..last_code]);
        for (index, comment) in block.iter().enumerate() {
            let is_in_whole = is_whole_snippet && (first_code..last_code).contains(&index);
            if is_disabled_rust_code(code[index]) && (is_in_whole || is_snippet_start(&code, index))
            {
                analyse_commented_out_code_comment(file, comment, findings);
            }
        }
    }
}

/// Report whether lines form disabled code: they parse as Rust and hold no pseudocode placeholder. Comment text
/// is untrusted, so text the parser could recurse through too deeply is never parsed: a snippet longer than
/// 16 KiB, or holding more than 256 tokens that can open a nested expression (a bracket, a prefix operator, a
/// closure bar, or `return`, `break`, `yield`, `move` or `box`), counts as prose. A comment such as
/// `// let x = ((((…1))));` nested thousands deep would otherwise overflow the stack and abort the run.
fn is_snippet(lines: &[&str]) -> bool {
    const MAX_SNIPPET_BYTES: usize = 16 * 1024;
    const MAX_NESTING_TOKENS: usize = 256;
    let text = lines.join("\n");
    if text.len() > MAX_SNIPPET_BYTES {
        return false;
    }
    let nesting_marks = text
        .chars()
        .filter(|character| {
            matches!(
                character,
                '(' | '[' | '{' | '<' | '|' | '-' | '!' | '*' | '&'
            )
        })
        .count();
    let nesting_words = text
        .split(|character: char| !character.is_alphanumeric() && character != '_')
        .filter(|word| matches!(*word, "return" | "break" | "yield" | "move" | "box"))
        .count();
    nesting_marks + nesting_words <= MAX_NESTING_TOKENS
        && !has_code_placeholder(&text)
        && is_parseable_rust(&text)
}

/// Report whether a snippet that parses starts at `start`, trying the shortest window first, so prose after it
/// in the same comment run does not hide it. A snippet ends where code does, so only a window whose last line
/// ends in `;`, `}`, `)` or `]` is parsed; a run of `{`-ending lines costs no parse at all.
fn is_snippet_start(code: &[&str], start: usize) -> bool {
    const WINDOW_LINES: usize = 24;
    (start + 1..=code.len().min(start + WINDOW_LINES))
        .filter(|&end| code[end - 1].ends_with([';', '}', ')', ']']))
        .any(|end| is_snippet(&code[start..end]))
}

/// Report whether a file is a clippy or rustc UI test: some line's own first comment is an annotation such as
/// `//~^ ERROR` or `//~v lint_name`. A `//~` mentioned inside another comment, a doc comment or a block comment,
/// and a `//~~~~` or `//~ Helpers` banner, do not count.
fn is_ui_test_source(masked: &str) -> bool {
    static UI_ANNOTATION_REGEX: OnceLock<Regex> = OnceLock::new();
    let annotation = static_regex(
        &UI_ANNOTATION_REGEX,
        r"^//~(?:\^+|v+|\|)?\s*(?:ERROR|WARN|WARNING|NOTE|HELP|SUGGESTION|[a-z][a-z0-9_:]*)\b",
    );
    masked.lines().any(|line| {
        line.find("//").is_some_and(|position| {
            !line[..position].contains("/*") && annotation.is_match(&line[position..])
        })
    })
}

/// Split non-doc comments into runs on consecutive lines, leaving out Markdown-fenced lines, so each run
/// can be judged as one snippet. A fence never reaches past the end of its run.
fn contiguous_comment_blocks(comments: &[RustComment]) -> Vec<Vec<&RustComment>> {
    let mut blocks: Vec<Vec<&RustComment>> = Vec::new();
    let mut in_fence = false;
    let mut previous_line: Option<usize> = None;
    for comment in comments.iter().filter(|comment| !comment.is_doc) {
        if previous_line.is_none_or(|line| comment.line != line + 1) {
            in_fence = false;
            blocks.push(Vec::new());
        }
        previous_line = Some(comment.line);
        if comment.text.trim_start().starts_with("```") {
            in_fence = !in_fence;
            continue;
        }
        if let Some(block) = blocks.last_mut().filter(|_| !in_fence) {
            block.push(comment);
        }
    }
    // A run made only of a fenced example keeps no line, and an empty run holds nothing to judge.
    blocks.retain(|block| !block.is_empty());
    blocks
}

/// Report whether text parses as Rust items or as statements inside a block.
fn is_parseable_rust(text: &str) -> bool {
    syn::parse_str::<syn::File>(text).is_ok()
        || syn::parse_str::<syn::Block>(&format!("{{\n{text}\n}}")).is_ok()
}

/// Report a placeholder that marks pseudocode outside string literals: `...`, `…`, or a bare `..` standing
/// for an elided expression.
fn has_code_placeholder(text: &str) -> bool {
    let code = crate::strip_rust_string_literals(text);
    code.contains("...")
        || code.contains('…')
        || code
            .match_indices("..")
            .any(|(index, _)| is_elided_expression(&code, index))
}

/// A `..` stands for an elided expression when spaces surround it and what precedes it is a keyword, an
/// operator or the line start, as in `if .. {` or `x = ..;`. A spaced range (`0 .. n`, `start .. end`), a rest
/// pattern (`Some(..)`, `{ x, .. }`, `(first, ..)`), a slice (`[..]`) and a struct update
/// (`..Default::default()`) are code.
fn is_elided_expression(code: &str, index: usize) -> bool {
    const KEYWORDS: &[&str] = &[
        "if", "match", "while", "for", "in", "return", "else", "let", "loop",
    ];
    let before = &code[..index];
    let after = &code[index + 2..];
    let is_spaced_before = before.is_empty() || before.ends_with(char::is_whitespace);
    let is_spaced_after =
        after.is_empty() || after.starts_with(char::is_whitespace) || after.starts_with(';');
    if !is_spaced_before || !is_spaced_after {
        return false;
    }
    let previous = before.trim_end();
    // Step back by the separator's own width: a Rust identifier such as `café` may end in a multi-byte letter.
    let word_start = previous
        .char_indices()
        .rev()
        .find(|(_, character)| !character.is_alphanumeric() && *character != '_')
        .map_or(0, |(position, character)| position + character.len_utf8());
    let previous_word = &previous[word_start..];
    if previous_word.is_empty() {
        return !matches!(
            previous.chars().last(),
            Some(',' | '(' | '[' | '{' | ')' | ']')
        );
    }
    KEYWORDS.contains(&previous_word)
}

/// Emit one commented-out-code finding for a comment the caller has judged to be disabled code.
pub(crate) fn analyse_commented_out_code_comment(
    file: &SourceFile,
    comment: &RustComment,
    findings: &mut Vec<Finding>,
) {
    findings.push(Finding::new(FindingDescriptor {
                rule_id: "docs.commented-out-code".to_string(),
                message: "Comment payload looks like disabled Rust code; remove or document intent.".to_string(),
                file_path: file.display_path.clone(),
                line: Some(comment.line),
                severity: Severity::Advisory,
                pillar: Pillar::Documentation,
                confidence: Confidence::Medium,
                symbol: None,
                remediation: Some(
                    "Delete the commented-out code or convert it to a comment explaining why it is intentionally kept."
                        .to_string(),
                ),
                metadata: json!({}),
            }));
}

pub(crate) fn is_disabled_rust_code(text: &str) -> bool {
    let trimmed = text.trim();
    if trimmed.is_empty() || trimmed.len() < 5 {
        return false;
    }
    const STARTERS: &[&str] = &[
        "let ",
        "let mut ",
        "fn ",
        "pub fn ",
        "pub(",
        "use ",
        "if ",
        "match ",
        "for ",
        "while ",
        "loop {",
        "return ",
        "return;",
        "struct ",
        "enum ",
        "trait ",
        "impl ",
        "type ",
        "const ",
        "static ",
        "async fn ",
        "unsafe ",
        "mod ",
        "mut ",
        "self.",
    ];
    let starter_ok = STARTERS.iter().any(|prefix| trimmed.starts_with(prefix));
    if !starter_ok {
        return false;
    }
    let last = trimmed.as_bytes().last().copied().unwrap_or(0);
    matches!(last, b';' | b'}' | b'{')
}

pub(crate) fn analyse_item_rules(file: &SourceFile, ast: &syn::File, findings: &mut Vec<Finding>) {
    for item in &ast.items {
        analyse_public_item(file, item, findings);
    }
}

pub(crate) fn analyse_public_item(file: &SourceFile, item: &Item, findings: &mut Vec<Finding>) {
    match item {
        Item::Mod(item_mod) => analyse_public_module_item(file, item_mod, findings),
        Item::Struct(item_struct) => {
            analyse_public_named_item_doc(
                file,
                PublicItemDoc {
                    visibility: &item_struct.vis,
                    attrs: &item_struct.attrs,
                    name: item_struct.ident.to_string(),
                    span: item_struct.ident.span(),
                },
                findings,
            );
        }
        Item::Enum(item_enum) => {
            analyse_public_named_item_doc(
                file,
                PublicItemDoc {
                    visibility: &item_enum.vis,
                    attrs: &item_enum.attrs,
                    name: item_enum.ident.to_string(),
                    span: item_enum.ident.span(),
                },
                findings,
            );
        }
        Item::Trait(item_trait) => {
            analyse_public_named_item_doc(
                file,
                PublicItemDoc {
                    visibility: &item_trait.vis,
                    attrs: &item_trait.attrs,
                    name: item_trait.ident.to_string(),
                    span: item_trait.ident.span(),
                },
                findings,
            );
        }
        _ => {}
    }
}

pub(crate) fn analyse_public_module_item(
    file: &SourceFile,
    item_mod: &syn::ItemMod,
    findings: &mut Vec<Finding>,
) {
    if item_mod.content.is_some() {
        analyse_public_named_item_doc(
            file,
            PublicItemDoc {
                visibility: &item_mod.vis,
                attrs: &item_mod.attrs,
                name: item_mod.ident.to_string(),
                span: item_mod.ident.span(),
            },
            findings,
        );
    }
    if let Some((_, items)) = &item_mod.content {
        for nested in items {
            analyse_public_item(file, nested, findings);
        }
    }
}

pub(crate) struct PublicItemDoc<'a> {
    pub(crate) visibility: &'a Visibility,
    pub(crate) attrs: &'a [syn::Attribute],
    pub(crate) name: String,
    pub(crate) span: proc_macro2::Span,
}

pub(crate) fn analyse_public_named_item_doc(
    file: &SourceFile,
    item: PublicItemDoc<'_>,
    findings: &mut Vec<Finding>,
) {
    if is_externally_public(item.visibility) && !has_doc_attr(item.attrs) {
        push_missing_public_item_doc(file, item.name, item.span, findings);
    }
}

pub(crate) fn push_missing_public_item_doc(
    file: &SourceFile,
    name: String,
    span: proc_macro2::Span,
    findings: &mut Vec<Finding>,
) {
    findings.push(Finding::new(FindingDescriptor {
        rule_id: "docs.missing-public-doc".to_string(),
        message: format!(
            "Public item `{name}` needs a brief intent description above its declaration (one plain-English line, not a restatement of the type)."
        ),
        file_path: file.display_path.clone(),
        line: Some(line_from_span(span.start())),
        severity: Severity::Advisory,
        pillar: Pillar::Documentation,
        confidence: Confidence::Medium,
        symbol: Some(name),
        remediation: Some(
            "Add a one-line `/// Description.` above the declaration. This rule wants content, not boilerplate - if your project policy is 'no comments', that policy is about avoiding comments that restate code, not about removing documentation. The description should answer 'what is this for, what does it represent, what should the caller know'."
                .to_string(),
        ),
        metadata: json!({}),
    }));
}

pub(crate) fn rust_function_blocks(ast: &syn::File, source: &str) -> Vec<FunctionBlock> {
    let lines: Vec<&str> = source.lines().collect();
    let mut blocks = Vec::new();

    for item in &ast.items {
        collect_function_blocks(item, &lines, false, &mut blocks);
    }

    blocks
}

pub(crate) fn collect_function_blocks(
    item: &Item,
    lines: &[&str],
    test_context: bool,
    blocks: &mut Vec<FunctionBlock>,
) {
    match item {
        Item::Fn(item_fn) => push_item_function_block(item_fn, lines, test_context, blocks),
        Item::Impl(item_impl) => push_impl_function_blocks(item_impl, lines, test_context, blocks),
        Item::Mod(item_mod) => {
            collect_module_function_blocks(item_mod, lines, test_context, blocks)
        }
        _ => {}
    }
}

pub(crate) fn push_item_function_block(
    item_fn: &syn::ItemFn,
    lines: &[&str],
    test_context: bool,
    blocks: &mut Vec<FunctionBlock>,
) {
    blocks.push(function_block_from_parts(FunctionBlockParts {
        lines,
        name: item_fn.sig.ident.to_string(),
        param_count: count_params(&item_fn.sig.inputs),
        visibility: &item_fn.vis,
        attrs: &item_fn.attrs,
        test_context,
        is_async: item_fn.sig.asyncness.is_some(),
        returns_bool: is_bool_return_type(&item_fn.sig.output),
        returns_result: is_result_return_type(&item_fn.sig.output),
        name_start: item_fn.sig.ident.span().start(),
        block_end: item_fn.block.span().end(),
        block: &item_fn.block,
    }));
}

pub(crate) fn push_impl_function_blocks(
    item_impl: &syn::ItemImpl,
    lines: &[&str],
    test_context: bool,
    blocks: &mut Vec<FunctionBlock>,
) {
    let impl_test_context =
        test_context || has_test_attr(&item_impl.attrs) || has_cfg_test_attr(&item_impl.attrs);
    for impl_item in &item_impl.items {
        if let ImplItem::Fn(method) = impl_item {
            push_impl_method_function_block(method, lines, impl_test_context, blocks);
        }
    }
}

pub(crate) fn push_impl_method_function_block(
    method: &syn::ImplItemFn,
    lines: &[&str],
    test_context: bool,
    blocks: &mut Vec<FunctionBlock>,
) {
    blocks.push(function_block_from_parts(FunctionBlockParts {
        lines,
        name: method.sig.ident.to_string(),
        param_count: count_params(&method.sig.inputs),
        visibility: &method.vis,
        attrs: &method.attrs,
        test_context,
        is_async: method.sig.asyncness.is_some(),
        returns_bool: is_bool_return_type(&method.sig.output),
        returns_result: is_result_return_type(&method.sig.output),
        name_start: method.sig.ident.span().start(),
        block_end: method.block.span().end(),
        block: &method.block,
    }));
}
