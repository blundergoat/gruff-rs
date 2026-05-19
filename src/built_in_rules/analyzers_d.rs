use super::*;

pub(crate) fn collect_module_function_blocks(
    item_mod: &syn::ItemMod,
    lines: &[&str],
    test_context: bool,
    blocks: &mut Vec<FunctionBlock>,
) {
    let Some((_, items)) = &item_mod.content else {
        return;
    };
    let nested_test_context = test_context || is_test_module(item_mod);
    for nested in items {
        collect_function_blocks(nested, lines, nested_test_context, blocks);
    }
}

pub(crate) struct FunctionBlockParts<'a> {
    pub(crate) lines: &'a [&'a str],
    pub(crate) name: String,
    pub(crate) param_count: usize,
    pub(crate) visibility: &'a Visibility,
    pub(crate) attrs: &'a [syn::Attribute],
    pub(crate) test_context: bool,
    pub(crate) is_async: bool,
    pub(crate) returns_bool: bool,
    pub(crate) returns_result: bool,
    pub(crate) name_start: LineColumn,
    pub(crate) block_end: LineColumn,
    pub(crate) block: &'a syn::Block,
}

pub(crate) fn function_block_from_parts(parts: FunctionBlockParts<'_>) -> FunctionBlock {
    let function_index = line_from_span(parts.name_start).saturating_sub(1);
    let start = function_start_index(parts.lines, function_index);
    let end = line_from_span(parts.block_end)
        .saturating_sub(1)
        .min(parts.lines.len().saturating_sub(1))
        .max(start);
    let body = line_slice(parts.lines, start, end);
    let is_test = has_test_attr(parts.attrs);

    FunctionBlock {
        name: parts.name,
        param_count: parts.param_count,
        start_line: start + 1,
        line_count: end.saturating_sub(start) + 1,
        body,
        is_externally_public: is_externally_public(parts.visibility),
        is_test,
        test_context: parts.test_context,
        is_async: parts.is_async,
        returns_bool: parts.returns_bool,
        returns_result: parts.returns_result,
        ignore_without_reason: has_ignore_without_reason(parts.attrs),
        body_is_declarative_literal: is_declarative_literal_body(parts.block),
    }
}

/// True iff the block is exactly one trailing expression whose shape is a
/// "data declaration": array literal, `vec!` macro, struct/enum literal,
/// or a `match` whose every arm body is a pure expression (no statements
/// inside any arm block). Used by `size.function-length` to avoid flagging
/// functions whose length is entirely table data, not logic. Anything with
/// preceding statements, control flow outside the trailing expression, or
/// match arms with embedded statement blocks is NOT declarative.
pub(crate) fn is_declarative_literal_body(block: &syn::Block) -> bool {
    if block.stmts.len() != 1 {
        return false;
    }
    match &block.stmts[0] {
        syn::Stmt::Expr(expr, None) => is_declarative_literal_expr(expr),
        _ => false,
    }
}

pub(crate) fn is_declarative_literal_expr(expr: &syn::Expr) -> bool {
    match expr {
        syn::Expr::Array(_) | syn::Expr::Struct(_) => true,
        syn::Expr::Macro(mac) => mac
            .mac
            .path
            .segments
            .last()
            .map(|segment| segment.ident == "vec")
            .unwrap_or(false),
        syn::Expr::Match(match_expr) => match_expr.arms.iter().all(|arm| {
            if let syn::Expr::Block(block_expr) = arm.body.as_ref() {
                block_expr.block.stmts.is_empty()
            } else {
                true
            }
        }),
        _ => false,
    }
}

pub(crate) fn function_start_index(lines: &[&str], index: usize) -> usize {
    let mut start = index;
    while start > 0 {
        let previous = lines[start - 1].trim();
        if previous.starts_with("#[") || previous.starts_with("///") || previous.is_empty() {
            start -= 1;
            continue;
        }
        break;
    }
    start
}

pub(crate) fn line_slice(lines: &[&str], start: usize, end: usize) -> String {
    if lines.is_empty() {
        return String::new();
    }
    lines[start..=end].join("\n")
}

pub(crate) fn count_params(
    inputs: &syn::punctuated::Punctuated<FnArg, syn::token::Comma>,
) -> usize {
    inputs
        .iter()
        .filter(|input| !matches!(input, FnArg::Receiver(_)))
        .count()
}

pub(crate) fn returns_bool(output: &ReturnType) -> bool {
    let ReturnType::Type(_, ty) = output else {
        return false;
    };
    let Type::Path(path) = ty.as_ref() else {
        return false;
    };
    path.path.is_ident("bool")
}

/// True iff the function signature returns a syntactic `Result<...>` or
/// `std::result::Result<...>`. Type aliases (`Result<T>` defined as
/// `type Result<T> = std::result::Result<T, MyError>`) cannot be detected
/// without type resolution, so they are intentionally NOT covered by this
/// rule per ADR-008.
pub(crate) fn returns_result(output: &ReturnType) -> bool {
    let ReturnType::Type(_, ty) = output else {
        return false;
    };
    let Type::Path(path) = ty.as_ref() else {
        return false;
    };
    path.path
        .segments
        .last()
        .map(|segment| segment.ident == "Result")
        .unwrap_or(false)
}

pub(crate) fn is_public(visibility: &Visibility) -> bool {
    !matches!(visibility, Visibility::Inherited)
}

/// Strict counterpart to `is_public` — see `visibility_is_externally_public`.
pub(crate) fn is_externally_public(visibility: &Visibility) -> bool {
    matches!(visibility, Visibility::Public(_))
}

pub(crate) fn has_doc_attr(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|attr| attr.path().is_ident("doc"))
}

pub(crate) fn has_ignore_without_reason(attrs: &[syn::Attribute]) -> bool {
    attrs
        .iter()
        .filter(|attr| attr.path().is_ident("ignore"))
        .any(|attr| match &attr.meta {
            syn::Meta::Path(_) => true,
            syn::Meta::List(list) => list.tokens.is_empty(),
            syn::Meta::NameValue(value) => match &value.value {
                syn::Expr::Lit(lit) => match &lit.lit {
                    syn::Lit::Str(reason) => reason.value().trim().is_empty(),
                    _ => true,
                },
                _ => true,
            },
        })
}

pub(crate) fn has_doc_comment_before(block: &str) -> bool {
    block
        .lines()
        .take_while(|line| !line.contains("fn "))
        .any(|line| line.trim_start().starts_with("///"))
}

pub(crate) fn is_generic_name(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "process" | "handle" | "do_it" | "run" | "execute" | "manage"
    )
}

pub(crate) fn is_boolean_predicate_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    let words: Vec<&str> = lower.split('_').collect();
    // Passive-voice shape (`X_was_Y`, `X_by_Y`, `X_by`) is not a predicate.
    if words.last() == Some(&"by") {
        return false;
    }
    // Predicate verbs that read as a boolean test when used anywhere in
    // the name. Subject-predicate forms (`visibility_is_public`,
    // `line_in_ranges`, `path_matches`) ride on these.
    const PREDICATE_WORDS: &[&str] = &[
        "is",
        "has",
        "can",
        "should",
        "allows",
        "supports",
        "contains",
        "needs",
        "uses",
        "matches",
        "in",
        "intersects",
        "overlaps",
    ];
    if words.iter().any(|word| PREDICATE_WORDS.contains(word)) {
        return true;
    }
    // Compound predicates that combine two words (no separator on the
    // first half).
    lower.starts_with("starts_with") || lower.starts_with("ends_with")
}

pub(crate) fn is_placeholder_identifier(name: &str) -> bool {
    matches!(name, "foo" | "bar" | "baz" | "qux")
}

pub(crate) fn strip_rust_string_literals(source: &str) -> String {
    let bytes = source.as_bytes();
    let mut output = String::with_capacity(source.len());
    let mut index = 0usize;

    while index < bytes.len() {
        if let Some(raw_end) = raw_string_end(bytes, index) {
            mask_bytes(bytes, index, raw_end, &mut output);
            index = raw_end;
            continue;
        }

        if let Some(char_end) = char_literal_end(bytes, index) {
            mask_bytes(bytes, index, char_end, &mut output);
            index = char_end;
            continue;
        }

        if bytes[index] == b'"' {
            output.push(' ');
            index += 1;
            while index < bytes.len() {
                let byte = bytes[index];
                mask_byte(byte, &mut output);
                index += 1;
                if byte == b'\\' && index < bytes.len() {
                    mask_byte(bytes[index], &mut output);
                    index += 1;
                    continue;
                }
                if byte == b'"' {
                    break;
                }
            }
            continue;
        }

        output.push(bytes[index] as char);
        index += 1;
    }

    output
}

/// Returns the byte index just past a Rust character literal that starts at
/// `start`. Recognises `'X'`, escape sequences (`'\n'`, `'\''`), byte escapes
/// (`'\x41'`), and unicode escapes (`'\u{0041}'`). Returns `None` for
/// lifetimes (`'a`, `'static`) and any other shape, so the masker leaves
/// them alone.
pub(crate) fn char_literal_end(bytes: &[u8], start: usize) -> Option<usize> {
    if bytes.get(start).copied()? != b'\'' {
        return None;
    }
    let mut cursor = start + 1;
    if bytes.get(cursor).copied()? == b'\\' {
        cursor += 1;
        let escape = bytes.get(cursor).copied()?;
        cursor += 1;
        match escape {
            b'x' => cursor = cursor.checked_add(2)?,
            b'u' => {
                if bytes.get(cursor).copied()? == b'{' {
                    cursor += 1;
                    while bytes.get(cursor).copied()? != b'}' {
                        cursor += 1;
                        if cursor.saturating_sub(start) > 12 {
                            return None;
                        }
                    }
                    cursor += 1;
                } else {
                    return None;
                }
            }
            _ => {}
        }
    } else {
        cursor += 1;
    }
    (bytes.get(cursor).copied()? == b'\'').then_some(cursor + 1)
}

/// Masks Rust comments (`//`, `///`, `//!`, `/* */`, `/** */`) into spaces
/// while preserving newlines, so line indices stay aligned. Intended to be
/// run AFTER `strip_rust_string_literals`, so comment-shaped sequences
/// inside string literals are already spaces and do not false-trigger the
/// comment detector.
pub(crate) fn strip_rust_comments_after_string_mask(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut output = String::with_capacity(input.len());
    let mut index = 0usize;
    while index < bytes.len() {
        if index + 1 < bytes.len() && bytes[index] == b'/' && bytes[index + 1] == b'/' {
            while index < bytes.len() && bytes[index] != b'\n' {
                output.push(' ');
                index += 1;
            }
            continue;
        }
        if index + 1 < bytes.len() && bytes[index] == b'/' && bytes[index + 1] == b'*' {
            output.push(' ');
            output.push(' ');
            index += 2;
            while index < bytes.len() {
                if index + 1 < bytes.len() && bytes[index] == b'*' && bytes[index + 1] == b'/' {
                    output.push(' ');
                    output.push(' ');
                    index += 2;
                    break;
                }
                let byte = bytes[index];
                if byte == b'\n' {
                    output.push('\n');
                } else {
                    output.push(' ');
                }
                index += 1;
            }
            continue;
        }
        output.push(bytes[index] as char);
        index += 1;
    }
    output
}

pub(crate) fn raw_string_end(bytes: &[u8], start: usize) -> Option<usize> {
    let (hashes, cursor) = raw_string_opening(bytes, start)?;
    find_raw_string_end(bytes, hashes, cursor).or(Some(bytes.len()))
}

pub(crate) fn raw_string_opening(bytes: &[u8], start: usize) -> Option<(usize, usize)> {
    (bytes.get(start).copied()? == b'r').then_some(())?;
    let mut cursor = start + 1;
    let hashes = count_raw_string_hashes(bytes, &mut cursor);
    (bytes.get(cursor) == Some(&b'"')).then_some((hashes, cursor + 1))
}

pub(crate) fn count_raw_string_hashes(bytes: &[u8], cursor: &mut usize) -> usize {
    let mut hashes = 0usize;
    while bytes.get(*cursor) == Some(&b'#') {
        hashes += 1;
        *cursor += 1;
    }
    hashes
}

pub(crate) fn find_raw_string_end(bytes: &[u8], hashes: usize, mut cursor: usize) -> Option<usize> {
    while cursor < bytes.len() {
        if bytes[cursor] == b'"' && raw_string_hashes_match(bytes, cursor + 1, hashes) {
            return Some(cursor + 1 + hashes);
        }
        cursor += 1;
    }
    None
}

pub(crate) fn raw_string_hashes_match(bytes: &[u8], start: usize, hashes: usize) -> bool {
    bytes
        .get(start..start + hashes)
        .is_some_and(|slice| slice.iter().all(|byte| *byte == b'#'))
}

pub(crate) fn mask_bytes(bytes: &[u8], start: usize, end: usize, output: &mut String) {
    for byte in &bytes[start..end] {
        mask_byte(*byte, output);
    }
}

pub(crate) fn mask_byte(byte: u8, output: &mut String) {
    if byte == b'\n' {
        output.push('\n');
    } else {
        output.push(' ');
    }
}

pub(crate) fn max_nesting_depth(source: &str) -> usize {
    let mut depth = 0usize;
    let mut max_depth = 0usize;
    for character in source.chars() {
        match character {
            '{' => {
                depth += 1;
                max_depth = max_depth.max(depth);
            }
            '}' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    max_depth.saturating_sub(1)
}

pub(crate) fn approximate_npath(source: &str) -> usize {
    let branch_decisions = count_regex(
        source,
        static_regex(&NPATH_BRANCH_REGEX, r"\b(if|match|for|while|loop)\b"),
    );
    let boolean_decisions = count_regex(source, static_regex(&NPATH_BOOLEAN_REGEX, r"&&|\|\||\?"));
    let mut paths = 1usize;
    for _ in 0..branch_decisions.min(20) {
        paths = paths.saturating_mul(2);
    }
    paths.saturating_add(boolean_decisions)
}

pub(crate) fn function_metrics(source: &str, cyclomatic: usize) -> FunctionMetrics {
    let tokens = metric_tokens(source);
    let unique_tokens: BTreeSet<&str> = tokens.iter().map(String::as_str).collect();
    let total_tokens = tokens.len();
    let unique_count = unique_tokens.len();
    let halstead_volume = if unique_count <= 1 {
        0.0
    } else {
        total_tokens as f64 * (unique_count as f64).log2()
    };
    let pressure = total_tokens as f64 * 0.08 + cyclomatic as f64 * 2.0 + halstead_volume / 60.0;
    let maintainability_score = 100.0 - pressure.min(100.0);

    FunctionMetrics {
        total_tokens,
        unique_tokens: unique_count,
        halstead_volume,
        maintainability_score,
    }
}

pub(crate) fn metric_tokens(source: &str) -> Vec<String> {
    static_regex(
            &METRIC_TOKEN_REGEX,
            r"[A-Za-z_][A-Za-z0-9_]*|\d+(?:\.\d+)?|==|!=|<=|>=|&&|\|\||::|->|=>|[{}()\[\];,.:+\-*/%&|^!<>?=]",
        )
        .find_iter(source)
        .map(|token| token.as_str().to_string())
        .collect()
}

pub(crate) fn round_one_decimal(value: f64) -> f64 {
    (value * 10.0).round() / 10.0
}

pub(crate) fn loop_pattern_count(source: &str, pattern: &Regex) -> usize {
    let loop_start = static_regex(&LOOP_START_REGEX, r"\b(for|while|loop)\b");
    let mut state = LoopPatternState::default();

    for line in source.lines() {
        state.process_line(line, pattern, loop_start);
    }

    state.occurrences
}

#[derive(Default)]
pub(crate) struct LoopPatternState {
    depth: usize,
    loop_depths: Vec<usize>,
    pending_loop: bool,
    occurrences: usize,
}

impl LoopPatternState {
    fn process_line(&mut self, line: &str, pattern: &Regex, loop_start: &Regex) {
        let matches: Vec<usize> = pattern.find_iter(line).map(|found| found.start()).collect();
        let mut next_match = 0usize;
        if loop_start.is_match(line) {
            self.pending_loop = true;
        }
        for (byte_index, character) in line.char_indices() {
            next_match = self.count_matches_until(&matches, next_match, byte_index);
            self.apply_source_char(character);
        }
        self.count_remaining_matches(&matches, next_match);
    }

    fn count_matches_until(
        &mut self,
        matches: &[usize],
        mut next_match: usize,
        byte_index: usize,
    ) -> usize {
        while next_match < matches.len() && matches[next_match] <= byte_index {
            self.count_match_inside_loop();
            next_match += 1;
        }
        next_match
    }

    fn count_remaining_matches(&mut self, matches: &[usize], mut next_match: usize) {
        while next_match < matches.len() {
            self.count_match_inside_loop();
            next_match += 1;
        }
    }

    fn count_match_inside_loop(&mut self) {
        if !self.loop_depths.is_empty() {
            self.occurrences += 1;
        }
    }

    fn apply_source_char(&mut self, character: char) {
        match character {
            '{' => self.enter_scope(),
            '}' => self.leave_scope(),
            _ => {}
        }
    }

    fn enter_scope(&mut self) {
        self.depth += 1;
        if self.pending_loop {
            self.loop_depths.push(self.depth);
            self.pending_loop = false;
        }
    }

    fn leave_scope(&mut self) {
        self.loop_depths
            .retain(|loop_depth| *loop_depth < self.depth);
        self.depth = self.depth.saturating_sub(1);
    }
}
