//! Function-block metrics turn parsed Rust functions into deterministic rule input.
//! The builder keeps the user's existing report anchor stable while separating
//! attached documentation from the declaration-through-body size measurement.

use super::*;

/// One parsed Rust function and the source facts used by block-level rules.
/// Users reach this internal boundary whenever a scan evaluates documentation,
/// size, complexity, test, security, or reliability findings for a function.
#[derive(Clone)]
pub(crate) struct FunctionBlock {
    pub(crate) name: String,
    pub(crate) param_count: usize,
    /// First line of the block, its attached docs and attributes included; body offsets count from here.
    pub(crate) start_line: usize,
    /// Line of the function's name, where a block finding is reported, so the report names the signature a
    /// developer edits rather than its first doc or attribute line.
    pub(crate) declaration_line: usize,
    pub(crate) line_count: usize,
    pub(crate) executable_line_count: usize,
    pub(crate) body: String,
    pub(crate) rustdoc: Option<FunctionRustdoc>,
    pub(crate) is_externally_public: bool,
    pub(crate) is_test: bool,
    pub(crate) test_context: bool,
    pub(crate) is_async: bool,
    pub(crate) returns_result: bool,
    pub(crate) ignore_without_reason: bool,
    pub(crate) body_is_declarative_literal: bool,
    /// Cyclomatic, nesting and cognitive complexity counted on the parsed body.
    pub(crate) complexity: SyntaxComplexity,
}

impl FunctionBlock {
    /// Report whether this function belongs to test code and should skip production-only rules.
    ///
    /// Returns true when the function carries a test or cfg-test attribute or was collected inside test code, and false otherwise.
    pub(crate) fn is_test_context(&self) -> bool {
        self.is_test || self.test_context
    }
}

/// Collect the function blocks declared inside an inline module body; a module declared without a body adds nothing.
///
/// `item_mod` is the parsed module and `lines` its source lines; a function-name span past the end of `lines` can panic while a block is built.
/// `test_context` is true inside test code, and it is turned on for this module's items when `is_test_module` accepts `item_mod`.
/// Each block found in the module's items is appended to `blocks`.
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

/// Raw parser facts used to build one function record before the user's rules run.
/// A scan reaches these facts after Rust source parses successfully.
pub(crate) struct FunctionBlockParts<'a> {
    pub(crate) lines: &'a [&'a str],
    pub(crate) name: String,
    pub(crate) param_count: usize,
    pub(crate) visibility: &'a Visibility,
    pub(crate) attrs: &'a [syn::Attribute],
    pub(crate) test_context: bool,
    pub(crate) is_async: bool,
    pub(crate) returns_result: bool,
    pub(crate) name_start: LineColumn,
    pub(crate) block_end: LineColumn,
    pub(crate) block: &'a syn::Block,
}

/// Build one block consumed by documentation, size, complexity, and behavior rules.
///
/// `parts` carries the parsed name, signature facts, attributes, span ends and body plus the file's lines, and is consumed.
/// A function-name span past the end of those lines can panic while the block is built.
/// Returns the block with 1-based start and declaration lines, its body text from the block start to its last line, and its rule flags.
pub(crate) fn function_block_from_parts(parts: FunctionBlockParts<'_>) -> FunctionBlock {
    let function_index = line_from_span(parts.name_start).saturating_sub(1);
    let source_context = function_source_context(parts.lines, parts.attrs, function_index);
    let start = source_context.block_start_index;
    let end = line_from_span(parts.block_end)
        .saturating_sub(1)
        .min(parts.lines.len().saturating_sub(1))
        .max(start);
    let body = line_slice(parts.lines, start, end);
    let is_test = has_test_attr(parts.attrs);
    let test_context = parts.test_context || has_cfg_test_attr(parts.attrs);

    FunctionBlock {
        name: parts.name,
        param_count: parts.param_count,
        start_line: start + 1,
        declaration_line: function_index + 1,
        line_count: end.saturating_sub(start) + 1,
        executable_line_count: declaration_code_line_count(
            &body,
            function_index.saturating_sub(start),
        ),
        body,
        rustdoc: source_context.rustdoc,
        is_externally_public: is_externally_public(parts.visibility),
        is_test,
        test_context,
        is_async: parts.is_async,
        returns_result: parts.returns_result,
        ignore_without_reason: has_ignore_without_reason(parts.attrs),
        body_is_declarative_literal: is_declarative_literal_body(parts.block),
        complexity: syntax_complexity(parts.block),
    }
}

/// Count the code lines from the declaration line to the end of the body (FAMILY-CONTRACT section 12, search `Code
/// lines in every line count`). The body slice starts at the attached docs and attributes, so it is lexically whole.
///
/// `body` is the block's text from its start line, and `declaration_offset` is the 0-based index of the declaration line within it.
/// Returns how many lines from that index on hold code, or 0 when the offset is past the body's last line.
fn declaration_code_line_count(body: &str, declaration_offset: usize) -> usize {
    rust_code_line_flags(body)
        .into_iter()
        .skip(declaration_offset)
        .filter(|is_code| *is_code)
        .count()
}

/// True iff the block is exactly one trailing expression whose shape is a
/// "data declaration": array literal, `vec!` macro, struct/enum literal,
/// or a `match` whose every arm body is a pure expression (no statements
/// inside any arm block). Used by `size.function-length` to avoid flagging
/// functions whose length is entirely table data, not logic. Anything with
/// preceding statements, control flow outside the trailing expression, or
/// match arms with embedded statement blocks is NOT declarative.
///
/// Returns true when `block` holds only such a trailing expression, and false otherwise.
pub(crate) fn is_declarative_literal_body(block: &syn::Block) -> bool {
    if block.stmts.len() != 1 {
        return false;
    }
    match &block.stmts[0] {
        syn::Stmt::Expr(expr, None) => is_declarative_literal_expr(expr),
        _ => false,
    }
}

/// Classify one trailing expression as table data or logic for `is_declarative_literal_body`.
///
/// `expr` is the expression to classify, normally a block's only trailing expression.
/// Returns true for an array or struct literal, a macro call whose path ends in `vec`, or a qualifying `match`, and false for anything else.
/// A `match` qualifies when every arm body is a non-block expression or an empty block, so an arm block holding even a tail expression fails.
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

/// Join an inclusive range of source lines back into one newline-separated text block.
///
/// `lines` holds the source lines, and `start` and `end` are the 0-based indices of the first and last line to include.
/// Returns the joined text, or an empty string when `lines` is empty.
/// Slicing panics when `end` is past the last line or `start` is more than one past `end`.
pub(crate) fn line_slice(lines: &[&str], start: usize, end: usize) -> String {
    if lines.is_empty() {
        return String::new();
    }
    lines[start..=end].join("\n")
}

/// Count a signature's declared parameters, leaving out any `self` receiver.
///
/// `inputs` is the signature's parsed, comma-separated parameter list.
/// Returns the number of non-receiver parameters, 0 for a function that takes none or only `self`.
pub(crate) fn count_params(
    inputs: &syn::punctuated::Punctuated<FnArg, syn::token::Comma>,
) -> usize {
    inputs
        .iter()
        .filter(|input| !matches!(input, FnArg::Receiver(_)))
        .count()
}

/// True iff the function signature's return type is a path whose last segment is `Result`, so `Result<...>`,
/// `std::result::Result<...>` and an alias spelled `Result`, such as `io::Result<T>`, all match.
///
/// An alias under another name (`type Res<T> = std::result::Result<T, MyError>`) cannot be detected without type resolution,
/// so it is intentionally NOT covered by this rule per ADR-008.
///
/// `output` is the signature's parsed return type.
/// Returns true for such a path and false for a function with no `->` or a return type that is not a path, such as a reference or tuple.
pub(crate) fn is_result_return_type(output: &ReturnType) -> bool {
    let ReturnType::Type(_, return_type) = output else {
        return false;
    };
    let Type::Path(path) = return_type.as_ref() else {
        return false;
    };
    path.path
        .segments
        .last()
        .map(|segment| segment.ident == "Result")
        .unwrap_or(false)
}

/// Counts occurrences of `pattern` that appear inside a loop body in
/// `source`. `count_line` selects the source lines eligible for the caller's pattern.
///
/// Returns the count of eligible matches inside scopes taken for loop bodies, or 0 when none are found.
/// A line with a loop keyword marks the next `{` from that line's start, even one before the keyword, as a loop body.
/// Each line marks at most one scope and none when `loop_header_is_static_bounded` accepts it, so this is a line-based heuristic.
pub(crate) fn loop_pattern_count_filtered<F>(source: &str, pattern: &Regex, count_line: F) -> usize
where
    F: Fn(&str) -> bool,
{
    let loop_start = static_regex(&LOOP_START_REGEX, r"\b(for|while|loop)\b");
    let mut state = LoopPatternState::default();

    for line in source.lines() {
        state.process_line(line, pattern, loop_start, &count_line);
    }

    state.occurrences
}

#[derive(Default)]
pub(crate) struct LoopPatternState {
    depth: usize,
    loop_depths: Vec<usize>,
    pending_loop_ignored: Option<bool>,
    occurrences: usize,
}

impl LoopPatternState {
    /// Advance the loop-tracking state across one source line, counting the caller's pattern matches inside scopes taken for loop bodies.
    ///
    /// `line` is the line to scan, `pattern` the caller's regex, and `count_line`, given the line as a `&str`, decides whether its matches count.
    /// `loop_start` spots a loop keyword anywhere in `line`, arming the next `{` from the line's start, even one before the keyword.
    /// A static-bounded header arms nothing, and each match counts only while an armed scope is open at its byte position.
    ///
    /// Returns nothing; the counts accumulate in `self`.
    fn process_line<F: Fn(&str) -> bool>(
        &mut self,
        line: &str,
        pattern: &Regex,
        loop_start: &Regex,
        count_line: &F,
    ) {
        let line_counts = count_line(line);
        let matches: Vec<usize> = if line_counts {
            pattern.find_iter(line).map(|found| found.start()).collect()
        } else {
            Vec::new()
        };
        let mut next_match = 0usize;
        if loop_start.is_match(line) {
            self.pending_loop_ignored = Some(loop_header_is_static_bounded(line));
        }
        for (byte_index, character) in line.char_indices() {
            next_match = self.count_matches_until(&matches, next_match, byte_index);
            self.apply_source_char(character);
        }
        self.count_remaining_matches(&matches, next_match);
    }

    /// Consume the line's matches that start at or before the current byte, counting each one while a tracked loop scope is open.
    ///
    /// `matches` holds the line's match start offsets in order and `next_match` is the index of the first one not yet counted.
    /// Returns the index of the first match that starts after `byte_index`, or `matches.len()` once every match is consumed.
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

    /// Consume any matches still left after the line's last character, counting each one while a tracked loop scope is open.
    ///
    /// `matches` holds the line's match start offsets in order and `next_match` is the index of the first one not yet counted.
    fn count_remaining_matches(&mut self, matches: &[usize], mut next_match: usize) {
        while next_match < matches.len() {
            self.count_match_inside_loop();
            next_match += 1;
        }
    }

    /// Count one pattern match when a tracked loop scope is open at the current position, and ignore it otherwise.
    fn count_match_inside_loop(&mut self) {
        if !self.loop_depths.is_empty() {
            self.occurrences += 1;
        }
    }

    /// Track brace depth for one source character, ignoring every character but braces.
    ///
    /// `character` is the line's next character: `{` enters a scope and `}` leaves one.
    fn apply_source_char(&mut self, character: char) {
        match character {
            '{' => self.enter_scope(),
            '}' => self.leave_scope(),
            _ => {}
        }
    }

    /// Open one brace scope, track it as a loop scope when a pending loop marker is not static bounded, and clear that marker.
    fn enter_scope(&mut self) {
        self.depth += 1;
        if let Some(ignored) = self.pending_loop_ignored.take() {
            if !ignored {
                self.loop_depths.push(self.depth);
            }
        }
    }

    /// Close one brace scope, dropping every loop body opened at or inside the current depth.
    fn leave_scope(&mut self) {
        self.loop_depths
            .retain(|loop_depth| *loop_depth < self.depth);
        self.depth = self.depth.saturating_sub(1);
    }
}

/// Decide whether a `for` header iterates what looks like a constant, so its braces are not treated as a loop body.
///
/// `line` is the source line that holds the loop header.
/// Returns true when the line holds `for name in`, an optional `&`, then an upper-case letter, as in `for rule in &RULES`; otherwise false.
fn loop_header_is_static_bounded(line: &str) -> bool {
    static STATIC_FOR_LOOP_REGEX: OnceLock<Regex> = OnceLock::new();
    static_regex(
        &STATIC_FOR_LOOP_REGEX,
        r"\bfor\s+[A-Za-z_][A-Za-z0-9_]*\s+in\s+&?[A-Z][A-Z0-9_]*(?:\s*\.iter\(\))?\s*\{?",
    )
    .is_match(line)
}
