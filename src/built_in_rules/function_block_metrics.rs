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

pub(crate) fn is_bool_return_type(output: &ReturnType) -> bool {
    let ReturnType::Type(_, return_type) = output else {
        return false;
    };
    let Type::Path(path) = return_type.as_ref() else {
        return false;
    };
    path.path.is_ident("bool")
}

/// True iff the function signature returns a syntactic `Result<...>` or
/// `std::result::Result<...>`. Type aliases (`Result<T>` defined as
/// `type Result<T> = std::result::Result<T, MyError>`) cannot be detected
/// without type resolution, so they are intentionally NOT covered by this
/// rule per ADR-008.
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
